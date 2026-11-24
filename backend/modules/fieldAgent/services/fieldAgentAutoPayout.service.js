/**
 * BARBER ENGINE V1
 * backend/modules/fieldAgent/services/fieldAgentAutoPayout.service.js
 *
 * FA-P4-D Step 1 — CashfreePayoutProvider wired into the EXISTING Field
 * Agent payout lifecycle and the SAME wallet engine (WalletBalanceService /
 * WalletLedger, entityType FIELD_AGENT):
 *
 *   REQUESTED  (hold  AVAILABLE -> LOCKED)                       unchanged
 *   APPROVED by an admin  -> PROCESSING  (LOCKED -> PROCESSING)  unchanged
 *        provider chosen at approval from Revenue Settings ->
 *        "Auto Payout Enabled":  OFF -> MANUAL (ManualProvider path, untouched)
 *                                ON  -> CASHFREE
 *   CASHFREE transfer (beneficiary reuse/create, then transfer)
 *   SUCCESS -> PAID   (PROCESSING debited, UTR + provider ref saved)
 *   FAILED  -> FAILED (PROCESSING -> AVAILABLE, fundsReleased)
 *
 * The setting is CommercialPolicyVersion.autoPayoutEnabled — the field the
 * existing Finance -> Revenue Settings page already edits; no new setting.
 *
 * Why the transfer is NOT executed inside SettlementEngine.execute(): that
 * runs the provider inside the caller's DB transaction. For an async
 * external gateway that is unsafe — if the transaction aborted after
 * Cashfree accepted the transfer, money would be sent while the wallet
 * rolled back. Instead the approval transaction commits first (funds
 * PROCESSING, provider CASHFREE), and only then is Cashfree called, via the
 * same PayoutProviderResolver / provider contract. If the process dies in
 * between, the payout is a visible PROCESSING/CASHFREE row that
 * reconciliation resolves using the deterministic transfer_id. Manual
 * result/retry/cancel refuse CASHFREE payouts.
 *
 * Final states arrive from (a) the signed Cashfree webhook and (b) the
 * reconciliation job polling transfer status. Both funnel through
 * applyTransferOutcome(), which is idempotent (status guard + the wallet
 * ledger's own idempotency keys).
 */

import mongoose from "mongoose";
import CommercialPolicyVersion from "../models/CommercialPolicyVersion.js";
import { COMMERCIAL_POLICY_STATUS } from "../constants/commercialPolicy.constants.js";
import User from "../../../models/User.js";
import WalletBalanceService from "../../../services/WalletBalanceService.js";
import PayoutProviderResolver from "../../../services/settlement/PayoutProviderResolver.js";
import { CASHFREE_PROVIDER_NAME } from "../../../services/settlement/providers/CashfreePayoutProvider.js";
import { buildBeneficiaryId } from "../../../services/settlement/cashfree/cashfreePayoutClient.js";
import { assertValidProviderResult } from "../../../services/settlement/PayoutProvider.js";
import { SETTLEMENT_STATUS } from "../../../services/settlement/SettlementEnums.js";
import { isCashfreePayoutConfigured } from "../../../services/settlement/cashfree/cashfreePayoutClient.js";
import { decrypt } from "../../kyc/services/encryption.service.js";
import KYC from "../../kyc/models/KYC.js";
import { APPLICANT_TYPE } from "../../kyc/constants/kyc.constants.js";
import FieldAgent from "../models/FieldAgent.js";
import FieldAgentAuditEvent from "../models/FieldAgentAuditEvent.js";
import FieldAgentPayoutRequest, {
  FIELD_AGENT_PAYOUT_STATUS,
  FIELD_AGENT_PAYOUT_PROVIDER,
} from "../models/FieldAgentPayoutRequest.js";
import { AUDIT_ACTOR_TYPE, AUDIT_ACTION, AUDIT_ENTITY_TYPE } from "../constants/fieldAgent.constants.js";
import { Errors } from "../../../utils/response.js";
import logger from "../../../utils/logger.js";

const WALLET_TYPE = "FIELD_AGENT";
const MAX_ATTEMPTS = 6;
const isTransientConflict = (err) =>
  err?.hasErrorLabel?.("TransientTransactionError") || err?.code === 112 || err?.codeName === "WriteConflict";

// ─── SETTING (Finance -> Revenue Settings -> Auto Payout Enabled) ───
// Read from the current PUBLISHED CommercialPolicyVersion — the same row the
// Revenue Settings page edits. No published version = OFF.
export const isAutoPayoutEnabled = async () => {
  const version = await CommercialPolicyVersion.findOne({ status: COMMERCIAL_POLICY_STATUS.PUBLISHED }).select("autoPayoutEnabled").lean();
  return version?.autoPayoutEnabled === true;
};

// ─── DESTINATION (decrypted bank account, never persisted) ──────────
/**
 * Resolves the full bank destination from the agent's verified KYC and
 * checks it still matches the snapshot taken when the withdrawal was
 * requested. Returns null when it cannot be safely resolved — the
 * caller then leaves the payout in the manual queue untouched.
 */
export const resolveDestination = async (payout) => {
  const fieldAgent = await FieldAgent.findById(payout.fieldAgentRef).select("userRef").lean();
  if (!fieldAgent) return null;
  const [kyc, user] = await Promise.all([
    KYC.findOne({ ownerId: fieldAgent.userRef, applicantType: APPLICANT_TYPE.FIELD_AGENT, isDeleted: { $ne: true } }).select("bank").lean(),
    User.findById(fieldAgent.userRef).select("phone").lean(),
  ]);
  const bank = kyc?.bank;
  if (!bank || bank.pennyDropStatus !== "SUCCESS" || !bank.encryptedAccount) return null;

  const accountNumber = decrypt(bank.encryptedAccount);
  const snap = payout.bankSnapshot || {};
  if (!accountNumber) return null;
  if (bank.ifsc !== snap.ifsc || bank.maskedAccount !== snap.maskedAccount) return null;
  if (!String(snap.maskedAccount || "").endsWith(accountNumber.slice(-4))) return null;

  const phone = String(user?.phone || "").replace(/\D/g, "").slice(-10);
  if (phone.length !== 10) return null;

  return { name: bank.accountHolder, accountNumber, ifsc: bank.ifsc, phone };
};

// Plain (non-transactional) writes can still hit a WriteConflict when they
// race a transaction that touches the same payout document (e.g. a webhook
// arriving while the initiating transaction is open). Retry those.
const retryOnConflict = async (fn) => {
  let lastErr;
  for (let attempt = 0; attempt < 5; attempt++) {
    try { return await fn(); } catch (err) {
      lastErr = err;
      if (!isTransientConflict(err)) throw err;
      await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
    }
  }
  throw lastErr;
};

// ─── TRANSACTION HELPER ─────────────────────────────────────────────
const withTxn = async (fn) => {
  let lastErr;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const session = await mongoose.startSession();
    try {
      session.startTransaction();
      const out = await fn(session);
      await session.commitTransaction();
      return out;
    } catch (err) {
      if (session.inTransaction()) await session.abortTransaction();
      lastErr = err;
      if (isTransientConflict(err) && attempt < MAX_ATTEMPTS - 1) {
        // back off so the transaction that holds the payout row can commit
        await new Promise((r) => setTimeout(r, 200 * (attempt + 1)));
        continue;
      }
      throw err;
    } finally {
      session.endSession();
    }
  }
  throw lastErr;
};

const audit = (session, payout, action, oldStatus, newValue, reason) =>
  FieldAgentAuditEvent.create(
    [{
      entityType: AUDIT_ENTITY_TYPE.FIELD_AGENT_PAYOUT_REQUEST,
      entityId:   payout._id,
      actorRef:   null,
      actorType:  AUDIT_ACTOR_TYPE.SYSTEM,
      action,
      oldValue:   { status: oldStatus },
      newValue,
      ...(reason ? { reason } : {}),
    }],
    { session }
  );

const walletMove = (payout, extra) => ({
  entityType:    WALLET_TYPE,
  entityId:      payout.fieldAgentRef,
  amountInPaise: payout.amountInPaise,
  refType:       "WITHDRAWAL",
  refId:         payout._id,
  triggeredBy:   "SYSTEM",
  ...extra,
});

// ─── OUTCOME (webhook + reconciliation + immediate response) ────────
/**
 * Idempotently applies a final provider outcome to a CASHFREE payout.
 * @param {"SUCCESS"|"FAILED"} outcome
 * @returns {Promise<{applied:boolean, reason?:string, payout?:object}>}
 */
export const applyTransferOutcome = async ({ payoutId, outcome, utr = null, providerPayoutId = null, providerStatus = null, failureReason = null, providerResponse = null }) => {
  if (!mongoose.isValidObjectId(payoutId)) return { applied: false, reason: "INVALID_ID" };

  return withTxn(async (session) => {
    const payout = await FieldAgentPayoutRequest.findById(payoutId).session(session);
    if (!payout || payout.payoutProvider !== FIELD_AGENT_PAYOUT_PROVIDER.CASHFREE) {
      return { applied: false, reason: "NOT_A_CASHFREE_PAYOUT" };
    }

    if (outcome === SETTLEMENT_STATUS.SUCCESS) {
      if (payout.status === FIELD_AGENT_PAYOUT_STATUS.PAID) return { applied: false, reason: "ALREADY_PAID", payout };
      if (payout.status !== FIELD_AGENT_PAYOUT_STATUS.PROCESSING) {
        // e.g. we already failed+released this payout and Cashfree now says SUCCESS:
        // money left the platform without a wallet debit. Never auto-resolve — flag it.
        logger.error("[FieldAgentAutoPayout] SUCCESS reported for a payout that is not PROCESSING — needs manual review", { payoutId: String(payout._id), status: payout.status });
        return { applied: false, reason: `STATUS_${payout.status}`, payout };
      }
      const from = payout.status;
      payout.status = FIELD_AGENT_PAYOUT_STATUS.PAID;
      payout.utr = utr || payout.utr;
      payout.isOpen = false;
      payout.providerStatus = providerStatus || "SUCCESS";
      if (providerPayoutId) payout.providerPayoutId = providerPayoutId;
      if (providerResponse) payout.providerResponse = providerResponse;
      await payout.save({ session });

      await WalletBalanceService.completePayout(walletMove(payout, {
        idempotencyKey: `payout:complete:${payout._id}`,
        session,
        remarks: utr ? `Cashfree UTR: ${utr}` : "Cashfree payout confirmed",
      }));
      await audit(session, payout, AUDIT_ACTION.FIELD_AGENT_PAYOUT_PAID, from, { status: payout.status, utr: payout.utr, provider: CASHFREE_PROVIDER_NAME });
      return { applied: true, payout };
    }

    // outcome FAILED
    if (payout.status === FIELD_AGENT_PAYOUT_STATUS.FAILED) return { applied: false, reason: "ALREADY_FAILED", payout };
    if (payout.status !== FIELD_AGENT_PAYOUT_STATUS.PROCESSING) {
      logger.error("[FieldAgentAutoPayout] FAILED/REVERSED reported for a payout that is not PROCESSING — needs manual review", { payoutId: String(payout._id), status: payout.status });
      return { applied: false, reason: `STATUS_${payout.status}`, payout };
    }
    const from = payout.status;
    payout.status = FIELD_AGENT_PAYOUT_STATUS.FAILED;
    payout.failureReason = String(failureReason || "Cashfree transfer failed").slice(0, 500);
    payout.isOpen = false;
    payout.fundsReleased = true;
    payout.providerStatus = providerStatus || "FAILED";
    if (providerPayoutId) payout.providerPayoutId = providerPayoutId;
    if (providerResponse) payout.providerResponse = providerResponse;
    await payout.save({ session });

    // PROCESSING -> AVAILABLE
    await WalletBalanceService.failPayout(walletMove(payout, {
      idempotencyKey: `payout:fail:${payout._id}`,
      session,
      remarks: payout.failureReason,
    }));
    await audit(session, payout, AUDIT_ACTION.FIELD_AGENT_PAYOUT_FAILED, from, { status: payout.status, failureReason: payout.failureReason, provider: CASHFREE_PROVIDER_NAME }, payout.failureReason);
    return { applied: true, payout };
  });
};

// ─── PROVIDER SELECTION (called by approvePayout, before its transaction) ──
/**
 * Which provider should pay this payout? CASHFREE only when Auto Payout is
 * ON in Revenue Settings, Cashfree credentials are configured, and the bank
 * destination can be proven identical to the requested snapshot. Otherwise
 * MANUAL — the existing ManualProvider path, unchanged.
 */
export const selectPayoutProvider = async (payout) => {
  if (!(await isAutoPayoutEnabled())) return FIELD_AGENT_PAYOUT_PROVIDER.MANUAL;
  if (!isCashfreePayoutConfigured()) return FIELD_AGENT_PAYOUT_PROVIDER.MANUAL;
  if (!(await resolveDestination(payout))) return FIELD_AGENT_PAYOUT_PROVIDER.MANUAL;
  return FIELD_AGENT_PAYOUT_PROVIDER.CASHFREE;
};

// ─── DISPATCH (call Cashfree for a payout already PROCESSING/CASHFREE) ──
/**
 * Beneficiary reuse/create + transfer through CashfreePayoutProvider.
 * Safe to call repeatedly (deterministic beneficiary + transfer ids).
 */
export const dispatchCashfreeTransfer = async (payoutId) => {
  // Without Payouts credentials nothing can be sent: leave the payout exactly as it is
  // (still PROCESSING, funds held) — no DB read, no state change, no network call.
  if (!isCashfreePayoutConfigured()) return { dispatched: false, reason: "CASHFREE_PAYOUT_NOT_CONFIGURED" };
  const payout = await FieldAgentPayoutRequest.findById(payoutId);
  if (!payout || payout.status !== FIELD_AGENT_PAYOUT_STATUS.PROCESSING || payout.payoutProvider !== FIELD_AGENT_PAYOUT_PROVIDER.CASHFREE) {
    return { dispatched: false, reason: "NOT_IN_FLIGHT" };
  }

  const destination = await resolveDestination(payout);
  if (!destination) {
    // Funds are already PROCESSING; the destination can no longer be proven
    // identical to the snapshot. Nothing was sent, so fail safe and return the money.
    const r = await applyTransferOutcome({ payoutId, outcome: SETTLEMENT_STATUS.FAILED, failureReason: "Bank details could not be verified for automatic payout", providerStatus: "NOT_SENT" });
    return { dispatched: false, reason: "DESTINATION_UNAVAILABLE", ...r };
  }

  const result = await PayoutProviderResolver.resolve(CASHFREE_PROVIDER_NAME).execute({ payout, destination });
  assertValidProviderResult(result);
  const beneficiaryId = result.providerResponse?.beneficiaryId
    || buildBeneficiaryId({ fieldAgentId: payout.fieldAgentRef, accountNumber: destination.accountNumber, ifsc: destination.ifsc });
  const common = { payoutId, providerPayoutId: result.providerPayoutId, providerResponse: result.providerResponse };

  if (result.status === SETTLEMENT_STATUS.SUCCESS) {
    await retryOnConflict(() => FieldAgentPayoutRequest.updateOne({ _id: payoutId }, { $set: { providerBeneficiaryId: beneficiaryId } }));
    return { dispatched: true, ...(await applyTransferOutcome({ ...common, outcome: SETTLEMENT_STATUS.SUCCESS, utr: result.utr, providerStatus: "SUCCESS" })) };
  }
  if (result.status === SETTLEMENT_STATUS.FAILED) {
    return { dispatched: true, ...(await applyTransferOutcome({ ...common, outcome: SETTLEMENT_STATUS.FAILED, failureReason: result.failureReason, providerStatus: "FAILED" })) };
  }

  // PENDING (accepted, or outcome unknown): stays PROCESSING; webhook / reconciliation resolves it.
  await retryOnConflict(() => FieldAgentPayoutRequest.updateOne(
    { _id: payoutId, status: FIELD_AGENT_PAYOUT_STATUS.PROCESSING },
    { $set: {
        providerStatus: result.providerResponse?.unknownOutcome ? "UNKNOWN" : (result.providerResponse?.status || "RECEIVED"),
        ...(result.providerPayoutId ? { providerPayoutId: result.providerPayoutId } : {}),
        providerBeneficiaryId: beneficiaryId,
        providerResponse: result.providerResponse,
    } }
  ));
  return { dispatched: true, applied: false, reason: "PENDING" };
};

/** Post-approval hook for the admin controller. Never throws. */
export const dispatchAfterApproval = async (payout) => {
  if (payout?.payoutProvider !== FIELD_AGENT_PAYOUT_PROVIDER.CASHFREE) return { dispatched: false, reason: "MANUAL" };
  try {
    return await dispatchCashfreeTransfer(payout._id);
  } catch (err) {
    logger.error("[FieldAgentAutoPayout] transfer dispatch failed — payout left for reconciliation", { payoutId: String(payout._id), message: err.message });
    return { dispatched: false, reason: "ERROR", error: err.message };
  }
};

// ─── WEBHOOK ────────────────────────────────────────────────────────
const WEBHOOK_SUCCESS = new Set(["SUCCESS", "TRANSFER_SUCCESS"]);
const WEBHOOK_FAILED  = new Set(["FAILED", "REJECTED", "REVERSED", "TRANSFER_FAILED", "TRANSFER_REJECTED", "TRANSFER_REVERSED"]);

/**
 * Handles an already signature-verified Cashfree payout webhook payload.
 * Always resolves (the endpoint answers 200) — including for events it
 * deliberately ignores — so Cashfree does not retry harmlessly-ignored ones.
 */
export const handlePayoutWebhookEvent = async (payload) => {
  const data = payload?.data || {};
  const transferId = data.transfer_id || payload?.transfer_id;
  const event = String(payload?.event || payload?.type || "").toUpperCase();
  const state = String(data.status || event).toUpperCase();

  if (!transferId || !String(transferId).startsWith("FAP_")) return { handled: false, reason: "NOT_OUR_TRANSFER" };
  const payoutId = String(transferId).slice(4);
  if (!mongoose.isValidObjectId(payoutId)) return { handled: false, reason: "BAD_TRANSFER_ID" };

  const isSuccess = WEBHOOK_SUCCESS.has(state) || WEBHOOK_SUCCESS.has(event);
  const isFailed  = WEBHOOK_FAILED.has(state) || WEBHOOK_FAILED.has(event);
  if (!isSuccess && !isFailed) {
    // Intermediate (e.g. ACKNOWLEDGED / PENDING) — record and wait for the final event.
    await retryOnConflict(() => FieldAgentPayoutRequest.updateOne(
      { _id: payoutId, status: FIELD_AGENT_PAYOUT_STATUS.PROCESSING, payoutProvider: FIELD_AGENT_PAYOUT_PROVIDER.CASHFREE },
      { $set: { providerStatus: state.slice(0, 60) } }
    ));
    return { handled: true, reason: "INTERMEDIATE" };
  }

  const payout = await FieldAgentPayoutRequest.findById(payoutId).lean();
  if (!payout) return { handled: false, reason: "UNKNOWN_PAYOUT" };

  // Amount cross-check on success: never mark PAID for an amount we did not request.
  if (isSuccess && data.transfer_amount !== undefined && Math.round(Number(data.transfer_amount) * 100) !== payout.amountInPaise) {
    logger.error("[FieldAgentAutoPayout] webhook amount mismatch — ignored", { payoutId, expected: payout.amountInPaise, got: data.transfer_amount });
    return { handled: false, reason: "AMOUNT_MISMATCH" };
  }

  const res = await applyTransferOutcome({
    payoutId,
    outcome: isSuccess ? SETTLEMENT_STATUS.SUCCESS : SETTLEMENT_STATUS.FAILED,
    utr: data.transfer_utr || null,
    providerPayoutId: data.cf_transfer_id != null ? String(data.cf_transfer_id) : null,
    providerStatus: state.slice(0, 60),
    failureReason: data.status_description || data.reason || `Cashfree ${state}`,
  });
  return { handled: true, ...res };
};

// ─── RECONCILIATION ─────────────────────────────────────────────────
/**
 * Resolves in-flight CASHFREE payouts whose webhook never arrived (or whose
 * create call timed out) by polling Cashfree by our deterministic transfer_id.
 */
export const reconcileCashfreePayouts = async ({ olderThanMs = 5 * 60 * 1000, limit = 25 } = {}) => {
  if (!isCashfreePayoutConfigured()) return { checked: 0, resolved: 0 };
  const cutoff = new Date(Date.now() - olderThanMs);
  const stuck = await FieldAgentPayoutRequest.find({
    payoutProvider: FIELD_AGENT_PAYOUT_PROVIDER.CASHFREE,
    status: FIELD_AGENT_PAYOUT_STATUS.PROCESSING,
    updatedAt: { $lt: cutoff },
  }).sort({ updatedAt: 1 }).limit(limit).select("_id").lean();

  let resolved = 0;
  for (const { _id } of stuck) {
    try {
      const st = await PayoutProviderResolver.resolve(CASHFREE_PROVIDER_NAME).fetchStatus(_id);
      if (!st.known) continue;
      if (st.notFound) { await dispatchCashfreeTransfer(_id); continue; } // create never landed — safe to (re)send, transfer_id is idempotent
      if (st.status === SETTLEMENT_STATUS.SUCCESS) {
        const r = await applyTransferOutcome({ payoutId: _id, outcome: SETTLEMENT_STATUS.SUCCESS, utr: st.utr, providerPayoutId: st.providerPayoutId, providerStatus: "SUCCESS", providerResponse: st.providerResponse });
        if (r.applied) resolved++;
      } else if (st.status === SETTLEMENT_STATUS.FAILED) {
        const r = await applyTransferOutcome({ payoutId: _id, outcome: SETTLEMENT_STATUS.FAILED, failureReason: st.failureReason, providerPayoutId: st.providerPayoutId, providerStatus: String(st.providerResponse?.status || "FAILED"), providerResponse: st.providerResponse });
        if (r.applied) resolved++;
      } else {
        await retryOnConflict(() => FieldAgentPayoutRequest.updateOne({ _id }, { $set: { providerStatus: String(st.providerResponse?.status || "PENDING").slice(0, 60) } }));
      }
    } catch (err) {
      logger.error("[FieldAgentAutoPayout] reconcile failed for a payout", { payoutId: String(_id), message: err.message });
    }
  }
  return { checked: stuck.length, resolved };
};
