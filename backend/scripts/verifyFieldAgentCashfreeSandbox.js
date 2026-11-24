/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyFieldAgentCashfreeSandbox.js
 *
 * FA-P4-D Step 1 — LIVE verification against the real Cashfree SANDBOX
 * (no stub). Refuses to run unless CASHFREE_ENV is SANDBOX. Uses the
 * Payouts-only CASHFREE_PAYOUT_CLIENT_ID / CASHFREE_PAYOUT_CLIENT_SECRET from
 * .env (NOT the Secure ID CASHFREE_CLIENT_ID / CASHFREE_CLIENT_SECRET) and
 * refuses to run without them — values are never printed.
 *
 * Steps: (0) preflight — is the server allowed to call Payouts at all?
 * (1) real withdrawal, Auto Payout ON (Revenue Settings endpoint), real admin
 * approve -> real sandbox beneficiary + transfer
 * (2) poll the real transfer to a final state and reconcile the wallet
 * from that real answer. Fixtures (and the policy version this creates —
 * the script needs commercialpolicyversions to be empty) are purged in `finally`.
 *
 * Sandbox test beneficiary: Cashfree's documented sandbox account
 * (override with CF_SANDBOX_ACCOUNT / CF_SANDBOX_IFSC).
 *
 * Run:  cd backend && node scripts/verifyFieldAgentCashfreeSandbox.js
 */

import "dotenv/config";
import mongoose from "mongoose";
import app from "../app.js";
import connectDB from "../config/db.js";
import { generateAccessToken } from "../services/token.service.js";
import User from "../models/User.js";
import CommercialPolicyVersion from "../modules/fieldAgent/models/CommercialPolicyVersion.js";
import SalonEarnings from "../models/SalonEarnings.js";
import WalletLedger from "../models/WalletLedger.js";
import FieldAgent from "../modules/fieldAgent/models/FieldAgent.js";
import FieldAgentApplication from "../modules/fieldAgent/models/FieldAgentApplication.js";
import FieldAgentEarningLedger from "../modules/fieldAgent/models/FieldAgentEarningLedger.js";
import FieldAgentPayoutRequest from "../modules/fieldAgent/models/FieldAgentPayoutRequest.js";
import FieldAgentAuditEvent from "../modules/fieldAgent/models/FieldAgentAuditEvent.js";
import KYC from "../modules/kyc/models/KYC.js";
import { encrypt } from "../modules/kyc/services/encryption.service.js";
import { reconcileCashfreePayouts } from "../modules/fieldAgent/services/fieldAgentAutoPayout.service.js";
import { getTransfer, getPayoutBaseUrl, isCashfreePayoutConfigured } from "../services/settlement/cashfree/cashfreePayoutClient.js";

const P = "ZTEST_FAP4D1SBX_";
const oid = () => new mongoose.Types.ObjectId();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ACCOUNT = process.env.CF_SANDBOX_ACCOUNT || "026291800001191";
const IFSC = process.env.CF_SANDBOX_IFSC || "YESB0000262";

const purge = async () => {
  const users = await User.find({ name: new RegExp(`^${P}`) }).select("_id").lean();
  const userIds = users.map((u) => u._id);
  const agents = await FieldAgent.find({ userRef: { $in: userIds } }).select("_id applicationRef").lean();
  const agentIds = agents.map((a) => a._id);
  const payoutIds = await FieldAgentPayoutRequest.distinct("_id", { fieldAgentRef: { $in: agentIds } });
  await WalletLedger.collection.deleteMany({ ownerId: { $in: agentIds } });
  await SalonEarnings.deleteMany({ entityType: "FIELD_AGENT", entityId: { $in: agentIds } });
  await FieldAgentEarningLedger.collection.deleteMany({ fieldAgentRef: { $in: agentIds } });
  await FieldAgentAuditEvent.deleteMany({ entityId: { $in: payoutIds } });
  await FieldAgentPayoutRequest.deleteMany({ _id: { $in: payoutIds } });
  await KYC.deleteMany({ ownerId: { $in: userIds } });
  await FieldAgent.deleteMany({ _id: { $in: agentIds } });
  await FieldAgentApplication.deleteMany({ _id: { $in: agents.map((a) => a.applicationRef) } });
  await User.deleteMany({ _id: { $in: userIds } });
};

const run = async () => {
  if (process.env.CASHFREE_ENV === "PRODUCTION") { console.error("Refusing to run: CASHFREE_ENV is PRODUCTION"); process.exit(2); }
  if (!isCashfreePayoutConfigured()) { console.error("Refusing to run: CASHFREE_PAYOUT_CLIENT_ID / CASHFREE_PAYOUT_CLIENT_SECRET are not set (Payouts-only sandbox credentials)"); process.exit(2); }
  if (process.env.CF_SANDBOX_ALLOW_OVERRIDE !== "1") delete process.env.CASHFREE_PAYOUT_BASE_URL; // real sandbox, no stub (override only for dry-running this script itself)
  console.log(`Cashfree Payouts base: ${getPayoutBaseUrl()} (env ${process.env.CASHFREE_ENV})`);

  // ── 0. preflight ─────────────────────────────────────────────
  const probe = await getTransfer(`FAP_PREFLIGHT_${Date.now()}`);
  console.log(`PREFLIGHT GET /transfers → HTTP ${probe.httpStatus} ${JSON.stringify({ type: probe.json?.type, code: probe.json?.code, message: probe.json?.message })}`);
  if (probe.httpStatus === 403 || probe.httpStatus === 401 || probe.networkError) {
    console.log("\nBLOCKED — Cashfree did not accept this server for Payouts. Nothing further was attempted.");
    process.exit(3);
  }

  await connectDB();
  await purge();
  if ((await CommercialPolicyVersion.countDocuments()) !== 0) { console.error("Refusing: commercialpolicyversions is not empty"); process.exit(2); }
  let ok = true;
  const say = (label, cond, extra = "") => { if (!cond) ok = false; console.log(`${cond ? "✅" : "❌"} ${label} ${extra}`); };
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  const port = server.address().port;
  try {
    const user = await User.create({ name: `${P}AGENT`, phone: `8${Math.floor(100000000 + Math.random() * 899999999)}`, role: "FIELD_AGENT", accountStatus: "ACTIVE" });
    const application = await FieldAgentApplication.create({ userRef: oid(), phone: `9${Math.floor(100000000 + Math.random() * 899999999)}`, status: "APPROVED", nonTerminal: false });
    const agent = await FieldAgent.create({ userRef: user._id, applicationRef: application._id, agentCode: `ZFP4D1S-${Date.now()}`, operationalStatus: "ACTIVE", commercialPath: "ACQUISITION_AGENT" });
    await KYC.create({ ownerId: user._id, applicantType: "FIELD_AGENT", bank: { accountHolder: "Test Beneficiary", maskedAccount: `XXXX${ACCOUNT.slice(-4)}`, encryptedAccount: encrypt(ACCOUNT), ifsc: IFSC, bankName: "Sandbox Bank", pennyDropStatus: "SUCCESS" } });
    await FieldAgentEarningLedger.create({ bookingRef: oid(), entitlementType: "ACQUISITION", idempotencyKey: `${P}LEDGER_${oid()}`, fieldAgentRef: agent._id, policySource: "NATIONAL", policyVersionRef: oid(), appliedRatePercent: 10, bookingCommissionAmountInPaise: 100000, rawEligibleAmountInPaise: 100000, creditedAmountInPaise: 100000, creditOutcome: "CREDITED", bookingCompletedAt: new Date() });
    const token = generateAccessToken({ _id: user._id, role: "FIELD_AGENT", tokenVersion: 0 });

    const admin = await User.findOne({ role: "ADMIN", adminLevel: "INDIA" }).select("+tokenVersion").lean();
    const adminToken = generateAccessToken({ _id: admin._id, role: "ADMIN", adminLevel: "INDIA", tokenVersion: admin.tokenVersion ?? 0 });
    const api = (path, tok, method, body) => fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}` }, body: body ? JSON.stringify(body) : undefined });

    // Auto Payout ON via the same endpoint the Revenue Settings page uses
    const set = await api("/api/admin/revenue/settings", adminToken, "PATCH", { acquisitionReward: 200, recoveryPercentage: 50, autoPayoutEnabled: true });
    say("Revenue Settings: Auto Payout Enabled = ON", set.status === 200);

    const r = await api("/api/field-agent/payout/withdraw", token, "POST", { amountInPaise: 50000, idempotencyKey: `${P}KEY_${oid()}` });
    const payout = (await r.json()).data?.payout;
    say("withdraw ₹500 created", r.status === 201 && !!payout?._id);

    const ap = await api(`/api/admin/field-agent/payouts/${payout._id}/approve`, adminToken, "PATCH");
    const apBody = await ap.json();
    console.log("admin approve →", ap.status, JSON.stringify({ status: apBody.data?.payout?.status, provider: apBody.data?.payout?.payoutProvider, providerStatus: apBody.data?.payout?.providerStatus, beneficiary: apBody.data?.payout?.providerBeneficiaryId }));
    let doc = await FieldAgentPayoutRequest.findById(payout._id).select("+providerResponse").lean();
    say("payout handed to Cashfree (provider CASHFREE)", doc.payoutProvider === "CASHFREE", `status=${doc.status} providerStatus=${doc.providerStatus} cf_id=${doc.providerPayoutId}`);

    for (let i = 0; i < 24 && doc.status === "PROCESSING"; i++) {
      await sleep(5000);
      await reconcileCashfreePayouts({ olderThanMs: 0 });
      doc = await FieldAgentPayoutRequest.findById(payout._id).lean();
    }
    console.log(`final: status=${doc.status} providerStatus=${doc.providerStatus} utr=${doc.utr} failureReason=${doc.failureReason}`);
    const w = await SalonEarnings.findOne({ entityType: "FIELD_AGENT", entityId: agent._id }).lean();
    if (doc.status === "PAID") say("wallet reconciled after real SUCCESS", w.processingBalanceInPaise === 0 && w.availableBalanceInPaise === 50000 && w.lifetimeWithdrawalsInPaise === 50000, JSON.stringify(w));
    else if (doc.status === "FAILED") say("wallet reconciled after real FAILURE (funds returned)", w.processingBalanceInPaise === 0 && w.availableBalanceInPaise === 100000, JSON.stringify(w));
    else say("transfer reached a final state", false, `still ${doc.status}`);
  } catch (err) {
    ok = false; console.log("❌ UNEXPECTED", err.stack || err);
  } finally {
    const versions = await CommercialPolicyVersion.find({}).select("_id").lean();
    await CommercialPolicyVersion.collection.deleteMany({ _id: { $in: versions.map((v) => v._id) } });
    await FieldAgentAuditEvent.deleteMany({ entityId: { $in: versions.map((v) => v._id) } });
    await purge().catch(() => {});
    server.close();
    await mongoose.disconnect();
  }
  console.log(ok ? "\nSANDBOX RESULT: PASS" : "\nSANDBOX RESULT: FAIL");
  process.exit(ok ? 0 : 1);
};
run();
