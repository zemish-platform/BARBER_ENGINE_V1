/**
 * BARBER ENGINE V1
 * backend/services/settlement/cashfree/cashfreePayoutClient.js
 *
 * FA-P4-D Step 1 — thin HTTP client for Cashfree Payouts V2 (standard
 * transfer). Transport only: no Mongo, no wallet, no lifecycle — that
 * stays in SettlementEngine's neighbours (fieldAgentAutoPayout.service.js).
 *
 * CREDENTIALS: CASHFREE_PAYOUT_CLIENT_ID / CASHFREE_PAYOUT_CLIENT_SECRET —
 * Payouts-only. They are deliberately separate from CASHFREE_CLIENT_ID /
 * CASHFREE_CLIENT_SECRET, which belong to Secure ID (KYC verification,
 * modules/kyc/providers/cashfree.provider.js): adding Secure ID credentials
 * must never make Payouts configured. Cashfree issues credentials per
 * product, so these must belong to an account with the Payouts product
 * enabled. CASHFREE_ENV (exactly "PRODUCTION" for live) is shared with
 * Secure ID. Payouts additionally requires the server's outbound IP to be
 * whitelisted in the Cashfree dashboard — Cashfree answers 403 "IP not
 * whitelisted" otherwise.
 *
 * Without both payout credentials, Payouts is unconfigured and call() makes
 * NO network request (see below).
 *
 * ENDPOINTS (x-api-version 2024-01-01):
 *   GET  {base}/beneficiary?beneficiary_id=   fetch a beneficiary
 *   POST {base}/beneficiary          create a beneficiary
 *   POST {base}/transfers            create a transfer
 *   GET  {base}/transfers?transfer_id=  fetch a transfer
 *   webhook signature: base64(HMAC-SHA256(timestamp + rawBody, secret))
 *   headers x-webhook-timestamp / x-webhook-signature
 *
 * Every transfer uses a deterministic transfer_id, so a retried create
 * can never send money twice — Cashfree answers 409 for a duplicate id.
 */

import crypto from "crypto";

const API_VERSION = "2024-01-01";
const TIMEOUT_MS = 20_000;
export const WEBHOOK_TOLERANCE_MS = 5 * 60 * 1000;

const isProduction = () => process.env.CASHFREE_ENV === "PRODUCTION";

// CASHFREE_PAYOUT_BASE_URL exists only so a local stub server can stand
// in for Cashfree in disposable verification scripts; it is ignored in
// PRODUCTION so it can never redirect real money.
export const getPayoutBaseUrl = () => {
  if (!isProduction() && process.env.CASHFREE_PAYOUT_BASE_URL) return process.env.CASHFREE_PAYOUT_BASE_URL;
  return isProduction() ? "https://api.cashfree.com/payout" : "https://sandbox.cashfree.com/payout";
};

// Payouts-only credentials — never the Secure ID CASHFREE_CLIENT_ID / CASHFREE_CLIENT_SECRET.
const payoutCredentials = () => ({
  clientId:     process.env.CASHFREE_PAYOUT_CLIENT_ID,
  clientSecret: process.env.CASHFREE_PAYOUT_CLIENT_SECRET,
});

export const isCashfreePayoutConfigured = () => {
  const { clientId, clientSecret } = payoutCredentials();
  return !!clientId && !!clientSecret;
};

// Falls back to the Payouts client secret only — never to the Secure ID secret.
const webhookSecret = () => process.env.CASHFREE_PAYOUT_WEBHOOK_SECRET || process.env.CASHFREE_PAYOUT_CLIENT_SECRET || "";

// Deterministic per payout — Cashfree transfer_id: <=40 chars, [A-Za-z0-9_-].
export const buildTransferId = (payoutId) => `FAP_${String(payoutId)}`;

// Deterministic per (agent, account, IFSC): the SAME bank account always maps to
// the SAME Cashfree beneficiary (reuse), and a changed account maps to a new one.
// [A-Za-z0-9_], well under Cashfree's 50-char limit.
export const buildBeneficiaryId = ({ fieldAgentId, accountNumber, ifsc }) =>
  `FAB_${String(fieldAgentId)}_${crypto.createHash("sha256").update(`${accountNumber}|${ifsc}`).digest("hex").slice(0, 12)}`;

export const paiseToRupees = (paise) => Number((paise / 100).toFixed(2));

/**
 * @returns {Promise<{ok:boolean, httpStatus:number|null, json:object, networkError:boolean}>}
 *   networkError:true means the request outcome is UNKNOWN (timeout /
 *   connection error) — the transfer may or may not have been created.
 *
 *   Payouts unconfigured: returns at once WITHOUT any network request, as
 *   an unknown outcome (networkError:true, notConfigured:true) — callers map
 *   that to PENDING / known:false, never to FAILED, so no money is released.
 */
const call = async (method, path, body) => {
  if (!isCashfreePayoutConfigured()) {
    return { ok: false, httpStatus: null, json: { message: "Cashfree Payouts not configured" }, networkError: true, notConfigured: true };
  }
  const { clientId, clientSecret } = payoutCredentials();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${getPayoutBaseUrl()}${path}`, {
      method,
      headers: {
        "Content-Type":    "application/json",
        "x-api-version":   API_VERSION,
        "x-client-id":     clientId,
        "x-client-secret": clientSecret,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const json = await res.json().catch(() => ({}));
    return { ok: res.ok, httpStatus: res.status, json, networkError: false };
  } catch (err) {
    return { ok: false, httpStatus: null, json: { message: err.name === "AbortError" ? "Cashfree API timeout" : `Cashfree API error: ${err.message}` }, networkError: true };
  } finally {
    clearTimeout(timeout);
  }
};

export const getBeneficiary = (beneficiaryId) =>
  call("GET", `/beneficiary?beneficiary_id=${encodeURIComponent(beneficiaryId)}`);

export const createBeneficiary = ({ beneficiaryId, beneficiary }) =>
  call("POST", "/beneficiary", {
    beneficiary_id:   beneficiaryId,
    beneficiary_name: beneficiary.name,
    beneficiary_instrument_details: {
      bank_account_number: beneficiary.accountNumber,
      bank_ifsc:           beneficiary.ifsc,
    },
    beneficiary_contact_details: {
      beneficiary_phone:        beneficiary.phone,
      beneficiary_country_code: "+91",
    },
  });

// Transfer to an already-registered beneficiary (created/reused first).
export const createTransfer = ({ transferId, amountInPaise, beneficiaryId, remarks }) =>
  call("POST", "/transfers", {
    transfer_id:       transferId,
    transfer_amount:   paiseToRupees(amountInPaise),
    transfer_currency: "INR",
    transfer_mode:     "banktransfer",
    transfer_remarks:  remarks || "Zemish Field Agent payout",
    beneficiary_details: { beneficiary_id: beneficiaryId },
  });

export const getTransfer = (transferId) =>
  call("GET", `/transfers?transfer_id=${encodeURIComponent(transferId)}`);

/**
 * Verifies a Payouts webhook. `rawBody` MUST be the exact bytes received
 * (string/Buffer) — re-serialising parsed JSON changes the signature.
 * Rejects stale timestamps (replay) and uses a constant-time compare.
 */
export const verifyWebhookSignature = ({ rawBody, signature, timestamp, now = Date.now() }) => {
  const secret = webhookSecret();
  if (!secret || !signature || !timestamp || rawBody === undefined || rawBody === null) return false;

  const ts = Number(timestamp);
  const tsMs = ts < 1e12 ? ts * 1000 : ts; // Cashfree sends epoch seconds; tolerate ms
  if (!Number.isFinite(tsMs) || Math.abs(now - tsMs) > WEBHOOK_TOLERANCE_MS) return false;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(String(timestamp) + (Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody)))
    .digest("base64");

  const a = Buffer.from(expected);
  const b = Buffer.from(String(signature));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// Test helper — produces a signature exactly as Cashfree would.
export const signWebhookForTest = (rawBody, timestamp) =>
  crypto.createHmac("sha256", webhookSecret()).update(String(timestamp) + rawBody).digest("base64");
