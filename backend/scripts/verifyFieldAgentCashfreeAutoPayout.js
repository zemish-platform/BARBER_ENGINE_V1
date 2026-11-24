/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyFieldAgentCashfreeAutoPayout.js
 *
 * FA-P4-D Step 1 — disposable verification of CashfreePayoutProvider
 * inside the Field Agent payout lifecycle, over real HTTP + real MongoDB
 * (Atlas dev DB, prefixed fixtures, purged before/after).
 *
 * The Cashfree side is a LOCAL STUB HTTP SERVER speaking the Payouts V2
 * shapes (beneficiary + transfers) selected through
 * CASHFREE_PAYOUT_BASE_URL — honoured only when CASHFREE_ENV != PRODUCTION.
 * It proves OUR side (provider selection, beneficiary reuse, request
 * shape, lifecycle, webhook verification, wallet reconciliation). It is
 * NOT a substitute for verifyFieldAgentCashfreeSandbox.js.
 *
 * The Auto Payout switch is driven through the REAL admin endpoint the
 * Revenue Settings page uses (PATCH /api/admin/revenue/settings). That
 * writes CommercialPolicyVersion rows; the script only runs when that
 * collection is empty and deletes what it created.
 *
 * Run:  cd backend && node scripts/verifyFieldAgentCashfreeAutoPayout.js
 */

import "dotenv/config";
import http from "http";
import mongoose from "mongoose";

process.env.CASHFREE_PAYOUT_WEBHOOK_SECRET = "ztest_webhook_secret_fap4d1";
// Payouts-only credentials (the Secure ID CASHFREE_CLIENT_ID/SECRET no longer configure Payouts).
// Synthetic values: every request goes to the local stub server below, never to Cashfree.
process.env.CASHFREE_PAYOUT_CLIENT_ID = "ztest_payout_client_id";
process.env.CASHFREE_PAYOUT_CLIENT_SECRET = "ztest_payout_client_secret";

import app from "../app.js";
import connectDB from "../config/db.js";
import { generateAccessToken } from "../services/token.service.js";
import User from "../models/User.js";
import SalonEarnings from "../models/SalonEarnings.js";
import WalletLedger from "../models/WalletLedger.js";
import FieldAgent from "../modules/fieldAgent/models/FieldAgent.js";
import FieldAgentApplication from "../modules/fieldAgent/models/FieldAgentApplication.js";
import FieldAgentEarningLedger from "../modules/fieldAgent/models/FieldAgentEarningLedger.js";
import FieldAgentPayoutRequest from "../modules/fieldAgent/models/FieldAgentPayoutRequest.js";
import FieldAgentAuditEvent from "../modules/fieldAgent/models/FieldAgentAuditEvent.js";
import CommercialPolicyVersion from "../modules/fieldAgent/models/CommercialPolicyVersion.js";
import KYC from "../modules/kyc/models/KYC.js";
import { encrypt } from "../modules/kyc/services/encryption.service.js";
import { reconcileCashfreePayouts } from "../modules/fieldAgent/services/fieldAgentAutoPayout.service.js";
import { computeAvailableBalance } from "../modules/fieldAgent/services/fieldAgentPayout.service.js";
import PayoutProviderResolver from "../services/settlement/PayoutProviderResolver.js";
import { signWebhookForTest, verifyWebhookSignature, getPayoutBaseUrl, buildTransferId, buildBeneficiaryId } from "../services/settlement/cashfree/cashfreePayoutClient.js";

let pass = 0, fail = 0;
const results = [];
const check = (name, cond, detail) => {
  if (cond) { pass++; results.push(`✅ ${name}`); }
  else { fail++; results.push(`❌ ${name}${detail !== undefined ? " — " + JSON.stringify(detail) : ""}`); }
};

const P = "ZTEST_FAP4D1_";
const oid = () => new mongoose.Types.ObjectId();
const phone = (p) => `${p}${Math.floor(100000000 + Math.random() * 899999999)}`;
const key = () => `${P}KEY_${oid()}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Cashfree stub ────────────────────────────────────────────────────
// Scenario is chosen by the beneficiary's bank account number.
const ACCT = {
  OK:        "0000000000001111", // transfer accepted (RECEIVED); resolved later by webhook
  IMMEDIATE: "0000000000002222", // transfer answers SUCCESS + UTR
  REJECT:    "0000000000003333", // transfer definitively rejected (400)
  UNKNOWN:   "0000000000004444", // transfer answers 500 but IS created (SUCCESS)
  LOST:      "0000000000005555", // transfer answers 500 and is NOT created (first time only)
  BENFAIL:   "0000000000007777", // beneficiary creation rejected (422)
  CONC:      "0000000000006666", // accepted; concurrency check
};
const stub = { transfers: new Map(), beneficiaries: new Map(), creates: [], benCreates: [], benGets: [], gets: [], lostOnce: new Set() };
const stubServer = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const send = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/beneficiary") {
      if (req.method === "GET") {
        const id = url.searchParams.get("beneficiary_id"); stub.benGets.push(id);
        return stub.beneficiaries.has(id) ? send(200, { beneficiary_id: id, beneficiary_status: "VERIFIED" }) : send(404, { type: "invalid_request_error", code: "beneficiary_not_found", message: "Beneficiary not found" });
      }
      const b = JSON.parse(raw || "{}"); stub.benCreates.push({ body: b, headers: req.headers });
      const acct = b?.beneficiary_instrument_details?.bank_account_number;
      if (stub.beneficiaries.has(b.beneficiary_id)) return send(409, { code: "beneficiary_id_already_exists", message: "exists" });
      if (acct === ACCT.BENFAIL) return send(422, { type: "invalid_request_error", code: "beneficiary_instrument_details_invalid", message: "Invalid bank account for beneficiary" });
      stub.beneficiaries.set(b.beneficiary_id, acct);
      return send(200, { beneficiary_id: b.beneficiary_id, beneficiary_status: "VERIFIED" });
    }
    if (req.method === "POST" && url.pathname === "/transfers") {
      const b = JSON.parse(raw || "{}");
      stub.creates.push({ body: b, headers: req.headers });
      const acct = stub.beneficiaries.get(b?.beneficiary_details?.beneficiary_id);
      if (!acct) return send(404, { code: "beneficiary_not_found", message: "Beneficiary not found" });
      if (stub.transfers.has(b.transfer_id)) return send(409, { code: "transfer_id_already_exists", message: "Transfer already exists" });
      const make = (status, extra = {}) => { const t = { transfer_id: b.transfer_id, cf_transfer_id: `CF${stub.transfers.size + 1}`, status, transfer_amount: b.transfer_amount, ...extra }; stub.transfers.set(b.transfer_id, t); return t; };
      if (acct === ACCT.REJECT) return send(400, { type: "invalid_request_error", code: "transfer_failed", message: "Beneficiary bank account is closed" });
      if (acct === ACCT.IMMEDIATE) return send(200, make("SUCCESS", { transfer_utr: "UTRIMMEDIATE001" }));
      if (acct === ACCT.UNKNOWN) { make("SUCCESS", { transfer_utr: "UTRRECON001" }); return send(500, { message: "Internal error" }); }
      if (acct === ACCT.LOST) {
        if (!stub.lostOnce.has(b.transfer_id)) { stub.lostOnce.add(b.transfer_id); return send(500, { message: "Internal error" }); }
        return send(200, make("SUCCESS", { transfer_utr: "UTRRESEND001" }));
      }
      return send(200, make("RECEIVED"));
    }
    if (req.method === "GET" && url.pathname === "/transfers") {
      const id = url.searchParams.get("transfer_id"); stub.gets.push(id);
      const t = stub.transfers.get(id);
      return t ? send(200, t) : send(404, { code: "transfer_not_found", message: "Transfer not found" });
    }
    return send(404, {});
  });
});

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
  await FieldAgent.deleteMany({ _id: { $in: agents.map((a) => a._id) } });
  await FieldAgentApplication.deleteMany({ _id: { $in: agents.map((a) => a.applicationRef) } });
  await User.deleteMany({ _id: { $in: userIds } });
};

const run = async () => {
  await connectDB();
  await purge();
  if ((await CommercialPolicyVersion.countDocuments()) !== 0) {
    console.error("Refusing to run: commercialpolicyversions is not empty (this script creates and deletes its own policy versions).");
    process.exit(2);
  }
  await new Promise((r) => stubServer.listen(0, r));
  process.env.CASHFREE_PAYOUT_BASE_URL = `http://127.0.0.1:${stubServer.address().port}`;
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  const port = server.address().port;

  const call = (path, token, { method = "GET", body, headers = {}, raw } = {}) =>
    fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { ...(body && !raw ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
      body: raw !== undefined ? raw : body ? JSON.stringify(body) : undefined,
    }).then(async (r) => ({ status: r.status, data: await r.json().catch(() => ({})) }));
  const W = "/api/field-agent/payout";
  const ADMIN = "/api/admin/field-agent/payouts";
  let policyIds = [];

  try {
    const mkAgent = async (label, acct = ACCT.OK, credit = 300000) => {
      const user = await User.create({ name: `${P}${label}`, phone: phone("8"), role: "FIELD_AGENT", accountStatus: "ACTIVE" });
      const application = await FieldAgentApplication.create({ userRef: oid(), phone: phone("9"), status: "APPROVED", nonTerminal: false });
      const agent = await FieldAgent.create({
        userRef: user._id, applicationRef: application._id,
        agentCode: `ZFP4D1-${label}-${Date.now()}-${Math.floor(Math.random() * 100000)}`,
        operationalStatus: "ACTIVE", commercialPath: "ACQUISITION_AGENT",
      });
      await KYC.create({
        ownerId: user._id, applicantType: "FIELD_AGENT",
        bank: { accountHolder: `${label} Holder`, maskedAccount: `XXXX${acct.slice(-4)}`, encryptedAccount: encrypt(acct), ifsc: "HDFC0000123", bankName: "HDFC Bank", pennyDropStatus: "SUCCESS" },
      });
      await FieldAgentEarningLedger.create({
        bookingRef: oid(), entitlementType: "ACQUISITION", idempotencyKey: `${P}LEDGER_${oid()}`,
        fieldAgentRef: agent._id, policySource: "NATIONAL", policyVersionRef: oid(), appliedRatePercent: 10,
        bookingCommissionAmountInPaise: credit, rawEligibleAmountInPaise: credit, creditedAmountInPaise: credit,
        creditOutcome: "CREDITED", bookingCompletedAt: new Date(),
      });
      return { user, agent, token: generateAccessToken({ _id: user._id, role: "FIELD_AGENT", tokenVersion: 0 }) };
    };
    const withdraw = async (a, amountInPaise) => {
      const r = await call(`${W}/withdraw`, a.token, { method: "POST", body: { amountInPaise, idempotencyKey: key() } });
      if (r.status !== 201) throw new Error(`withdraw failed ${r.status} ${JSON.stringify(r.data?.message)}`);
      return r.data.data.payout;
    };
    const fetchP = (id) => FieldAgentPayoutRequest.findById(id).select("+providerResponse").lean();
    const waitFor = async (id, pred, ms = 12000) => {
      const t0 = Date.now(); let doc;
      while (Date.now() - t0 < ms) { doc = await fetchP(id); if (pred(doc)) return doc; await sleep(150); }
      return doc;
    };
    const walletDoc = (a) => SalonEarnings.findOne({ entityType: "FIELD_AGENT", entityId: a.agent._id }).lean();
    const ledger = (a) => WalletLedger.collection.find({ ownerId: a.agent._id }).sort({ createdAt: 1, _id: 1 }).toArray();
    const seqFor = async (a, id) => (await ledger(a)).filter((x) => String(x.entityId) === String(id)).map((x) => x.action).join(",");
    const webhook = (payload, { sign = true, ts = Math.floor(Date.now() / 1000), badSig = false } = {}) => {
      const rawBody = JSON.stringify(payload);
      const headers = { "content-type": "application/json" };
      if (sign) { headers["x-webhook-timestamp"] = String(ts); headers["x-webhook-signature"] = badSig ? "AAAA" + signWebhookForTest(rawBody, ts).slice(4) : signWebhookForTest(rawBody, ts); }
      return call("/api/webhooks/cashfree/payout", null, { method: "POST", raw: rawBody, headers });
    };
    const evt = (event, payoutId, extra = {}) => ({ event, data: { transfer_id: buildTransferId(payoutId), cf_transfer_id: "CFX", status: event.replace("TRANSFER_", ""), ...extra } });

    const indiaAdmin = await User.findOne({ role: "ADMIN", adminLevel: "INDIA" }).select("+tokenVersion").lean();
    const adminToken = generateAccessToken({ _id: indiaAdmin._id, role: "ADMIN", adminLevel: "INDIA", tokenVersion: indiaAdmin.tokenVersion ?? 0 });
    const approve = (id) => call(`${ADMIN}/${id}/approve`, adminToken, { method: "PATCH" });
    // The Revenue Settings page's own endpoint.
    const setAuto = (enabled) => call("/api/admin/revenue/settings", adminToken, { method: "PATCH", body: { acquisitionReward: 200, recoveryPercentage: 50, autoPayoutEnabled: enabled } });
    const cfCalls = () => stub.creates.length + stub.benCreates.length + stub.benGets.length;

    // ═══ Unit ═══════════════════════════════════════════════════
    const body0 = JSON.stringify({ a: 1 }); const ts0 = Math.floor(Date.now() / 1000);
    check("U1 valid signature verifies", verifyWebhookSignature({ rawBody: body0, signature: signWebhookForTest(body0, ts0), timestamp: ts0 }));
    check("U2 tampered body rejected", !verifyWebhookSignature({ rawBody: body0 + " ", signature: signWebhookForTest(body0, ts0), timestamp: ts0 }));
    check("U3 stale timestamp (10 min) rejected", !verifyWebhookSignature({ rawBody: body0, signature: signWebhookForTest(body0, ts0 - 600), timestamp: ts0 - 600 }));
    check("U4 missing signature / timestamp rejected", !verifyWebhookSignature({ rawBody: body0, signature: "", timestamp: ts0 }) && !verifyWebhookSignature({ rawBody: body0, signature: "x", timestamp: undefined }));
    const envBefore = process.env.CASHFREE_ENV;
    process.env.CASHFREE_ENV = "PRODUCTION";
    check("U5 base-url override is IGNORED in PRODUCTION (real money can't be redirected)", getPayoutBaseUrl() === "https://api.cashfree.com/payout", getPayoutBaseUrl());
    process.env.CASHFREE_ENV = envBefore;
    check("U6 non-production honours the override (stub)", getPayoutBaseUrl().startsWith("http://127.0.0.1"));
    check("U7 CashfreePayoutProvider is registered in the existing provider factory; ManualProvider still resolves",
      PayoutProviderResolver.resolve("CASHFREE").name === "CASHFREE" && PayoutProviderResolver.resolve("MANUAL").name === "MANUAL");
    check("U8 beneficiary id is deterministic per agent+account and changes with the account",
      buildBeneficiaryId({ fieldAgentId: "a", accountNumber: "1", ifsc: "X" }) === buildBeneficiaryId({ fieldAgentId: "a", accountNumber: "1", ifsc: "X" }) &&
      buildBeneficiaryId({ fieldAgentId: "a", accountNumber: "1", ifsc: "X" }) !== buildBeneficiaryId({ fieldAgentId: "a", accountNumber: "2", ifsc: "X" }));

    // ═══ Setting = Revenue Settings → Auto Payout Enabled ═════
    let r = await setAuto(false);
    check("R1 Revenue Settings PATCH autoPayoutEnabled:false", r.status === 200 && r.data.data.autoPayoutEnabled === false, r.data);

    // ═══ OFF → ManualProvider path, untouched ═════════════════
    const off = await mkAgent("OFF");
    const pOff = await withdraw(off, 60000);
    r = await approve(pOff._id);
    check("B1 OFF: admin approve → PROCESSING, provider MANUAL, Cashfree never called",
      r.status === 200 && r.data.data.payout.status === "PROCESSING" && r.data.data.payout.payoutProvider === "MANUAL" && cfCalls() === 0, { s: r.status, calls: cfCalls() });
    r = await call(`${ADMIN}/${pOff._id}/manual-result`, adminToken, { method: "PATCH", body: { success: true, utr: `${P}MANUALUTR0` } });
    check("B2 OFF: manual mark-paid still works exactly as before", r.status === 200 && r.data.data.payout.status === "PAID" && (await walletDoc(off)).lifetimeWithdrawalsInPaise === 60000);

    // ═══ ON → CashfreePayoutProvider ══════════════════════════
    r = await setAuto(true);
    check("R2 Revenue Settings PATCH autoPayoutEnabled:true; GET reflects it", r.status === 200 && r.data.data.autoPayoutEnabled === true && (await call("/api/admin/revenue/settings", adminToken)).data.data.autoPayoutEnabled === true);

    // S1 — REQUESTED → APPROVED → PROCESSING → CASHFREE → (webhook) PAID
    const s1 = await mkAgent("S1", ACCT.OK);
    const p1 = await withdraw(s1, 75000);
    check("S1.0 request alone never calls Cashfree (approval is still the admin's step)", (await fetchP(p1._id)).status === "REQUESTED" && cfCalls() === 0);
    r = await approve(p1._id);
    const a1 = r.data?.data?.payout;
    const d1 = await fetchP(p1._id);
    const benId1 = buildBeneficiaryId({ fieldAgentId: s1.agent._id, accountNumber: ACCT.OK, ifsc: "HDFC0000123" });
    const create1 = stub.creates.find((c) => c.body.transfer_id === buildTransferId(p1._id));
    check("S1.1 admin approve with Auto ON → PROCESSING, provider CASHFREE, approved by the admin", r.status === 200 && a1.status === "PROCESSING" && a1.payoutProvider === "CASHFREE" && String(d1.approvedBy) === String(indiaAdmin._id), { s: r.status, a1 });
    check("S1.2 beneficiary created once with the decrypted verified account, IFSC, holder, 10-digit phone",
      stub.benCreates.length === 1 && stub.benCreates[0].body.beneficiary_id === benId1 && stub.benCreates[0].body.beneficiary_instrument_details.bank_account_number === ACCT.OK &&
      stub.benCreates[0].body.beneficiary_instrument_details.bank_ifsc === "HDFC0000123" && stub.benCreates[0].body.beneficiary_name === "S1 Holder" && /^\d{10}$/.test(stub.benCreates[0].body.beneficiary_contact_details.beneficiary_phone), stub.benCreates[0]?.body);
    check("S1.3 transfer request: deterministic transfer_id, ₹ amount, INR, banktransfer, beneficiary_id (no raw account)",
      create1?.body.transfer_id === `FAP_${p1._id}` && create1.body.transfer_amount === 750 && create1.body.transfer_currency === "INR" && create1.body.transfer_mode === "banktransfer" &&
      create1.body.beneficiary_details.beneficiary_id === benId1 && !JSON.stringify(create1.body).includes(ACCT.OK), create1?.body);
    check("S1.4 credentials sent as x-client-id/x-client-secret + x-api-version", !!create1?.headers["x-client-id"] && !!create1?.headers["x-client-secret"] && create1?.headers["x-api-version"] === "2024-01-01");
    check("S1.5 provider reference (cf_transfer_id) and beneficiary id saved", /^CF\d+$/.test(d1.providerPayoutId || "") && d1.providerBeneficiaryId === benId1 && d1.providerStatus === "RECEIVED", d1);
    let w = await walletDoc(s1);
    check("S1.6 wallet: processing 75000, locked 0", w.processingBalanceInPaise === 75000 && w.lockedBalanceInPaise === 0, w);

    const okPayload = evt("TRANSFER_SUCCESS", p1._id, { transfer_utr: "UTRWEBHOOK0001", transfer_amount: 750 });
    r = await webhook(okPayload, { sign: false });
    check("W1 unsigned webhook → 401, nothing changed", r.status === 401 && (await fetchP(p1._id)).status === "PROCESSING");
    r = await webhook(okPayload, { badSig: true });
    check("W2 wrong signature → 401, nothing changed", r.status === 401 && (await fetchP(p1._id)).status === "PROCESSING");
    r = await webhook(okPayload, { ts: Math.floor(Date.now() / 1000) - 900 });
    check("W3 replayed (stale) webhook → 401", r.status === 401);
    r = await webhook({ ...okPayload, data: { ...okPayload.data, transfer_amount: 1 } });
    check("W4 signed but amount ≠ requested → ignored (200 handled:false), still PROCESSING", r.status === 200 && r.data.handled === false && (await fetchP(p1._id)).status === "PROCESSING", r.data);
    r = await webhook(okPayload);
    const paid1 = await fetchP(p1._id);
    w = await walletDoc(s1);
    check("W5 signed TRANSFER_SUCCESS → 200; PAID, UTR saved, isOpen false", r.status === 200 && paid1.status === "PAID" && paid1.utr === "UTRWEBHOOK0001" && paid1.isOpen === false, { s: r.status, paid1 });
    check("W6 wallet reconciled: processing 0, available 225000, lifetime withdrawals 75000", w.processingBalanceInPaise === 0 && w.availableBalanceInPaise === 225000 && w.lifetimeWithdrawalsInPaise === 75000, w);
    check("W7 same ledger lifecycle as Salon: HOLD×2, PROCESSING×2, PAYOUT_SUCCESS", (await seqFor(s1, p1._id)) === "WITHDRAWAL_HOLD,WITHDRAWAL_HOLD,WITHDRAWAL_PROCESSING,WITHDRAWAL_PROCESSING,PAYOUT_SUCCESS", await seqFor(s1, p1._id));
    const nBefore = (await ledger(s1)).length;
    r = await webhook(okPayload);
    check("W8 duplicate webhook → 200, no second debit", r.status === 200 && (await ledger(s1)).length === nBefore && (await walletDoc(s1)).lifetimeWithdrawalsInPaise === 75000);
    r = await webhook(evt("TRANSFER_SUCCESS", oid(), { transfer_utr: "X" }));
    check("W9 signed event for an unknown payout → 200 (no retry storm)", r.status === 200 && r.data.handled === false);
    r = await call("/api/webhooks/cashfree/payout", null, { method: "POST", raw: "not json", headers: { "x-webhook-timestamp": String(ts0), "x-webhook-signature": signWebhookForTest("not json", ts0) } });
    check("W10 signed but malformed body → 400", r.status === 400, r.status);

    // Beneficiary REUSE — same agent, same account, second payout
    const benCreatesBefore = stub.benCreates.length, benGetsBefore = stub.benGets.length;
    const p1c = await withdraw(s1, 50000);
    r = await approve(p1c._id);
    const d1c = await fetchP(p1c._id);
    check("S1.7 second payout to the same account REUSES the beneficiary (looked up, not re-created)", r.status === 200 && stub.benCreates.length === benCreatesBefore && stub.benGets.length === benGetsBefore + 1 && d1c.providerBeneficiaryId === benId1 && d1c.payoutProvider === "CASHFREE", { creates: stub.benCreates.length - benCreatesBefore });
    await webhook(evt("TRANSFER_SUCCESS", p1c._id, { transfer_utr: "UTRWEBHOOK0002", transfer_amount: 500 }));

    // Manual paths refuse an in-flight CASHFREE payout
    const s1b = await mkAgent("S1B", ACCT.OK);
    const p1b = await withdraw(s1b, 60000);
    await approve(p1b._id);
    r = await call(`${ADMIN}/${p1b._id}/manual-result`, adminToken, { method: "PATCH", body: { success: true, utr: "MANUALTRY" } });
    check("M1 manual 'mark paid' refused for an in-flight Cashfree payout (409) — no double payment", r.status === 409 && (await fetchP(p1b._id)).status === "PROCESSING", r.status);
    check("M2 second approve refused (409)", (await approve(p1b._id)).status === 409);
    check("M3 agent cannot cancel once processing (409)", (await call(`${W}/mine/${p1b._id}/cancel`, s1b.token, { method: "POST" })).status === 409);

    // S2 — immediate SUCCESS
    const s2 = await mkAgent("S2", ACCT.IMMEDIATE);
    const p2 = await withdraw(s2, 55000);
    r = await approve(p2._id);
    const d2 = await fetchP(p2._id);
    check("S2 transfer answers SUCCESS+UTR → PAID at approval, UTR saved, wallet debited; approve response shows PAID",
      r.data.data.payout.status === "PAID" && d2.status === "PAID" && d2.utr === "UTRIMMEDIATE001" && (await walletDoc(s2)).processingBalanceInPaise === 0 && (await walletDoc(s2)).lifetimeWithdrawalsInPaise === 55000, d2);

    // S3 — definitive transfer rejection → FAILED + released
    const s3 = await mkAgent("S3", ACCT.REJECT);
    const p3 = await withdraw(s3, 65000);
    r = await approve(p3._id);
    const d3 = await fetchP(p3._id);
    w = await walletDoc(s3);
    check("S3.1 definitive rejection → FAILED with reason, isOpen false, fundsReleased", d3.status === "FAILED" && /closed/i.test(d3.failureReason || "") && d3.isOpen === false && d3.fundsReleased === true, d3);
    check("S3.2 funds returned: available 300000, processing 0, locked 0", w.availableBalanceInPaise === 300000 && w.processingBalanceInPaise === 0 && w.lockedBalanceInPaise === 0, w);
    check("S3.3 ledger: HOLD×2, PROCESSING×2, PAYOUT_FAILED_REVERSAL×2", (await seqFor(s3, p3._id)) === "WITHDRAWAL_HOLD,WITHDRAWAL_HOLD,WITHDRAWAL_PROCESSING,WITHDRAWAL_PROCESSING,PAYOUT_FAILED_REVERSAL,PAYOUT_FAILED_REVERSAL", await seqFor(s3, p3._id));
    check("S3.4 dashboard availablePayout counts the released funds", (await computeAvailableBalance(s3.agent._id)).availableInPaise === 300000);
    check("S3.5 wallet endpoint: no pending request, full balance", (await call(`${W}/wallet`, s3.token)).data?.data?.hasPendingRequest === false && (await call(`${W}/wallet`, s3.token)).data.data.availableBalance === 300000);
    check("S3.6 retry and manual-result refused for a released failure (409)",
      (await call(`${ADMIN}/${p3._id}/retry`, adminToken, { method: "PATCH" })).status === 409 && (await call(`${ADMIN}/${p3._id}/manual-result`, adminToken, { method: "PATCH", body: { success: true, utr: "X" } })).status === 409);
    check("S3.7 agent can request again immediately (201)", (await call(`${W}/withdraw`, s3.token, { method: "POST", body: { amountInPaise: 50000, idempotencyKey: key() } })).status === 201);

    // S3B — beneficiary rejected → nothing sent → FAILED + released
    const s3b = await mkAgent("S3B", ACCT.BENFAIL);
    const p3b = await withdraw(s3b, 60000);
    const tBefore = stub.creates.length;
    await approve(p3b._id);
    const d3b = await fetchP(p3b._id);
    check("S3B beneficiary rejected → FAILED + funds released, NO transfer attempted", d3b.status === "FAILED" && d3b.fundsReleased === true && /account/i.test(d3b.failureReason || "") && stub.creates.length === tBefore && (await walletDoc(s3b)).availableBalanceInPaise === 300000, d3b);

    // S4 — webhook failure; late SUCCESS must not apply
    const s4 = await mkAgent("S4", ACCT.OK);
    const p4 = await withdraw(s4, 80000);
    await approve(p4._id);
    r = await webhook(evt("TRANSFER_FAILED", p4._id, { status_description: "Beneficiary bank rejected" }));
    const d4 = await fetchP(p4._id);
    w = await walletDoc(s4);
    check("S4.1 signed TRANSFER_FAILED → FAILED + released (available 300000, processing 0)", r.status === 200 && d4.status === "FAILED" && d4.fundsReleased && d4.failureReason === "Beneficiary bank rejected" && w.availableBalanceInPaise === 300000 && w.processingBalanceInPaise === 0, { d4, w });
    const nB = (await ledger(s4)).length;
    await webhook(evt("TRANSFER_FAILED", p4._id));
    await webhook(evt("TRANSFER_SUCCESS", p4._id, { transfer_utr: "LATE", transfer_amount: 800 }));
    check("S4.2 duplicate FAILED and a late SUCCESS are not applied (no wallet movement)", (await ledger(s4)).length === nB && (await fetchP(p4._id)).status === "FAILED" && (await walletDoc(s4)).availableBalanceInPaise === 300000);
    check("S4.3 intermediate event is recorded, not final", await (async () => {
      const s = await mkAgent("S4B", ACCT.OK); const p = await withdraw(s, 50000); await approve(p._id);
      const rr = await webhook({ event: "TRANSFER_ACKNOWLEDGED", data: { transfer_id: buildTransferId(p._id), status: "PENDING" } });
      const d = await fetchP(p._id);
      return rr.status === 200 && d.status === "PROCESSING" && d.providerStatus === "PENDING";
    })());

    // S5 — unknown outcome → PROCESSING → reconciled by polling
    const s5 = await mkAgent("S5", ACCT.UNKNOWN);
    const p5 = await withdraw(s5, 52000);
    await approve(p5._id);
    const d5 = await fetchP(p5._id);
    check("S5.1 5xx from Cashfree = UNKNOWN: stays PROCESSING, funds NOT released", d5.status === "PROCESSING" && d5.providerStatus === "UNKNOWN" && (await walletDoc(s5)).processingBalanceInPaise === 52000, d5);
    const rec = await reconcileCashfreePayouts({ olderThanMs: 0 });
    const d5b = await fetchP(p5._id);
    check("S5.2 reconciliation polls by transfer_id → PAID with UTR", rec.resolved >= 1 && d5b.status === "PAID" && d5b.utr === "UTRRECON001" && (await walletDoc(s5)).processingBalanceInPaise === 0, { rec, d5b });

    // S6 — create never landed → reconciliation re-sends idempotently
    const s6 = await mkAgent("S6", ACCT.LOST);
    const p6 = await withdraw(s6, 51000);
    await approve(p6._id);
    check("S6.1 transfer does not exist at Cashfree yet; payout UNKNOWN", !stub.transfers.has(buildTransferId(p6._id)) && (await fetchP(p6._id)).providerStatus === "UNKNOWN");
    await reconcileCashfreePayouts({ olderThanMs: 0 });
    const d6 = await fetchP(p6._id);
    check("S6.2 reconcile: 404 → re-sent with the SAME transfer_id → PAID (exactly one transfer)", d6.status === "PAID" && d6.utr === "UTRRESEND001" && [...stub.transfers.keys()].filter((k) => k === buildTransferId(p6._id)).length === 1, d6);

    // S7 — bank changed since request → falls back to MANUAL approval
    const s7 = await mkAgent("S7", ACCT.OK);
    const p7 = await withdraw(s7, 50000);
    await KYC.updateOne({ ownerId: s7.user._id }, { $set: { "bank.ifsc": "ICIC0000999" } });
    const callsBefore = cfCalls();
    r = await approve(p7._id);
    check("S7 bank changed since request → provider falls back to MANUAL, Cashfree never called", r.status === 200 && r.data.data.payout.payoutProvider === "MANUAL" && r.data.data.payout.status === "PROCESSING" && cfCalls() === callsBefore, r.data?.data?.payout);
    r = await call(`${ADMIN}/${p7._id}/manual-result`, adminToken, { method: "PATCH", body: { success: true, utr: `${P}MANUALUTR7` } });
    check("S7.1 …and it is finished through the untouched manual path", r.status === 200 && r.data.data.payout.status === "PAID");

    // Concurrency — two simultaneous approvals → one transfer
    const sc = await mkAgent("CONC", ACCT.CONC);
    const pc = await withdraw(sc, 50000);
    const [c1, c2] = await Promise.all([approve(pc._id), approve(pc._id)]);
    const transfersForPc = stub.creates.filter((c) => c.body.transfer_id === buildTransferId(pc._id)).length;
    check("K1 two concurrent admin approvals → exactly one wins and ONE Cashfree transfer is made",
      [c1.status, c2.status].filter((x) => x === 200).length === 1 && transfersForPc === 1 && (await walletDoc(sc)).processingBalanceInPaise === 50000, { st: [c1.status, c2.status], transfersForPc });

    // Reconciliation across every fixture wallet
    let allOk = true;
    for (const a of [off, s1, s1b, s2, s3, s3b, s4, s5, s6, s7, sc]) {
      const rows = await ledger(a);
      const sum = (b) => rows.filter((x) => x.bucket === b).reduce((s, x) => s + (x.direction === "CREDIT" ? x.amountInPaise : -x.amountInPaise), 0);
      const wl = await walletDoc(a);
      if (sum("AVAILABLE") !== wl.availableBalanceInPaise || sum("LOCKED") !== (wl.lockedBalanceInPaise || 0) || sum("PROCESSING") !== (wl.processingBalanceInPaise || 0)) { allOk = false; results.push(`   mismatch ${a.user.name}`); }
    }
    check("L1 every fixture wallet reconciles with its ledger (Available/Locked/Processing)", allOk);
    const agentView = JSON.stringify((await call(`${W}/mine`, s1.token)).data);
    check("L2 agent payout API shows status/UTR only — never provider response or secrets", agentView.includes("PAID") && !agentView.includes("providerResponse") && !agentView.includes(process.env.CASHFREE_PAYOUT_CLIENT_SECRET));
  } catch (err) {
    fail++; results.push(`❌ UNEXPECTED ERROR — ${err.stack || err}`);
  } finally {
    // remove the policy versions this script created (the collection was empty at start)
    const versions = await CommercialPolicyVersion.find({}).select("_id").lean();
    policyIds = versions.map((v) => v._id);
    await CommercialPolicyVersion.collection.deleteMany({ _id: { $in: policyIds } });
    await FieldAgentAuditEvent.deleteMany({ entityId: { $in: policyIds } });
    await purge().catch((e) => results.push(`⚠️ purge error ${e.message}`));
    server.close(); stubServer.close();
    await mongoose.disconnect();
  }
  console.log(results.join("\n"));
  console.log(`\nRESULT: ${pass} PASS / ${fail} FAIL`);
  process.exit(fail ? 1 : 0);
};
run();
