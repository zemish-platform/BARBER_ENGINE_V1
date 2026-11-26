/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyCashfreeCredentialSeparation.js
 *
 * Verifies that Cashfree Payouts uses its OWN credentials and never becomes configured
 * through the Secure ID (KYC) credentials:
 *
 *   Secure ID (KYC)  — CASHFREE_CLIENT_ID / CASHFREE_CLIENT_SECRET          (modules/kyc/providers/cashfree.provider.js)
 *   Payouts          — CASHFREE_PAYOUT_CLIENT_ID / CASHFREE_PAYOUT_CLIENT_SECRET
 *                      (services/settlement/cashfree/cashfreePayoutClient.js)
 *   Both             — CASHFREE_ENV (exactly "PRODUCTION" for live)
 *
 * Hermetic by design — it never connects to MongoDB, Redis, Cashfree or Razorpay:
 *   - global fetch is replaced by a recording stub (any call is counted and answered locally);
 *   - Mongoose model statics the payout service would touch are replaced by spies that throw,
 *     so "exits before database access" is proven, not assumed;
 *   - Redis autoconnect is skipped; source files are only READ as text for the static checks.
 *
 *   cd backend && node scripts/verifyCashfreeCredentialSeparation.js
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

process.env.SKIP_REDIS_AUTOCONNECT = "true";
const CASHFREE_VARS = [
  "CASHFREE_CLIENT_ID", "CASHFREE_CLIENT_SECRET", "CASHFREE_PAYOUT_CLIENT_ID", "CASHFREE_PAYOUT_CLIENT_SECRET",
  "CASHFREE_PAYOUT_WEBHOOK_SECRET", "CASHFREE_ENV", "CASHFREE_PAYOUT_BASE_URL",
];
for (const name of CASHFREE_VARS) delete process.env[name];

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.resolve(__dirname, "..");
const REPO_DIR = path.resolve(BACKEND_DIR, "..");

// Synthetic credentials — distinct values so headers prove which pair was used.
const SECURE_ID = { CASHFREE_CLIENT_ID: "zt_secureid_client_id", CASHFREE_CLIENT_SECRET: "zt_secureid_client_secret" };
const PAYOUT = { CASHFREE_PAYOUT_CLIENT_ID: "zt_payout_client_id", CASHFREE_PAYOUT_CLIENT_SECRET: "zt_payout_client_secret" };
const setEnv = (vars = {}) => {
  for (const name of CASHFREE_VARS) delete process.env[name];
  Object.assign(process.env, vars);
};

// ─── fetch stub ─────────────────────────────────────────────────────────────
const fetchCalls = [];
let fetchResponder = () => ({ status: 200, body: {} });
globalThis.fetch = async (url, init = {}) => {
  fetchCalls.push({ url: String(url), headers: { ...(init.headers || {}) }, method: init.method });
  const { status, body } = fetchResponder(String(url), init);
  return { ok: status >= 200 && status < 300, status, json: async () => body };
};
const resetFetch = (responder = () => ({ status: 200, body: {} })) => { fetchCalls.length = 0; fetchResponder = responder; };

// ─── modules under test (imported after the environment is prepared) ────────
const client = await import("../services/settlement/cashfree/cashfreePayoutClient.js");
const { default: CashfreePayoutProvider } = await import("../services/settlement/providers/CashfreePayoutProvider.js");
const { SETTLEMENT_STATUS } = await import("../services/settlement/SettlementEnums.js");
const autoPayout = await import("../modules/fieldAgent/services/fieldAgentAutoPayout.service.js");
const { default: FieldAgentPayoutRequest } = await import("../modules/fieldAgent/models/FieldAgentPayoutRequest.js");
const { default: CommercialPolicyVersion } = await import("../modules/fieldAgent/models/CommercialPolicyVersion.js");

// Any database access through these models fails the test that triggered it.
const dbAccess = [];
const forbid = (model, label, statics) => {
  for (const name of statics) {
    model[name] = (...args) => { dbAccess.push(`${label}.${name}`); throw new Error(`database access: ${label}.${name}`); };
  }
};
forbid(FieldAgentPayoutRequest, "FieldAgentPayoutRequest", ["findById", "find", "findOne", "findOneAndUpdate", "updateOne", "updateMany"]);

// ─── tiny harness ───────────────────────────────────────────────────────────
const results = [];
const test = async (id, name, fn) => {
  dbAccess.length = 0;
  try {
    await fn();
    results.push({ id, ok: true });
    console.log(`  ✅ ${id} ${name}`);
  } catch (error) {
    results.push({ id, ok: false });
    console.log(`  ❌ ${id} ${name} — ${String(error?.message || error)}`);
  }
};
const expect = (condition, label) => { if (!condition) throw new Error(label); };
const section = (title) => console.log(`\n── ${title} ──`);

const PAYOUT_ID = "64b000000000000000000001";
const PAYOUT_DOC = { _id: PAYOUT_ID, amount: 12345, fieldAgentRef: "64b000000000000000000002" };
const DESTINATION = { name: "ZTEST AGENT", accountNumber: "000111222333", ifsc: "TEST0000001", phone: "9000000000" };

console.log("Cashfree credential separation — Secure ID vs Payouts (hermetic; fetch and database stubbed)");

// ═══ C — configuration ══════════════════════════════════════════════════════
section("C  which credentials configure Payouts");

await test("C1", "Secure ID credentials alone do NOT configure Payouts", async () => {
  setEnv({ ...SECURE_ID, CASHFREE_ENV: "PRODUCTION" });
  expect(client.isCashfreePayoutConfigured() === false, "Payouts configured by Secure ID credentials");
});

await test("C2", "Payout-specific credentials configure Payouts", async () => {
  setEnv({ ...PAYOUT });
  expect(client.isCashfreePayoutConfigured() === true, "Payouts not configured by its own credentials");
});

await test("C3", "Only one of the two payout credentials is not enough", async () => {
  setEnv({ CASHFREE_PAYOUT_CLIENT_ID: PAYOUT.CASHFREE_PAYOUT_CLIENT_ID });
  expect(client.isCashfreePayoutConfigured() === false, "configured with the id only");
  setEnv({ CASHFREE_PAYOUT_CLIENT_SECRET: PAYOUT.CASHFREE_PAYOUT_CLIENT_SECRET });
  expect(client.isCashfreePayoutConfigured() === false, "configured with the secret only");
  setEnv({ ...SECURE_ID, CASHFREE_PAYOUT_CLIENT_ID: PAYOUT.CASHFREE_PAYOUT_CLIENT_ID });
  expect(client.isCashfreePayoutConfigured() === false, "a Secure ID secret completed the payout pair");
});

// ═══ N — no network without payout credentials ══════════════════════════════
section("N  no network call without payout credentials");

const CLIENT_CALLS = {
  getBeneficiary: () => client.getBeneficiary("FAB_x"),
  createBeneficiary: () => client.createBeneficiary({ beneficiaryId: "FAB_x", beneficiary: DESTINATION }),
  createTransfer: () => client.createTransfer({ transferId: "FAP_x", amountInPaise: 100, beneficiaryId: "FAB_x" }),
  getTransfer: () => client.getTransfer("FAP_x"),
};
for (const [i, [name, fn]] of Object.entries(CLIENT_CALLS).entries()) {
  await test(`N${i + 1}`, `${name}: 0 fetch calls with only Secure ID credentials set; unknown outcome returned`, async () => {
    setEnv({ ...SECURE_ID, CASHFREE_ENV: "PRODUCTION" });
    resetFetch();
    const res = await fn();
    expect(fetchCalls.length === 0, `${fetchCalls.length} fetch call(s) made`);
    expect(res.ok === false && res.networkError === true && res.notConfigured === true, `unexpected result ${JSON.stringify(res)}`);
  });
}

// ═══ F — never FAILED / never refunded when credentials are missing ═════════
section("F  missing credentials never mean FAILED or a refund");

await test("F1", "provider.execute → PENDING (not FAILED), 0 fetch calls", async () => {
  setEnv({ ...SECURE_ID });
  resetFetch();
  const r = await CashfreePayoutProvider.execute({ payout: PAYOUT_DOC, destination: DESTINATION });
  expect(fetchCalls.length === 0, `${fetchCalls.length} fetch call(s) made`);
  expect(r.status === SETTLEMENT_STATUS.PENDING, `status ${r.status}`);
  expect(r.status !== SETTLEMENT_STATUS.FAILED, "a missing credential was treated as a definitive failure");
});

await test("F2", "provider.fetchStatus → known:false (reconciliation would skip it), 0 fetch calls", async () => {
  setEnv({});
  resetFetch();
  const st = await CashfreePayoutProvider.fetchStatus(PAYOUT_ID);
  expect(fetchCalls.length === 0, `${fetchCalls.length} fetch call(s) made`);
  expect(st.known === false && !st.notFound, `unexpected status ${JSON.stringify(st)}`);
});

await test("F3", "dispatchCashfreeTransfer exits BEFORE database access: no read, no FAILED, no refund", async () => {
  setEnv({ ...SECURE_ID, CASHFREE_ENV: "PRODUCTION" });
  resetFetch();
  const r = await autoPayout.dispatchCashfreeTransfer(PAYOUT_ID);
  expect(dbAccess.length === 0, `database touched: ${dbAccess.join(", ")}`);
  expect(fetchCalls.length === 0, `${fetchCalls.length} fetch call(s) made`);
  expect(r.dispatched === false && r.reason === "CASHFREE_PAYOUT_NOT_CONFIGURED", `unexpected result ${JSON.stringify(r)}`);
});

await test("F4", "reconcileCashfreePayouts does nothing when unconfigured: {checked:0, resolved:0}, no DB, no fetch", async () => {
  setEnv({ ...SECURE_ID, CASHFREE_ENV: "PRODUCTION" });
  resetFetch();
  const r = await autoPayout.reconcileCashfreePayouts();
  expect(dbAccess.length === 0, `database touched: ${dbAccess.join(", ")}`);
  expect(fetchCalls.length === 0, `${fetchCalls.length} fetch call(s) made`);
  expect(r.checked === 0 && r.resolved === 0, `unexpected result ${JSON.stringify(r)}`);
});

// ═══ M — MANUAL behaviour unchanged ═════════════════════════════════════════
section("M  MANUAL payouts unchanged");

await test("M1", "Auto Payout ON + only Secure ID credentials → provider selection stays MANUAL", async () => {
  setEnv({ ...SECURE_ID, CASHFREE_ENV: "PRODUCTION" });
  const originalFindOne = CommercialPolicyVersion.findOne;
  CommercialPolicyVersion.findOne = () => ({ select: () => ({ lean: async () => ({ autoPayoutEnabled: true }) }) });
  try {
    const provider = await autoPayout.selectPayoutProvider(PAYOUT_DOC);
    expect(provider === "MANUAL", `selected ${provider}`);
  } finally {
    CommercialPolicyVersion.findOne = originalFindOne;
  }
});

await test("M2", "dispatchAfterApproval on a MANUAL payout → MANUAL, whatever credentials are set", async () => {
  for (const vars of [{}, SECURE_ID, PAYOUT, { ...SECURE_ID, ...PAYOUT }]) {
    setEnv(vars);
    resetFetch();
    const r = await autoPayout.dispatchAfterApproval({ _id: PAYOUT_ID, payoutProvider: "MANUAL" });
    expect(r.dispatched === false && r.reason === "MANUAL", `unexpected result ${JSON.stringify(r)}`);
    expect(fetchCalls.length === 0 && dbAccess.length === 0, "a MANUAL payout reached Cashfree or the database");
  }
});

// ═══ H — independent credentials on the wire ════════════════════════════════
section("H  each product sends its own credentials");

await test("H1", "Payout API headers carry the PAYOUT credentials, never the Secure ID ones", async () => {
  setEnv({ ...SECURE_ID, ...PAYOUT });
  resetFetch(() => ({ status: 404, body: {} }));
  await client.getTransfer("FAP_x");
  expect(fetchCalls.length === 1, `${fetchCalls.length} fetch call(s)`);
  const h = fetchCalls[0].headers;
  expect(h["x-client-id"] === PAYOUT.CASHFREE_PAYOUT_CLIENT_ID, "x-client-id is not the payout id");
  expect(h["x-client-secret"] === PAYOUT.CASHFREE_PAYOUT_CLIENT_SECRET, "x-client-secret is not the payout secret");
  expect(h["x-api-version"] === "2024-01-01", "x-api-version changed");
});

const loadSecureId = async (tag) => import(`../modules/kyc/providers/cashfree.provider.js?${tag}`);

await test("H2", "Secure ID still sends its ORIGINAL credentials (CASHFREE_CLIENT_ID/SECRET), never the payout ones", async () => {
  setEnv({ ...SECURE_ID, ...PAYOUT });
  const kyc = await loadSecureId("h2");
  resetFetch(() => ({ status: 200, body: { valid: true, reference_id: "1" } }));
  await kyc.verifyPANCashfree({ panNumber: "ABCDE1234F", nameOnPAN: "ZTEST" });
  expect(fetchCalls.length === 1, `${fetchCalls.length} fetch call(s)`);
  const h = fetchCalls[0].headers;
  expect(h["x-client-id"] === SECURE_ID.CASHFREE_CLIENT_ID, "Secure ID x-client-id changed");
  expect(h["x-client-secret"] === SECURE_ID.CASHFREE_CLIENT_SECRET, "Secure ID x-client-secret changed");
});

await test("H3", "Secure ID works with ONLY its own credentials (payout credentials not required)", async () => {
  setEnv({ ...SECURE_ID });
  const kyc = await loadSecureId("h3");
  resetFetch(() => ({ status: 200, body: { valid: true, reference_id: "1" } }));
  const r = await kyc.verifyPANCashfree({ panNumber: "ABCDE1234F", nameOnPAN: "ZTEST" });
  expect(fetchCalls.length === 1 && r.success === true, `Secure ID did not run (${fetchCalls.length} calls)`);
});

await test("H4", "Secure ID with ONLY payout credentials stays not-configured (0 fetch calls)", async () => {
  setEnv({ ...PAYOUT });
  const kyc = await loadSecureId("h4");
  resetFetch();
  const r = await kyc.verifyPANCashfree({ panNumber: "ABCDE1234F" });
  expect(fetchCalls.length === 0 && r.success === false, "Secure ID used the payout credentials");
});

// ═══ W — webhook secret ═════════════════════════════════════════════════════
section("W  payout webhook verification");

const signWith = async (secret, rawBody, ts) => {
  const crypto = await import("node:crypto");
  return crypto.createHmac("sha256", secret).update(String(ts) + rawBody).digest("base64");
};
const BODY = JSON.stringify({ type: "TRANSFER_SUCCESS", data: { transfer_id: "FAP_x" } });

await test("W1", "the Secure ID secret can NOT verify a payout webhook (no payout secrets set)", async () => {
  setEnv({ ...SECURE_ID });
  const ts = Math.floor(Date.now() / 1000);
  const signature = await signWith(SECURE_ID.CASHFREE_CLIENT_SECRET, BODY, ts);
  expect(client.verifyWebhookSignature({ rawBody: BODY, signature, timestamp: ts }) === false, "accepted a Secure ID signature");
});

await test("W2", "the Secure ID secret can NOT verify a payout webhook (payout credentials set)", async () => {
  setEnv({ ...SECURE_ID, ...PAYOUT });
  const ts = Math.floor(Date.now() / 1000);
  const signature = await signWith(SECURE_ID.CASHFREE_CLIENT_SECRET, BODY, ts);
  expect(client.verifyWebhookSignature({ rawBody: BODY, signature, timestamp: ts }) === false, "accepted a Secure ID signature");
});

await test("W3", "fallback: the PAYOUT client secret verifies when no webhook secret is set", async () => {
  setEnv({ ...PAYOUT });
  const ts = Math.floor(Date.now() / 1000);
  const signature = await signWith(PAYOUT.CASHFREE_PAYOUT_CLIENT_SECRET, BODY, ts);
  expect(client.verifyWebhookSignature({ rawBody: BODY, signature, timestamp: ts }) === true, "payout client secret rejected");
});

await test("W4", "CASHFREE_PAYOUT_WEBHOOK_SECRET still takes precedence", async () => {
  setEnv({ ...PAYOUT, CASHFREE_PAYOUT_WEBHOOK_SECRET: "zt_payout_webhook_secret" });
  const ts = Math.floor(Date.now() / 1000);
  const good = await signWith("zt_payout_webhook_secret", BODY, ts);
  const other = await signWith(PAYOUT.CASHFREE_PAYOUT_CLIENT_SECRET, BODY, ts);
  expect(client.verifyWebhookSignature({ rawBody: BODY, signature: good, timestamp: ts }) === true, "webhook secret rejected");
  expect(client.verifyWebhookSignature({ rawBody: BODY, signature: other, timestamp: ts }) === false, "client secret accepted over the webhook secret");
});

await test("W5", "no secrets at all → every webhook rejected", async () => {
  setEnv({});
  const ts = Math.floor(Date.now() / 1000);
  const signature = await signWith("", BODY, ts);
  expect(client.verifyWebhookSignature({ rawBody: BODY, signature, timestamp: ts }) === false, "accepted without any secret");
});

// ═══ E — CASHFREE_ENV unchanged ═════════════════════════════════════════════
section("E  CASHFREE_ENV behaviour unchanged");

await test("E1", "Payouts: exactly PRODUCTION → live URL; anything else → sandbox", async () => {
  const cases = [["PRODUCTION", "https://api.cashfree.com/payout"], ["production", "https://sandbox.cashfree.com/payout"],
    ["PRODUCTION ", "https://sandbox.cashfree.com/payout"], ["SANDBOX", "https://sandbox.cashfree.com/payout"], [undefined, "https://sandbox.cashfree.com/payout"]];
  for (const [value, url] of cases) {
    setEnv(value === undefined ? {} : { CASHFREE_ENV: value });
    expect(client.getPayoutBaseUrl() === url, `CASHFREE_ENV=${JSON.stringify(value)} → ${client.getPayoutBaseUrl()}`);
  }
});

await test("E2", "Payouts: CASHFREE_PAYOUT_BASE_URL override honoured off PRODUCTION, ignored in PRODUCTION", async () => {
  setEnv({ CASHFREE_ENV: "SANDBOX", CASHFREE_PAYOUT_BASE_URL: "http://127.0.0.1:9" });
  expect(client.getPayoutBaseUrl() === "http://127.0.0.1:9", "override not honoured on sandbox");
  setEnv({ CASHFREE_ENV: "PRODUCTION", CASHFREE_PAYOUT_BASE_URL: "http://127.0.0.1:9" });
  expect(client.getPayoutBaseUrl() === "https://api.cashfree.com/payout", "override honoured in PRODUCTION");
});

await test("E3", "Secure ID: exactly PRODUCTION → live verification URL; anything else → sandbox", async () => {
  for (const [value, base] of [["PRODUCTION", "https://api.cashfree.com/verification"], ["production", "https://sandbox.cashfree.com/verification"], [undefined, "https://sandbox.cashfree.com/verification"]]) {
    setEnv({ ...SECURE_ID, ...(value === undefined ? {} : { CASHFREE_ENV: value }) });
    const kyc = await loadSecureId(`e3-${value}`);
    resetFetch(() => ({ status: 200, body: { valid: true } }));
    await kyc.verifyPANCashfree({ panNumber: "ABCDE1234F" });
    expect(fetchCalls[0]?.url === `${base}/pan`, `CASHFREE_ENV=${JSON.stringify(value)} → ${fetchCalls[0]?.url}`);
  }
});

// ═══ S — static scope checks (read as text) ═════════════════════════════════
section("S  scope: Secure ID and Razorpay untouched by the separation");

const read = (rel) => fs.readFileSync(path.join(BACKEND_DIR, rel), "utf8");
const code = (rel) => read(rel).split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join("\n");

await test("S1", "the payout client never reads the Secure ID variables", async () => {
  const src = code("services/settlement/cashfree/cashfreePayoutClient.js");
  expect(!/process\.env\.CASHFREE_CLIENT_(ID|SECRET)\b/.test(src), "payout client reads CASHFREE_CLIENT_ID/SECRET");
  expect(/process\.env\.CASHFREE_PAYOUT_CLIENT_ID\b/.test(src) && /process\.env\.CASHFREE_PAYOUT_CLIENT_SECRET\b/.test(src), "payout variables not read");
});

await test("S2", "Secure ID still reads CASHFREE_CLIENT_ID/SECRET and never the payout variables", async () => {
  for (const rel of ["modules/kyc/providers/cashfree.provider.js", "modules/kyc/services/verification.service.js"]) {
    const src = code(rel);
    expect(/process\.env\.CASHFREE_CLIENT_ID\b/.test(src) && /process\.env\.CASHFREE_CLIENT_SECRET\b/.test(src), `${rel}: Secure ID variables missing`);
    expect(!/CASHFREE_PAYOUT_/.test(src), `${rel}: reads a payout variable`);
  }
});

await test("S3", "Razorpay / RazorpayX code does not read any Cashfree variable", async () => {
  for (const rel of ["services/Razorpay.service.js", "services/settlement/razorpayx/razorpayxPayoutClient.js", "services/settlement/providers/RazorpayXPayoutProvider.js"]) {
    expect(!/CASHFREE_/.test(code(rel)), `${rel} references a Cashfree variable`);
  }
});

await test("S4", "dispatchCashfreeTransfer checks the payout configuration before its first database read", async () => {
  const src = read("modules/fieldAgent/services/fieldAgentAutoPayout.service.js");
  const body = src.slice(src.indexOf("export const dispatchCashfreeTransfer"));
  const guard = body.indexOf("if (!isCashfreePayoutConfigured())");
  const firstRead = body.indexOf("await FieldAgentPayoutRequest.");
  expect(guard >= 0 && firstRead > guard, "guard missing or after the first database read");
});

await test("S5", "backend-ci.yml runs this script", async () => {
  const ci = fs.readFileSync(path.join(REPO_DIR, ".github/workflows/backend-ci.yml"), "utf8");
  expect(/^\s+run: node scripts\/verifyCashfreeCredentialSeparation\.js$/m.test(ci), "CI step missing");
});

// ─── summary ────────────────────────────────────────────────────────────────
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length === 0 ? 0 : 1);
