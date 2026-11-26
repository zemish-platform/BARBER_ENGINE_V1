/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyWalletTopupCredit.js
 *
 * Hermetic verification of the wallet top-up credit rules (services/walletTopupCredit.service.js)
 * through the REAL Express app: POST /api/v1/wallet/add-money/verify and the REAL Razorpay webhook
 * route (raw body, HMAC signature, event dedupe), plus a booking-payment regression.
 *
 * NO real Razorpay: the SDK instance (razorpayInstance) is stubbed in-process — orders.create,
 * orders.fetch, payments.fetch return entities from a local map. Signatures use throwaway secrets
 * set below. NO real database: refuses to run unless ZTEST_MONGO_URI and ZTEST_REDIS_URL point at
 * 127.0.0.1 / localhost on an explicit NON-default port (27017 / 6379 are refused), with no
 * credentials, and the database is named ztest_*. The live connection is re-checked after connecting,
 * and cleanup drops only that ztest_ database (a throwaway replica set is required for transactions).
 *
 * Run (from backend/):
 *   ZTEST_MONGO_URI="mongodb://127.0.0.1:37217/ztest_wallet_topup?replicaSet=rsz" \
 *   ZTEST_REDIS_URL="redis://127.0.0.1:36479" node scripts/verifyWalletTopupCredit.js
 */

import crypto from "crypto";

// ─── connection-target safety (BEFORE anything connects) ───────────
// This script drops its test database at the end. It therefore refuses to run unless the target is
// provably a throwaway: loopback host, an explicit non-default port, a database named ztest_*, no
// credentials. Anything it cannot parse or verify is refused (fail closed). Refusal messages name
// the rule only — never the connection string, host details beyond the rule, or credentials.
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"]);
const REFUSED_MONGO_PORTS = new Set([27017]); // the default port — where a real local database lives
const REFUSED_REDIS_PORTS = new Set([6379]);  // likewise for Redis
const TEST_DB_NAME_RE = /^ztest_[A-Za-z0-9_]{1,50}$/;

const refuse = (reason) => {
  console.error(`Refusing to run: ${reason}`);
  process.exit(2);
};

const parseTarget = (raw, scheme) => {
  const value = String(raw ?? "").trim();
  if (!value) return { error: "is not set" };
  if (!value.startsWith(`${scheme}://`)) return { error: `must use the plain ${scheme}:// scheme` };
  if (value.slice(scheme.length + 3).split(/[/?]/)[0].includes(",")) return { error: "must name exactly one host" };
  let url;
  try { url = new URL(value); } catch { return { error: "could not be parsed" }; }
  if (url.username || url.password) return { error: "must not contain credentials" };
  if (!LOOPBACK_HOSTS.has(url.hostname)) return { error: "must point at 127.0.0.1 or localhost" };
  if (!/^\d+$/.test(url.port)) return { error: "must name an explicit port" };
  return { url, port: Number(url.port) };
};

const mongoTarget = parseTarget(process.env.ZTEST_MONGO_URI, "mongodb");
if (mongoTarget.error) refuse(`ZTEST_MONGO_URI ${mongoTarget.error}.`);
if (REFUSED_MONGO_PORTS.has(mongoTarget.port)) refuse("ZTEST_MONGO_URI uses MongoDB's default port 27017 — use a throwaway mongod on another port.");
const TEST_DB_NAME = decodeURIComponent(mongoTarget.url.pathname.replace(/^\//, ""));
if (!TEST_DB_NAME_RE.test(TEST_DB_NAME)) refuse("ZTEST_MONGO_URI must name a database starting with ztest_ (letters, digits, _ only).");
if (mongoTarget.url.searchParams.has("authSource")) refuse("ZTEST_MONGO_URI must not set authSource (a throwaway database needs no authentication).");

const redisTarget = parseTarget(process.env.ZTEST_REDIS_URL, "redis");
if (redisTarget.error) refuse(`ZTEST_REDIS_URL ${redisTarget.error}.`);
if (REFUSED_REDIS_PORTS.has(redisTarget.port)) refuse("ZTEST_REDIS_URL uses Redis's default port 6379 — use a throwaway redis-server on another port.");

// Environment BEFORE any app module is imported (dynamic imports below).
process.env.NODE_ENV = "test";
process.env.MONGODB_URI = process.env.ZTEST_MONGO_URI;
process.env.REDIS_URL = process.env.ZTEST_REDIS_URL;
process.env.RAZORPAY_KEY_ID = "rzp_test_ztestdummykey";
process.env.RAZORPAY_KEY_SECRET = "ztest_key_secret_not_real";
process.env.RAZORPAY_WEBHOOK_SECRET = "ztest_webhook_secret_not_real";
process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "ztest_jwt_access_secret";
process.env.JWT_SECRET = process.env.JWT_SECRET || "ztest_jwt_secret";
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "ztest_jwt_refresh_secret";
delete process.env.RAZORPAY_ALLOW_TEST_BYPASS;

const mongoose = (await import("mongoose")).default;
const { default: app } = await import("../app.js");
const { default: connectDB } = await import("../config/db.js");
const { default: redis } = await import("../config/redis.js");
const { generateAccessToken } = await import("../services/token.service.js");
const { razorpayInstance } = await import("../services/Razorpay.service.js");
const { default: NotificationService } = await import("../services/NotificationService.js");
const { default: User } = await import("../models/User.js");
const { default: Salon } = await import("../models/Salon.js");
const { default: Booking, BOOKING_STATUS } = await import("../models/Booking.js");
const { default: Transaction } = await import("../models/Transaction.js");
const { default: WalletTransaction } = await import("../models/WalletTransaction.js");
const { default: WebhookEvent } = await import("../models/WebhookEvent.js");
const { evaluateTopupPayment, TOPUP_CREDIT_OUTCOME } = await import("../services/walletTopupCredit.service.js");

// ─── harness ───────────────────────────────────────────────────────
let pass = 0, fail = 0;
const check = (id, name, cond, detail) => {
  if (cond) { pass++; console.log(`  ✅ ${id} ${name}`); }
  else { fail++; console.log(`  ❌ ${id} ${name}${detail !== undefined ? " — " + JSON.stringify(detail) : ""}`); }
};
const section = (t) => console.log(`\n── ${t} ──`);
const oid = () => new mongoose.Types.ObjectId();
let seq = 0;
const uniq = () => `${Date.now().toString(36)}${(++seq).toString(36)}`;
const phone = () => `9${Math.floor(100000000 + Math.random() * 899999999)}`;

// ─── Razorpay stub (in-process; nothing leaves the machine) ────────
const orders = new Map();
const payments = new Map();
razorpayInstance.orders.create = async ({ amount, currency, receipt, notes }) => {
  const o = { id: `order_ZT${uniq()}`, entity: "order", amount, currency, receipt, notes: notes || {}, status: "created" };
  orders.set(o.id, o);
  return o;
};
razorpayInstance.orders.fetch = async (id) => {
  if (!orders.has(id)) { const e = new Error("not found"); e.statusCode = 400; e.error = { code: "BAD_REQUEST_ERROR", description: "The id provided does not exist" }; throw e; }
  return orders.get(id);
};
razorpayInstance.payments.fetch = async (id) => {
  if (!payments.has(id)) { const e = new Error("not found"); e.statusCode = 400; e.error = { code: "BAD_REQUEST_ERROR", description: "The id provided does not exist" }; throw e; }
  return { ...payments.get(id) };
};
razorpayInstance.payments.fetchMultipleRefund = async () => ({ items: [] });
const mkPayment = (order, over = {}) => {
  const p = { id: `pay_ZT${uniq()}`, entity: "payment", order_id: order.id, amount: order.amount, currency: "INR", status: "captured", amount_refunded: 0, refund_status: null, notes: order.notes || {}, ...over };
  payments.set(p.id, p);
  return p;
};

// Notifications: counted; can be made to throw.
let notifications = 0;
let notificationsThrow = false;
NotificationService.send = async () => {
  if (notificationsThrow) throw new Error("ztest notification provider down");
  notifications++;
  return { ok: true };
};

// ─── HTTP ──────────────────────────────────────────────────────────
await connectDB();
// Post-connect: the live connection must be exactly the validated throwaway target, else stop
// WITHOUT running tests or cleanup.
{
  const c = mongoose.connection;
  const sameDb = c.readyState === 1 && c.name === TEST_DB_NAME;
  const sameHost = LOOPBACK_HOSTS.has(String(c.host)) && Number(c.port) === mongoTarget.port;
  if (!sameDb || !sameHost) {
    console.error("Refusing to run: the live MongoDB connection is not the validated ztest_ target.");
    await mongoose.disconnect().catch(() => {});
    process.exit(2);
  }
}
// A fresh throwaway database builds indexes in the background; the unique indexes ARE the
// idempotency guarantees under test, so wait until they exist (production already has them).
// (Booking is left out: one of its pre-existing index specs mixes `sparse` with
// `partialFilterExpression`, which MongoDB rejects on a fresh database — not touched here.)
await Promise.all([Transaction, WalletTransaction, WebhookEvent].map((m) => m.init()));
for (let i = 0; i < 50 && !redis.isReady; i++) await new Promise((r) => setTimeout(r, 100));
const server = app.listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const port = server.address().port;
const call = (path, token, { method = "GET", body, headers = {}, raw } = {}) =>
  fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { ...(body && !raw ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    body: raw !== undefined ? raw : body ? JSON.stringify(body) : undefined,
  }).then(async (r) => ({ status: r.status, data: await r.json().catch(() => ({})) }));

const sign = (orderId, paymentId) => crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(`${orderId}|${paymentId}`).digest("hex");
const whSign = (raw) => crypto.createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET).update(raw).digest("hex");
const envelope = (event, entities) => ({
  entity: "event", account_id: "acc_ztest", event, contains: Object.keys(entities),
  payload: Object.fromEntries(Object.entries(entities).map(([k, v]) => [k, { entity: v }])),
  created_at: Math.floor(Date.now() / 1000),
});
const webhook = (payload, { id = `evt_ZT${uniq()}`, signed = true, badSig = false } = {}) => {
  const raw = JSON.stringify(payload);
  const headers = { "content-type": "application/json", "x-razorpay-event-id": id };
  if (signed) headers["x-razorpay-signature"] = badSig ? whSign(raw + "x") : whSign(raw);
  return call("/api/webhooks/razorpay", null, { method: "POST", raw, headers }).then((r) => ({ ...r, id }));
};

const mkUser = async () => {
  const u = await User.create({ name: `ZTEST_WTU_${uniq()}`, phone: phone(), role: "USER", accountStatus: "ACTIVE", walletBalance: 0 });
  return { u, token: generateAccessToken({ _id: u._id, role: "USER", tokenVersion: 0 }) };
};
const balance = async (user) => (await User.findById(user.u._id).select("walletBalance").lean()).walletBalance;
const row = (orderId) => WalletTransaction.findOne({ razorpayOrderId: orderId }).lean();
const createTopup = async (user, amount = 500) => (await call("/api/v1/wallet/add-money/create-order", user.token, { method: "POST", body: { amount } })).data;
const verify = (user, orderId, paymentId, sig) =>
  call("/api/v1/wallet/add-money/verify", user.token, { method: "POST", body: { orderId, paymentId, signature: sig ?? sign(orderId, paymentId) } });
const evtStatus = async (id) => (await WebhookEvent.findOne({ eventId: id }).lean())?.status;

try {
  // ═══ 0. pure rule ═══════════════════════════════════════════════
  section("0  evaluateTopupPayment (pure)");
  const t0 = { razorpayOrderId: "order_A", amountInPaise: 50000, currency: "INR", userId: "u1" };
  const p0 = { id: "pay_A", order_id: "order_A", amount: 50000, currency: "INR", status: "captured", amount_refunded: 0, notes: { userId: "u1" } };
  check("0.1", "captured + matching → allowed", evaluateTopupPayment({ txn: t0, payment: p0 }) === null);
  check("0.2", "authorized → NOT_CAPTURED", evaluateTopupPayment({ txn: t0, payment: { ...p0, status: "authorized" } }) === TOPUP_CREDIT_OUTCOME.NOT_CAPTURED);
  check("0.3", "failed → PAYMENT_FAILED", evaluateTopupPayment({ txn: t0, payment: { ...p0, status: "failed" } }) === TOPUP_CREDIT_OUTCOME.PAYMENT_FAILED);
  check("0.4", "created / refunded / unknown status → never allowed", ["created", "refunded", "pending", "", undefined].every((s) => evaluateTopupPayment({ txn: t0, payment: { ...p0, status: s } }) !== null));
  check("0.5", "other order → ORDER_MISMATCH", evaluateTopupPayment({ txn: t0, payment: { ...p0, order_id: "order_B" } }) === TOPUP_CREDIT_OUTCOME.ORDER_MISMATCH);
  check("0.6", "amount ±1 paise → AMOUNT_MISMATCH", [49999, 50001].every((a) => evaluateTopupPayment({ txn: t0, payment: { ...p0, amount: a } }) === TOPUP_CREDIT_OUTCOME.AMOUNT_MISMATCH));
  check("0.7", "amount as string → AMOUNT_MISMATCH", evaluateTopupPayment({ txn: t0, payment: { ...p0, amount: "50000" } }) === TOPUP_CREDIT_OUTCOME.AMOUNT_MISMATCH);
  check("0.8", "USD → CURRENCY_MISMATCH", evaluateTopupPayment({ txn: t0, payment: { ...p0, currency: "USD" } }) === TOPUP_CREDIT_OUTCOME.CURRENCY_MISMATCH);
  check("0.9", "notes.userId of another user → USER_MISMATCH", evaluateTopupPayment({ txn: t0, payment: { ...p0, notes: { userId: "u2" } } }) === TOPUP_CREDIT_OUTCOME.USER_MISMATCH);
  check("0.10", "partially refunded → PAYMENT_REFUNDED", evaluateTopupPayment({ txn: t0, payment: { ...p0, amount_refunded: 100 } }) === TOPUP_CREDIT_OUTCOME.PAYMENT_REFUNDED);
  check("0.11", "missing payment → never allowed", evaluateTopupPayment({ txn: t0, payment: null }) !== null);

  // ═══ 1. verify endpoint ═════════════════════════════════════════
  section("1  POST /add-money/verify");
  {
    const a = await mkUser();
    const o = await createTopup(a, 500);
    check("1.1", "create-order: server amount in paise, INR, PENDING row", o.success && o.amount === 50000 && o.currency === "INR" && (await row(o.orderId))?.status === "PENDING", o);

    const pAuth = mkPayment(orders.get(o.orderId), { status: "authorized" });
    const r1 = await verify(a, o.orderId, pAuth.id);
    const rowA = await row(o.orderId);
    check("1.2", "authorized → 202 pending, NO credit, row stays PENDING", r1.status === 202 && r1.data.pending === true && (await balance(a)) === 0 && rowA.status === "PENDING" && !rowA.razorpayPaymentId, { r1, rowA: rowA.status });

    payments.get(pAuth.id).status = "captured"; // the bank completes capture
    const n0 = notifications;
    const r2 = await verify(a, o.orderId, pAuth.id);
    const rowA2 = await row(o.orderId);
    check("1.3", "captured + matching → 200 credited exactly once", r2.status === 200 && r2.data.success && (await balance(a)) === 500 && rowA2.status === "SUCCESS" && rowA2.razorpayPaymentId === pAuth.id, r2);
    check("1.4", "balance snapshots recorded (0 → 50000 paise), creditedVia=verify", rowA2.balanceBeforeInPaise === 0 && rowA2.balanceAfterInPaise === 50000 && rowA2.metadata?.creditedVia === "verify", rowA2);
    check("1.5", "exactly one notification for the credit", notifications === n0 + 1);
    const r3 = await verify(a, o.orderId, pAuth.id);
    check("1.6", "duplicate verify → 200 'Already credited', no second credit, no second notification", r3.status === 200 && /Already credited/.test(r3.data.message) && r3.data.walletBalance === 500 && (await balance(a)) === 500 && notifications === n0 + 1, r3);

    const b = await mkUser();
    const r4 = await verify(b, o.orderId, pAuth.id);
    check("1.7", "another user cannot verify this order → 404, their wallet unchanged", r4.status === 404 && (await balance(b)) === 0, r4);
  }
  {
    const a = await mkUser();
    const o = await createTopup(a, 300);
    const p = mkPayment(orders.get(o.orderId), { status: "failed" });
    const r = await verify(a, o.orderId, p.id);
    check("1.8", "failed payment → 400, NO credit, row FAILED (PAYMENT_FAILED)", r.status === 400 && (await balance(a)) === 0 && (await row(o.orderId)).status === "FAILED" && (await row(o.orderId)).failureCode === "PAYMENT_FAILED", r);
  }
  for (const [id, label, over] of [
    ["1.9", "wrong amount", { amount: 30001 }],
    ["1.10", "wrong currency", { currency: "USD" }],
  ]) {
    const a = await mkUser();
    const o = await createTopup(a, 300);
    const p = mkPayment(orders.get(o.orderId), over);
    const r = await verify(a, o.orderId, p.id);
    const rw = await row(o.orderId);
    check(id, `${label} → 409 needsReview, NO credit, row stays PENDING, review flag recorded`, r.status === 409 && r.data.needsReview && (await balance(a)) === 0 && rw.status === "PENDING" && rw.metadata?.reviewFlags?.length === 1 && !rw.razorpayPaymentId, { r, rw: rw.metadata });
  }
  {
    const a = await mkUser();
    const o1 = await createTopup(a, 300);
    const o2 = await createTopup(a, 300);
    const pOther = mkPayment(orders.get(o2.orderId)); // a real captured payment, but for ANOTHER order
    const r = await verify(a, o1.orderId, pOther.id);  // client claims it pays order 1 (signature computed over o1)
    check("1.11", "payment belonging to another order → 409, NO credit to either row", r.status === 409 && (await balance(a)) === 0 && (await row(o1.orderId)).status === "PENDING" && (await row(o2.orderId)).status === "PENDING", r);
  }
  {
    const a = await mkUser();
    const o = await createTopup(a, 300);
    const p = mkPayment(orders.get(o.orderId));
    const r = await verify(a, o.orderId, p.id, "0".repeat(64));
    check("1.12", "invalid signature → 400, NO credit (existing behaviour preserved)", r.status === 400 && (await balance(a)) === 0 && (await row(o.orderId)).status === "FAILED", r);
  }
  {
    const a = await mkUser();
    const oA = await createTopup(a, 300);
    const oB = await createTopup(a, 300);
    const p = mkPayment(orders.get(oA.orderId));
    await verify(a, oA.orderId, p.id);
    const r = await verify(a, oB.orderId, p.id);
    check("1.13", "one payment cannot credit a second top-up row → 409, balance credited once", r.status === 409 && (await balance(a)) === 300 && (await row(oB.orderId)).status === "PENDING", r);
  }

  // ═══ 2. notification failure ════════════════════════════════════
  section("2  notification failure after credit");
  {
    const a = await mkUser();
    const o = await createTopup(a, 700);
    const p = mkPayment(orders.get(o.orderId));
    notificationsThrow = true;
    const r1 = await verify(a, o.orderId, p.id);
    notificationsThrow = false;
    check("2.1", "notification throws → still 200 credited (credit is durable)", r1.status === 200 && r1.data.success && (await balance(a)) === 700 && (await row(o.orderId)).status === "SUCCESS", r1);
    const r2 = await verify(a, o.orderId, p.id);
    check("2.2", "client retry after that → 'Already credited', no duplicate credit", r2.status === 200 && /Already credited/.test(r2.data.message) && (await balance(a)) === 700, r2);
    const w = await webhook(envelope("payment.captured", { payment: payments.get(p.id) }));
    check("2.3", "late webhook for the same payment → ALREADY_CREDITED, no duplicate credit", w.status === 200 && w.data.outcome === "WALLET_TOPUP_ALREADY_CREDITED" && (await balance(a)) === 700, w);
  }

  // ═══ 3. webhook ═════════════════════════════════════════════════
  section("3  Razorpay webhook");
  {
    const a = await mkUser();
    const o = await createTopup(a, 400);
    const p = mkPayment(orders.get(o.orderId));
    const raw = envelope("payment.captured", { payment: payments.get(p.id) });
    check("3.1", "unsigned webhook → 401, no credit (signature preserved)", (await webhook(raw, { signed: false })).status === 401 && (await balance(a)) === 0);
    check("3.2", "bad signature → 401, no credit", (await webhook(raw, { badSig: true })).status === 401 && (await balance(a)) === 0);

    const w1 = await webhook(raw);
    check("3.3", "captured top-up via webhook (app closed) → credited once, PROCESSED", w1.status === 200 && w1.data.outcome === "WALLET_TOPUP_CREDITED" && (await balance(a)) === 400 && (await evtStatus(w1.id)) === "PROCESSED" && (await row(o.orderId)).metadata?.creditedVia === "webhook", w1);
    const w2 = await webhook(raw, { id: w1.id });
    check("3.4", "duplicate delivery (same event id) → 200 duplicate, no second credit", w2.status === 200 && w2.data.duplicate === true && (await balance(a)) === 400, w2);
    const w3 = await webhook(envelope("order.paid", { payment: payments.get(p.id), order: { ...orders.get(o.orderId), status: "paid" } }));
    check("3.5", "retry / order.paid for the same payment (new event id) → ALREADY_CREDITED, no second credit", w3.status === 200 && w3.data.outcome === "WALLET_TOPUP_ALREADY_CREDITED" && (await balance(a)) === 400, w3);
    const v = await verify(a, o.orderId, p.id);
    check("3.6", "app verifies after the webhook credited → 'Already credited', balance once", v.status === 200 && /Already credited/.test(v.data.message) && (await balance(a)) === 400, v);
  }
  {
    const a = await mkUser();
    const o = await createTopup(a, 400);
    const p = mkPayment(orders.get(o.orderId), { status: "authorized" });
    const wA = await webhook(envelope("payment.authorized", { payment: payments.get(p.id) }));
    check("3.7", "payment.authorized event → no credit (IGNORED)", wA.status === 200 && (await balance(a)) === 0 && (await evtStatus(wA.id)) === "IGNORED", wA);
    const v = await verify(a, o.orderId, p.id);
    check("3.8", "verify while authorized → 202, no credit", v.status === 202 && (await balance(a)) === 0, v);
    payments.get(p.id).status = "captured";
    const wC = await webhook(envelope("payment.captured", { payment: payments.get(p.id) }));
    check("3.9", "then payment.captured → credited exactly once", wC.data.outcome === "WALLET_TOPUP_CREDITED" && (await balance(a)) === 400, wC);
  }
  {
    const a = await mkUser();
    const o = await createTopup(a, 400);
    const p = mkPayment(orders.get(o.orderId), { status: "failed" });
    const w = await webhook(envelope("payment.failed", { payment: payments.get(p.id) }));
    check("3.10", "payment.failed → no credit, row still PENDING (customer may retry the order)", w.status === 200 && (await balance(a)) === 0 && (await row(o.orderId)).status === "PENDING", w);
  }
  for (const [id, label, over] of [
    ["3.11", "wrong amount", { amount: 39999 }],
    ["3.12", "wrong currency", { currency: "USD" }],
    ["3.13", "payment noted to another user", { notes: { userId: String(oid()) } }],
  ]) {
    const a = await mkUser();
    const o = await createTopup(a, 400);
    const p = mkPayment(orders.get(o.orderId), over);
    const w = await webhook(envelope("payment.captured", { payment: payments.get(p.id) }));
    const st = await evtStatus(w.id);
    check(id, `captured top-up with ${label} → NEEDS_REVIEW (not PROCESSED), NO credit, row PENDING`, w.status === 200 && st === "NEEDS_REVIEW" && (await balance(a)) === 0 && (await row(o.orderId)).status === "PENDING", { w, st });
  }
  {
    const a = await mkUser();
    const o = await createTopup(a, 400);
    const p1 = mkPayment(orders.get(o.orderId));
    const p2 = mkPayment(orders.get(o.orderId)); // a second captured payment on the same order
    await webhook(envelope("payment.captured", { payment: payments.get(p1.id) }));
    const w = await webhook(envelope("payment.captured", { payment: payments.get(p2.id) }));
    check("3.14", "second captured payment on an already-credited order → NEEDS_REVIEW, credited once", (await evtStatus(w.id)) === "NEEDS_REVIEW" && w.data.outcome === "WALLET_TOPUP_DIFFERENT_PAYMENT" && (await balance(a)) === 400, w);
  }
  {
    const a = await mkUser();
    const o = await createTopup(a, 400);
    const p = mkPayment(orders.get(o.orderId));
    await verify(a, o.orderId, p.id);
    const refund = { id: `rfnd_ZT${uniq()}`, entity: "refund", payment_id: p.id, amount: 40000, currency: "INR", status: "processed", notes: {} };
    payments.get(p.id).amount_refunded = 40000;
    const w = await webhook(envelope("refund.processed", { refund, payment: payments.get(p.id) }));
    check("3.15", "dashboard refund of a top-up → NEEDS_REVIEW REFUND_ON_WALLET_TOPUP, wallet NOT debited", w.status === 200 && w.data.outcome === "REFUND_ON_WALLET_TOPUP" && (await evtStatus(w.id)) === "NEEDS_REVIEW" && (await balance(a)) === 400, w);
  }

  // ═══ 4. concurrency ═════════════════════════════════════════════
  section("4  concurrent verify + webhook delivery");
  for (let round = 1; round <= 5; round++) {
    const a = await mkUser();
    const o = await createTopup(a, 250);
    const p = mkPayment(orders.get(o.orderId));
    const n0 = notifications;
    const ops = [
      verify(a, o.orderId, p.id),
      webhook(envelope("payment.captured", { payment: payments.get(p.id) })),
      verify(a, o.orderId, p.id),
      webhook(envelope("order.paid", { payment: payments.get(p.id), order: orders.get(o.orderId) })),
      verify(a, o.orderId, p.id),
      webhook(envelope("payment.captured", { payment: payments.get(p.id) })),
    ];
    const rs = await Promise.all(ops);
    const credits = rs.filter((r) => r.data?.outcome === "WALLET_TOPUP_CREDITED" || /credited successfully/.test(r.data?.message || "")).length;
    check(`4.${round}`, `6 parallel deliveries → exactly one credit, balance once, no 5xx, one notification`,
      credits === 1 && (await balance(a)) === 250 && rs.every((r) => r.status < 500) && notifications === n0 + 1 && (await row(o.orderId)).status === "SUCCESS",
      { credits, bal: await balance(a), statuses: rs.map((r) => r.status), notes: notifications - n0 });
  }

  // ═══ 5. booking payment regression ══════════════════════════════
  section("5  booking payment regression");
  {
    const owner = await User.create({ name: `ZTEST_WTU_OWNER_${uniq()}`, phone: phone(), role: "OWNER", accountStatus: "ACTIVE" });
    const dayTiming = { open: "09:00", close: "20:00" };
    const salon = await Salon.create({
      ownerId: owner._id, basicInfo: { shopName: `ZTEST_WTU_SALON_${uniq()}`, category: "UNISEX" },
      timings: Object.fromEntries(["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"].map((d) => [d, dayTiming])),
      location: { geo: { type: "Point", coordinates: [77, 28] }, address: "ztest addr" },
    });
    let slot = 0;
    const mkBooking = async (user, total = 12000) => {
      const start = new Date(Date.now() + (120 + slot++ * 45) * 60000);
      return Booking.create({
        userRef: user.u._id, salonRef: salon._id, chairRef: oid(), serviceRefs: [oid()],
        bookingDate: new Date().toISOString().slice(0, 10), startTime: start, endTime: new Date(start.getTime() + 30 * 60000),
        serviceDuration: 30, status: BOOKING_STATUS.HOLD, lockUntil: new Date(Date.now() + 10 * 60000),
        serviceAmountInPaise: total - 2000, commissionAmountInPaise: 2000, totalAmountInPaise: total,
      });
    };
    const createOrder = (user, bookingId) => call("/api/payments/create-order", user.token, { method: "POST", body: { bookingId: String(bookingId) } });
    const confirm = (user, bookingId, orderId, paymentId, sig) =>
      call("/api/v1/bookings/user/confirm", user.token, { method: "POST", body: { bookingId: String(bookingId), paymentMethod: "RAZORPAY", orderId, paymentId, razorpaySignature: sig ?? sign(orderId, paymentId) } });
    const status = async (id) => (await Booking.findById(id).lean()).status;

    const c = await mkUser();
    const b1 = await mkBooking(c);
    const o1 = (await createOrder(c, b1._id)).data;
    check("5.1", "create-order amount comes from the booking (server-side), INR", o1.success && orders.get(o1.orderId)?.amount === 12000 && orders.get(o1.orderId)?.currency === "INR", o1);

    const pAuth = mkPayment(orders.get(o1.orderId), { status: "authorized" });
    const r1 = await confirm(c, b1._id, o1.orderId, pAuth.id);
    check("5.2", "confirm with an AUTHORIZED payment → rejected, booking stays HOLD, no Transaction", r1.status >= 400 && (await status(b1._id)) === "HOLD" && !(await Transaction.exists({ bookingId: b1._id })), r1);

    const pWrong = mkPayment(orders.get(o1.orderId), { amount: 11999 });
    const r2 = await confirm(c, b1._id, o1.orderId, pWrong.id);
    check("5.3", "confirm with captured but WRONG amount → rejected, booking stays HOLD", r2.status >= 400 && (await status(b1._id)) === "HOLD" && !(await Transaction.exists({ bookingId: b1._id })), r2);

    const pGood = mkPayment(orders.get(o1.orderId));
    const r3 = await confirm(c, b1._id, o1.orderId, pGood.id, "f".repeat(64));
    check("5.4", "confirm with a BAD signature → rejected, booking stays HOLD", r3.status >= 400 && (await status(b1._id)) === "HOLD", r3);

    const r4 = await confirm(c, b1._id, o1.orderId, pGood.id);
    check("5.5", "confirm with captured + matching payment → CONFIRMED, exactly one Transaction", r4.status < 300 && (await status(b1._id)) === "CONFIRMED" && (await Transaction.countDocuments({ bookingId: b1._id })) === 1, r4);
    const r5 = await confirm(c, b1._id, o1.orderId, pGood.id);
    check("5.6", "repeat confirm → no second Transaction", (await Transaction.countDocuments({ bookingId: b1._id })) === 1, r5);
    const w1 = await webhook(envelope("payment.captured", { payment: payments.get(pGood.id) }));
    check("5.7", "webhook after client confirm → ALREADY_RECORDED (unchanged)", w1.data.outcome === "ALREADY_RECORDED" && (await Transaction.countDocuments({ bookingId: b1._id })) === 1, w1);
    check("5.8", "booking payments never touch the customer's wallet", (await balance(c)) === 0 && !(await WalletTransaction.exists({ userId: c.u._id })));

    const b2 = await mkBooking(c);
    const o2 = (await createOrder(c, b2._id)).data;
    const p2 = mkPayment(orders.get(o2.orderId));
    const w2 = await webhook(envelope("payment.captured", { payment: payments.get(p2.id) }));
    check("5.9", "webhook for a valid HOLD (app closed) → AUTO_CONFIRMED, one Transaction (unchanged)", w2.data.outcome === "AUTO_CONFIRMED" && (await status(b2._id)) === "CONFIRMED" && (await Transaction.countDocuments({ bookingId: b2._id })) === 1, w2);

    const b3 = await mkBooking(c);
    const o3 = (await createOrder(c, b3._id)).data;
    const p3 = mkPayment(orders.get(o3.orderId), { amount: 100 });
    const w3 = await webhook(envelope("payment.captured", { payment: payments.get(p3.id) }));
    check("5.10", "booking webhook amount mismatch → NEEDS_REVIEW, not confirmed (unchanged)", w3.data.outcome === "AMOUNT_MISMATCH" && (await status(b3._id)) === "HOLD", w3);

    const b4 = await mkBooking(c);
    const o4 = (await createOrder(c, b4._id)).data;
    const p4 = mkPayment(orders.get(o4.orderId), { status: "authorized" });
    const w4 = await webhook(envelope("payment.authorized", { payment: payments.get(p4.id) }));
    check("5.11", "authorized booking payment via webhook → not confirmed", (await status(b4._id)) === "HOLD" && w4.status === 200, w4);
  }
} catch (err) {
  fail++;
  console.log(`  ❌ harness error: ${err.stack || err.message}`);
} finally {
  server.close();
  // Drop ONLY the validated ztest_ database, re-checked at the moment of the drop.
  if (mongoose.connection.readyState === 1 && mongoose.connection.name === TEST_DB_NAME && TEST_DB_NAME_RE.test(mongoose.connection.name)) {
    await mongoose.connection.db.dropDatabase()
      .then(() => console.log(`\ncleanup: dropped test database ${TEST_DB_NAME}`))
      .catch((e) => console.log(`\ncleanup: could not drop test database (${e.message})`));
  } else {
    console.log("\ncleanup: skipped — connection is not the validated ztest_ database");
  }
  await mongoose.disconnect().catch(() => {});
  await redis.quit().catch(() => {});
}

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail === 0 ? 0 : 1);
