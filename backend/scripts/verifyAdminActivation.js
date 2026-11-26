/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyAdminActivation.js
 *
 * Hermetic verification of Admin Secure Activation (services/adminCredential.service.js,
 * controllers/adminAccount.controller.js, the adminLogin / protect / rotateSession gates and the
 * legacy district/state assignment flows) through the REAL Express app and the REAL OTP engine.
 *
 * NO real database, NO real SMS: refuses to run unless ZTEST_MONGO_URI and ZTEST_REDIS_URL point at
 * 127.0.0.1 / localhost on an explicit NON-default port (27017 / 6379 are refused), with no
 * credentials, and the database is named ztest_*. The live connection is re-checked after
 * connecting, and cleanup drops only that ztest_ database (a throwaway replica set is required for
 * the legacy flows' transactions). OTPs use the non-production fixed code (ALLOW_FIXED_OTP=true,
 * NODE_ENV=test) and the dev-log SMS provider — nothing leaves the machine.
 *
 * Run (from backend/):
 *   ZTEST_MONGO_URI="mongodb://127.0.0.1:37217/ztest_admin_activation?replicaSet=rsz" \
 *   ZTEST_REDIS_URL="redis://127.0.0.1:36479" node scripts/verifyAdminActivation.js
 */

// ─── connection-target safety (BEFORE anything connects) ───────────
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"]);
const REFUSED_MONGO_PORTS = new Set([27017]);
const REFUSED_REDIS_PORTS = new Set([6379]);
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
process.env.ALLOW_FIXED_OTP = "true";
process.env.RAZORPAY_KEY_ID = "rzp_test_ztestdummykey";       // app.js import needs these; never used here
process.env.RAZORPAY_KEY_SECRET = "ztest_key_secret_not_real";
process.env.RAZORPAY_WEBHOOK_SECRET = "ztest_webhook_secret_not_real";
process.env.ADMIN_PANEL_KEY = "ztest_admin_panel_key_not_real";
process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "ztest_jwt_access_secret";
process.env.JWT_SECRET = process.env.JWT_SECRET || "ztest_jwt_secret";
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "ztest_jwt_refresh_secret";
delete process.env.SMS_PROVIDER;
delete process.env.ADMIN_RESET_PASSWORD;

const bcrypt = (await import("bcryptjs")).default;
const mongoose = (await import("mongoose")).default;
const { default: app } = await import("../app.js");
const { default: connectDB } = await import("../config/db.js");
const { default: redis } = await import("../config/redis.js");
const { generateAccessToken } = await import("../services/token.service.js");
const { default: User } = await import("../models/User.js");
const { default: District } = await import("../models/District.js");
const { default: RefreshToken } = await import("../models/RefreshToken.js");
const { default: AdminAuditLog } = await import("../models/AdminAuditLog.js");
const { DEV_FIXED_OTP } = await import("../modules/otp/constants/otp.constants.js");
const svc = await import("../services/adminCredential.service.js");

// ─── harness ───────────────────────────────────────────────────────
let pass = 0, fail = 0;
const check = (id, name, cond, detail) => {
  if (cond) { pass++; console.log(`  ✅ ${id} ${name}`); }
  else { fail++; console.log(`  ❌ ${id} ${name}${detail !== undefined ? " — " + JSON.stringify(detail).slice(0, 400) : ""}`); }
};
const section = (t) => console.log(`\n── ${t} ──`);
const oid = () => new mongoose.Types.ObjectId();

await connectDB();
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
await User.init();
for (let i = 0; i < 50 && !redis.isReady; i++) await new Promise((r) => setTimeout(r, 100));
const server = app.listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const port = server.address().port;

// Every response body is collected so we can prove no OTP / password ever leaves the API.
const bodies = [];
let ipSeq = 0;
const call = (path, { token, method = "GET", body, cookie, ip } = {}) =>
  fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      // trust proxy = 1: a distinct client IP per call keeps the per-IP limiters out of the way
      // except in the test that targets them.
      "X-Forwarded-For": ip || `10.9.${Math.floor(++ipSeq / 250)}.${ipSeq % 250}`,
    },
    body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => {
    const text = await r.text();
    bodies.push(text);
    let data = {};
    try { data = JSON.parse(text); } catch { /* non-JSON */ }
    const setCookie = (r.headers.getSetCookie?.() || []).find((c) => c.startsWith("refreshToken=")) || null;
    return { status: r.status, data, code: data?.code || data?.error?.code || data?.errorCode, setCookie, cookie: setCookie ? setCookie.split(";")[0] : null };
  });
const codeOf = (r) => JSON.stringify(r.data);

const login = (email, password, extra = {}) => call("/api/admin-auth/login", { method: "POST", body: { email, password, ...extra } });
const requestOtp = (kind, phone, opts) => call(`/api/admin-auth/${kind === "RESET" ? "password-reset" : "activation"}/request-otp`, { method: "POST", body: { phone }, ...opts });
const complete = (kind, phone, otp, newPassword, opts) => call(`/api/admin-auth/${kind === "RESET" ? "password-reset" : "activation"}/complete`, { method: "POST", body: { phone, otp, newPassword }, ...opts });
const assign = (token, id, body) => call(`/api/admin/admin-accounts/${id}/assign`, { token, method: "POST", body });
const list = (token, qs = "") => call(`/api/admin/admin-accounts${qs}`, { token });
const otpHashKey = (purpose, phone) => `otp:admin:${purpose.toLowerCase()}:${phone}:hash`;
const otpLockKey = (purpose, phone) => `otp_lock:admin:${purpose.toLowerCase()}:${phone}`;
const clearOtpState = async (purpose, phone) => {
  await redis.del([otpHashKey(purpose, phone), otpLockKey(purpose, phone), `otp:admin:${purpose.toLowerCase()}:${phone}:attempts`]);
};
const ACT = "ADMIN_ACTIVATION";
const RST = "ADMIN_PASSWORD_RESET";
const tokenOf = (r) => r.data?.data?.accessToken;
const fresh = (id) => User.findById(id).select("+password +tokenVersion").lean();

try {
// ─── fixtures: a miniature of the seeded hierarchy ─────────────────
const SEED_PW = "ZtestSeed#Shared1";   // stands in for SEED_ADMIN_PASSWORD (shared by every seeded account)
const LEGACY_TEMP_PW = "Admin@12345";  // the old ADMIN_RESET_PASSWORD fallback
const seedHash = await bcrypt.hash(SEED_PW, 10);
const countryRef = oid();
const stateA = oid(), stateB = oid();
const distA1 = oid(), distA2 = oid(), distB1 = oid();

const mkAdmin = (doc) => User.create({ role: "ADMIN", countryRef, isActive: true, isDeleted: false, accountStatus: "ACTIVE", password: seedHash, mustChangePassword: true, ...doc });
const india = await mkAdmin({ name: "ZT India", email: "zt-india@ztest.local", phone: "9000000001", adminLevel: "INDIA", isPhoneVerified: true });
const saA = await mkAdmin({ name: "State A", email: "state-admin-za@yourapp.internal", phone: "9100000001", adminLevel: "STATE", adminSubRole: "PRIMARY", stateRef: stateA, isPhoneVerified: true });
const saA2 = await mkAdmin({ name: "State A backup", email: "state-backup-admin-za@yourapp.internal", phone: "9100000002", adminLevel: "STATE", adminSubRole: "SUPPORT", stateRef: stateA, isPhoneVerified: true });
const saB = await mkAdmin({ name: "State B", email: "state-admin-zb@yourapp.internal", phone: "9100000003", adminLevel: "STATE", adminSubRole: "PRIMARY", stateRef: stateB, isPhoneVerified: true });
const daA1 = await mkAdmin({ name: "District A1", email: "district-admin-za-a1@internal.local", phone: null, adminLevel: "DISTRICT", adminSubRole: "PRIMARY", stateRef: stateA, districtRef: distA1 });
const daA2 = await mkAdmin({ name: "District A2", email: "district-admin-za-a2@internal.local", phone: null, adminLevel: "DISTRICT", adminSubRole: "PRIMARY", stateRef: stateA, districtRef: distA2 });
const daB1 = await mkAdmin({ name: "District B1", email: "district-admin-zb-b1@internal.local", phone: null, adminLevel: "DISTRICT", adminSubRole: "PRIMARY", stateRef: stateB, districtRef: distB1 });
// District docs (raw insert — only the fields the legacy controllers read).
await District.collection.insertMany([
  { _id: distA1, name: "ZT A1", code: "ZTA1", slug: "zt-a1", normalizedName: "zt a1", stateRef: stateA, countryRef, primaryAdminRef: daA1._id, isActive: true, isDeleted: false },
  { _id: distA2, name: "ZT A2", code: "ZTA2", slug: "zt-a2", normalizedName: "zt a2", stateRef: stateA, countryRef, primaryAdminRef: daA2._id, isActive: true, isDeleted: false },
  { _id: distB1, name: "ZT B1", code: "ZTB1", slug: "zt-b1", normalizedName: "zt b1", stateRef: stateB, countryRef, primaryAdminRef: daB1._id, isActive: true, isDeleted: false },
]);

const STRONG = { india: "India#Founder2026", sa: "StateA#Employee26", saNew: "StateA#Rotated2026", da: "DistA1#Employee26" };
const EMP = {
  sa: { adminName: "Asha State", phone: "9811111111", email: "asha.state@ztest.local" },
  da: { adminName: "Ravi District", phone: "9822222222", email: "ravi.district@ztest.local" },
  daB: { adminName: "Bina District", phone: "9833333333", email: "bina.district@ztest.local" },
};
const KEY = process.env.ADMIN_PANEL_KEY;

  // ═══ 0. pure rules ═══════════════════════════════════════════════
  section("0  service rules (pure)");
  check("0.1", "password policy rejects short / no-symbol / no-digit / no-upper",
    ["Short#1a", "NoSymbolPassword1", "NoDigit#Password", "nouppercase#123"].every((p) => svc.validateNewPassword(p) !== null));
  check("0.2", "password policy accepts a strong password", svc.validateNewPassword("Strong#Pass2026") === null);
  check("0.3", "unassigned STATE account is NOT activation-eligible even with a verified phone", svc.isActivationEligible(saA.toObject()) === false);
  check("0.4", "INDIA account pending activation IS eligible (no superior to assign it)", svc.isActivationEligible(india.toObject()) === true);

  // ═══ 1. unassigned accounts cannot log in ═══════════════════════
  section("1  unassigned / pending admin login is rejected (server-side)");
  const l1 = await login(saA.email, SEED_PW);
  check("1.1", "seeded STATE account + shared seed password → 403 ACCOUNT_ACTIVATION_REQUIRED", l1.status === 403 && codeOf(l1).includes("ACCOUNT_ACTIVATION_REQUIRED"), l1.data);
  check("1.2", "…and no session: no access token, no refresh cookie, no RefreshToken row", !tokenOf(l1) && !l1.setCookie && !(await RefreshToken.exists({ userRef: saA._id })));
  const l1b = await login(daA1.email, SEED_PW);
  check("1.3", "seeded DISTRICT placeholder + seed password → 403", l1b.status === 403, l1b.data);
  const l1c = await login(saA.email, "Wrong#Password1");
  check("1.4", "wrong password still → 401 Invalid credentials (no status disclosure)", l1c.status === 401, l1c.data);
  const forged = generateAccessToken({ _id: saA._id, role: "ADMIN", tokenVersion: 0, adminLevel: "STATE", stateRef: stateA, countryRef });
  const p1 = await call("/api/admin/me", { token: forged });
  check("1.5", "protect refuses a (validly signed) token for a pending account → 403", p1.status === 403 && codeOf(p1).includes("ACCOUNT_ACTIVATION_REQUIRED"), p1.data);

  // ═══ 2. generated phone/email alone cannot activate ═════════════
  section("2  knowing a seeded email/phone is not enough");
  const g1 = await requestOtp("ACTIVATION", saA.phone);
  check("2.1", "activation OTP request for a seeded (unassigned) phone → generic 200", g1.status === 200 && g1.data?.message === svc.GENERIC_REQUEST_MESSAGE, g1.data);
  check("2.2", "…but NO OTP was issued (no Redis hash key)", !(await redis.exists(otpHashKey(ACT, saA.phone))));
  const g2 = await requestOtp("ACTIVATION", "9999999999");
  check("2.3", "unknown phone → the identical generic 200 (no enumeration)", g2.status === 200 && g2.data?.message === g1.data?.message);
  const g3 = await complete("ACTIVATION", saA.phone, DEV_FIXED_OTP, "Hijack#Attempt2026");
  check("2.4", "completing activation for the seeded phone with the dev OTP → 401 (no OTP was ever issued)", g3.status === 401, g3.data);
  check("2.5", "…account untouched (still pending, seed hash intact)", (await fresh(saA._id)).mustChangePassword === true && (await bcrypt.compare(SEED_PW, (await fresh(saA._id)).password)));

  // ═══ 3. INDIA self-activation (founder phone) ═══════════════════
  section("3  INDIA super admin activates via OTP to its configured phone");
  const i0 = await login(india.email, SEED_PW, { adminKey: KEY });
  check("3.1", "INDIA with seed password → 403 activation required", i0.status === 403, i0.data);
  check("3.2", "INDIA activation OTP request → 200 and an OTP hash is stored", (await requestOtp("ACTIVATION", india.phone)).status === 200 && !!(await redis.exists(otpHashKey(ACT, india.phone))));
  const i1 = await complete("ACTIVATION", india.phone, DEV_FIXED_OTP, STRONG.india);
  check("3.3", "INDIA activation complete → 200", i1.status === 200, i1.data);
  const i2 = await login(india.email, STRONG.india, { adminKey: KEY });
  check("3.4", "INDIA logs in with its own password (+ admin key) → 200", i2.status === 200 && !!tokenOf(i2), i2.data);
  check("3.5", "INDIA without admin key still → 401 (unchanged)", (await login(india.email, STRONG.india)).status === 401);
  const tIndia = tokenOf(i2);

  // ═══ 4. assignment authorization ════════════════════════════════
  section("4  assignment is authorized by the admin hierarchy");
  check("4.1", "no token → 401", (await assign(null, saA._id, EMP.sa)).status === 401);
  const a1 = await assign(tIndia, saA._id, EMP.sa);
  check("4.2", "INDIA assigns the seeded STATE A account → 200 PENDING_ACTIVATION", a1.status === 200 && a1.data?.data?.account?.status === "PENDING_ACTIVATION", a1.data);
  check("4.3", "…response has no password/OTP and a masked phone", !/password|otp/i.test(JSON.stringify(a1.data?.data || {})) && a1.data?.data?.account?.phone === "******1111");
  const saAdoc = await fresh(saA._id);
  check("4.4", "…seed password no longer matches (replaced by an unusable hash)", !(await bcrypt.compare(SEED_PW, saAdoc.password)) && !(await bcrypt.compare(LEGACY_TEMP_PW, saAdoc.password)));
  check("4.5", "…assignment marker + audit row written", !!saAdoc.adminAssignedAt && String(saAdoc.adminAssignedBy) === String(india._id) && !!(await AdminAuditLog.exists({ action: "ADMIN_ACCOUNT_ASSIGNED", targetId: saA._id })));
  check("4.6", "assigned but not yet activated → login with seed password 401, cannot use it", (await login(EMP.sa.email, SEED_PW)).status === 401);

  // ═══ 5. OTP: invalid / expired / replay / attempts ══════════════
  section("5  OTP verification: invalid, expired, attempts, replay");
  check("5.1", "activation OTP request for the assigned phone → 200, OTP stored", (await requestOtp("ACTIVATION", EMP.sa.phone)).status === 200 && !!(await redis.exists(otpHashKey(ACT, EMP.sa.phone))));
  const w1 = await complete("ACTIVATION", EMP.sa.phone, "000000", STRONG.sa);
  check("5.2", "wrong OTP → 401 INVALID_OTP, account still pending", w1.status === 401 && (await fresh(saA._id)).mustChangePassword === true, w1.data);
  const weak = await complete("ACTIVATION", EMP.sa.phone, DEV_FIXED_OTP, "weakpass");
  check("5.3", "weak new password → 400 (and the OTP is not consumed)", weak.status === 400 && !!(await redis.exists(otpHashKey(ACT, EMP.sa.phone))), weak.data);
  await redis.expire(otpHashKey(ACT, EMP.sa.phone), 1);
  await new Promise((r) => setTimeout(r, 1500));
  const ex = await complete("ACTIVATION", EMP.sa.phone, DEV_FIXED_OTP, STRONG.sa);
  check("5.4", "expired OTP (correct code after TTL) → 401, account still pending", ex.status === 401 && (await fresh(saA._id)).mustChangePassword === true, ex.data);
  await clearOtpState(ACT, EMP.sa.phone);
  check("5.5", "a RESET-purpose OTP cannot activate (purpose-bound keys)", (await requestOtp("RESET", EMP.sa.phone)).status === 200 && !(await redis.exists(otpHashKey(RST, EMP.sa.phone))) &&
    (await complete("ACTIVATION", EMP.sa.phone, DEV_FIXED_OTP, STRONG.sa)).status === 401);
  await clearOtpState(ACT, EMP.sa.phone);
  await requestOtp("ACTIVATION", EMP.sa.phone);
  for (let i = 0; i < 5; i++) await complete("ACTIVATION", EMP.sa.phone, "111111", STRONG.sa);
  const tm = await complete("ACTIVATION", EMP.sa.phone, DEV_FIXED_OTP, STRONG.sa);
  check("5.6", "after 5 wrong attempts even the correct OTP → 429 TOO_MANY_ATTEMPTS", tm.status === 429 && (await fresh(saA._id)).mustChangePassword === true, tm.data);
  await clearOtpState(ACT, EMP.sa.phone);

  // ═══ 6. valid OTP activates; own password; seed password dead ═══
  section("6  valid OTP → activation with the employee's own password");
  await requestOtp("ACTIVATION", EMP.sa.phone);
  const ok1 = await complete("ACTIVATION", EMP.sa.phone, DEV_FIXED_OTP, STRONG.sa);
  check("6.1", "valid OTP + strong password → 200", ok1.status === 200, ok1.data);
  const saAact = await fresh(saA._id);
  check("6.2", "account active: mustChangePassword false, phone verified, passwordChangedAt set, bcrypt hash", saAact.mustChangePassword === false && saAact.isPhoneVerified === true && !!saAact.passwordChangedAt && /^\$2[aby]\$12\$/.test(saAact.password));
  const rp = await complete("ACTIVATION", EMP.sa.phone, DEV_FIXED_OTP, "Another#Pass2026");
  check("6.3", "replaying the same OTP → 401 (consumed), password unchanged", rp.status === 401 && (await bcrypt.compare(STRONG.sa, (await fresh(saA._id)).password)), rp.data);
  check("6.4", "shared seed password no longer works → 401", (await login(EMP.sa.email, SEED_PW)).status === 401);
  check("6.5", "legacy temp password Admin@12345 does not work → 401", (await login(EMP.sa.email, LEGACY_TEMP_PW)).status === 401);
  const sl = await login(EMP.sa.email, STRONG.sa);
  check("6.6", "employee logs in with their own password → 200 + refresh cookie", sl.status === 200 && !!tokenOf(sl) && !!sl.cookie, sl.data);
  check("6.7", "activation audit row written", !!(await AdminAuditLog.exists({ action: "ADMIN_ACCOUNT_ACTIVATED", targetId: saA._id })));
  check("6.8", "activation again for an active account → no OTP issued", (await requestOtp("ACTIVATION", EMP.sa.phone)).status === 200 && !(await redis.exists(otpHashKey(ACT, EMP.sa.phone))));
  let tStateA = tokenOf(sl);

  // ═══ 7. duplicate phone / email ═════════════════════════════════
  section("7  duplicate email/phone assignment is rejected");
  const d1 = await assign(tIndia, saB._id, { ...EMP.daB, phone: EMP.sa.phone });
  check("7.1", "phone already on another admin → 409", d1.status === 409, d1.data);
  const d2 = await assign(tIndia, saB._id, { ...EMP.daB, email: EMP.sa.email.toUpperCase() });
  check("7.2", "email already on another admin (case-insensitive) → 409", d2.status === 409, d2.data);
  const d3 = await assign(tIndia, saB._id, { ...EMP.daB, phone: saA2.phone });
  check("7.3", "phone equal to another seeded account's generated phone → 409", d3.status === 409, d3.data);
  check("7.4", "rejected assignments left State B untouched", !(await fresh(saB._id)).adminAssignedAt);
  check("7.5", "invalid phone/email → 400", (await assign(tIndia, saB._id, { ...EMP.daB, phone: "12345" })).status === 400 && (await assign(tIndia, saB._id, { ...EMP.daB, email: "not-an-email" })).status === 400);

  // ═══ 8. State scope ═════════════════════════════════════════════
  section("8  a State Admin cannot reach another state's accounts");
  const ls = await list(tStateA);
  const lsItems = ls.data?.data?.items || [];
  check("8.1", "State A list → only DISTRICT accounts of state A", ls.status === 200 && lsItems.length === 2 && lsItems.every((x) => x.adminLevel === "DISTRICT" && String(x.stateRef) === String(stateA)), ls.data);
  check("8.2", "list never contains passwords and phones are masked", !/password|\$2[aby]\$/i.test(JSON.stringify(ls.data)) && lsItems.every((x) => x.phone === null || x.phone.startsWith("******")));
  check("8.3", "State A list filtered to state B → 403", (await list(tStateA, `?stateId=${stateB}`)).status === 403);
  check("8.4", "State A assigns a state-B district account → 403", (await assign(tStateA, daB1._id, EMP.daB)).status === 403);
  check("8.5", "State A assigns a STATE account (its own backup) → 403", (await assign(tStateA, saA2._id, EMP.daB)).status === 403);
  check("8.6", "State A reads a state-B district (existing route) → 403", (await call(`/api/admin/districts/${distB1}`, { token: tStateA })).status === 403);
  const ad = await assign(tStateA, daA1._id, EMP.da);
  check("8.7", "State A assigns its own district A1 placeholder → 200 PENDING_ACTIVATION", ad.status === 200 && ad.data?.data?.account?.status === "PENDING_ACTIVATION", ad.data);

  // ═══ 9. District scope ══════════════════════════════════════════
  section("9  a District Admin cannot reach another district's accounts");
  await requestOtp("ACTIVATION", EMP.da.phone);
  check("9.1", "district employee activates via OTP → 200", (await complete("ACTIVATION", EMP.da.phone, DEV_FIXED_OTP, STRONG.da)).status === 200);
  const dl = await login(EMP.da.email, STRONG.da);
  const tDistA1 = tokenOf(dl);
  check("9.2", "district employee logs in → 200", dl.status === 200 && !!tDistA1, dl.data);
  check("9.3", "District list → 403", (await list(tDistA1)).status === 403);
  check("9.4", "District assigns district A2 → 403", (await assign(tDistA1, daA2._id, EMP.daB)).status === 403);
  check("9.5", "District reads district A2 (existing route) → 403", (await call(`/api/admin/districts/${distA2}`, { token: tDistA1 })).status === 403);
  check("9.6", "District reads its own district → 200", (await call(`/api/admin/districts/${distA1}`, { token: tDistA1 })).status === 200);

  // ═══ 10. existing role permissions unchanged ════════════════════
  section("10  existing India/State/District permissions intact");
  const li = await list(tIndia, "?adminLevel=STATE");
  check("10.1", "INDIA lists STATE accounts (all states) → 200, 3 items", li.status === 200 && li.data?.data?.items?.length === 3, li.data);
  check("10.2", "INDIA list never includes the INDIA account itself", !(await list(tIndia)).data?.data?.items?.some((x) => x.adminLevel === "INDIA"));
  check("10.3", "STATE → POST /api/admin/states (INDIA-only) → 403", (await call("/api/admin/states", { token: tStateA, method: "POST", body: { stateName: "X", adminName: "X", phone: "9876543210" } })).status === 403);
  check("10.4", "DISTRICT → POST /api/admin/districts (INDIA/STATE-only) → 403", (await call("/api/admin/districts", { token: tDistA1, method: "POST", body: {} })).status === 403);
  check("10.5", "GET /api/admin/me works for INDIA, STATE and DISTRICT", (await Promise.all([tIndia, tStateA, tDistA1].map((t) => call("/api/admin/me", { token: t })))).every((r) => r.status === 200));
  check("10.6", "INDIA cannot assign its own account → 403", (await assign(tIndia, india._id, EMP.daB)).status === 403);

  // ═══ 11. login / refresh / logout ═══════════════════════════════
  section("11  login, refresh and logout keep working");
  const l2 = await login(EMP.sa.email, STRONG.sa);
  tStateA = tokenOf(l2);
  const rf = await call("/api/admin-auth/refresh", { method: "POST", cookie: l2.cookie });
  check("11.1", "refresh with cookie → 200 + new access token + rotated cookie", rf.status === 200 && !!tokenOf(rf) && !!rf.cookie && rf.cookie !== l2.cookie, rf.data);
  check("11.2", "GET /api/admin-auth/me with refreshed token → 200", (await call("/api/admin-auth/me", { token: tokenOf(rf) })).status === 200);
  const lo = await call("/api/admin-auth/logout", { method: "POST", token: tokenOf(rf), cookie: rf.cookie });
  check("11.3", "logout → 200", lo.status === 200, lo.data);
  check("11.4", "refresh with the logged-out cookie → 401", (await call("/api/admin-auth/refresh", { method: "POST", cookie: rf.cookie })).status === 401);

  // ═══ 12. password reset invalidates old sessions ════════════════
  section("12  verified password reset invalidates old sessions");
  const s1 = await login(EMP.sa.email, STRONG.sa);
  const oldToken = tokenOf(s1), oldCookie = s1.cookie;
  check("12.1", "pre-reset session works", (await call("/api/admin-auth/me", { token: oldToken })).status === 200);
  check("12.2", "reset OTP for an UNASSIGNED/pending phone → not issued", (await requestOtp("RESET", saB.phone)).status === 200 && !(await redis.exists(otpHashKey(RST, saB.phone))));
  check("12.3", "reset OTP for the active employee → issued", (await requestOtp("RESET", EMP.sa.phone)).status === 200 && !!(await redis.exists(otpHashKey(RST, EMP.sa.phone))));
  check("12.4", "reset with wrong OTP → 401", (await complete("RESET", EMP.sa.phone, "222222", STRONG.saNew)).status === 401);
  const rs = await complete("RESET", EMP.sa.phone, DEV_FIXED_OTP, STRONG.saNew);
  check("12.5", "reset with valid OTP → 200", rs.status === 200, rs.data);
  check("12.6", "old access token → 401", (await call("/api/admin-auth/me", { token: oldToken })).status === 401);
  check("12.7", "old refresh cookie → 401", (await call("/api/admin-auth/refresh", { method: "POST", cookie: oldCookie })).status === 401);
  check("12.8", "all refresh tokens revoked", (await RefreshToken.countDocuments({ userRef: saA._id, revokedAt: null })) === 0);
  check("12.9", "old password → 401, new password → 200", (await login(EMP.sa.email, STRONG.sa)).status === 401 && (await login(EMP.sa.email, STRONG.saNew)).status === 200);
  check("12.10", "reset audit row written", !!(await AdminAuditLog.exists({ action: "ADMIN_PASSWORD_RESET", targetId: saA._id })));

  // ═══ 13. reassignment of an active account ══════════════════════
  section("13  reassigning an active account kills the old holder's access");
  const before = await login(EMP.da.email, STRONG.da);
  const r0 = await assign(tIndia, daA1._id, EMP.daB);
  check("13.1", "active account without confirmReassign → 409", r0.status === 409, r0.data);
  const r1 = await assign(tIndia, daA1._id, { ...EMP.daB, confirmReassign: true });
  check("13.2", "with confirmReassign → 200 PENDING_ACTIVATION", r1.status === 200 && r1.data?.data?.account?.status === "PENDING_ACTIVATION", r1.data);
  check("13.3", "previous holder's access token and refresh cookie → rejected", (await call("/api/admin/me", { token: tokenOf(before) })).status === 401 && (await call("/api/admin-auth/refresh", { method: "POST", cookie: before.cookie })).status === 401);
  check("13.4", "previous holder's password no longer works", (await login(EMP.daB.email, STRONG.da)).status === 401 && (await login(EMP.da.email, STRONG.da)).status === 401);

  // ═══ 14. legacy create/assign flows: no shared temp password ════
  section("14  legacy district assign flow: unusable password, no tempPassword");
  const lg = await call(`/api/admin/districts/${distA2}/admin`, { token: tIndia, method: "POST", body: { adminName: "Legacy Flow", phone: "9844444444", email: "legacy.flow@ztest.local" } });
  check("14.1", "POST /api/admin/districts/:id/admin → 200", lg.status === 200, lg.data);
  check("14.2", "response has no tempPassword / password", !/tempPassword|password/i.test(JSON.stringify(lg.data)), lg.data);
  const lgDoc = await fresh(daA2._id);
  check("14.3", "account pending activation with assignment marker", lgDoc.mustChangePassword === true && !!lgDoc.adminAssignedAt && lgDoc.phone === "9844444444");
  check("14.4", "legacy temp password and seed password → cannot log in", (await login("legacy.flow@ztest.local", LEGACY_TEMP_PW)).status === 401 && (await login("legacy.flow@ztest.local", SEED_PW)).status === 401);
  const bk = await call(`/api/admin/states/${stateB}/backup-admin`, { token: tIndia, method: "POST", body: { adminName: "Backup B", phone: "9855555555", email: "backup.b@ztest.local" } });
  check("14.5", "backup-admin flow (no State doc) still 404s cleanly", bk.status === 404, bk.data);

  // ═══ 15. limiter + no secret leakage ════════════════════════════
  section("15  rate limit and no OTP/password leakage");
  let limited = false;
  for (let i = 0; i < 12; i++) {
    const r = await requestOtp("ACTIVATION", "9999999998", { ip: "10.250.250.250" });
    if (r.status === 429) { limited = true; break; }
  }
  check("15.1", "per-IP limiter on activation endpoints → 429 after 10 requests", limited);
  const allText = bodies.join("\n");
  check("15.2", "no response body ever contained the OTP", !allText.includes(DEV_FIXED_OTP) && !/"otp"\s*:/i.test(allText));
  check("15.3", "no response body ever contained any password or bcrypt hash",
    ![SEED_PW, LEGACY_TEMP_PW, ...Object.values(STRONG)].some((p) => allText.includes(p)) && !/\$2[aby]\$\d\d\$/.test(allText) && !/tempPassword/i.test(allText));
} catch (err) {
  fail++;
  console.log(`  ❌ harness error: ${err.stack || err.message}`);
} finally {
  server.close();
  if (mongoose.connection.readyState === 1 && mongoose.connection.name === TEST_DB_NAME && TEST_DB_NAME_RE.test(mongoose.connection.name)) {
    await mongoose.connection.db.dropDatabase()
      .then(() => console.log(`\ncleanup: dropped test database ${TEST_DB_NAME}`))
      .catch((e) => console.log(`\ncleanup: could not drop test database (${e.message})`));
  } else {
    console.log("\ncleanup: skipped — connection is not the validated ztest_ database");
  }
  await redis.flushDb().catch(() => {});
  await mongoose.disconnect().catch(() => {});
  await redis.quit().catch(() => {});
}

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail === 0 ? 0 : 1);
