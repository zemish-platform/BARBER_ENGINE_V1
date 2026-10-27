/**
 * BARBER_ENGINE_V1
 * backend/utils/stagingGuards.js
 *
 * Staging-only security helpers. Pure functions: no logging, no process.exit,
 * no I/O. Every behaviour here is keyed to NODE_ENV being exactly "staging";
 * on "production" and on local development ("development"/"test"/unset) the
 * helpers are no-ops, so those environments behave exactly as before.
 *
 * ── What staging mode does ───────────────────────────────────────────
 *  • OTP: the legacy ALLOW_FIXED_OTP mode (one public constant, echoed in the
 *    send response, valid for every phone) is never used on staging. Instead
 *    STAGING_TEST_LOGINS lists the ONLY phones that can log in, each with its
 *    own secret OTP. An unlisted phone gets a success-shaped send response but
 *    an unusable token, and its verify is vetoed even if a stored hash matched.
 *  • The OTP is never returned in a response and never logged.
 *  • Verify attempts are limited to 10 failures per 7,200 s for every phone
 *    (listed or not, so the policy itself can't be used to tell them apart).
 *  • assertStagingSafety() is run by config/stagingBootGuard.js, the first
 *    import after dotenv in server.js, so an unsafe configuration stops the
 *    process before the app, Redis or Mongo are touched.
 *
 * ── STAGING_TEST_LOGINS (set in the Render dashboard only) ───────────
 *  Format:  <phone>:<otp>,<phone>:<otp>,...     (no spaces, max 25 entries)
 *    phone  10 digits, first digit 6-9, no +91 / spaces
 *    otp    exactly 6 digits, per tester, not guessable (all-same digits,
 *           straight runs, repeated pairs/triples, aabbcc, or the last six
 *           digits of the phone are rejected at boot)
 *  The value is parsed on every call (never cached) and is never printed:
 *  boot errors name only the entry NUMBER and the rule that failed.
 *
 * ── Secret rotation ──────────────────────────────────────────────────
 *  1. Edit STAGING_TEST_LOGINS in the Render dashboard (save + deploy; an env
 *     change only takes effect on the next deploy/restart).
 *  2. Old OTP hashes already in Redis live at most 5 minutes (hash TTL 300 s).
 *     For immediate invalidation, delete the staging Redis keys
 *     otp:<role>:<purpose>:<phone>:hash for that phone.
 *  3. Hand the new secret to the tester out of band (never in chat or git).
 *
 * ── Tester lockout recovery ──────────────────────────────────────────
 *  After 10 wrong codes a (role, purpose, phone) counter locks that login for
 *  7,200 s from the last failure; locked calls do not extend it. To unlock
 *  sooner, delete that phone's counter keys in the STAGING Redis only:
 *    otp:user:login:<phone>:attempts
 *    otp:owner:salon_login:<phone>:attempts
 *    otp:field_agent:field_agent_apply:<phone>:attempts
 *    otp:field_agent:field_agent_login:<phone>:attempts
 *  Rotating the secret does not clear a counter. Attempts are visible in the
 *  OtpAuditLog collection (phone, purpose, status, ip, failureReason).
 *
 * ── Staging DATABASE POLICY (utils/mongoTarget.js decides what MONGODB_URI means) ──
 *  The database named by MONGODB_URI is read with the MongoDB driver's own parser, never a
 *  regex, and must be one of exactly two names:
 *    1. barber_engine_staging  — the dedicated staging database (default; no extra setting).
 *    2. barber_engine_v1       — the shared DEVELOPMENT/TEST database. This is the founder's
 *       approved choice for now, but it is the same data the developer's local backend uses, so
 *       it is only accepted when STAGING_ACK_SHARED_DEV_DATABASE is set to exactly
 *       "barber_engine_v1" (an explicit, deliberate acknowledgment — a leftover URI cannot
 *       silently satisfy it).
 *  Any other database name, a missing/ambiguous database, or an unparseable URI refuses to boot.
 *  Sharing barber_engine_v1 means staging background jobs and tester logins write to the same
 *  documents as local development; the code cannot prevent that, only make it explicit.
 *
 * ── Endpoint deny-lists (both REQUIRED on staging) ───────────────────────────
 *  STAGING_FORBIDDEN_MONGO_ENDPOINTS / STAGING_FORBIDDEN_REDIS_ENDPOINTS hold comma-separated
 *  16-hex fingerprints of the PRODUCTION endpoints (compute them with
 *  scripts/fingerprintEndpoint.js from the production service's values — nothing is printed
 *  but the fingerprint). Staging refuses to boot if its own MONGODB_URI / REDIS_URL endpoint
 *  matches an entry, or if either list is missing or malformed. Requiring the lists is what turns
 *  "production isolation" from an assumption into something the founder must declare.
 *  Neither hosts nor fingerprints are ever printed (messages name only the variable).
 *
 * ── Startup verification (utils/stagingStartupGate.js, wired in server.js) ───
 *  1. Pre-flight, BEFORE mongoose.connect(): a raw driver client runs the read-only
 *     `connectionStatus` (showPrivileges) and is closed; the database must satisfy the policy and
 *     every effective privilege must be scoped to that one database. A refused boot writes nothing.
 *  2. Post-connect gate (defense in depth): jobs and HTTP listening start only after the live
 *     Mongoose connection is verified the same way (connected database name, authenticated user,
 *     privileges scoped to that one database).
 *
 * ── What the code still cannot prove ─────────────────────────────────────────
 *  - That a fingerprint list is COMPLETE or CORRECT: it only contains what the founder declared.
 *  - That barber_engine_v1 is not used by production under a hostname form we do not normalise.
 *  - Anything about Redis beyond its endpoint: keys have no environment prefix, so a shared
 *    Redis would share OTP/session namespaces. A human must confirm separation in the dashboards.
 *  - Mongo collection/index builds (autoIndex: true) still happen after a PASSED pre-flight; they are
 *    confined to the allowed database, whose credentials were just proven scoped to it.
 *  - Background jobs still act on whatever data the allowed database holds (shared barber_engine_v1):
 *    the job allow-list is a separate, not-yet-implemented change.
 *  - Render identity depends on RENDER_SERVICE_NAME / RENDER_GIT_BRANCH being what Render documents.
 *    A staging service that was RENAMED, deploys a branch other than develop, was left at Render's
 *    default NODE_ENV=production AND carries none of the staging-only variables (R-ID-6) looks exactly
 *    like production and is not detected; only pinning NODE_ENV=staging in its configuration prevents it.
 */

import crypto from "node:crypto";
import { assertEnvironmentIdentity } from "./environmentIdentity.js";
import {
  mongoFingerprints,
  parseFingerprintList,
  parseMongoTarget,
  parseRedisTarget,
  redisFingerprint,
} from "./mongoTarget.js";

export const STAGING_ENV_NAME = "staging";
export const STAGING_DB_NAME = "barber_engine_staging";
export const STAGING_SHARED_DEV_DB_NAME = "barber_engine_v1";
export const STAGING_ALLOWED_DB_NAMES = Object.freeze([STAGING_DB_NAME, STAGING_SHARED_DEV_DB_NAME]);
export const STAGING_SHARED_DEV_ACK_VAR = "STAGING_ACK_SHARED_DEV_DATABASE";
export const MAX_STAGING_TEST_LOGINS = 25;

// Staging-only verify-attempt policy, passed to the (unchanged) Lua script.
export const STAGING_OTP_ATTEMPT_LIMIT = 10;
export const STAGING_OTP_ATTEMPT_WINDOW_SECONDS = 7200;

// Public in-code fallbacks used outside production when the env var is missing
// (controllers/booking.controller.js, district/state controllers). Staging must
// never run on them.
const FALLBACK_OTP_SECRET = "otp-fallback-secret-change-in-prod";
const FALLBACK_OTP_ENCRYPT_KEY = "barber-engine-otp-key-32-chars!!";
const DEFAULT_ADMIN_RESET_PASSWORD = "Admin@12345";

const isSet = (value) => typeof value === "string" && value.trim() !== "";
const isOffFlag = (value) => !isSet(value) || value.trim() === "false";

// ─── Environment predicates ─────────────────────────────────────────

export const isStagingEnv = (env = process.env) => env.NODE_ENV === STAGING_ENV_NAME;

// Strict CORS applies to production (as before) and to staging.
export const isStrictCorsEnv = (env = process.env) =>
  env.NODE_ENV === "production" || env.NODE_ENV === STAGING_ENV_NAME;

// ─── Phone / OTP helpers ────────────────────────────────────────────

// Same canonical form as controllers/auth.controller.js#normalizePhone.
const canonicalPhone = (value) => {
  if (typeof value !== "string") return null;
  let cleaned = value.replace(/\D/g, "");
  if (cleaned.startsWith("91") && cleaned.length === 12) cleaned = cleaned.slice(2);
  return /^[6-9]\d{9}$/.test(cleaned) ? cleaned : null;
};

const isWeakOtp = (otp, phone) => {
  const digits = otp.split("").map(Number);
  if (digits.every((d) => d === digits[0])) return true; // 000000, 111111
  const steps = digits.slice(1).map((d, i) => d - digits[i]);
  if (steps.every((s) => s === 1) || steps.every((s) => s === -1)) return true; // 123456, 654321
  if (otp.slice(0, 2) === otp.slice(2, 4) && otp.slice(2, 4) === otp.slice(4, 6)) return true; // 121212
  if (otp.slice(0, 3) === otp.slice(3, 6)) return true; // 123123
  if (digits[0] === digits[1] && digits[2] === digits[3] && digits[4] === digits[5]) return true; // 112233
  if (phone && phone.slice(-6) === otp) return true; // last six digits of the phone
  return false;
};

/**
 * parseStagingTestLogins(raw) -> { logins: Map<phone, otp>, errors: string[] }
 * Only VALID entries enter the map. Error strings carry the entry number and the
 * rule only, never a phone or an OTP.
 */
export const parseStagingTestLogins = (raw) => {
  const logins = new Map();
  const errors = [];
  if (!isSet(raw)) return { logins, errors };

  const entries = raw.split(",");
  if (entries.length > MAX_STAGING_TEST_LOGINS) {
    errors.push(`STAGING_TEST_LOGINS has more than ${MAX_STAGING_TEST_LOGINS} entries`);
  }

  entries.forEach((entry, index) => {
    const n = index + 1;
    const trimmed = entry.trim();
    if (trimmed === "") {
      errors.push(`STAGING_TEST_LOGINS entry ${n}: empty entry`);
      return;
    }
    const parts = trimmed.split(":");
    if (parts.length !== 2) {
      errors.push(`STAGING_TEST_LOGINS entry ${n}: expected <phone>:<otp>`);
      return;
    }
    const [phone, otp] = parts;
    let valid = true;
    if (!/^[6-9]\d{9}$/.test(phone)) {
      errors.push(`STAGING_TEST_LOGINS entry ${n}: phone must be 10 digits starting 6-9`);
      valid = false;
    }
    if (!/^\d{6}$/.test(otp)) {
      errors.push(`STAGING_TEST_LOGINS entry ${n}: otp must be exactly 6 digits`);
      valid = false;
    } else if (isWeakOtp(otp, valid ? phone : null)) {
      errors.push(`STAGING_TEST_LOGINS entry ${n}: otp is too guessable`);
      valid = false;
    }
    if (valid && logins.has(phone)) {
      errors.push(`STAGING_TEST_LOGINS entry ${n}: duplicate phone`);
      valid = false;
    }
    if (valid) logins.set(phone, otp);
  });

  return { logins, errors };
};

export const getStagingTestLogins = (env = process.env) =>
  parseStagingTestLogins(env.STAGING_TEST_LOGINS).logins;

export const stagingTestOtpFor = (phone, env = process.env) => {
  const canonical = canonicalPhone(phone);
  if (!canonical) return null;
  return getStagingTestLogins(env).get(canonical) ?? null;
};

export const isStagingTestPhone = (phone, env = process.env) =>
  stagingTestOtpFor(phone, env) !== null;

// A non-numeric token no 4- or 6-digit input can ever match. Used as the "OTP"
// for unlisted phones: it is hashed and stored like a real one, and goes nowhere.
export const stagingUnusableOtp = () => crypto.randomBytes(16).toString("hex");

/**
 * maskPhoneForLog(phone) — staging: "******" + last 4 digits; elsewhere: the value
 * unchanged, so production and local logs are exactly as before. Never throws.
 */
export const maskPhoneForLog = (phone, env = process.env) => {
  if (!isStagingEnv(env)) return phone;
  try {
    const digits = String(phone ?? "").replace(/\D/g, "");
    return digits.length >= 4 ? `******${digits.slice(-4)}` : "******";
  } catch {
    return "******";
  }
};

// ─── Boot-time safety assertions ────────────────────────────────────

/**
 * evaluateStagingDatabasePolicy(dbName, env) -> string | null
 * The documented staging database policy (see the header). Returns a violation message, or null
 * when `dbName` is acceptable. Used by the boot guard AND the post-connect startup gate.
 */
export const evaluateStagingDatabasePolicy = (dbName, env = process.env) => {
  if (dbName === STAGING_DB_NAME) return null;
  if (dbName === STAGING_SHARED_DEV_DB_NAME) {
    return env[STAGING_SHARED_DEV_ACK_VAR] === STAGING_SHARED_DEV_DB_NAME
      ? null
      : `MONGODB_URI names the shared development database; set ${STAGING_SHARED_DEV_ACK_VAR} to exactly that database's name to acknowledge using it on staging`;
  }
  return `MONGODB_URI database is not allowed on staging (allowed: ${STAGING_ALLOWED_DB_NAMES.join(", ")})`;
};

// Endpoint deny-list check shared by MongoDB and Redis. Messages name only the variables.
const checkEndpointDenyList = ({ listVar, targetVar, rawList, targetFingerprints }) => {
  const parsed = parseFingerprintList(rawList);
  if (!parsed.ok) {
    return [`${listVar} must be set to comma-separated 16-character lowercase hex fingerprints of the production endpoints (required on staging)`];
  }
  if (targetFingerprints && targetFingerprints.some((f) => parsed.list.has(f))) {
    return [`${targetVar} points at an endpoint listed in ${listVar} (a production or otherwise forbidden endpoint)`];
  }
  return [];
};

/**
 * assertStagingSafety(env) -> string[]
 * Returns violation messages (empty = safe). Messages name the rule and, for
 * env vars, the variable NAME; they never contain a value.
 */
export const assertStagingSafety = (env = process.env) => {
  const violations = [];
  const nodeEnv = env.NODE_ENV;

  // A typo such as "Staging" / "stage" would silently skip every staging rule.
  if (typeof nodeEnv === "string" && /^stag/i.test(nodeEnv) && nodeEnv !== STAGING_ENV_NAME) {
    violations.push('NODE_ENV looks like staging but is not exactly "staging"');
    return violations;
  }

  // Render identity vs NODE_ENV (inert unless RENDER === "true"). Runs for EVERY NODE_ENV: the
  // failure it exists for is a staging service silently running with NODE_ENV=production.
  violations.push(...assertEnvironmentIdentity(env));

  if (nodeEnv === "production") {
    if (isSet(env.STAGING_TEST_LOGINS)) {
      violations.push("STAGING_TEST_LOGINS must not be set when NODE_ENV=production");
    }
    return violations;
  }

  if (nodeEnv !== STAGING_ENV_NAME) return violations; // development / test / unset

  // R1/R2 — per-tester secret OTPs.
  const { logins, errors } = parseStagingTestLogins(env.STAGING_TEST_LOGINS);
  if (!isSet(env.STAGING_TEST_LOGINS)) {
    violations.push("STAGING_TEST_LOGINS is not set (at least one test login is required)");
  } else {
    violations.push(...errors);
    if (errors.length === 0 && logins.size === 0) {
      violations.push("STAGING_TEST_LOGINS has no valid entries");
    }
  }

  // R3 — legacy fixed-OTP mode and the payment test bypass.
  if (!isOffFlag(env.ALLOW_FIXED_OTP)) {
    violations.push("ALLOW_FIXED_OTP must be unset or false on staging");
  }
  if (!isOffFlag(env.RAZORPAY_ALLOW_TEST_BYPASS)) {
    violations.push("RAZORPAY_ALLOW_TEST_BYPASS must be unset or false on staging");
  }

  // R4 — Razorpay test mode.
  if (!isSet(env.RAZORPAY_KEY_ID)) {
    violations.push("RAZORPAY_KEY_ID is not set");
  } else if (env.RAZORPAY_KEY_ID.trim().startsWith("rzp_live_")) {
    violations.push("RAZORPAY_KEY_ID is a LIVE key; staging requires a test-mode key");
  } else if (!env.RAZORPAY_KEY_ID.trim().startsWith("rzp_test_")) {
    violations.push("RAZORPAY_KEY_ID must be a test-mode key (rzp_test_...)");
  }
  if (!isSet(env.RAZORPAY_KEY_SECRET)) violations.push("RAZORPAY_KEY_SECRET is not set");

  // R5 — Cashfree sandbox only; no payout base-URL overrides (honoured outside production).
  if (isSet(env.CASHFREE_ENV) && /^production$/i.test(env.CASHFREE_ENV.trim())) {
    violations.push("CASHFREE_ENV must not be PRODUCTION on staging");
  }
  if (isSet(env.RAZORPAYX_ROUTE_BASE_URL)) {
    violations.push("RAZORPAYX_ROUTE_BASE_URL must be unset on staging");
  }
  if (isSet(env.CASHFREE_PAYOUT_BASE_URL)) {
    violations.push("CASHFREE_PAYOUT_BASE_URL must be unset on staging");
  }

  // R6 — no paid KYC, no real SMS.
  if (isSet(env.SUREPASS_TOKEN)) violations.push("SUREPASS_TOKEN must be unset on staging");
  if (isSet(env.SMS_PROVIDER) && env.SMS_PROVIDER.trim().toLowerCase() !== "none") {
    violations.push('SMS_PROVIDER must be unset or "none" on staging');
  }
  if (Object.keys(env).some((k) => /^MSG91_/.test(k) && isSet(env[k]))) {
    violations.push("MSG91_* variables must be unset on staging");
  }
  if (Object.keys(env).some((k) => /^TWILIO_/.test(k) && isSet(env[k]))) {
    violations.push("TWILIO_* variables must be unset on staging");
  }

  // R7 — push disabled until isolation is verified.
  if (isSet(env.PUSH_PROVIDER) && env.PUSH_PROVIDER.trim().toLowerCase() !== "none") {
    violations.push('PUSH_PROVIDER must be unset or "none" on staging');
  }
  for (const name of ["EXPO_ACCESS_TOKEN", "FIREBASE_PROJECT_ID", "FIREBASE_CLIENT_EMAIL", "FIREBASE_PRIVATE_KEY"]) {
    if (isSet(env[name])) violations.push(`${name} must be unset on staging`);
  }

  // R8 — no outbound email / WhatsApp / call / bot providers.
  for (const name of ["SMTP_HOST", "WHATSAPP_PROVIDER", "CALL_PROVIDER", "BOT_PROVIDER"]) {
    if (isSet(env[name])) violations.push(`${name} must be unset on staging`);
  }

  // R9 — MongoDB target, read with the MongoDB driver's own parser (utils/mongoTarget.js):
  //   explicit + unambiguous database, on the documented staging database policy, and not on a
  //   forbidden (production) endpoint. A URI without a path would silently use "test".
  const mongo = parseMongoTarget(env.MONGODB_URI);
  if (!isSet(env.MONGODB_URI)) {
    violations.push("MONGODB_URI is not set");
  } else if (!mongo.ok) {
    violations.push(
      "MONGODB_URI is not a valid MongoDB URI that names one explicit, unambiguous database (checked with the MongoDB driver's own parser)"
    );
  } else {
    const policyViolation = evaluateStagingDatabasePolicy(mongo.dbName, env);
    if (policyViolation) violations.push(policyViolation);
  }
  violations.push(
    ...checkEndpointDenyList({
      listVar: "STAGING_FORBIDDEN_MONGO_ENDPOINTS",
      targetVar: "MONGODB_URI",
      rawList: env.STAGING_FORBIDDEN_MONGO_ENDPOINTS,
      targetFingerprints: mongo.ok ? mongoFingerprints(mongo.hosts) : null,
    })
  );

  // R10 — Redis must be configured explicitly (unset = silent localhost default), parse as a
  //   redis:// or rediss:// URL, and not point at a forbidden (production) endpoint.
  const redisTarget = parseRedisTarget(env.REDIS_URL);
  if (!isSet(env.REDIS_URL)) {
    violations.push("REDIS_URL is not set");
  } else if (!redisTarget.ok) {
    violations.push("REDIS_URL must be a valid redis:// or rediss:// URL");
  }
  violations.push(
    ...checkEndpointDenyList({
      listVar: "STAGING_FORBIDDEN_REDIS_ENDPOINTS",
      targetVar: "REDIS_URL",
      rawList: env.STAGING_FORBIDDEN_REDIS_ENDPOINTS,
      targetFingerprints: redisTarget.ok ? [redisFingerprint(redisTarget.host)] : null,
    })
  );

  // R11 — secrets, validated against how the code actually uses them.
  //   JWT_ACCESS_SECRET signs every access token with NO fallback
  //   (services/token.service.js); JWT_SECRET is only a verify fallback and is
  //   deliberately not accepted as a substitute.
  if (!isSet(env.JWT_ACCESS_SECRET) || env.JWT_ACCESS_SECRET.length < 32) {
    violations.push("JWT_ACCESS_SECRET must be set (at least 32 characters)");
  }
  if (!isSet(env.OTP_SECRET) || env.OTP_SECRET.length < 32 || env.OTP_SECRET === FALLBACK_OTP_SECRET) {
    violations.push("OTP_SECRET must be set (at least 32 characters, not the in-code fallback)");
  }
  //   OTP_ENCRYPT_KEY accepts any length (non-32-byte keys are SHA-256 derived).
  if (!isSet(env.OTP_ENCRYPT_KEY) || env.OTP_ENCRYPT_KEY.length < 32 || env.OTP_ENCRYPT_KEY === FALLBACK_OTP_ENCRYPT_KEY) {
    violations.push("OTP_ENCRYPT_KEY must be set (at least 32 characters, not the in-code fallback)");
  }
  if (!isSet(env.ADMIN_RESET_PASSWORD) || env.ADMIN_RESET_PASSWORD === DEFAULT_ADMIN_RESET_PASSWORD) {
    violations.push("ADMIN_RESET_PASSWORD must be set to a non-default value");
  }
  //   KYC_ENCRYPTION_KEY is read lazily and must be 64 hex characters when used.
  if (isSet(env.KYC_ENCRYPTION_KEY) && !/^[0-9a-fA-F]{64}$/.test(env.KYC_ENCRYPTION_KEY)) {
    violations.push("KYC_ENCRYPTION_KEY must be 64 hex characters when set");
  }

  // R12 — strict CORS allow-list (the list is split on "," with no trimming).
  if (isSet(env.CORS_ORIGIN)) {
    env.CORS_ORIGIN.split(",").forEach((origin, index) => {
      if (!/^https:\/\/[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d{1,5})?$/.test(origin)) {
        violations.push(
          `CORS_ORIGIN entry ${index + 1} must be an exact https://host[:port] origin (no spaces, wildcard, path, trailing slash or localhost)`
        );
      }
    });
  }

  return violations;
};
