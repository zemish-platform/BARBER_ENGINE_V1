/**
 * BARBER ENGINE V1
 * backend/modules/otp/services/otp.service.js
 *
 * OTP Engine V1.0 — the single, centralized enterprise OTP service.
 * Every OTP send/verify across every app (User, Salon Partner, Field
 * Agent apply, Field Agent operational login, Booking no-show) routes
 * through this file. No controller contains OTP business logic — a
 * controller's job is: validate/normalize the phone, call
 * sendOtp()/verifyOtp() with an explicit purpose AND role, and
 * translate the structured result into its own (unchanged) HTTP
 * response shape. Function signatures are unchanged from the previous
 * revision — every existing controller call site keeps working
 * without modification (this revision's scope is the OTP module only).
 *
 * PURPOSE IS MANDATORY AND IMMUTABLE (Revision 2) — every exported
 * function requires `purpose` as an explicit argument, never inferred
 * from `role`. The Redis VALUE stored at generation time now embeds
 * the purpose alongside the hash (see PAYLOAD below); verify compares
 * the caller-supplied purpose against the one embedded in that stored
 * payload, atomically, inside the same Lua script that checks the
 * hash. A client cannot change purpose after generation — the
 * verify-time purpose is read from wherever the key namespace itself
 * routes to (Revision 3), and the payload comparison is a second,
 * independent, defense-in-depth guarantee that does not rely on key
 * construction alone ever being correct.
 *
 * REDIS KEY CONTRACT (Revision 3) — see otpBaseKey()/hashKey()/
 * attemptKey() below:
 *   otp:{role}:{purpose}:{phone}:hash
 *   otp:{role}:{purpose}:{phone}:attempts
 * role and purpose are lowercased. This replaces the previous
 * revision's purpose-only namespace lookup — role is now part of the
 * key itself, not just an audit field. See this file's own
 * REDIS_MIGRATION_NOTE below for the deploy-time impact.
 *
 * IDEMPOTENCY LOCK (OTP-1.1 Correction 1) — a SEPARATE key family,
 * `otp_lock:{role}:{purpose}:{phone}` (30s TTL), independent of the
 * hash/attempts keys above — see idempotencyLockKey()/
 * assertIdempotencyLock() below for the full contract.
 *
 * ATOMIC VERIFY — unchanged from the previous revision's fix: a single
 * Redis Lua script performs attempt-check, hash-read, purpose-compare,
 * and delete-on-match/increment-on-mismatch as one indivisible
 * operation, closing the TOCTOU race a naive GET-then-DEL sequence has
 * under concurrent verification.
 *
 * ASYNCHRONOUS AUDIT (Revision 1) — this file NEVER writes
 * OtpAuditLog. It writes OtpAuditOutbox only (fire-and-forget, a
 * single cheap Mongo insert, never awaited by the request path); a
 * background job (jobs/otpAuditOutbox.job.js, registered explicitly in
 * server.js as of OTP-2 Part D) drains the outbox into OtpAuditLog
 * asynchronously, with retry on failure. See that job's own header for
 * the full state machine. The API response never waits on OtpAuditLog
 * at all.
 *
 * PRODUCTION BOOT GUARD (Revision 4) — importing guards/productionBootGuard.js
 * below runs its check at module-evaluation time, before Express ever
 * starts listening. See that file's own header for why this lives
 * here rather than in server.js this phase.
 */

import crypto from "crypto";
import logger from "../../../utils/logger.js";
import { resolveProvider } from "../providers/index.js";
import OtpAuditOutbox from "../models/OtpAuditOutbox.js";
import { OTP_PURPOSE, REDIS_BACKED_PURPOSES } from "../constants/otpPurpose.constants.js";
import {
  OTP_HASH_TTL_SECONDS,
  OTP_ATTEMPT_LIMIT,
  OTP_ATTEMPT_WINDOW_SECONDS,
  OTP_RESEND_COOLDOWN_SECONDS,
  OTP_AUDIT_STATUS,
  DEV_FIXED_OTP,
} from "../constants/otp.constants.js";

// Revision 4 — boot-time-only safety check, runs at import time.
import "../guards/productionBootGuard.js";

const ALLOW_FIXED_OTP = () => process.env.ALLOW_FIXED_OTP === "true";

// ─── PURE PRIMITIVES ────────────────────────────────────────────────

export const generateOtp = () => {
  if (ALLOW_FIXED_OTP()) return DEV_FIXED_OTP;
  return crypto.randomInt(100000, 999999).toString();
};

export const hashOtp = (otp) => crypto.createHash("sha256").update(otp).digest("hex");

export const isValidOtpFormat = (otp) => typeof otp === "string" && /^\d{6}$/.test(otp);

// ─── REVISION 3 — REDIS KEY CONTRACT ────────────────────────────────
//
// otp:{role}:{purpose}:{phone}:{hash|attempts}, role and
// purpose lowercased. `role` is REQUIRED for every Redis-backed
// purpose (LOGIN, SALON_LOGIN, FIELD_AGENT_APPLY, FIELD_AGENT_LOGIN) —
// every controller already passes it for audit purposes; it is now
// also load-bearing for key construction, not merely descriptive.
//
// REDIS_MIGRATION_NOTE: this key format differs from the previous
// revision's (`otp:hash:{purposeNamespace}:{phone}`, no role segment,
// no `:hash` suffix). Any OTP hash written under the OLD format before
// this deploy will not be found by the NEW verify path — a narrow,
// self-healing window bounded by the 5-minute hash TTL: at worst, a
// handful of users mid-login at the exact deploy moment see
// "OTP expired, please request a new one" and retry once. No data is
// lost or exposed; this is a short-TTL cache key format change, not a
// durable-data migration, and needs no backfill/dual-read shim.
const assertRole = (role, purpose) => {
  if (!role || typeof role !== "string") {
    throw new Error(`otp.service: role is required to build a Redis key for purpose "${purpose}" (role must not be null/empty)`);
  }
};

const otpBaseKey = (role, purpose, phone) => `otp:${role.toLowerCase()}:${purpose.toLowerCase()}:${phone}`;
const hashKey = (role, purpose, phone) => `${otpBaseKey(role, purpose, phone)}:hash`;
const attemptKey = (role, purpose, phone) => `${otpBaseKey(role, purpose, phone)}:attempts`;

// OTP-1.1 CORRECTION 1 — dedicated idempotency-lock namespace, kept
// entirely separate from the otp:{role}:{purpose}:{phone}:* hash/
// attempts keys above (this lock's own TTL/lifecycle has nothing to do
// with the OTP record's TTL — see assertIdempotencyLock's own header).
const idempotencyLockKey = (role, purpose, phone) => `otp_lock:${role.toLowerCase()}:${purpose.toLowerCase()}:${phone}`;

const assertPurpose = (purpose, fnName) => {
  if (!purpose || !Object.values(OTP_PURPOSE).includes(purpose)) {
    throw new Error(`otp.service.${fnName}: invalid or missing purpose "${purpose}"`);
  }
};

// ─── SECURITY — production response-echo gate ───────────────────────
// Single allow-list flag (ALLOW_FIXED_OTP) — see server.js's own
// unchanged boot guardrail and this file's own Revision 4 guard above
// for why this can never reach a real NODE_ENV=production deploy.
const shouldEchoOtpInResponse = () => ALLOW_FIXED_OTP();

// ─── REVISION 1 — ASYNCHRONOUS AUDIT ────────────────────────────────
//
// Writes ONLY to OtpAuditOutbox (a single flat insert, no relations,
// no aggregation) — never to OtpAuditLog directly, and never awaited
// by the caller. jobs/otpAuditOutbox.job.js drains this outbox into
// OtpAuditLog asynchronously, retrying on failure — see that file's
// own header for the full claim/apply/reclaim state machine. A slow
// or momentarily-down Mongo can delay when an audit row becomes
// visible in OtpAuditLog; it can never delay or fail an OTP send/verify
// response, and (short of the outbox insert itself throwing, logged
// below and otherwise unrecoverable — the same edge case
// jobs/ratingOutbox.job.js's own initial event write has) it cannot
// silently lose the record either, since a failed drain attempt keeps
// the outbox row for retry rather than deleting it.
const safeAuditWrite = (doc) => {
  OtpAuditOutbox.create(doc).catch((err) => {
    logger.error("OtpAuditOutbox write failed", { message: err.message, purpose: doc.purpose, status: doc.status });
  });
};

const extractRequestContext = (req) => ({
  ip: req?.ip || null,
  userAgent: req?.headers?.["user-agent"] || null,
  deviceId: req?.headers?.["x-device-id"] || null,
});

// ─── RESEND / SEND ──────────────────────────────────────────────────

/**
 * OTP-1.1 CORRECTION 1 — SEND OTP IDEMPOTENCY LOCK.
 *
 * Before ANY SMS is sent, this must be the first thing sendOtp() does.
 * Guarantees: the first request in a 30s window acquires the lock and
 * proceeds to send; every other request for the same {role, purpose,
 * phone} during that window is turned away WITHOUT ever reaching
 * dispatchOtpSms()/MSG91 — a rapid double-tap, or 10 rapid taps, can
 * never trigger more than one real provider call, protecting SMS
 * cost/DLT quota exactly as required.
 *
 * ATOMICITY: `SET key val NX EX ttl` is a single Redis command — the
 * "does the key already exist" check and "create it" write happen as
 * one atomic operation server-side. Two concurrent requests racing to
 * acquire the same lock can never both succeed: Redis processes
 * commands one at a time (single-threaded core), so exactly one SET
 * NX returns success and the other(s) always see the key already
 * present. No race condition is possible.
 *
 * INDEPENDENT FROM THE OTP RECORD: this lock (`otp_lock:{role}:
 * {purpose}:{phone}`, its own 30s TTL) shares no key, no code path,
 * and no storage with the OTP hash/attempts keys (`otp:{role}:
 * {purpose}:{phone}:hash` / `:attempts`, 5-minute TTL) — a client
 * whose lock has already expired can still be mid-verification against
 * a perfectly valid, still-live OTP hash; the two lifecycles never
 * interact. The lock is expiry-only (Redis TTL) — no code path ever
 * deletes it early, so it always expires automatically even if a
 * request crashes mid-flight after acquiring it.
 *
 * BACKWARD COMPATIBLE: same {ok:false, retryAfterSeconds} shape this
 * function has always returned — sendOtp() below still turns that into
 * the same {success:false, code:"RESEND_TOO_SOON", retryAfterSeconds}
 * response every existing controller/frontend already handles.
 */
const assertIdempotencyLock = async (redis, role, purpose, phone) => {
  const key = idempotencyLockKey(role, purpose, phone);
  const claimed = await redis.set(key, "1", { NX: true, EX: OTP_RESEND_COOLDOWN_SECONDS });
  if (claimed === null) {
    const ttl = await redis.ttl(key);
    return { ok: false, retryAfterSeconds: ttl > 0 ? ttl : OTP_RESEND_COOLDOWN_SECONDS };
  }
  return { ok: true };
};

/**
 * dispatchOtpSms({ phone, otp, purpose, role, req })
 *
 * The low-level "resolve a provider, send, write one audit row" step,
 * with NO Redis hash/attempt/lock involvement — used internally by
 * sendOtp() below, and exposed directly for BOOKING_NOSHOW, whose OTP
 * hash intentionally lives on the Booking document itself (a stronger,
 * HMAC-based local hash — see controllers/booking.controller.js's own
 * header), not in Redis. This keeps that flow's bespoke storage 100%
 * unchanged while still routing its SMS dispatch and audit logging
 * through the one centralized engine.
 */
export const dispatchOtpSms = async ({ phone, otp, purpose, role = null, req = null }) => {
  assertPurpose(purpose, "dispatchOtpSms");

  const provider = resolveProvider();
  const result = await provider.sendOtp(phone, otp, { purpose });
  const { ip, userAgent, deviceId } = extractRequestContext(req);

  // OTP-1.1 — surface circuit-breaker state for LOGGING ONLY on a
  // failed send (never in the audit row / never in any HTTP response —
  // see CircuitBreaker.js's own header). Cheap: only called on the
  // failure path, and getState() is a plain object read.
  if (!result.success && typeof provider.getState === "function") {
    logger.warn("OTP send failed — provider state at time of failure", provider.getState());
  }

  safeAuditWrite({
    phone,
    role,
    purpose,
    provider: result.provider,
    status: result.success ? OTP_AUDIT_STATUS.SENT : OTP_AUDIT_STATUS.SEND_FAILED,
    ip,
    userAgent,
    deviceId,
    latencyMs: result.latencyMs,
    failureReason: result.success ? null : result.error,
  });

  return result;
};

/**
 * sendOtp({ phone, purpose, role, req, redis })
 *
 * Full Redis-backed flow: idempotency-lock check -> generate -> hash ->
 * store {hash, purpose} (TTL) -> dispatch -> audit (async outbox).
 * Also IS the resend function — a "Resend OTP" tap from any frontend
 * is just another call to this same function.
 *
 * `role` is REQUIRED for every Redis-backed purpose (see
 * REDIS_BACKED_PURPOSES) — it is now part of the Redis key itself.
 *
 * Returns:
 *   { success: true, otp?: string }                          on send
 *   { success: false, code: "RESEND_TOO_SOON", retryAfterSeconds }
 *   { success: false, code: "SMS_SEND_FAILED" }
 */
export const sendOtp = async ({ phone, purpose, role = null, req = null, redis }) => {
  assertPurpose(purpose, "sendOtp");
  if (!redis) {
    throw new Error("otp.service.sendOtp: redis client is required");
  }
  if (REDIS_BACKED_PURPOSES.includes(purpose)) {
    assertRole(role, purpose);
  }

  const lock = await assertIdempotencyLock(redis, role, purpose, phone);
  if (!lock.ok) {
    const { ip, userAgent, deviceId } = extractRequestContext(req);
    safeAuditWrite({
      phone,
      role,
      purpose,
      provider: "n/a",
      status: OTP_AUDIT_STATUS.RATE_LIMITED,
      ip,
      userAgent,
      deviceId,
      latencyMs: null,
      failureReason: "RESEND_TOO_SOON",
    });
    return { success: false, code: "RESEND_TOO_SOON", retryAfterSeconds: lock.retryAfterSeconds };
  }

  const otp = generateOtp();
  // Revision 2 — the stored VALUE is now {hash, purpose}, not a bare
  // hash string. Verify compares BOTH fields atomically (see
  // VERIFY_SCRIPT) — purpose is a first-class, immutable part of the
  // stored payload, not just an artifact of which key it lives at.
  const payload = JSON.stringify({ hash: hashOtp(otp), purpose });
  await redis.set(hashKey(role, purpose, phone), payload, { EX: OTP_HASH_TTL_SECONDS });

  const result = await dispatchOtpSms({ phone, otp, purpose, role, req });

  if (!result.success) {
    return { success: false, code: "SMS_SEND_FAILED", provider: result.provider, error: result.error };
  }

  return {
    success: true,
    provider: result.provider,
    latencyMs: result.latencyMs,
    ...(shouldEchoOtpInResponse() && { otp }),
  };
};

// ─── VERIFY ─────────────────────────────────────────────────────────
//
// Atomic compare-and-consume. KEYS[1]=hash key, KEYS[2]=attempt key.
// ARGV[1]=sha256(supplied otp), ARGV[2]=attempt limit,
// ARGV[3]=attempt-window seconds, ARGV[4]=expected purpose.
//
// Order: attempt-limit check first (so an exhausted caller gets
// TOO_MANY_ATTEMPTS even if the hash has since expired) -> hash-key
// read -> JSON decode -> PURPOSE comparison (Revision 2 — a stored
// payload whose purpose doesn't match what the caller asked to verify
// is rejected outright, distinct from a plain hash mismatch) -> hash
// comparison -> delete-on-match / increment-on-mismatch. All of this
// runs as one indivisible Redis Lua script — no window exists between
// "read" and "consume" for two concurrent callers to both win.
const VERIFY_SCRIPT = `
local attempts = tonumber(redis.call('GET', KEYS[2]) or '0')
if attempts >= tonumber(ARGV[2]) then
  return {0, 'TOO_MANY_ATTEMPTS'}
end
local raw = redis.call('GET', KEYS[1])
if not raw then
  return {0, 'OTP_EXPIRED'}
end
local ok, payload = pcall(cjson.decode, raw)
if not ok or type(payload) ~= 'table' or not payload.hash then
  return {0, 'OTP_EXPIRED'}
end
if payload.purpose ~= ARGV[4] then
  return {0, 'PURPOSE_MISMATCH'}
end
if payload.hash ~= ARGV[1] then
  redis.call('INCR', KEYS[2])
  redis.call('EXPIRE', KEYS[2], ARGV[3])
  return {0, 'INVALID_OTP'}
end
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
return {1, 'OK'}
`;

const VERIFY_RESULT_MESSAGE = Object.freeze({
  TOO_MANY_ATTEMPTS: "Too many OTP attempts. Try again later.",
  OTP_EXPIRED: "OTP expired. Please request a new one.",
  INVALID_OTP: "Invalid OTP",
  // Structurally unreachable via any real controller today (the
  // purpose used to look up the key is always the same one used to
  // verify), but a genuine, independent guarantee if key construction
  // ever drifts — see this file's own header (Revision 2).
  PURPOSE_MISMATCH: "Invalid OTP",
});

/**
 * verifyOtp({ phone, purpose, otp, role, req, redis })
 *
 * `role` is REQUIRED for every Redis-backed purpose — same key
 * requirement as sendOtp().
 *
 * Returns { ok: true } on success, or { ok: false, code, message } on
 * failure — unchanged shape from the previous revision, so every
 * controller's existing
 * `if (!attempt.ok) { status = attempt.code==="TOO_MANY_ATTEMPTS"?429:401; ... }`
 * branch keeps working without modification.
 */
export const verifyOtp = async ({ phone, purpose, otp, role = null, req = null, redis }) => {
  assertPurpose(purpose, "verifyOtp");
  if (!redis) {
    throw new Error("otp.service.verifyOtp: redis client is required");
  }
  if (REDIS_BACKED_PURPOSES.includes(purpose)) {
    assertRole(role, purpose);
  }

  const suppliedHash = hashOtp(otp);
  const [success, code] = await redis.eval(VERIFY_SCRIPT, {
    keys: [hashKey(role, purpose, phone), attemptKey(role, purpose, phone)],
    arguments: [suppliedHash, String(OTP_ATTEMPT_LIMIT), String(OTP_ATTEMPT_WINDOW_SECONDS), purpose],
  });

  const { ip, userAgent, deviceId } = extractRequestContext(req);
  const ok = success === 1;

  safeAuditWrite({
    phone,
    role,
    purpose,
    provider: "n/a",
    status: ok ? OTP_AUDIT_STATUS.VERIFIED : OTP_AUDIT_STATUS.VERIFY_FAILED,
    ip,
    userAgent,
    deviceId,
    latencyMs: null,
    failureReason: ok ? null : code,
  });

  if (ok) return { ok: true };
  return { ok: false, code, message: VERIFY_RESULT_MESSAGE[code] || "Verification failed" };
};
