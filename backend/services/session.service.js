import { isAdminActivationBlocked } from "../utils/adminActivationGate.js";
import crypto from "crypto";
import mongoose from "mongoose";
import redis from "../config/redis.js";
import RefreshToken from "../models/RefreshToken.js";
import User from "../models/User.js";
import logger from "../utils/logger.js";
import { generateAccessToken } from "./token.service.js";

const SESSION_PREFIX = "session:";
const USER_SESSION_PREFIX = "user_sessions:";

// ROLLING window — reset to a fresh SESSION_TTL on every successful
// rotateSession() call (see below). This is what actually governs a
// genuinely-idle user: if the app makes zero requests for longer than
// this, the last-set expiresAt lapses with nothing to renew it,
// regardless of how far off the absolute ceiling still is. Raised
// from 7 to 30 days (2026-09 session policy update) so that the
// product requirement "15+ days idle must not force re-login" holds
// with real margin, without weakening anything else — rotation,
// single-use enforcement, and family-compromise/reuse detection
// below are completely unchanged.
const SESSION_TTL = 60 * 60 * 24 * 30; // 30 days

// ABSOLUTE ceiling — fixed once at createSession() time and carried
// forward unchanged through every rotation (never extended by
// activity). This is the real security backstop: even a user who
// opens the app every single day is still forced through a genuine
// re-login at this point. Previously derived as SESSION_TTL * 4,
// which silently became 120 days the moment SESSION_TTL above grew —
// pulled out as its own explicit, independent constant so the
// absolute ceiling is a deliberate policy choice, not a side effect
// of the rolling-window value.
const SESSION_ABSOLUTE_TTL = 60 * 60 * 24 * 90; // 90 days

// Legitimate concurrent duplicate refresh calls happen in practice —
// e.g. a client's proactive pre-expiry timer racing a reactive
// 401-triggered refresh, with no shared lock between them. Without
// this, whichever call loses that race sees the winner's just-rotated
// token as reuse/theft and revokes the ENTIRE family, killing the
// winner's brand-new tokens too, even though nothing was stolen. This
// cache lets a loser arriving within a short grace window replay the
// exact tokens the winner already received instead of escalating to
// compromise. A token reused well outside this window (no matching
// cache entry) still escalates to full family compromise exactly as
// before.
//
// IMPORTANT: the server cannot distinguish "two genuinely concurrent
// callers" from "one caller replaying an old token milliseconds after
// a legitimate rotation" — both look identical (a revoked-but-recent
// token presented again). So this window tolerates ANY reuse within
// ROTATION_GRACE_SEC, not just true same-instant races — e.g. a
// stolen token replayed within that window would also succeed
// silently instead of triggering compromise. This is the same
// trade-off industry refresh-rotation implementations make (a short
// "reuse interval"); keep ROTATION_GRACE_SEC as small as realistic
// client-side races require, not larger.
const REPLAY_PREFIX = "rotation_replay:";
const ROTATION_GRACE_SEC = 2;

/* =======================================================
   HASH TOKEN
======================================================= */
const hashToken = (raw) =>
  crypto.createHash("sha256").update(raw).digest("hex");

/* =======================================================
   WAIT FOR ROTATION REPLAY (short poll, handles the winner's
   Redis write landing a beat after the loser's check)
======================================================= */
const waitForReplay = async (tokenHash) => {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const cached = await redis.get(REPLAY_PREFIX + tokenHash);
      if (cached) return JSON.parse(cached);
    } catch (err) {
      logger.warn("Redis replay check failed", { message: err.message });
      return null;
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return null;
};

/* =======================================================
   CREATE NEW SESSION
======================================================= */
export const createSession = async (user, req) => {
  const rawToken = crypto.randomBytes(64).toString("hex");
  const tokenHash = hashToken(rawToken);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL * 1000);
  const absoluteExpiresAt = new Date(
    now.getTime() + SESSION_ABSOLUTE_TTL * 1000
  );

  const familyId = new mongoose.Types.ObjectId();

  const ipAddress =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.connection?.remoteAddress ||
    req.ip;

  await RefreshToken.create({
    userRef: user._id,
    tokenHash,
    familyId,
    tokenVersion: Number(user.tokenVersion) || 0,
    expiresAt,
    absoluteExpiresAt,
    ipAddress,
    userAgent: req.headers["user-agent"],
    deviceId: req.headers["x-device-id"] || null,
    platform: req.headers["x-platform"] || null,
    appVersion: req.headers["x-app-version"] || null,
    buildNumber: req.headers["x-build-number"] || null,
  });

  /* Redis session cache */
  try {
    await redis.set(
      SESSION_PREFIX + tokenHash,
      JSON.stringify({
        userId: user._id.toString(),
        tokenVersion: Number(user.tokenVersion) || 0,
      }),
      { EX: SESSION_TTL }
    );

    await redis.set(
      USER_SESSION_PREFIX + user._id.toString(),
      "active",
      { EX: SESSION_TTL }
    );
  } catch (err) {
    logger.warn("Redis session write failed", { message: err.message });
  }

  return rawToken;
};

/* =======================================================
   VERIFY SESSION (REDIS FAST PATH + DB VALIDATION)
======================================================= */
export const verifySession = async (rawToken) => {
  const tokenHash = hashToken(rawToken);
  const now = new Date();

  /* ---------------------------
     REDIS FAST PATH
  --------------------------- */
  try {
    const cached = await redis.get(SESSION_PREFIX + tokenHash);

    if (cached) {
      const parsed = JSON.parse(cached);

      const user = await User.findById(parsed.userId).select(
        "_id role tokenVersion isActive isDeleted accountStatus mustChangePassword adminAssignedAt adminLevel countryRef stateRef districtRef cityRef"
      );

      if (!user) return null;
      if (!user.isActive || user.isDeleted) return null;
      if (user.accountStatus === "SUSPENDED" || user.accountStatus === "BLOCKED") return null;
      if (Number(user.tokenVersion) !== Number(parsed.tokenVersion))
        return null;

      return { user, tokenHash, cached: true };
    }
  } catch (err) {
    logger.warn("Redis fast path failed, fallback to DB", {
      message: err.message,
    });
  }

  /* ---------------------------
     DB FALLBACK
  --------------------------- */
  const tokenDoc = await RefreshToken.findOne({
    tokenHash,
    revokedAt: null,
  })
    .select(
      "_id userRef familyId tokenVersion expiresAt absoluteExpiresAt lastUsedAt isCompromised"
    )
    .lean();

  if (!tokenDoc) return null;
  if (tokenDoc.expiresAt < now) return null;
  if (tokenDoc.absoluteExpiresAt < now) return null;
  if (tokenDoc.isCompromised) return null;

  /* CHECK FAMILY COMPROMISE */
  const compromisedFamily = await RefreshToken.findOne({
    familyId: tokenDoc.familyId,
    isCompromised: true,
  }).lean();

  if (compromisedFamily) return null;

  const user = await User.findById(tokenDoc.userRef).select(
    "_id role tokenVersion isActive isDeleted accountStatus mustChangePassword adminAssignedAt adminLevel countryRef stateRef districtRef cityRef"
  );

  if (!user) return null;
  if (!user.isActive || user.isDeleted) return null;
  if (user.accountStatus === "SUSPENDED" || user.accountStatus === "BLOCKED") return null;
  if (Number(user.tokenVersion) !== Number(tokenDoc.tokenVersion))
    return null;

  /* CACHE AFTER VALIDATION */
  try {
    await redis.set(
      SESSION_PREFIX + tokenHash,
      JSON.stringify({
        userId: user._id.toString(),
        tokenVersion: Number(user.tokenVersion),
      }),
      { EX: SESSION_TTL }
    );
  } catch (err) {
    logger.warn("Redis cache write failed", { message: err.message });
  }

  return { user, tokenDoc, tokenHash };
};

/* =======================================================
   ROTATE SESSION (ATOMIC + REUSE SAFE)
======================================================= */
export const rotateSession = async (rawToken, req) => {
  const tokenHash = hashToken(rawToken);
  const now = new Date();

  const existingToken = await RefreshToken.findOne({ tokenHash })
    .select(
      "_id userRef familyId tokenVersion expiresAt absoluteExpiresAt revokedAt lastUsedAt isCompromised"
    )
    .lean();

  if (!existingToken) return null;

  // ── STALE / ALREADY-USED TOKEN PRESENTED ──────────────────
  // This token was already rotated (or explicitly revoked) before.
  // Whether this is a delayed replay of a stolen token, or a client
  // bug retrying an old value, the safe response is identical: treat
  // it as reuse and kill the ENTIRE token family immediately. This
  // used to silently `return null` here without escalating — meaning
  // sequential reuse (not just same-millisecond race reuse) never
  // triggered family revocation. Fixed: both paths now compromise
  // the whole family.
  if (existingToken.revokedAt) {
    // Grace-period idempotent replay — see REPLAY_PREFIX comment above.
    const replay = await waitForReplay(tokenHash);
    if (replay) return replay;

    await RefreshToken.updateMany(
      { familyId: existingToken.familyId },
      {
        $set: {
          revokedAt: now,
          isCompromised: true,
          revokedReason: "reuse_detected_stale",
        },
      }
    );

    logger.error("Refresh token reuse detected (stale token replay)", {
      userId: existingToken.userRef.toString(),
      familyId: existingToken.familyId.toString(),
    });

    try {
      await redis.del(SESSION_PREFIX + tokenHash);
    } catch (err) {
      logger.warn("Redis del failed", { message: err.message });
    }

    return null;
  }

  if (existingToken.expiresAt < now) return null;
  if (existingToken.absoluteExpiresAt < now) return null;
  if (existingToken.isCompromised) return null;

  const user = await User.findById(existingToken.userRef).select(
    "_id role tokenVersion isActive isDeleted accountStatus mustChangePassword adminAssignedAt adminLevel countryRef stateRef districtRef cityRef"
  );

  if (!user) return null;
  if (!user.isActive || user.isDeleted) return null;
  if (user.accountStatus === "SUSPENDED" || user.accountStatus === "BLOCKED") return null;
  // Admin secure activation: an ADMIN account pending activation can never
  // hold a live session (see services/adminCredential.service.js).
  if (isAdminActivationBlocked(user)) return null;
  if (Number(user.tokenVersion) !== Number(existingToken.tokenVersion))
    return null;

  /* ATOMIC ROTATION (handles same-millisecond concurrent reuse) */
  const updateResult = await RefreshToken.updateOne(
    {
      _id: existingToken._id,
      revokedAt: null,
    },
    {
      $set: {
        lastUsedAt: now,
        revokedAt: now,
        revokedReason: "rotated",
      },
    }
  );

  if (updateResult.modifiedCount === 0) {
    // Grace-period idempotent replay — same-millisecond race variant
    // of the check above (this caller's initial read won, but lost
    // the atomic update to another legitimate concurrent caller).
    const replay = await waitForReplay(tokenHash);
    if (replay) return replay;

    /* REUSE DETECTED — concurrent race lost */
    await RefreshToken.updateMany(
      { familyId: existingToken.familyId },
      {
        $set: {
          revokedAt: now,
          isCompromised: true,
          revokedReason: "reuse_detected",
        },
      }
    );

    logger.error("Refresh token reuse detected", {
      userId: existingToken.userRef.toString(),
      familyId: existingToken.familyId.toString(),
    });

    try {
      await redis.del(SESSION_PREFIX + tokenHash);
      await redis.del(SESSION_PREFIX + existingToken.familyId.toString());
    } catch (err) {
      logger.warn("Redis del failed", { message: err.message });
    }

    return null;
  }

  /* CREATE NEW TOKEN */
  const newRawToken = crypto.randomBytes(64).toString("hex");
  const newHash = hashToken(newRawToken);

  const newExpiresAt = new Date(now.getTime() + SESSION_TTL * 1000);

  await RefreshToken.create({
    userRef: user._id,
    tokenHash: newHash,
    familyId: existingToken.familyId,
    rotatedFrom: existingToken._id,
    tokenVersion: Number(user.tokenVersion) || 0,
    expiresAt: newExpiresAt,
    absoluteExpiresAt: existingToken.absoluteExpiresAt,
    ipAddress:
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.connection?.remoteAddress ||
      req.ip,
    userAgent: req.headers["user-agent"],
    deviceId: req.headers["x-device-id"] || null,
    platform: req.headers["x-platform"] || null,
    appVersion: req.headers["x-app-version"] || null,
    buildNumber: req.headers["x-build-number"] || null,
  });

  const accessToken = generateAccessToken(user);

  const rotationResult = {
    accessToken,
    refreshToken: newRawToken,
    user,
  };

  try {
    await redis.del(SESSION_PREFIX + tokenHash);

    await redis.set(
      SESSION_PREFIX + newHash,
      JSON.stringify({
        userId: user._id.toString(),
        tokenVersion: Number(user.tokenVersion),
      }),
      { EX: SESSION_TTL }
    );

    // Refresh the "active session exists for this user" marker too
    await redis.set(
      USER_SESSION_PREFIX + user._id.toString(),
      "active",
      { EX: SESSION_TTL }
    );

    // Grace-period replay cache — see REPLAY_PREFIX comment at top of
    // file. Only the fields actual callers (auth.routes.js,
    // adminAuth.controller.js) read off `.user` are cached, not the
    // full Mongoose doc.
    await redis.set(
      REPLAY_PREFIX + tokenHash,
      JSON.stringify({
        accessToken,
        refreshToken: newRawToken,
        user: {
          _id: user._id.toString(),
          role: user.role,
          tokenVersion: Number(user.tokenVersion),
          adminLevel: user.adminLevel ?? null,
          countryRef: user.countryRef ?? null,
          stateRef: user.stateRef ?? null,
          districtRef: user.districtRef ?? null,
          cityRef: user.cityRef ?? null,
        },
      }),
      { EX: ROTATION_GRACE_SEC }
    );
  } catch (err) {
    logger.warn("Redis rotate write failed", { message: err.message });
  }

  logger.info("[analytics] refresh_success", { userId: user._id.toString() });

  return rotationResult;
};

/* =======================================================
   LOGOUT SESSION
======================================================= */
export const revokeSession = async (rawToken) => {
  const tokenHash = hashToken(rawToken);

  const tokenDoc = await RefreshToken.findOneAndUpdate(
    { tokenHash, revokedAt: null },
    {
      revokedAt: new Date(),
      revokedReason: "logout",
    }
  ).select("userRef");

  if (tokenDoc?.userRef) {
    logger.info("[analytics] logout", { userId: tokenDoc.userRef.toString() });
  }

  try {
    await redis.del(SESSION_PREFIX + tokenHash);

    // Only clear the user-level "active session" marker if this was
    // the user's last/only known session marker. Since we don't track
    // a count here, we clear it — it gets re-set on next login/refresh
    // if the user actually still has another active session elsewhere.
    if (tokenDoc?.userRef) {
      await redis.del(USER_SESSION_PREFIX + tokenDoc.userRef.toString());
    }
  } catch (err) {
    logger.warn("Redis del failed", { message: err.message });
  }
};

/* =======================================================
   LOGOUT ALL DEVICES
======================================================= */
export const revokeAllSessions = async (userId) => {
  logger.info("[analytics] logout_all", { userId: userId.toString() });

  await RefreshToken.updateMany(
    { userRef: userId, revokedAt: null },
    {
      revokedAt: new Date(),
      revokedReason: "logout_all",
    }
  );

  await User.updateOne(
    { _id: userId },
    { $inc: { tokenVersion: 1 } }
  );

  try {
    await redis.del(USER_SESSION_PREFIX + userId.toString());
  } catch (err) {
    logger.warn("Redis del failed", { message: err.message });
  }

  // Individual session: keys still expire naturally via tokenVersion
  // mismatch on next verifySession() call, even if not explicitly deleted.
};