/**
 * BARBER_ENGINE_V1
 * backend/services/adminCredential.service.js
 *
 * Admin secure activation and password reset.
 *
 * WHY: seeded State/District admin accounts (scripts/seedMasterStates.js,
 * scripts/seedMasterDistricts.js) and the Admin Panel create/assign flows all
 * used one shared password. This service replaces "shared password" with:
 *
 *   1. ASSIGNMENT — an authorized admin (hierarchy-checked by the caller)
 *      assigns an employee's phone/email to an existing admin account.
 *      markAdminAssigned() sets adminAssignedAt/By, replaces the password with
 *      an unusable random hash (so any seed/shared/temp password stops working
 *      immediately) and forces mustChangePassword: true.
 *   2. ACTIVATION — the employee requests an OTP to the ASSIGNED phone
 *      (existing OTP engine: 5-min expiry, 5 attempts / 5 min, atomic
 *      compare-and-consume, resend cooldown) and sets their own password.
 *   3. PASSWORD RESET — same OTP proof for an already-active account.
 *
 * After activation or reset: new bcrypt hash, mustChangePassword false,
 * tokenVersion bumped and every refresh session revoked.
 *
 * Eligibility for ACTIVATION: active, not deleted/suspended, mustChangePassword
 * true, a phone is set, and EITHER the account was assigned by an authorized
 * admin (adminAssignedAt) OR it is the INDIA super admin (whose phone comes
 * from INDIA_ADMIN_PHONE, configured by the founder). A seeded, never-assigned
 * State/District account can never be activated — knowing its generated email
 * or phone is not enough.
 *
 * Request endpoints always answer with the same generic message, so they never
 * reveal whether an account exists or is eligible. OTPs and passwords are never
 * returned or logged here.
 */
import bcrypt from "bcryptjs";
import crypto from "crypto";
import User from "../models/User.js";
import { OTP_PURPOSE } from "../modules/otp/constants/otpPurpose.constants.js";
import { sendOtp as sendOtpEngine, verifyOtp as verifyOtpEngine } from "../modules/otp/services/otp.service.js";
import { revokeAllSessions } from "./session.service.js";
import { logAdminAction } from "../utils/auditLog.js";
import { AUDIT_ACTIONS } from "../utils/auditActions.js";
import logger from "../utils/logger.js";

export const ADMIN_OTP_ROLE = "ADMIN";
export const BCRYPT_COST = 12;
export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 128;
export const GENERIC_REQUEST_MESSAGE = "If this number is eligible, an OTP has been sent.";
export const GENERIC_VERIFY_FAILURE = "Invalid or expired OTP";

const ACCOUNT_LEVELS_ASSIGNABLE = Object.freeze(["STATE", "DISTRICT"]);

/** India mobile, same rule as the User model: 10 digits starting 6-9. */
export const normalizeAdminPhone = (phone) => {
  if (typeof phone !== "string") return null;
  let p = phone.replace(/\D/g, "");
  if (p.length === 12 && p.startsWith("91")) p = p.slice(2);
  return /^[6-9]\d{9}$/.test(p) ? p : null;
};

/** Returns null when acceptable, otherwise a human-readable reason (no password echoed). */
export const validateNewPassword = (password) => {
  if (typeof password !== "string") return "Password is required";
  if (password.length < PASSWORD_MIN_LENGTH) return `Password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Password must be at most ${PASSWORD_MAX_LENGTH} characters`;
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Password must include upper-case, lower-case, a number and a symbol";
  }
  return null;
};

/** A bcrypt hash of 32 random bytes nobody ever sees — the account cannot be logged into with any password. */
export const unusablePasswordHash = () => bcrypt.hash(crypto.randomBytes(32).toString("base64"), BCRYPT_COST);

export const isAssignableAdminLevel = (level) => ACCOUNT_LEVELS_ASSIGNABLE.includes(String(level || "").toUpperCase());

const isUsableAccount = (admin) =>
  !!admin &&
  admin.role === "ADMIN" &&
  admin.isActive !== false &&
  admin.isDeleted !== true &&
  admin.accountStatus !== "SUSPENDED" &&
  admin.accountStatus !== "BLOCKED" &&
  !!admin.phone;

export const isActivationEligible = (admin) =>
  isUsableAccount(admin) &&
  admin.mustChangePassword === true &&
  (!!admin.adminAssignedAt || admin.adminLevel === "INDIA");

export const isResetEligible = (admin) => isUsableAccount(admin) && admin.mustChangePassword !== true;

/**
 * Apply an assignment to an admin document IN MEMORY (caller saves, inside its
 * own transaction if it has one, then calls revokeAllSessions after commit).
 */
export const markAdminAssigned = async (adminDoc, assignerId) => {
  Object.assign(adminDoc, await adminAssignmentFields(assignerId));
  adminDoc.loginAttempts = 0;
  adminDoc.lockUntil = undefined;
  return adminDoc;
};

/** Credential fields for a NEWLY created, assigned admin account (spread into User.create). */
export const adminAssignmentFields = async (assignerId) => ({
  password: await unusablePasswordHash(),
  mustChangePassword: true,
  isPhoneVerified: false,
  adminAssignedAt: new Date(),
  adminAssignedBy: assignerId || null,
});

const PURPOSE_FOR = Object.freeze({
  ACTIVATION: OTP_PURPOSE.ADMIN_ACTIVATION,
  RESET: OTP_PURPOSE.ADMIN_PASSWORD_RESET,
});

const findAdminByPhone = (phone) =>
  User.findOne({ phone, role: "ADMIN", isDeleted: { $ne: true } })
    .select("+password +tokenVersion role adminLevel phone isActive isDeleted accountStatus mustChangePassword adminAssignedAt");

/**
 * requestCredentialOtp({ kind: "ACTIVATION"|"RESET", phone, req, redis })
 * Always resolves to the same generic outcome for ineligible/unknown phones.
 * Returns { ok:true } or { ok:false, code:"RESEND_TOO_SOON"|"SMS_SEND_FAILED"|"INVALID_PHONE", retryAfterSeconds? }.
 */
export const requestCredentialOtp = async ({ kind, phone, req, redis }) => {
  const purpose = PURPOSE_FOR[kind];
  if (!purpose) throw new Error(`adminCredential: unknown kind ${kind}`);
  const normalized = normalizeAdminPhone(phone);
  if (!normalized) return { ok: false, code: "INVALID_PHONE" };

  const admin = await findAdminByPhone(normalized);
  const eligible = kind === "ACTIVATION" ? isActivationEligible(admin) : isResetEligible(admin);
  if (!eligible) {
    logger.info("[AdminCredential] OTP request for an ineligible or unknown phone — no OTP sent", { kind });
    return { ok: true };
  }
  const result = await sendOtpEngine({ phone: normalized, purpose, role: ADMIN_OTP_ROLE, req, redis });
  if (!result?.success) {
    if (result?.code === "RESEND_TOO_SOON") return { ok: false, code: "RESEND_TOO_SOON", retryAfterSeconds: result.retryAfterSeconds };
    return { ok: false, code: "SMS_SEND_FAILED" };
  }
  return { ok: true };
};

/**
 * completeCredentialSet({ kind, phone, otp, newPassword, req, redis })
 * Returns { ok:true, adminId } or { ok:false, status, code, message } — never echoes the OTP or password.
 */
export const completeCredentialSet = async ({ kind, phone, otp, newPassword, req, redis }) => {
  const purpose = PURPOSE_FOR[kind];
  if (!purpose) throw new Error(`adminCredential: unknown kind ${kind}`);
  const normalized = normalizeAdminPhone(phone);
  if (!normalized || typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
    return { ok: false, status: 400, code: "BAD_REQUEST", message: "A valid phone and 6-digit OTP are required" };
  }
  const passwordProblem = validateNewPassword(newPassword);
  if (passwordProblem) return { ok: false, status: 400, code: "WEAK_PASSWORD", message: passwordProblem };

  // OTP first (counts attempts, consumes on success — no replay), then eligibility.
  const attempt = await verifyOtpEngine({ phone: normalized, purpose, otp, role: ADMIN_OTP_ROLE, req, redis });
  if (!attempt?.ok) {
    const tooMany = attempt?.code === "TOO_MANY_ATTEMPTS";
    return { ok: false, status: tooMany ? 429 : 401, code: tooMany ? "TOO_MANY_ATTEMPTS" : "INVALID_OTP", message: tooMany ? "Too many OTP attempts. Try again later." : GENERIC_VERIFY_FAILURE };
  }
  const admin = await findAdminByPhone(normalized);
  const eligible = kind === "ACTIVATION" ? isActivationEligible(admin) : isResetEligible(admin);
  if (!eligible) return { ok: false, status: 401, code: "INVALID_OTP", message: GENERIC_VERIFY_FAILURE };

  const newHash = await bcrypt.hash(newPassword, BCRYPT_COST);
  // Conditional write: the account must still be in the state we checked (no double activation).
  const updated = await User.updateOne(
    { _id: admin._id, phone: normalized, mustChangePassword: kind === "ACTIVATION" ? true : { $ne: true } },
    {
      $set: { password: newHash, mustChangePassword: false, isPhoneVerified: true, passwordChangedAt: new Date(), loginAttempts: 0 },
      $unset: { lockUntil: 1 },
    }
  );
  if (updated.matchedCount !== 1) return { ok: false, status: 409, code: "STATE_CHANGED", message: "Account state changed. Please start again." };

  // Kill every old credential: all refresh sessions revoked + tokenVersion bumped (old access tokens die).
  await revokeAllSessions(admin._id);

  logAdminAction({
    adminId: admin._id,
    action: kind === "ACTIVATION" ? AUDIT_ACTIONS.ADMIN_ACCOUNT_ACTIVATED : AUDIT_ACTIONS.ADMIN_PASSWORD_RESET,
    targetType: "ADMIN_ACCOUNT",
    targetId: admin._id,
    meta: { adminLevel: admin.adminLevel },
    req,
  });
  logger.info(`[AdminCredential] ${kind === "ACTIVATION" ? "account activated" : "password reset"}`, { adminId: String(admin._id) });
  return { ok: true, adminId: admin._id };
};

/** Account status as shown to authorized admins (never includes credentials). */
export const adminAccountStatus = (admin) =>
  admin.mustChangePassword !== true ? "ACTIVE" : admin.adminAssignedAt ? "PENDING_ACTIVATION" : "UNASSIGNED";
