import Salon from "../models/Salon.js";
import { createSession } from "../services/session.service.js";
import { generateAccessToken } from "../services/token.service.js";
import logger from "../utils/logger.js";
import { createOrFindUser, isValidOtpFormat } from "../utils/otp.helpers.js";
import { sendOtp as sendOtpEngine, verifyOtp as verifyOtpEngine } from "../modules/otp/services/otp.service.js";
import { OTP_PURPOSE } from "../modules/otp/constants/otpPurpose.constants.js";
import {
  REFRESH_COOKIE_NAME,
  getRefreshCookieOptions as getCookieOptions,
} from "../utils/refreshCookie.js";

//////////////////////////////////////////////////////
// PHONE NORMALIZER
//////////////////////////////////////////////////////

const normalizePhone = (phone) => {
  if (!phone || typeof phone !== "string") return null;
  let cleaned = phone.replace(/\D/g, "");
  if (cleaned.startsWith("91") && cleaned.length === 12)
    cleaned = cleaned.slice(2);
  if (!/^[6-9]\d{9}$/.test(cleaned)) return null;
  return cleaned;
};

//////////////////////////////////////////////////////
// STANDARD ERROR RESPONSE HELPER
// Success responses stay FLAT (accessToken/userId directly on
// the body) because LoginScreen.js / AuthContext.js already
// consume them that way — nesting under `data` now would break
// the already-working login flow without a coordinated frontend
// change. Error responses get a structured `error.code` for future
// use, while keeping a top-level `message` for backward-compat
// with existing `res?.message` reads in the frontend.
//////////////////////////////////////////////////////

const sendError = (res, status, code, message) =>
  res.status(status).json({
    success: false,
    message,
    error: { code, message },
  });

//////////////////////////////////////////////////////
// ANALYTICS EVENT HOOK
// Structured log events for now — swap for a real analytics SDK
// (Firebase/Mixpanel/etc) later without touching call sites.
//////////////////////////////////////////////////////

const trackEvent = (event, props = {}) => {
  logger.info(`[analytics] ${event}`, props);
};

//////////////////////////////////////////////////////
// PARTNER — SEND OTP
//////////////////////////////////////////////////////

export const sendOtp = async (req, res) => {
  try {
    const normalizedPhone = normalizePhone(req.body.phone);
    if (!normalizedPhone) {
      return sendError(res, 400, "INVALID_PHONE", "Invalid phone number format");
    }

    const redis = req.redis;
    if (!redis) {
      logger.error("Redis unavailable during sendOtp (OWNER)", { phone: normalizedPhone });
      return sendError(res, 503, "SERVICE_UNAVAILABLE", "Service temporarily unavailable. Please try again.");
    }

    const result = await sendOtpEngine({ phone: normalizedPhone, purpose: OTP_PURPOSE.SALON_LOGIN, role: "OWNER", req, redis });

    if (!result.success) {
      if (result.code === "RESEND_TOO_SOON") {
        res.set("Retry-After", String(result.retryAfterSeconds));
        return sendError(res, 429, "RESEND_TOO_SOON", "Please wait before requesting another OTP.");
      }
      trackEvent("otp_send_failed", { role: "OWNER", phone: normalizedPhone, provider: result.provider, error: result.error });
      return sendError(res, 502, "SMS_SEND_FAILED", "Could not send OTP. Please try again.");
    }

    trackEvent("otp_sent", { role: "OWNER", phone: normalizedPhone, provider: result.provider, latencyMs: result.latencyMs });

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      ...(result.otp && { otp: result.otp }),
    });

  } catch (error) {
    logger.error("sendOtp error", { message: error.message, stack: error.stack });
    return sendError(res, 500, "SERVER_ERROR", "Server error");
  }
};

//////////////////////////////////////////////////////
// PARTNER — VERIFY OTP
//////////////////////////////////////////////////////

export const verifyOtp = async (req, res) => {
  try {
    const normalizedPhone = normalizePhone(req.body.phone);
    const { otp } = req.body;

    if (!normalizedPhone) {
      return sendError(res, 400, "INVALID_PHONE", "Invalid phone number format");
    }
    if (!isValidOtpFormat(otp)) {
      return sendError(res, 400, "INVALID_OTP_FORMAT", "OTP must be a 6-digit code");
    }

    const redis = req.redis;
    if (!redis) {
      logger.error("Redis unavailable during verifyOtp (OWNER)", { phone: normalizedPhone });
      return sendError(res, 503, "SERVICE_UNAVAILABLE", "Service temporarily unavailable. Please try again.");
    }

    const attempt = await verifyOtpEngine({ phone: normalizedPhone, purpose: OTP_PURPOSE.SALON_LOGIN, otp, role: "OWNER", req, redis });
    if (!attempt.ok) {
      const status = attempt.code === "TOO_MANY_ATTEMPTS" ? 429 : 401;
      trackEvent("otp_verify_failed", { role: "OWNER", phone: normalizedPhone, code: attempt.code });
      return sendError(res, status, attempt.code, attempt.message);
    }

    //////////////////////////////////////////////////////
    // PARTNER USER — FIND OR CREATE
    //////////////////////////////////////////////////////

    const user = await createOrFindUser(normalizedPhone, "OWNER", "Salon Owner");

    if (user.status === "SUSPENDED") {
      return sendError(res, 403, "ACCOUNT_SUSPENDED", "Account suspended");
    }

    //////////////////////////////////////////////////////
    // SALON CHECK
    //////////////////////////////////////////////////////

    const salon = await Salon.findOne(
      { ownerId: user._id },
      { _id: 1, approval: 1, onboarding: 1 }
    ).lean();

    //////////////////////////////////////////////////////
    // SESSION
    //////////////////////////////////////////////////////

    const refreshToken = await createSession(user, req);
    const accessToken = generateAccessToken(user, salon?._id);

    res.cookie(REFRESH_COOKIE_NAME, refreshToken, getCookieOptions());

    //////////////////////////////////////////////////////
    // ROUTING LOGIC
    //////////////////////////////////////////////////////

    let step = 0;
    let salonId = null;
    let status = null;
    let route = "ONBOARDING";

    if (salon) {
      salonId = salon._id;
      step = salon.onboarding?.step || 0;
      status = salon.approval?.status || null;

      if (status === "APPROVED") route = "DASHBOARD";
      else if (status === "PENDING") route = "PENDING";
      else if (status === "REJECTED") route = "REJECTED";
    }

    trackEvent("login_success", { role: "OWNER", userId: user._id.toString() });

    return res.status(200).json({
      success: true,
      accessToken,
      refreshToken,
      userId: user._id,
      role: user.role,
      salonId,
      step,
      status,
      route,
      message: salon
        ? "OTP Verified. Resuming session."
        : "OTP Verified. Starting onboarding flow",
    });

  } catch (error) {
    // FA-17 F3 remediation — a real unique index on {phone,role} now
    // exists (previously it silently failed to build); a genuine
    // concurrent-race duplicate must surface as the same safe 409
    // conflict this codebase already uses elsewhere (errorHandler.js's
    // own E11000 branch, state.controller.js's admin-provisioning
    // conflict responses) — never a raw 500.
    if (error.code === 11000) {
      logger.error("verifyOtp duplicate identity conflict", { message: error.message });
      return sendError(res, 409, "CONFLICT", "An account with this phone number already exists");
    }
    logger.error("verifyOtp error", { message: error.message, stack: error.stack });
    return sendError(res, 500, "SERVER_ERROR", "Internal server error during verification");
  }
};

//////////////////////////////////////////////////////
// USER — SEND OTP
//////////////////////////////////////////////////////

export const sendUserOtp = async (req, res) => {
  try {
    const normalizedPhone = normalizePhone(req.body.phone);
    if (!normalizedPhone) {
      return sendError(res, 400, "INVALID_PHONE", "Invalid phone number format");
    }

    const redis = req.redis;
    if (!redis) {
      logger.error("Redis unavailable during sendUserOtp", { phone: normalizedPhone });
      return sendError(res, 503, "SERVICE_UNAVAILABLE", "Service temporarily unavailable. Please try again.");
    }

    const result = await sendOtpEngine({ phone: normalizedPhone, purpose: OTP_PURPOSE.LOGIN, role: "USER", req, redis });

    if (!result.success) {
      if (result.code === "RESEND_TOO_SOON") {
        res.set("Retry-After", String(result.retryAfterSeconds));
        return sendError(res, 429, "RESEND_TOO_SOON", "Please wait before requesting another OTP.");
      }
      trackEvent("otp_send_failed", { role: "USER", phone: normalizedPhone, provider: result.provider, error: result.error });
      return sendError(res, 502, "SMS_SEND_FAILED", "Could not send OTP. Please try again.");
    }

    trackEvent("otp_sent", { role: "USER", phone: normalizedPhone, provider: result.provider, latencyMs: result.latencyMs });

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      ...(result.otp && { otp: result.otp }),
    });

  } catch (error) {
    logger.error("sendUserOtp error", { message: error.message, stack: error.stack });
    return sendError(res, 500, "SERVER_ERROR", "Server error");
  }
};

//////////////////////////////////////////////////////
// USER — VERIFY OTP
//////////////////////////////////////////////////////

export const verifyUserOtp = async (req, res) => {
  try {
    const normalizedPhone = normalizePhone(req.body.phone);
    const { otp } = req.body;

    if (!normalizedPhone) {
      return sendError(res, 400, "INVALID_PHONE", "Invalid phone number format");
    }
    if (!isValidOtpFormat(otp)) {
      return sendError(res, 400, "INVALID_OTP_FORMAT", "OTP must be a 6-digit code");
    }

    const redis = req.redis;
    if (!redis) {
      logger.error("Redis unavailable during verifyUserOtp", { phone: normalizedPhone });
      return sendError(res, 503, "SERVICE_UNAVAILABLE", "Service temporarily unavailable. Please try again.");
    }

    const attempt = await verifyOtpEngine({ phone: normalizedPhone, purpose: OTP_PURPOSE.LOGIN, otp, role: "USER", req, redis });
    if (!attempt.ok) {
      const status = attempt.code === "TOO_MANY_ATTEMPTS" ? 429 : 401;
      trackEvent("otp_verify_failed", { role: "USER", phone: normalizedPhone, code: attempt.code });
      return sendError(res, status, attempt.code, attempt.message);
    }

    //////////////////////////////////////////////////////
    // USER — FIND OR CREATE
    //////////////////////////////////////////////////////

    const user = await createOrFindUser(normalizedPhone, "USER", "Customer");

    if (user.status === "SUSPENDED") {
      return sendError(res, 403, "ACCOUNT_SUSPENDED", "Account suspended");
    }

    //////////////////////////////////////////////////////
    // SESSION
    //////////////////////////////////////////////////////

    const refreshToken = await createSession(user, req);
    const accessToken = generateAccessToken(user);

    res.cookie(REFRESH_COOKIE_NAME, refreshToken, getCookieOptions());

    trackEvent("login_success", { role: "USER", userId: user._id.toString() });

    //////////////////////////////////////////////////////
    // RESPONSE
    //////////////////////////////////////////////////////

    return res.status(200).json({
      success: true,
      accessToken,
      refreshToken,
      userId: user._id,
      role: user.role,
      isNewUser: !user.name || user.name === "Customer",
      message: "Login successful",
    });

  } catch (error) {
    // FA-17 F3 remediation — see verifyOtp's identical comment above.
    if (error.code === 11000) {
      logger.error("verifyUserOtp duplicate identity conflict", { message: error.message });
      return sendError(res, 409, "CONFLICT", "An account with this phone number already exists");
    }
    logger.error("verifyUserOtp error", { message: error.message, stack: error.stack });
    return sendError(res, 500, "SERVER_ERROR", "Internal server error");
  }
};