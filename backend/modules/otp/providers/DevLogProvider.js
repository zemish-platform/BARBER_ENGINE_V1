/**
 * BARBER ENGINE V1
 * backend/modules/otp/providers/DevLogProvider.js
 *
 * OTP-1 — the "none"/unset SMS_PROVIDER fallback, ported from the
 * pre-OTP-1 services/sms.service.js "none" case with one hardening
 * fix (Part G). Never sends a real SMS; logs the OTP to the server
 * log ONLY, and only when NODE_ENV !== "production".
 *
 * HARDENING FIX vs. the pre-OTP-1 version: that version returned
 * `success: true` from this branch UNCONDITIONALLY, including in
 * production with no real provider configured — it logged an error
 * ("OTP not sent") but still told the caller (and therefore the HTTP
 * client) the send had succeeded. That is a silent-failure mode: a
 * misconfigured production deploy (SMS_PROVIDER left unset/"none")
 * would report every OTP as "sent" while never actually delivering
 * one. This version returns `success: false` in that specific case —
 * NODE_ENV === "production" and no real provider resolved — so a
 * misconfiguration surfaces as a real 502, not a false 200.
 *
 * SECURITY: this is the one remaining place in the entire OTP engine
 * that ever logs a plaintext OTP value, and only under the
 * non-production guard above. No other provider, and no other file in
 * modules/otp/, logs an OTP value.
 */

import logger from "../../../utils/logger.js";
import { OtpProvider } from "./OtpProvider.js";

export class DevLogProvider extends OtpProvider {
  get name() {
    return "none";
  }

  async sendOtp(phone, otp) {
    const startedAt = Date.now();

    if (process.env.NODE_ENV !== "production") {
      logger.debug(`[DEV SMS] OTP for +91${phone}: ${otp}`);
      return {
        success: true,
        provider: this.name,
        messageId: null,
        latencyMs: Date.now() - startedAt,
        error: null,
      };
    }

    logger.error("SMS_PROVIDER not configured in production — OTP not sent", { phone });
    return {
      success: false,
      provider: this.name,
      messageId: null,
      latencyMs: Date.now() - startedAt,
      error: "SMS_PROVIDER_NOT_CONFIGURED",
    };
  }
}
