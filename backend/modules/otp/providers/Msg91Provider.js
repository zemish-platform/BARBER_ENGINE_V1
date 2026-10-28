/**
 * BARBER ENGINE V1
 * backend/modules/otp/providers/Msg91Provider.js
 *
 * OTP-2 — real MSG91 v5 SendOTP production integration. This app
 * generates/hashes/stores/verifies the OTP itself (otp.service.js) —
 * MSG91 is used purely as an SMS delivery channel, never as MSG91's
 * own OTP generate/verify API. Reads MSG91_AUTH_KEY / MSG91_TEMPLATE_ID
 * / MSG91_SENDER_ID from environment only — never hardcoded, never
 * accepted as a parameter. Boot-time presence of all three is enforced
 * by guards/msg91EnvGuard.js (Part A "fail fast"), imported by
 * providers/index.js — this file itself still defensively re-checks
 * before every call, in case SMS_PROVIDER is switched to "msg91" at
 * runtime in a process that booted under a different provider.
 *
 * E.164 NORMALIZATION (Part B) — toE164() below produces the
 * canonical `+91XXXXXXXXXX` form and validates it against the E.164
 * shape before any request is built, so a malformed phone can never
 * reach MSG91's API silently mismatched. MSG91's own OTP endpoint
 * separately requires the country code WITHOUT the leading `+` and
 * without a leading zero (its own documented convention, unrelated to
 * E.164) — the wire-format `mobile` param is derived FROM the
 * validated E.164 value (stripping only the `+`), not built
 * independently, so the two representations can never drift apart.
 *
 * RETRY-SAFE RESPONSE MAPPING (Part B) — every outcome maps to one of
 * exactly three stable error codes (SMS_PROVIDER_NOT_CONFIGURED /
 * SMS_PROVIDER_TIMEOUT / SMS_SEND_FAILED) or a clean success, so a
 * caller can always distinguish "definitely not sent" (config/4xx
 * rejection) from "unknown — request may or may not have reached
 * MSG91" (timeout) without inspecting provider-specific payload
 * shapes. Actual duplicate-send protection is enforced upstream by
 * otp.service.js's own 30s idempotency lock (OTP-1.1 Correction 1,
 * unchanged by this phase) — this file's job is only to report
 * outcomes accurately, not to itself decide whether to retry.
 *
 * NEVER LEAKS PROVIDER PAYLOADS TO CLIENTS — MSG91's raw response
 * body only ever reaches logger.error() (server-side only). Every
 * controller that calls through to this provider (see
 * controllers/auth.controller.js, modules/fieldAgent/controllers/*)
 * only ever forwards a fixed, generic client-facing message
 * ("Could not send OTP. Please try again.") regardless of what MSG91
 * actually returned — confirmed unchanged this phase (Part C: no
 * controller was touched).
 */

import logger from "../../../utils/logger.js";
import { OtpProvider } from "./OtpProvider.js";

const SMS_TIMEOUT_MS = 5000;
const MSG91_OTP_URL = "https://control.msg91.com/api/v5/otp";
const E164_PATTERN = /^\+[1-9]\d{6,14}$/;

const withTimeout = (promise, ms) =>
  Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("SMS_PROVIDER_TIMEOUT")), ms)),
  ]);

/**
 * toE164(barePhone) -> "+91XXXXXXXXXX"
 *
 * `phone` arriving here is always the bare 10-digit Indian mobile
 * number already validated upstream (^[6-9]\d{9}$) by every
 * controller before otp.service.js is ever called — this function's
 * job is to produce (and verify) the canonical international form,
 * not to re-validate the national number itself.
 */
const toE164 = (barePhone) => {
  const e164 = `+91${barePhone}`;
  if (!E164_PATTERN.test(e164)) {
    throw new Error(`Msg91Provider: phone does not normalize to a valid E.164 number ("${e164}")`);
  }
  return e164;
};

export class Msg91Provider extends OtpProvider {
  get name() {
    return "msg91";
  }

  async sendOtp(phone, otp) {
    const startedAt = Date.now();

    const authKey = process.env.MSG91_AUTH_KEY;
    const templateId = process.env.MSG91_TEMPLATE_ID;
    const senderId = process.env.MSG91_SENDER_ID;

    if (!authKey || !templateId || !senderId) {
      logger.error("MSG91_AUTH_KEY / MSG91_TEMPLATE_ID / MSG91_SENDER_ID missing in env", {
        phone,
        missing: [
          !authKey && "MSG91_AUTH_KEY",
          !templateId && "MSG91_TEMPLATE_ID",
          !senderId && "MSG91_SENDER_ID",
        ].filter(Boolean),
      });
      return {
        success: false,
        provider: this.name,
        messageId: null,
        latencyMs: Date.now() - startedAt,
        error: "SMS_PROVIDER_NOT_CONFIGURED",
      };
    }

    try {
      // E.164 first (canonical, validated) — MSG91's own wire format
      // (no "+", no leading zero) is then derived from it, never built
      // independently. See this file's own header for why.
      const e164Phone = toE164(phone);
      const mobile = e164Phone.slice(1); // strip only the leading "+"

      const url =
        `${MSG91_OTP_URL}` +
        `?template_id=${encodeURIComponent(templateId)}` +
        `&mobile=${encodeURIComponent(mobile)}` +
        `&otp=${encodeURIComponent(otp)}` +
        `&sender=${encodeURIComponent(senderId)}`;

      const response = await withTimeout(
        fetch(url, {
          method: "POST",
          headers: { authkey: authKey, "Content-Type": "application/JSON" },
        }),
        SMS_TIMEOUT_MS
      );

      const data = await response.json().catch(() => null);

      // MSG91 v5 success responses have `type: "success"`. Anything
      // else (including a non-2xx HTTP status) is a failed send — the
      // exact error message from MSG91 is logged (never the otp value,
      // never returned to the client) so failures are diagnosable
      // without guessing.
      if (response.ok && data?.type === "success") {
        return {
          success: true,
          provider: this.name,
          messageId: data?.request_id || null,
          latencyMs: Date.now() - startedAt,
          error: null,
        };
      }

      logger.error("MSG91 send failed", { phone, httpStatus: response.status, responseBody: data });
      return {
        success: false,
        provider: this.name,
        messageId: null,
        latencyMs: Date.now() - startedAt,
        error: data?.message || "SMS_SEND_FAILED",
      };
    } catch (err) {
      logger.error("MSG91 send failed", { message: err.message, phone });
      return {
        success: false,
        provider: this.name,
        messageId: null,
        latencyMs: Date.now() - startedAt,
        error: err.message === "SMS_PROVIDER_TIMEOUT" ? "SMS_PROVIDER_TIMEOUT" : "SMS_SEND_FAILED",
      };
    }
  }
}
