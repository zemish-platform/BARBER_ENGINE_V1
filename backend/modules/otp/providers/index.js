/**
 * BARBER ENGINE V1
 * backend/modules/otp/providers/index.js
 *
 * OTP-1 PART A — provider registry/resolver. Reads SMS_PROVIDER from
 * environment ONLY (never a function argument sourced from a request),
 * mirroring the pre-OTP-1 services/sms.service.js switch exactly in
 * intent, now expressed as a provider-instance lookup instead of an
 * inline switch. Frontends never see this module and never talk to
 * any SMS provider directly — only this backend dispatches.
 *
 * OTP-1.1 CORRECTION 2 — the "msg91" case now resolves to a
 * CircuitBreaker wrapping the real Msg91Provider singleton, not the
 * raw provider. This is entirely transparent to every caller
 * (otp.service.js, dispatchOtpSms) — the breaker implements the exact
 * same OtpProvider.sendOtp() contract, so nothing outside this file
 * needed to change. See ./CircuitBreaker.js for the full state
 * machine. DevLogProvider/TwilioProvider/AwsSnsProvider are
 * intentionally NOT wrapped — DevLogProvider never fails in a way a
 * breaker would help with, and the two stubs already return a clean,
 * immediate NOT_IMPLEMENTED failure with no real network call to
 * protect against.
 */

import logger from "../../../utils/logger.js";
// OTP-2 Part A — fail-fast boot check, runs at import time. Must be
// imported before the Msg91Provider singleton below is constructed so
// a misconfigured production deploy never gets as far as issuing a
// single request.
import "../guards/msg91EnvGuard.js";
import { DevLogProvider } from "./DevLogProvider.js";
import { Msg91Provider } from "./Msg91Provider.js";
import { TwilioProvider } from "./TwilioProvider.js";
import { AwsSnsProvider } from "./AwsSnsProvider.js";
import { CircuitBreaker } from "./CircuitBreaker.js";

const devLogProvider = new DevLogProvider();
const msg91CircuitBreaker = new CircuitBreaker(new Msg91Provider());
const twilioProvider = new TwilioProvider();
const awsSnsProvider = new AwsSnsProvider();

/**
 * An "unknown provider name" pseudo-provider — matches the pre-OTP-1
 * `default` switch branch exactly: logs a warning, returns a clean
 * normalized failure. Never silently falls back to DevLogProvider
 * (which could leak an OTP into logs, or claim false success) just
 * because SMS_PROVIDER was mistyped in a real environment.
 */
const unknownProvider = (providerName) => ({
  name: providerName,
  async sendOtp(phone) {
    const startedAt = Date.now();
    logger.warn(`Unknown SMS_PROVIDER "${providerName}"`);
    return {
      success: false,
      provider: providerName,
      messageId: null,
      latencyMs: Date.now() - startedAt,
      error: "SMS_PROVIDER_UNKNOWN",
    };
  },
});

/**
 * resolveProvider() — reads process.env.SMS_PROVIDER fresh on every
 * call (not cached at module-load) so tests can flip the env var
 * between cases without re-importing this module.
 */
export const resolveProvider = () => {
  const providerName = process.env.SMS_PROVIDER || "none";

  switch (providerName) {
    case "none":
      return devLogProvider;
    case "msg91":
      return msg91CircuitBreaker;
    case "twilio":
      return twilioProvider;
    case "aws_sns":
      return awsSnsProvider;
    default:
      return unknownProvider(providerName);
  }
};

/**
 * OTP-1.1 — observability accessor for LOGGING ONLY (see
 * CircuitBreaker.js's own header). Never wired into any HTTP response
 * — callers must only ever pass this to a logger, not to res.json().
 */
export const getMsg91CircuitBreakerState = () => msg91CircuitBreaker.getState();
