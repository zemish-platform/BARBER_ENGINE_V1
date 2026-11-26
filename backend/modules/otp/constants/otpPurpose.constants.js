/**
 * BARBER ENGINE V1
 * backend/modules/otp/constants/otpPurpose.constants.js
 *
 * OTP-1 — every OTP send/verify call must carry an explicit `purpose`,
 * chosen by the calling controller, never inferred from role or any
 * other request field (see otp.service.js's own header for why).
 *
 * REGISTER and PHONE_CHANGE are reserved for future flows that do not
 * exist anywhere in this codebase yet — defined here per the OTP-1
 * contract, but not wired to any controller/route. Wiring a real flow
 * for either later means adding a new controller call site with that
 * purpose; nothing here needs to change.
 *
 * REVISION 3 — the Redis key is now built directly from the caller's
 * own `role` + `purpose` arguments (both lowercased) — see
 * otp.service.js's own `otpRedisKey()`. There is no longer a separate
 * namespace-lookup table here (the pre-revision OTP_REDIS_NAMESPACE
 * mapping is retired): `otp:{role}:{purpose}:{phone}` is unambiguous
 * on its own, and every Redis-backed purpose below already has a
 * well-defined role at its one call site.
 */

export const OTP_PURPOSE = Object.freeze({
  LOGIN: "LOGIN", // USER (customer) app login
  REGISTER: "REGISTER", // reserved — no dedicated register-OTP flow exists yet
  SALON_LOGIN: "SALON_LOGIN", // Salon Owner (Partner App) login
  FIELD_AGENT_APPLY: "FIELD_AGENT_APPLY", // FA-2 pre-approval application OTP
  FIELD_AGENT_LOGIN: "FIELD_AGENT_LOGIN", // FA-13A approved-agent operational login
  BOOKING_NOSHOW: "BOOKING_NOSHOW", // Booking Engine no-show confirmation OTP (never Redis-backed — see otp.service.js#dispatchOtpSms)
  PHONE_CHANGE: "PHONE_CHANGE", // reserved — no phone-change flow exists yet
  // PAN-India Field Agent Assisted Onboarding, Phase 1 — a Field
  // Agent proves the SALON OWNER's phone possession on the owner's
  // behalf, without ever issuing that owner a session (see
  // modules/fieldAgent/services/assistedOnboarding.service.js). This
  // is a genuinely NEW purpose, not a reuse of SALON_LOGIN — the
  // Redis key namespace this file builds is `otp:{role}:{purpose}:
  // {phone}`, so an OTP sent under this purpose is structurally
  // unusable to satisfy a real SALON_LOGIN verify (and vice versa),
  // even for the exact same phone number. That separation is the
  // whole point: an assisted-onboarding OTP must never be redeemable
  // as a real owner login credential.
  ASSISTED_ONBOARDING_OWNER_VERIFY: "ASSISTED_ONBOARDING_OWNER_VERIFY",
  // Admin secure activation (services/adminCredential.service.js). Separate
  // purposes so an activation OTP can never be redeemed as a reset, and
  // neither can satisfy any login purpose (Redis key includes the purpose).
  ADMIN_ACTIVATION: "ADMIN_ACTIVATION",
  ADMIN_PASSWORD_RESET: "ADMIN_PASSWORD_RESET",
});

// Which purposes are actually backed by a Redis hash/attempts/cooldown
// key today (BOOKING_NOSHOW is not — its OTP lives on the Booking
// document; REGISTER/PHONE_CHANGE are unwired reservations).
export const REDIS_BACKED_PURPOSES = Object.freeze([
  OTP_PURPOSE.LOGIN,
  OTP_PURPOSE.SALON_LOGIN,
  OTP_PURPOSE.FIELD_AGENT_APPLY,
  OTP_PURPOSE.FIELD_AGENT_LOGIN,
  OTP_PURPOSE.ASSISTED_ONBOARDING_OWNER_VERIFY,
  OTP_PURPOSE.ADMIN_ACTIVATION,
  OTP_PURPOSE.ADMIN_PASSWORD_RESET,
]);
