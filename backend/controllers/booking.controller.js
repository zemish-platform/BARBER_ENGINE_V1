import crypto from "crypto";
import mongoose from "mongoose";
import Booking from "../models/Booking.js";
import Salon from "../models/Salon.js";
import SalonEarnings from "../models/SalonEarnings.js";
import Service from "../models/Service.js";
import Transaction, {
  PAYMENT_METHOD,
  TRANSACTION_STATUS,
  TRANSACTION_TYPE,
} from "../models/Transaction.js";
import User from "../models/User.js";
import WalletTransaction, {
  WALLET_TXN_DIRECTION,
  WALLET_TXN_SOURCE,
  WALLET_TXN_STATUS,
  WALLET_TXN_TYPE,
} from "../models/WalletTransaction.js";
import CancellationPolicyService from "../services/CancellationPolicyService.js";
// Phase 2 (additive, 2026-10-12) — getPublishedGstPolicy/
// resolvePlatformFeeForArea are no longer called directly here; both
// now live inside the shared calculateBookingPricing(), which this
// file calls instead, so lockSlot and GET /v1/bookings/user/quote
// use the exact same formula.
import { calculateBookingPricing } from "../services/bookingPricing.service.js";
import { splitRefundComponents } from "../services/refundComponentSplitter.js";
import NotificationService from "../services/NotificationService.js";
import { NOTIFICATION_EVENTS } from "../modules/notifications/constants/notificationEvents.constants.js";
import { NOTIFICATION_CHANNEL } from "../constants/notification.constants.js";
import { getSmartSlots, invalidateNextSlotCache } from "../services/slotEngine.service.js";
import { formatISTDateFromUtc } from "../utils/dateRange.helpers.js";
import {
  getEligibleSlotsForProfessional,
  selectAnyProfessional,
  revalidateProfessionalForBooking,
} from "../services/professionalAvailability.service.js";
import WalletBalanceService from "../services/WalletBalanceService.js";
import { fetchAndEvaluateCapturedPayment, fetchRazorpayOrder, isRazorpayNotFound } from "../services/Razorpay.service.js";
import {
  BOOKING_STATUS,
  transitionBookingStatus,
  validateBookingTransition,
} from "../utils/bookingState.machine.js";
import { toFriendlyId } from "../utils/friendlyId.js";
// generateOtp + dispatchOtpSms only — hashOtp is NOT imported here:
// this file already has its own local hashOtp (HMAC-SHA256 with
// OTP_SECRET, below) used for check-in OTP, which is stronger than
// the centralized engine's plain SHA-256 (no secret). The no-show OTP
// is booking-scoped exactly like check-in OTP, so it reuses the SAME
// local, stronger hashOtp and the SAME Booking-document-based storage
// (noShowOtp/noShowOtpExpiresAt) — NOT Redis. OTP-1 — only the
// generate + SMS-dispatch step now routes through the centralized
// modules/otp/services/otp.service.js (for provider abstraction +
// audit logging, purpose=BOOKING_NOSHOW); the hash/store/verify
// mechanics on the Booking document below are unchanged.
import { generateOtp, dispatchOtpSms } from "../modules/otp/services/otp.service.js";
import { OTP_PURPOSE } from "../modules/otp/constants/otpPurpose.constants.js";
import { isSalonReadyForBooking } from "../utils/salonReady.guard.js";
import { createRevenueSplitForBooking } from "../modules/finance/services/RevenueSplitIntegrationService.js"; // P0 Revenue Calculation Engine — Step 3

//////////////////////////////////////////////////////////////
// 🔥 CONFIG
//////////////////////////////////////////////////////////////

const LOCK_DURATION           = 2 * 60 * 1000; // 2 minutes
const RAZORPAY_KEY_SECRET     = process.env.RAZORPAY_KEY_SECRET;
const MIN_PAYMENT_ID_LENGTH   = 10;
// OTP_SECRET: hard-fails in production if missing — a fallback secret in prod
// means every deployment with a missing env var silently uses the same known
// string, making all OTP hashes precomputable by anyone who reads this file.
// Dev/test environments get the fallback so local runs work without .env setup.
if (process.env.NODE_ENV === "production" && !process.env.OTP_SECRET) {
  throw new Error(
    "OTP_SECRET environment variable is required in production. " +
    "Set it to a random 32+ character string."
  );
}
const OTP_SECRET = process.env.OTP_SECRET || "otp-fallback-secret-change-in-prod";

// AES-256 encryption for OTP — allows user to see OTP in booking history.
// Same hard-fail rationale as OTP_SECRET above — a fallback key in prod
// means every deployment with a missing env var uses the same known key.
if (process.env.NODE_ENV === "production" && !process.env.OTP_ENCRYPT_KEY) {
  throw new Error(
    "OTP_ENCRYPT_KEY environment variable is required in production. " +
    "Set it to a random 32-character string."
  );
}
const OTP_ENCRYPT_KEY = process.env.OTP_ENCRYPT_KEY || "barber-engine-otp-key-32-chars!!"; // 32 chars

// aes-256-cbc requires EXACTLY a 32-byte key — Buffer.from(OTP_ENCRYPT_KEY)
// had no length check, so any deployment whose OTP_ENCRYPT_KEY env var
// isn't exactly 32 bytes throws "Invalid key length" on every single
// confirmBooking call (both WALLET and RAZORPAY — encryptOtp runs
// unconditionally, after either payment branch already succeeded),
// which is indistinguishable from a total outage since it's 100% of
// requests, every time.
//
// Fix: only when the raw key ISN'T already 32 bytes, derive a
// deterministic 32-byte key via SHA-256 instead of crashing. When it
// IS already 32 bytes, use it completely unchanged — any environment
// where this already worked (and may already have OTPs encrypted
// under the raw-byte key) decrypts them identically to before. The
// derived-key path only ever activates for a key length that could
// never have successfully encrypted anything previously (it always
// threw), so there is nothing pre-existing to preserve there.
const getOtpCipherKey = (rawKey) => {
  const rawBuffer = Buffer.from(rawKey, "utf8");
  return rawBuffer.length === 32
    ? rawBuffer
    : crypto.createHash("sha256").update(rawKey).digest();
};
const OTP_CIPHER_KEY = getOtpCipherKey(OTP_ENCRYPT_KEY);

const encryptOtp = (otp) => {
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", OTP_CIPHER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(otp)), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
};

const decryptOtp = (encrypted) => {
  const [ivHex, encHex] = encrypted.split(":");
  const iv      = Buffer.from(ivHex, "hex");
  const enc     = Buffer.from(encHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", OTP_CIPHER_KEY, iv);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString();
};

/**
 * Decrypts checkInOtpEncrypted for list responses (getMyBookings,
 * getUpcomingBookings) — never throws. One malformed/corrupted
 * ciphertext on a single old booking must not take down the entire
 * list response for every other booking the user has; falls back to
 * null, the same value already shown when there's no encrypted OTP
 * to begin with.
 */
const safeDecryptOtp = (encrypted) => {
  if (!encrypted) return null;
  try {
    return decryptOtp(encrypted);
  } catch (err) {
    console.warn("[safeDecryptOtp] Failed to decrypt checkInOtpEncrypted:", err.message);
    return null;
  }
};


//////////////////////////////////////////////////////////////
// 🧠 HELPERS
//////////////////////////////////////////////////////////////

/** Returns true if two Date values are within 60 seconds of each other */
const isSameTime = (a, b) => Math.abs(a.getTime() - b.getTime()) < 60_000;

/** Safe pagination — page capped at 1000, limit capped at 50 */
const getPagination = (query) => {
  const page  = Math.min(Math.max(parseInt(query.page)  || 1, 1), 1000);
  const limit = Math.min(           parseInt(query.limit) || 10,   50);
  const skip  = (page - 1) * limit;
  return { page, limit, skip };
};

/**
 * Chair-overlap conflict filter — shared by lockSlot() and
 * confirmBooking(), previously duplicated verbatim in both.
 *
 * Phase D fix: `endTime` (both the incoming candidate's and every
 * stored booking's) is ALREADY buffer-inclusive — generateSlotsFromGap()
 * in slotEngine.service.js computes slot.end = start + serviceDuration +
 * bufferTime, and that exact value is what lockSlot()/confirmBooking()
 * persist as Booking.endTime. This filter previously added bufferTime a
 * SECOND time on top of that (both for the incoming candidate's upper
 * bound and for each existing document's own endTime via $expr),
 * inflating every booking's true occupied window from
 * (duration + buffer) to (duration + 2×buffer) — confirmed via a real
 * production-data HTTP reproduction (10min service + 5min buffer
 * occupied 20 minutes instead of 15). Locked contract going forward:
 * Booking.endTime = start + serviceDuration + bufferTime, buffer applied
 * exactly once, never re-added when endTime is read back from storage.
 *
 * Two bookings conflict when: existing.endTime > incoming.startTime
 * AND existing.startTime < incoming.endTime — the standard interval-
 * overlap test, now using each side's true (already buffer-inclusive)
 * occupied window directly, with no further arithmetic.
 *
 * @param {object} params
 * @param {ObjectId} params.chairId
 * @param {Date}     params.startTime
 * @param {Date}     params.endTime — already buffer-inclusive
 * @param {ObjectId} [params.excludeBookingId] — confirmBooking's own
 *   booking already exists at query time and must not conflict with
 *   itself; lockSlot's booking doesn't exist yet, so it omits this.
 */
const buildChairOverlapFilter = ({ chairId, startTime, endTime, excludeBookingId }) => {
  const filter = {
    chairRef: chairId,
    $and: [
      {
        $or: [
          {
            status: {
              $in: [
                BOOKING_STATUS.CONFIRMED,
                BOOKING_STATUS.CHECKED_IN,
                BOOKING_STATUS.ONGOING,
              ],
            },
          },
          {
            status:    BOOKING_STATUS.HOLD,
            lockUntil: { $gt: new Date() },
          },
        ],
      },
      {
        startTime: { $lt: endTime },
        $expr: { $gt: ["$endTime", startTime] },
      },
    ],
  };

  if (excludeBookingId) {
    filter._id = { $ne: excludeBookingId };
  }

  return filter;
};

/**
 * PROFESSIONAL-overlap conflict filter (Phase C) — mirrors
 * buildChairOverlapFilter() above exactly, keyed on professionalRef
 * instead of chairRef. Physical chair count must never become
 * professional booking capacity: the SAME professional must never hold
 * two overlapping active/HOLD bookings on two DIFFERENT chairs at once
 * (this is what makes owner-only auto-chair selection safe — without
 * this, two free chairs could each independently accept a booking for
 * the one real person). Only ever queried when a professional was
 * actually resolved (specific id or ANY) — legacy no-professional
 * bookings never reach this filter.
 *
 * Phase D fix: same buffer-inclusive `endTime` contract and the same
 * double-buffer correction as buildChairOverlapFilter() above.
 */
const buildProfessionalOverlapFilter = ({ professionalId, startTime, endTime, excludeBookingId }) => {
  const filter = {
    professionalRef: professionalId,
    $and: [
      {
        $or: [
          {
            status: {
              $in: [
                BOOKING_STATUS.CONFIRMED,
                BOOKING_STATUS.CHECKED_IN,
                BOOKING_STATUS.ONGOING,
              ],
            },
          },
          {
            status:    BOOKING_STATUS.HOLD,
            lockUntil: { $gt: new Date() },
          },
        ],
      },
      {
        startTime: { $lt: endTime },
        $expr: { $gt: ["$endTime", startTime] },
      },
    ],
  };

  if (excludeBookingId) {
    filter._id = { $ne: excludeBookingId };
  }

  return filter;
};

/** Shared populate config for user-facing booking queries */
const USER_BOOKING_POPULATE = [
  { path: "salonRef",    select: "basicInfo.shopName basicInfo.phone location.address location.geo" },
  { path: "serviceRefs", select: "name price duration", match: { isDeleted: false } },
];


/**
 * 🔐 OTP HASHING
 *
 * Check-in OTPs are hashed with HMAC-SHA256 before storage so a
 * database leak does not expose valid OTPs (4-digit codes are
 * trivially brute-forced if stored in plaintext).
 *
 * hashOtp(otp) → hex string stored in booking.checkInOtp
 *
 * Also reused (Booking Engine V2 — Phase 6) for the no-show
 * cancellation OTP → booking.noShowOtp — same booking-scoped,
 * document-stored-hash pattern, different purpose.
 *
 * checkInBooking() verifies an incoming OTP by hashing it and using
 * the hash as a DB query filter (checkInOtp: hashedOtp), not an
 * in-application string comparison — so the match happens inside
 * MongoDB's own equality check, not a JS-level === on the hash.
 *
 * Uses HMAC (not plain SHA) so the secret is required to reproduce
 * the hash — protects against offline rainbow-table attacks.
 */
const hashOtp = (otp) =>
  crypto
    .createHmac("sha256", OTP_SECRET)
    .update(String(otp))
    .digest("hex");

/**
 * 🔐 RAZORPAY SIGNATURE VERIFICATION
 *
 * Razorpay HMAC-SHA256 signature format:
 *   signature = HMAC_SHA256(razorpay_order_id + "|" + razorpay_payment_id, secret)
 *
 * Call BEFORE confirming any booking or recording any transaction.
 * Throws with { status } attached so the catch block can return the right HTTP code.
 *
 * SECURITY FIX — the bypass below now requires THREE conditions
 * simultaneously (previously NODE_ENV alone), so a single misconfigured
 * environment variable can never silently disable verification, and a
 * real "RAZORPAY" payment can never take the bypass path even in
 * development — only the explicit "MOCK_RAZORPAY" paymentMethod can.
 */
const verifyRazorpaySignature = ({ orderId, paymentId, signature, paymentMethod }) => {
  // ── EXPLICIT MOCK-PAYMENT TEST BYPASS ───────────────────────────────────────
  // ALL THREE must be true — losing any one of them forces the real
  // verification below to run:
  //   1. NODE_ENV !== "production"
  //   2. RAZORPAY_ALLOW_TEST_BYPASS === "true"  (must be explicitly opted into —
  //      never set this in a real .env.production)
  //   3. paymentMethod === "MOCK_RAZORPAY"       (never "RAZORPAY" — a real
  //      Razorpay payment always goes through full verification, regardless
  //      of NODE_ENV or the bypass flag)
  // ──────────────────────────────────────────────────────────────────────────
  const isMockBypassAllowed =
    process.env.NODE_ENV !== "production" &&
    process.env.RAZORPAY_ALLOW_TEST_BYPASS === "true" &&
    paymentMethod === "MOCK_RAZORPAY";

  if (isMockBypassAllowed) {
    console.warn(
      "[Razorpay] Signature verification SKIPPED — explicit MOCK_RAZORPAY test bypass active. " +
      "Never set RAZORPAY_ALLOW_TEST_BYPASS in production."
    );
    return { bypassed: true }; // bypass — no further checks (P0-A: also skips the gateway fetch, since no real payment exists)
  }

  // ── FULL VERIFICATION (unchanged) ───────────────────────────────────────────

  if (!RAZORPAY_KEY_SECRET) {
    throw Object.assign(
      new Error("Payment gateway not configured on server"),
      { status: 500 }
    );
  }

  if (!orderId || !paymentId || !signature) {
    throw Object.assign(
      new Error("orderId, paymentId, and razorpaySignature are all required"),
      { status: 400 }
    );
  }

  const expectedSignature = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  // Constant-time comparison prevents timing attacks.
  // Wrapped in try/catch — Buffer.from(hex) throws on malformed input.
  let isValid = false;
  try {
    isValid = crypto.timingSafeEqual(
      Buffer.from(expectedSignature, "hex"),
      Buffer.from(signature,         "hex")
    );
  } catch {
    // Malformed signature string — treat as invalid, never crash the request
    isValid = false;
  }

  if (!isValid) {
    throw Object.assign(
      new Error("Payment verification failed — invalid signature"),
      { status: 403 }
    );
  }

  return { bypassed: false };
};

/**
 * P0-A — GATEWAY VERIFICATION of a Razorpay booking payment.
 *
 * The HMAC (verifyRazorpaySignature) only proves Razorpay signed
 * "order|payment". This additionally proves — against Razorpay's own
 * record — that the payment was made for THIS booking's order, for THIS
 * booking's amount, in INR, and is actually captured; and that neither the
 * order nor the payment has been used before.
 *
 * Throws Error with { status } like the rest of confirmBooking.
 */
const assertGatewayPaymentForBooking = async ({ booking, orderId, paymentId, session }) => {
  const expectedAmount = booking.totalAmountInPaise;

  // 1. Order must belong to this booking.
  if (booking.razorpayOrderId) {
    if (booking.razorpayOrderId !== orderId) {
      throw Object.assign(new Error("This payment was not made for this booking"), { status: 400 });
    }
  } else {
    // Booking predates order persistence: accept only an order Razorpay itself
    // says was created for this booking, for this amount; then record it.
    let order;
    try {
      order = await fetchRazorpayOrder(orderId);
    } catch (err) {
      if (isRazorpayNotFound(err)) {
        throw Object.assign(new Error("Payment order not found"), { status: 400 });
      }
      throw Object.assign(new Error("Could not verify the payment order with the payment gateway. Please retry."), { status: 502 });
    }
    if (String(order?.notes?.bookingId || "") !== String(booking._id) || order.amount !== expectedAmount) {
      throw Object.assign(new Error("This payment was not made for this booking"), { status: 400 });
    }
    booking.razorpayOrderId = orderId; // persisted by the booking.save() in the same transaction
  }

  // 2. Order / payment must not have been used before (payment id is also
  // covered by the unique index on Transaction.paymentId).
  const orderUsed = await Transaction.findOne({ orderId }).session(session).lean();
  if (orderUsed) {
    throw Object.assign(new Error("Duplicate payment detected"), { status: 409 });
  }

  // 3. Fetch the payment from Razorpay and check captured / order / amount / currency.
  let result;
  try {
    result = await fetchAndEvaluateCapturedPayment({ orderId, paymentId, amountInPaise: expectedAmount });
  } catch (err) {
    if (isRazorpayNotFound(err)) {
      throw Object.assign(new Error("Payment not found at the payment gateway"), { status: 400 });
    }
    throw Object.assign(new Error("Could not verify the payment with the payment gateway. Please retry."), { status: 502 });
  }
  if (!result.verdict.ok) {
    throw Object.assign(new Error(`Payment verification failed — ${result.verdict.message}`), { status: 400, code: result.verdict.code });
  }
};

/**
 * 📡 EMIT SOCKET.IO EVENT
 *
 * Emits a booking lifecycle event to all relevant rooms:
 *   - salon:{salonId}  — owner dashboard / chair grid
 *   - user:{userId}    — customer app
 *
 * Requires req.app.get("io") to be set in server.js:
 *   app.set("io", io);
 *
 * Non-blocking — a socket failure never breaks the HTTP response.
 */
const emitBookingEvent = (req, { event, salonId, userId, payload }) => {
  try {
    const io = req.app.get("io");
    if (!io) return;

    if (salonId) io.to(`salon:${salonId}`).emit(event, payload);
    if (userId)  io.to(`user:${userId}`) .emit(event, payload);
  } catch (socketError) {
    console.warn(`Socket emit failed [${event}]:`, socketError.message);
  }
};

/**
 * 🔐 ASSERT SALON OWNERSHIP
 *
 * Reusable ownership guard for all salon-only operations:
 *   startService(), completeService(), markNoShow(), extendService(),
 *   resendReminder(), generateNoShowOtp(), confirmNoShowCancellation(),
 *   extendArrivalGrace(), releaseChairForNoShow() (future).
 *
 * Single atomic query — matches BOTH the booking's salon AND the
 * caller as its owner. Eliminates the TOCTOU gap present in a
 * two-step (find by owner → compare _id) approach.
 *
 * Throws with { status: 403 } if the caller is not the owner.
 * Must be called inside a try/catch that aborts the session on error.
 *
 * @param {ObjectId} salonRef  - booking.salonRef
 * @param {ObjectId} userId    - req.user._id
 * @param {object}   [session] - mongoose session (optional)
 */
const assertSalonOwnership = async (salonRef, userId, session = null) => {
  const query = Salon.findOne({
    _id:     salonRef,
    ownerId: userId,
  }).select("_id").lean();

  if (session) query.session(session);

  const salon = await query;

  if (!salon) {
    throw Object.assign(
      new Error("Unauthorized — only the salon owner can perform this action"),
      { status: 403 }
    );
  }
};

//////////////////////////////////////////////////////////////
// 🚀 1. LOCK SLOT (HOLD BOOKING)
//////////////////////////////////////////////////////////////

export const lockSlot = async (req, res) => {
  try {
    const {
      salonId,
      date,
      serviceDuration,
      bufferTime = 0,
      requestedTime,
      serviceRefs,
      professionalId, // Phase 5 — optional. Absent = existing behavior, byte for byte.
    } = req.body;

    const userId  = req.user._id;
    const reqTime = new Date(requestedTime);

    //////////////////////////////////////////////////////////
    // 🛑 PREVENT MULTIPLE ACTIVE HOLDS
    //////////////////////////////////////////////////////////

    const existingHold = await Booking.findOne({
      userRef:   userId,
      status:    BOOKING_STATUS.HOLD,
      lockUntil: { $gt: new Date() },
    });

    if (existingHold) {
      return res.status(400).json({
        success: false,
        message: "You already have an active booking hold",
      });
    }

    //////////////////////////////////////////////////////////
    // 🏪 SALON READINESS CHECK
    //////////////////////////////////////////////////////////

    const readiness = await isSalonReadyForBooking(salonId);
    if (!readiness.ready) {
      return res.status(403).json({
        success: false,
        message: "Salon is not ready for bookings",
        reason:  readiness.reason,
      });
    }

    //////////////////////////////////////////////////////////
    // 📊 FETCH AVAILABLE SLOTS
    //////////////////////////////////////////////////////////

    const dateStr = typeof date === 'string' ? date : new Date(date).toISOString().split('T')[0];

    //////////////////////////////////////////////////////////
    // 🧑‍🎨 PHASE 5 — PROFESSIONAL-AWARE SLOT SOURCE (additive)
    //
    // professionalId absent: EXISTING path, completely unchanged —
    // this is the zero-regression guarantee for legacy clients.
    //////////////////////////////////////////////////////////

    let matchedSlot;
    let resolvedProfessionalId = null; // stays null unless a professional path resolves one

    if (professionalId) {
      let candidateProfessionalId = professionalId;

      if (professionalId === "ANY") {
        // Deterministic recommendation only — NOT authoritative yet.
        // Re-validated inside the transaction below before it is
        // ever persisted. "ANY" itself is never stored anywhere.
        candidateProfessionalId = await selectAnyProfessional({ salonId, serviceId: serviceRefs, date: dateStr });
        if (!candidateProfessionalId) {
          return res.status(400).json({
            success: false,
            message: "No professional is currently available for the selected service and date.",
          });
        }
      }

      const eligibleSlots = await getEligibleSlotsForProfessional({
        salonId, professionalId: candidateProfessionalId, serviceId: serviceRefs,
        date: dateStr, serviceDuration, bufferTime,
      });

      matchedSlot = eligibleSlots.find((s) => isSameTime(s.start, reqTime));

      if (!matchedSlot) {
        return res.status(400).json({
          success: false,
          message: "Requested slot is not available for the selected professional",
        });
      }

      resolvedProfessionalId = candidateProfessionalId;

    } else {
      // ── EXISTING PATH — completely unchanged ──
      const slots = await getSmartSlots({ salonId, date: dateStr, serviceDuration, bufferTime });

      matchedSlot = slots.find((s) => isSameTime(s.start, reqTime));

      if (!matchedSlot) {
        return res.status(400).json({
          success: false,
          message: "Requested slot is not available",
        });
      }
    }

    //////////////////////////////////////////////////////////
    // 🚫 HARD CONFLICT CHECK + 🔒 CREATE HOLD — ATOMIC SESSION
    //
    // Race condition without session:
    //   Two users hit lockSlot() simultaneously for the same slot.
    //   Both pass findOne() conflict check (neither HOLD exists yet),
    //   both call Booking.create() — double HOLD created.
    //
    // Fix:
    //   Wrap conflict check AND create inside one mongoose session.
    //   The session gives a consistent read snapshot so the second
    //   concurrent request sees the first HOLD and 409s correctly.
    //   A unique sparse compound index on (chairRef + startTime)
    //   acts as the final hard safety net if two slip through at the
    //   exact same millisecond (duplicate key → caught as 11000).
    //////////////////////////////////////////////////////////

    const lockSession = await mongoose.startSession();
    lockSession.startTransaction();

    let booking;

    try {
      const conflictingBooking = await Booking.findOne(
        buildChairOverlapFilter({
          chairId:   matchedSlot.chairId,
          startTime: matchedSlot.start,
          endTime:   matchedSlot.end,
        })
      ).session(lockSession);

      if (conflictingBooking) {
        await lockSession.abortTransaction();
        lockSession.endSession();
        return res.status(409).json({
          success: false,
          message: "Slot already taken. Please try another time.",
        });
      }

      //////////////////////////////////////////////////////////
      // 🧑‍🎨 PHASE 5 — FINAL, TRANSACTION-SCOPED PROFESSIONAL
      // RE-VALIDATION (never skipped, never moved outside this
      // session — closes the race where an owner changes/cancels
      // the assignment between slot-listing and this exact commit).
      // Only runs when a professional was actually resolved above;
      // the legacy (no-professional) path never reaches this block.
      //////////////////////////////////////////////////////////

      if (resolvedProfessionalId) {
        // Phase C — direct professional-level overlap check, run
        // unconditionally alongside the chair check above whenever a
        // professional was resolved (owner-only OR assignment-backed).
        // This is what actually enforces "professional capacity, not
        // chair count": without it, two free chairs could each
        // independently accept a booking for the same person.
        const conflictingProfessionalBooking = await Booking.findOne(
          buildProfessionalOverlapFilter({
            professionalId: resolvedProfessionalId,
            startTime:      matchedSlot.start,
            endTime:        matchedSlot.end,
          })
        ).session(lockSession);

        if (conflictingProfessionalBooking) {
          await lockSession.abortTransaction();
          lockSession.endSession();
          return res.status(409).json({
            success: false,
            message: "Selected professional is already booked for an overlapping time. Please choose another slot.",
          });
        }

        const stillValid = await revalidateProfessionalForBooking({
          salonId, professionalId: resolvedProfessionalId, serviceId: serviceRefs,
          chairId: matchedSlot.chairId, date: dateStr,
          slotStart: matchedSlot.start, slotEnd: matchedSlot.end,
          session: lockSession,
        });

        if (!stillValid) {
          await lockSession.abortTransaction();
          lockSession.endSession();
          return res.status(409).json({
            success: false,
            message: "Selected professional is no longer available for this slot. Please choose another.",
          });
        }
      }

      //////////////////////////////////////////////////////////
      // 🔒 CREATE HOLD BOOKING (inside session)
      //////////////////////////////////////////////////////////

      const lockUntil     = new Date(Date.now() + LOCK_DURATION);
      const holdExpiresAt = new Date(Date.now() + LOCK_DURATION);
      const bookingDate   = matchedSlot.start.toISOString().split("T")[0];

      //////////////////////////////////////////////////////////
      // 💰 CALCULATE TOTAL AMOUNT FROM SERVICE PRICES
      // Fetch selected services, sum their prices, convert to
      // paise (₹1 = 100 paise) to avoid floating-point errors.
      // This sets totalAmountInPaise which is required by
      // confirmBooking() for finance calculations.
      //////////////////////////////////////////////////////////

      //////////////////////////////////////////////////////////
      // 💰 PRICING — extracted into services/bookingPricing.service.js
      // (Phase 2, additive, 2026-10-12) so this exact formula is
      // shared, byte-for-byte, with the read-only GET
      // /v1/bookings/user/quote endpoint — quote and the real booking
      // can never independently disagree about a price. Behavior for
      // every existing field (serviceAmountInPaise, commissionInPaise,
      // gstRatePercent, gstAmountInPaise, platformFeePolicyRef,
      // gstPolicyVersionRef, totalAmountInPaise) is byte-for-byte
      // unchanged from the inline block this replaced — the only new
      // outputs are platformFeeGstConfigured/platformFeeGstRatePercent/
      // platformFeeGstAmountInPaise, which stay null/false (and
      // totalAmountInPaise's new 4th term stays a no-op +0) until an
      // admin publishes a GstPolicyVersion that actually contains a
      // valid platformFeeGstRatePercent — see that function's own
      // header for the full reasoning. Still runs inside this same
      // open transaction (lockSession passed through), reading the
      // exact same Service/Salon documents the old inline block read.
      //////////////////////////////////////////////////////////
      const {
        serviceAmountInPaise,
        commissionAmountInPaise: commissionInPaise,
        platformFeePolicyRef,
        gstRatePercent,
        gstAmountInPaise,
        gstPolicyVersionRef,
        platformFeeGstRatePercent,
        platformFeeGstAmountInPaise,
        totalAmountInPaise,
      } = await calculateBookingPricing({ salonId, serviceRefs, session: lockSession });

      [booking] = await Booking.create(
        [
          {
            userRef:            userId,
            salonRef:           salonId,
            chairRef:           matchedSlot.chairId,
            professionalRef:    resolvedProfessionalId || null,
            serviceRefs,
            bookingDate,
            startTime:          matchedSlot.start,
            endTime:            matchedSlot.end,
            serviceDuration,
            bufferTime,
            lockUntil,
            holdExpiresAt,
            totalAmountInPaise,
            serviceAmountInPaise,
            commissionAmountInPaise: commissionInPaise,
            gstRatePercent,
            gstAmountInPaise,
            // Phase 2 (additive, 2026-10-12) — separate GST charge on
            // the Platform Fee itself; null/absent on every booking
            // until an admin publishes a policy with a valid
            // platformFeeGstRatePercent (see bookingPricing.service.js).
            platformFeeGstRatePercent,
            platformFeeGstAmountInPaise,
            // STEP 8.2 (policy version follow-up) — audit-trail only,
            // never read for any dollar calculation (that's still
            // totalAmountInPaise/serviceAmountInPaise/
            // commissionAmountInPaise/gstAmountInPaise above, all
            // unchanged by this addition). Records exactly which
            // AreaPlatformFeePolicy/GstPolicyVersion document (if any)
            // was live when this booking was priced, so
            // RevenueSplitIntegrationService.js can copy real
            // traceability onto the RevenueSplit it creates instead of
            // a second, independent RevenueSettings lookup.
            platformFeePolicyRef,
            gstPolicyVersionRef,
            status:             BOOKING_STATUS.HOLD,
          },
        ],
        { session: lockSession }
      );

      await lockSession.commitTransaction();
      lockSession.endSession();

    } catch (lockError) {
      await lockSession.abortTransaction();
      lockSession.endSession();

      // Duplicate key = two concurrent requests hit at the exact same ms —
      // the unique sparse index caught what the session check missed.
      if (lockError.code === 11000) {
        return res.status(409).json({
          success: false,
          message: "Slot just taken by another user. Please try another time.",
        });
      }

      // Transaction WriteConflict ("TransientTransactionError" label) —
      // two concurrent transactions raced on the same unique index entry
      // before either committed, so MongoDB's storage engine aborts one
      // rather than surfacing a duplicate-key error. Same underlying
      // cause as the 11000 case above, different MongoDB-level shape —
      // must not leak the raw driver error to the client.
      if (typeof lockError.hasErrorLabel === "function" && lockError.hasErrorLabel("TransientTransactionError")) {
        return res.status(409).json({
          success: false,
          message: "Selected slot is no longer available.",
        });
      }

      throw lockError; // unexpected — re-throw so outer catch returns 500
    }

    const { lockUntil } = booking;

    //////////////////////////////////////////////////////////
    // 📡 REALTIME — notify salon chair grid of new hold
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:hold",
      salonId: salonId.toString(),
      userId:  userId.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   matchedSlot.chairId,
        startTime: matchedSlot.start,
        endTime:   matchedSlot.end,
        lockUntil,
        status:    BOOKING_STATUS.HOLD,
      },
    });

    // PHASE B (approved) — the Salon Owner must receive NO notification
    // (neither PUSH nor IN_APP) at hold time. The owner-facing
    // BOOKING_CREATED send that used to live here has moved to
    // runBookingConfirmedEffects(), firing only after payment is
    // verified and the booking is actually CONFIRMED. See that
    // function's own comment for the moved block.

    return res.status(200).json({
      success:   true,
      bookingId: booking._id,
      lockUntil,
      // Amount breakdown — frontend must display and charge exactly
      // this (not recalculate its own total), since this is what
      // confirmBooking's Razorpay order will actually charge.
      serviceAmountInPaise:    booking.serviceAmountInPaise,
      commissionAmountInPaise: booking.commissionAmountInPaise,
      gstRatePercent:          booking.gstRatePercent,
      gstAmountInPaise:        booking.gstAmountInPaise,
      // Phase 2 (additive, 2026-10-12) — null on every booking until
      // an admin publishes a policy with a valid
      // platformFeeGstRatePercent; never a fabricated rate.
      platformFeeGstRatePercent:   booking.platformFeeGstRatePercent,
      platformFeeGstAmountInPaise: booking.platformFeeGstAmountInPaise,
      totalAmountInPaise:      booking.totalAmountInPaise,
    });

  } catch (error) {
    console.error("lockSlot error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Failed to lock slot",
      // Additive — forwards calculateBookingPricing()'s machine-readable
      // code (e.g. PLATFORM_FEE_GST_NOT_CONFIGURED) when present, so the
      // app can show a dedicated "pricing temporarily unavailable, try
      // again shortly" state instead of a generic error. Absent for
      // every other error this catch already handled before this field
      // existed (undefined keys are simply omitted from the JSON).
      ...(error.code ? { code: error.code } : {}),
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 2. CONFIRM BOOKING — FULLY ATOMIC + RAZORPAY VERIFIED
//////////////////////////////////////////////////////////////

/**
 * The transactional heart of a booking confirmation (HOLD → CONFIRMED with
 * payment): validates the booking, verifies the payment (Razorpay: P0-A gateway
 * check), records the Transaction, credits the salon's PENDING wallet, moves
 * the booking to CONFIRMED and saves — all inside the caller's transaction.
 *
 * P0-B — extracted UNCHANGED from confirmBooking so the Razorpay webhook can
 * confirm a paid booking through the exact same code path as the client's
 * /confirm call (no duplicated money logic). The caller owns the session,
 * commit/abort and retry.
 *
 * @returns {Promise<{booking: object, otp: number, amount: number}>}
 */
export const runBookingConfirmationCore = async ({ session, bookingId, actorUserId, paymentMethod, paymentId, orderId, gatewayCheckBypassed = false }) => {
  const isWalletPayment = paymentMethod === "WALLET";

      //////////////////////////////////////////////////////////
    // 🔍 FETCH BOOKING (inside session)
    //////////////////////////////////////////////////////////

    const booking = await Booking.findById(bookingId).session(session);

    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    //////////////////////////////////////////////////////////
    // 🔐 USER OWNERSHIP CHECK
    //////////////////////////////////////////////////////////

    if (booking.userRef.toString() !== String(actorUserId)) {
      throw Object.assign(new Error("Unauthorized"), { status: 403 });
    }

    //////////////////////////////////////////////////////////
    // 🔁 STATE MACHINE VALIDATION
    //////////////////////////////////////////////////////////

    if (!validateBookingTransition(booking.status, BOOKING_STATUS.CONFIRMED)) {
      throw Object.assign(new Error("Invalid booking state transition"), { status: 400 });
    }

    //////////////////////////////////////////////////////////
    // ⌛ HOLD EXPIRY CHECK
    //////////////////////////////////////////////////////////

    if (!booking.lockUntil || booking.lockUntil < new Date()) {
      await transitionBookingStatus({ booking, nextStatus: BOOKING_STATUS.EXPIRED, session });
      throw Object.assign(new Error("Booking hold has expired"), { status: 400 });
    }

    //////////////////////////////////////////////////////////
    // 🚫 DOUBLE-BOOKING OVERLAP CHECK
    //////////////////////////////////////////////////////////

    const conflicting = await Booking.findOne(
      buildChairOverlapFilter({
        chairId:          booking.chairRef,
        startTime:        booking.startTime,
        endTime:          booking.endTime,
        excludeBookingId: booking._id,
      })
    ).session(session);

    if (conflicting) {
      throw Object.assign(new Error("Slot already booked by another user"), { status: 409 });
    }

    //////////////////////////////////////////////////////////
    // 💰 BOOKING AMOUNT VALIDATION
    //////////////////////////////////////////////////////////

    if (!booking.totalAmountInPaise) {
      throw Object.assign(new Error("Booking amount is missing"), { status: 400 });
    }

    //////////////////////////////////////////////////////////
    // 💰 WALLET PAYMENT — synthetic paymentId (no real Razorpay
    // payment exists for a wallet-funded booking). Deterministic
    // per-booking so a retried confirmBooking call for the same
    // booking hits the same idempotency check below rather than
    // generating a new "payment" each time.
    //////////////////////////////////////////////////////////

    const effectivePaymentId = isWalletPayment
      ? `wallet_${booking._id}`
      : paymentId;

    //////////////////////////////////////////////////////////
    // 🔐 PAYMENT IDEMPOTENCY CHECK
    //////////////////////////////////////////////////////////
  
    const existingTxn = await Transaction.findOne({ paymentId: effectivePaymentId }).session(session);
    if (existingTxn) {
      throw Object.assign(new Error("Duplicate payment detected"), { status: 409 });
    }

    //////////////////////////////////////////////////////////
    // 🔐 P0-A GATEWAY VERIFICATION — order↔booking, captured,
    // amount, currency, no reuse (RAZORPAY only; the dev
    // MOCK_RAZORPAY bypass has no real payment to fetch).
    //////////////////////////////////////////////////////////
    if (!isWalletPayment && !gatewayCheckBypassed) {
      await assertGatewayPaymentForBooking({ booking, orderId, paymentId, session });
    }
  
    //////////////////////////////////////////////////////////
    // 💰 FINANCE SPLIT — commission was already calculated and
    // locked in at booking-creation time (lockSlot), not
    // re-derived here.
    //////////////////////////////////////////////////////////

    const amount        = booking.totalAmountInPaise;
    const commission    = booking.commissionAmountInPaise;
    const payoutAmount  = booking.serviceAmountInPaise;

    //////////////////////////////////////////////////////////
    // 💰 WALLET DEBIT — only for paymentMethod: "WALLET". Atomic
    // conditional $inc (filter requires sufficient balance) so two
    // concurrent confirm attempts for the same user can never both
    // succeed and drive the balance negative — same pattern as
    // WalletBalanceService.applyLedgerEntry for salon wallets.
    //////////////////////////////////////////////////////////

    if (isWalletPayment) {
      const amountRupees = amount / 100;
      const userBefore = await User.findOne({ _id: booking.userRef, isDeleted: false })
        .select("walletBalance")
        .session(session);
      if (!userBefore) {
        throw Object.assign(new Error("User not found"), { status: 404 });
      }
      const balanceBeforeInPaise = Math.round((userBefore.walletBalance || 0) * 100);

      if (balanceBeforeInPaise < amount) {
        // 📬 NOTIFICATION (non-blocking) — real payment failure for a
        // WALLET-method attempt (insufficient funds), same class of
        // event as the Razorpay signature-failure notification above.
        await NotificationService.send({
          recipientId:   actorUserId,
          recipientType: "USER",
          templateKey:   NOTIFICATION_EVENTS.PAYMENT_FAILED,
          variables:     {},
          title:         "Payment Failed",
          message:       "Payment failed — insufficient wallet balance.",
          type:          "PAYMENT",
          priority:      "HIGH",
          actionType:    "OPEN_WALLET",
          actionUrl:     "/wallet",
          meta:          { bookingId: booking._id },
        });
        throw Object.assign(
          new Error("Insufficient wallet balance"),
          { status: 400 }
        );
      }

      const updatedUser = await User.findOneAndUpdate(
        {
          _id: booking.userRef,
          isDeleted: false,
          walletBalance: { $gte: amountRupees }, // re-check atomically at write time
        },
        { $inc: { walletBalance: -amountRupees } },
        { new: true, session }
      ).select("walletBalance");

      if (!updatedUser) {
        // Balance changed between the read above and this write
        // (concurrent debit) — fail safe rather than overdraw.
        // 📬 NOTIFICATION (non-blocking) — same real payment-failure
        // class as the pre-check above.
        await NotificationService.send({
          recipientId:   actorUserId,
          recipientType: "USER",
          templateKey:   NOTIFICATION_EVENTS.PAYMENT_FAILED,
          variables:     {},
          title:         "Payment Failed",
          message:       "Payment failed — insufficient wallet balance.",
          type:          "PAYMENT",
          priority:      "HIGH",
          actionType:    "OPEN_WALLET",
          actionUrl:     "/wallet",
          meta:          { bookingId: booking._id },
        });
        throw Object.assign(
          new Error("Insufficient wallet balance"),
          { status: 400 }
        );
      }

      await WalletTransaction.create(
        [{
          userId:        booking.userRef,
          bookingId:     booking._id,
          direction:     WALLET_TXN_DIRECTION.DEBIT,
          type:          WALLET_TXN_TYPE.BOOKING_PAYMENT,
          status:        WALLET_TXN_STATUS.SUCCESS,
          source:        WALLET_TXN_SOURCE.BOOKING,
          amountInPaise: amount,
          requestId:     `booking_payment:${booking._id}`,
          balanceBeforeInPaise,
          balanceAfterInPaise: Math.round(updatedUser.walletBalance * 100),
          metadata:      { bookingId: booking._id.toString() },
        }],
        { session }
      );
    }

    //////////////////////////////////////////////////////////
    // 💳 CREATE TRANSACTION
    //////////////////////////////////////////////////////////

    await Transaction.create(
      [
        {
          bookingId:  booking._id,
          userId:     booking.userRef,
          salonId:    booking.salonRef,
          resourceId: booking.chairRef,
          paymentId:  effectivePaymentId,
          orderId:    orderId || null,
          amount,
          commission,
          payoutAmount,
          status:     TRANSACTION_STATUS.PAID,
          type:       TRANSACTION_TYPE.BOOKING,
          paymentMethod: isWalletPayment ? PAYMENT_METHOD.WALLET : PAYMENT_METHOD.UPI,
        },
      ],
      { session }
    );


    //////////////////////////////////////////////////////////
    // 💰 WALLET CREDIT (PENDING) — via WalletBalanceService
    //////////////////////////////////////////////////////////
    await WalletBalanceService.creditPending({
      salonId:       booking.salonRef,
      amountInPaise: payoutAmount,
      action:        "BOOKING_SETTLEMENT",
      refType:       "BOOKING",
      refId:         booking._id,
      idempotencyKey: `booking:credit:${booking._id}`,
      session,
      triggeredBy:   "SYSTEM",
      remarks:       "Booking paid — held pending service delivery",
    });

    //////////////////////////////////////////////////////////
    // ✅ TRANSITION TO CONFIRMED
    //////////////////////////////////////////////////////////

    const otp       = Math.floor(1000 + Math.random() * 9000);
    const otpHashed = hashOtp(otp);

    await transitionBookingStatus({ booking, nextStatus: BOOKING_STATUS.CONFIRMED, session });
    booking.paymentStatus      = "PAID";
    booking.checkInOtp         = otpHashed;
    booking.lockUntil          = null;
    booking.checkInOtpEncrypted = encryptOtp(otp);

    booking.checkInOtpExpiresAt = new Date(
      booking.startTime.getTime() + 2 * 60 * 60 * 1000
    );

    booking.arrivalGraceUntil = new Date(
      booking.startTime.getTime() +
      booking.maxArrivalWaitMinutes * 60 * 1000
    );

    await booking.save({ session });

  return { booking, otp, amount };
};

/**
 * Post-commit side effects of a confirmation: slot cache, realtime events,
 * notifications. `req` only needs `.app` (the webhook passes `{ app }`).
 * P0-B — extracted unchanged from confirmBooking.
 */
export const runBookingConfirmedEffects = async ({ req, booking, amount }) => {
    //////////////////////////////////////////////////////////
    // 🗑️ CACHE INVALIDATION
    //////////////////////////////////////////////////////////
    await invalidateNextSlotCache(
      booking.salonRef.toString(),
      booking.startTime.toISOString().split("T")[0]
    );

    //////////////////////////////////////////////////////////
    // 📡 REALTIME
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:confirmed",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   booking.chairRef,
        startTime: booking.startTime,
        endTime:   booking.endTime,
        status:    BOOKING_STATUS.CONFIRMED,
      },
    });

    //////////////////////////////////////////////////////////
    // 📬 NOTIFICATION (non-blocking, after commit)
    //////////////////////////////////////////////////////////

    // COPY FIX (approved) — this previously read `bookingTimeStr`
    // (time-only, via toLocaleTimeString) and hardcoded the word
    // "today" in the message below, regardless of the booking's
    // actual date. Since a slot can be booked for today OR the next
    // day (same-day/next-day booking is an existing, supported
    // flow), that could tell a customer their appointment is "today"
    // when it is actually tomorrow — a real correctness defect, not
    // a style choice. Fixed by including the full date in the string
    // (same toLocaleString dateStyle/timeStyle pattern already used
    // elsewhere in this file for an identical purpose) and removing
    // the hardcoded "today" from the message entirely, so the text
    // is correct for both cases without a same-day/next-day branch.
    const bookingDateTimeStr = booking.startTime.toLocaleString("en-IN", {
      dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Kolkata",
    });
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_CONFIRMED,
      variables:     { date: bookingDateTimeStr },
      title:         "Booking Confirmed",
      message:       `Your appointment is confirmed for ${bookingDateTimeStr}.`,
      type:          "BOOKING",
      priority:      "HIGH",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    // Distinct from BOOKING_CONFIRMED above — a separate, finance-focused
    // notification for the payment itself, matching the reserved
    // PAYMENT_SUCCESS event in the registry.
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.PAYMENT_SUCCESS,
      variables:     { amount: Math.round(amount / 100) },
      title:         "Payment Successful",
      message:       `Your payment was successful. Tap to view details.`,
      type:          "PAYMENT",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, amountInPaise: amount },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    // PHASE B (approved) — Salon Owner "new booking" push, moved here
    // from lockSlot(): the owner must see this only once the booking
    // is actually CONFIRMED (payment verified), never at HOLD time.
    // Reuses the existing BOOKING_CREATED event key per the founder's
    // decision — this is the only call site for it now. Runs through
    // the exact same post-commit, non-blocking path, and the exact
    // same duplicate-confirmation guard, as BOOKING_CONFIRMED/
    // PAYMENT_SUCCESS above and the webhook path that also calls this
    // function (services/razorpayWebhook.service.js) — no second
    // confirmation/retry mechanism introduced.
    //
    // Deep-link payload contract note: PushProvider.js's
    // buildDeepLinkData() only forwards actionType/actionUrl(->deepLink)
    // /entityType/entityId into the actual push `data` a device
    // receives — `meta` below is for the IN_APP Notification document
    // only and never reaches the push payload. The booking id AND its
    // IST calendar date (needed by the Salon App to pick the right
    // Live Schedule day) are therefore both encoded into actionUrl's
    // query string, with entityId carrying the plain id as well.
    const bookingDateIST = formatISTDateFromUtc(booking.startTime);
    await NotificationService.send({
      recipientId:   booking.salonRef,
      recipientType: "SALON",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_CREATED,
      variables:     { date: bookingDateIST },
      title:         "New Booking Confirmed",
      message:       "You have received a new booking. Tap to view customer, service and booking details.",
      type:          "BOOKING",
      priority:      "HIGH",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}?date=${bookingDateIST}`,
      entityType:    "BOOKING",
      entityId:      booking._id,
      meta:          { bookingId: booking._id, bookingDate: bookingDateIST, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    //////////////////////////////////////////////////////////
    // 💰 P0 REVENUE CALCULATION ENGINE — STEP 3 (non-blocking, after
    // commit; Razorpay-paid bookings only; never throws — see that
    // file's own header for the full safety rationale)
    //////////////////////////////////////////////////////////
    await createRevenueSplitForBooking({ booking });
};

export const confirmBooking = async (req, res) => {
  // U1 PAYMENT SAFETY — bounded retry, same pattern as cancelBooking
  // (see that function's own comment for the full rationale). A
  // genuine concurrent-write collision on this booking (two /confirm
  // calls racing) is correctly aborted by MongoDB's own transaction
  // conflict detection, not corrupted. Retrying lets the loser
  // re-read the now-updated document fresh and land on the existing
  // deterministic rejection paths below instead of a raw 500.
  //
  // IMPORTANT: this retry does NOT and cannot undo an external
  // Razorpay charge that already succeeded before the losing
  // transaction was aborted — if the loser's payment was a genuine,
  // distinct Razorpay payment, that charge already happened at the
  // gateway. This only makes our own backend's response deterministic,
  // not a guarantee against an external double charge.
  const MAX_ATTEMPTS = 3;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
    const {
      bookingId,
      paymentMethod = "RAZORPAY", // "RAZORPAY" | "WALLET" | "MOCK_RAZORPAY" (test bypass only — see verifyRazorpaySignature)
      paymentId,         // razorpay_payment_id — required only for RAZORPAY
      orderId,           // razorpay_order_id — required only for RAZORPAY
      razorpaySignature, // razorpay_signature — required only for RAZORPAY
    } = req.body;

    const isWalletPayment = paymentMethod === "WALLET";
    let gatewayCheckBypassed = false; // true only for the explicit dev MOCK_RAZORPAY bypass

    //////////////////////////////////////////////////////////
    // 💳 PAYMENT ID FORMAT GUARD (RAZORPAY only — wallet payments
    // have no Razorpay payment ID at all)
    //////////////////////////////////////////////////////////
  
    if (!isWalletPayment) {
      if (!paymentId || paymentId.length < MIN_PAYMENT_ID_LENGTH) {
        throw Object.assign(
          new Error("Invalid payment ID — must be at least 10 characters"),
          { status: 400 }
        );
      }

      //////////////////////////////////////////////////////////
      // 🔐 RAZORPAY SIGNATURE VERIFICATION (server-side)
      //////////////////////////////////////////////////////////

      try {
        gatewayCheckBypassed = verifyRazorpaySignature({ orderId, paymentId, signature: razorpaySignature, paymentMethod }).bypassed;
      } catch (verifyErr) {
        // 📬 NOTIFICATION (non-blocking) — real gateway-level payment
        // failure, distinct from the booking-validation errors below
        // (hold expired, slot conflict, etc.) which are not payment
        // failures and intentionally do not send this notification.
        await NotificationService.send({
          recipientId:   req.user._id,
          recipientType: "USER",
          templateKey:   NOTIFICATION_EVENTS.PAYMENT_FAILED,
          variables:     {},
          title:         "Payment Failed",
          message:       "Your payment could not be verified. Please try again.",
          type:          "PAYMENT",
          priority:      "HIGH",
          actionType:    null,
          actionUrl:     null,
          meta:          { bookingId },
        });
        throw verifyErr;
      }
    }

    // P0-B — the Razorpay webhook may already have confirmed this booking with
    // THIS payment (payment.captured usually lands within a second of checkout).
    // Answer the client's own /confirm call idempotently with success instead of
    // an "invalid state" error for a booking that is in fact confirmed and paid.
    if (!isWalletPayment) {
      const already = await Booking.findById(bookingId).session(session);
      if (already && already.status === BOOKING_STATUS.CONFIRMED && String(already.userRef) === String(req.user._id)) {
        const paidTxn = await Transaction.findOne({ bookingId: already._id, paymentId }).session(session).lean();
        if (paidTxn) {
          await session.abortTransaction();
          session.endSession();
          return res.status(200).json({
            success:    true,
            bookingId:  already._id,
            checkInOtp: safeDecryptOtp(already.checkInOtpEncrypted),
            message:    "Booking already confirmed for this payment",
            alreadyConfirmed: true,
            serviceAmountInPaise:    already.serviceAmountInPaise,
            commissionAmountInPaise: already.commissionAmountInPaise,
            totalAmountInPaise:      already.totalAmountInPaise,
          });
        }
      }
    }

    const { booking, otp, amount } = await runBookingConfirmationCore({
      session,
      bookingId,
      actorUserId: req.user._id,
      paymentMethod,
      paymentId,
      orderId,
      gatewayCheckBypassed,
    });

    //////////////////////////////////////////////////////////
    // ✅ COMMIT
    //////////////////////////////////////////////////////////

    await session.commitTransaction();
    session.endSession();

    await runBookingConfirmedEffects({ req, booking, amount });

    return res.status(200).json({
      success:    true,
      bookingId:  booking._id,
      checkInOtp: otp,
      message:    "Booking confirmed successfully",
      serviceAmountInPaise:    booking.serviceAmountInPaise,
      commissionAmountInPaise: booking.commissionAmountInPaise,
      totalAmountInPaise:      booking.totalAmountInPaise,
    });

  } catch (error) {
    // Guarded: post-commit code (cache/socket/notification) runs
    // inside this same try block. If it throws AFTER a successful
    // commit, session.inTransaction() is already false, and calling
    // abortTransaction() unconditionally would itself throw
    // ("Cannot call abortTransaction after calling commitTransaction"),
    // masking the real error. Only abort a still-open transaction.
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    // Genuine concurrent-write collision (see comment above the
    // retry loop) — retry the whole attempt on a fresh session
    // rather than surface it. Every other error (not found,
    // unauthorized, invalid state, payment/wallet failures, etc.)
    // falls through unchanged to the existing response below.
    const isTransientConflict =
      typeof error.hasErrorLabel === "function" &&
      error.hasErrorLabel("TransientTransactionError");

    if (isTransientConflict && attempt < MAX_ATTEMPTS) {
      continue;
    }

    if (isTransientConflict) {
      // Exhausted retries on a genuine conflict (rare — would need
      // 3 consecutive collisions). Still not a raw driver error to
      // the client: a clean, retryable 409 the client's own retry
      // (same Idempotency-Key) can safely resolve.
      console.error("confirmBooking error (transient conflict, retries exhausted):", error);
      return res.status(409).json({
        success: false,
        message: "This booking is being updated. Please try again in a moment.",
      });
    }

    // validateBookingTransition (utils/bookingState.machine.js) throws
    // a bare Error (no .status) for "current === next" instead of
    // returning false — the `if (!validateBookingTransition(...))`
    // guard above it is therefore unreachable for this exact case.
    // Surfaces here specifically because a retried attempt (after the
    // concurrency conflict above) legitimately re-validates against
    // the booking's now-current status and finds it's already
    // CONFIRMED. Reworded to match checkBookingState middleware's
    // existing "Invalid booking state: <STATUS>" shape
    // (bookingState.middleware.js:19-22) — same pattern already
    // applied in cancelBooking for the identical underlying issue.
    if (error.message?.startsWith("Booking already in state:")) {
      const status = error.message.replace("Booking already in state: ", "");
      return res.status(400).json({
        success: false,
        message: `Invalid booking state: ${status}`,
      });
    }

    console.error("confirmBooking error:", error);
    return res.status(error.statusCode || error.status || 500).json({
      success: false,
      message: error.message || "Booking confirmation failed",
    });
    }
  }
};

//////////////////////////////////////////////////////////////
// 🚀 3. CHECK-IN
//////////////////////////////////////////////////////////////

export const checkInBooking = async (req, res) => {
  try {
    const { bookingId, otp } = req.body;

    if (!otp) {
      return res.status(400).json({
        success: false,
        message: "OTP is required",
      });
    }

    // OPTION-A: bookingId + otp both verified.
    //
    // Security improvement over OTP-only lookup:
    //   Without bookingId → attacker brute-forces 9000 OTP
    //     combinations across ALL CONFIRMED bookings.
    //   With bookingId → attacker must know the specific booking
    //     AND its OTP — two independent secrets required.
    //
    // Also tighter DB query: { _id, checkInOtp, status }
    // uses the _id index directly instead of scanning all
    // CONFIRMED bookings by OTP hash.
    const hashedOtp = hashOtp(otp);

    const booking = await Booking.findOne({
      _id:        bookingId,
      checkInOtp: hashedOtp,
      status:     BOOKING_STATUS.CONFIRMED,
    });

    if (!booking) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP or booking ID",
      });
    }

    //////////////////////////////////////////////////////////
    // ⏳ OTP EXPIRY CHECK
    //
    // checkInOtpExpiresAt is set to (startTime + 2 hours) in
    // confirmBooking(). If the customer tries to check in after
    // that window — e.g. a very late walk-in with a saved OTP —
    // reject before touching any state.
    //
    // Checked AFTER the findOne so we return "Invalid OTP" for
    // unknown OTPs and "OTP has expired" only for valid-but-stale
    // ones — avoids leaking which OTPs exist in the system.
    //////////////////////////////////////////////////////////

    if (
      booking.checkInOtpExpiresAt &&
      booking.checkInOtpExpiresAt < new Date()
    ) {
      return res.status(403).json({
        success: false,
        message: "OTP has expired. Please contact the salon to check in.",
      });
    }

    //////////////////////////////////////////////////////////
    // 🔁 STATE MACHINE VALIDATION
    //////////////////////////////////////////////////////////

    if (!validateBookingTransition(booking.status, BOOKING_STATUS.CHECKED_IN)) {
      return res.status(400).json({
        success: false,
        message: "Invalid state for check-in",
      });
    }

    //////////////////////////////////////////////////////////
    // ⏱ CHECK-IN TIME WINDOW (±30 minutes)
    //////////////////////////////////////////////////////////

    const now         = new Date();
    const diffMinutes = (now - booking.startTime) / (1000 * 60);

    if (diffMinutes < -30) {
      const opensAt    = new Date(booking.startTime.getTime() - 30 * 60 * 1000);
      const opensAtStr = opensAt.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", timeZone: "Asia/Kolkata" });
      return res.status(403).json({
        success: false,
        message: `Too early! Check-in opens at ${opensAtStr}`,
      });
    }

    if (diffMinutes > 30) {
      const bookingTimeStr = booking.startTime.toLocaleTimeString("en-IN", {
        hour: "2-digit", minute: "2-digit", timeZone: "Asia/Kolkata",
      });
      return res.status(403).json({
        success: false,
        message: `Check-in window closed. Booking was at ${bookingTimeStr}. Please contact the salon.`,
      });
    }

    //////////////////////////////////////////////////////////
    // ✅ TRANSITION TO CHECKED_IN — ATOMIC SESSION
    //
    // OTP fields are cleared on the in-memory document BEFORE
    // transitionBookingStatus() is called so that its internal
    // save persists the status change AND the OTP nullification
    // in one atomic write inside the same session.
    //////////////////////////////////////////////////////////

    const checkInSession = await mongoose.startSession();
    checkInSession.startTransaction();

    try {
      // Re-fetch inside the session immediately before mutating —
      // the OTP lookup above ran outside any session, so a
      // near-simultaneous retry (e.g. a mobile client resending
      // after a timeout) could have already checked this exact
      // booking in between. Re-verifying here turns that race into
      // a clean, expected rejection instead of a raw write conflict
      // surfacing as an unhandled error. Same defensive re-fetch
      // pattern already used by holdExpiry.job.js's expireOneBooking.
      const freshBooking = await Booking.findById(booking._id).session(checkInSession);

      if (!freshBooking || freshBooking.status !== BOOKING_STATUS.CONFIRMED) {
        throw Object.assign(
          new Error("This booking was already checked in or is no longer available"),
          { status: 409 }
        );
      }

      freshBooking.checkInOtp          = null;
      freshBooking.checkInOtpExpiresAt = null;

      // Clear delayed flag — customer did eventually arrive.
      // Without this, customerDelayedAt remains set even after
      // successful check-in, corrupting late-arrival analytics
      // (the booking would be counted as a delay even though the
      // customer showed up). Null here = "arrived within session".
      freshBooking.customerDelayedAt   = null;

      // Clear grace window — customer has arrived, the arrival
      // timer is no longer relevant. Without this, the
      // customerArrival.job.js worker may match stale grace windows
      // on CHECKED_IN bookings if the status index update and job
      // query race at the same second, emitting a spurious
      // booking:customerDelayed event for a customer already inside.
      freshBooking.arrivalGraceUntil   = null;

      await transitionBookingStatus({
        booking:    freshBooking,
        nextStatus: BOOKING_STATUS.CHECKED_IN,
        session:    checkInSession,
      });

      await checkInSession.commitTransaction();
      checkInSession.endSession();

    } catch (checkInError) {
      await checkInSession.abortTransaction();
      checkInSession.endSession();
      throw checkInError;
    }

    //////////////////////////////////////////////////////////
    // 📡 REALTIME — customer is in the salon
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:checkedIn",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   booking.chairRef,
        status:    BOOKING_STATUS.CHECKED_IN,
        checkedInAt: new Date(),
      },
    });

    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_CHECKED_IN,
      title:         "Checked In",
      message:       "You're checked in. The salon will start your service shortly.",
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    return res.status(200).json({
      success:   true,
      bookingId: booking._id,
      message:   "Check-in successful",
    });

  } catch (error) {
    console.error("checkInBooking error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Check-in failed",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 4. START SERVICE
//////////////////////////////////////////////////////////////

export const startService = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { bookingId } = req.body;

    //////////////////////////////////////////////////////////
    // 🔍 FETCH BOOKING (inside session)
    //////////////////////////////////////////////////////////

    const booking = await Booking.findById(bookingId).session(session);

    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    //////////////////////////////////////////////////////////
    // 🔐 SALON OWNERSHIP CHECK
    //////////////////////////////////////////////////////////

    await assertSalonOwnership(booking.salonRef, req.user._id, session);

    //////////////////////////////////////////////////////////
    // 🔁 MUST BE CHECKED_IN → ONGOING
    //////////////////////////////////////////////////////////

    if (!validateBookingTransition(booking.status, BOOKING_STATUS.ONGOING)) {
      throw Object.assign(
        new Error("Booking must be in CHECKED_IN state to start service"),
        { status: 400 }
      );
    }

    await transitionBookingStatus({
      booking,
      nextStatus: BOOKING_STATUS.ONGOING,
      session,
    });

    await session.commitTransaction();
    session.endSession();

    //////////////////////////////////////////////////////////
    // 📡 REALTIME — service timer starts on customer screen
    //         (after commit — socket never blocks finance path)
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:serviceStarted",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId:        booking._id,
        chairId:          booking.chairRef,
        status:           BOOKING_STATUS.ONGOING,
        serviceStartedAt: booking.serviceStartedAt,
      },
    });

    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.SERVICE_STARTED,
      title:         "Service Started",
      message:       "Your service has started. Sit back and relax!",
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    return res.status(200).json({
      success:          true,
      bookingId:        booking._id,
      serviceStartedAt: booking.serviceStartedAt,
      message:          "Service started",
    });

  } catch (error) {
    // Guarded: post-commit code (cache/socket/notification) runs
    // inside this same try block. If it throws AFTER a successful
    // commit, session.inTransaction() is already false, and calling
    // abortTransaction() unconditionally would itself throw
    // ("Cannot call abortTransaction after calling commitTransaction"),
    // masking the real error. Only abort a still-open transaction.
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error("startService error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Failed to start service",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 5. COMPLETE SERVICE — FULLY ATOMIC (mongoose session)
//////////////////////////////////////////////////////////////

export const completeService = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { bookingId } = req.body;

    //////////////////////////////////////////////////////////
    // 🔍 FETCH BOOKING (inside session)
    //////////////////////////////////////////////////////////

    const booking = await Booking.findById(bookingId).session(session);

    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    //////////////////////////////////////////////////////////
    // 🔐 SALON OWNERSHIP CHECK
    //////////////////////////////////////////////////////////

    await assertSalonOwnership(booking.salonRef, req.user._id, session);

    //////////////////////////////////////////////////////////
    // 🔁 STATE MACHINE VALIDATION
    //////////////////////////////////////////////////////////

    if (!validateBookingTransition(booking.status, BOOKING_STATUS.COMPLETED)) {
      throw Object.assign(
        new Error("Invalid state transition for service completion"),
        { status: 400 }
      );
    }

    //////////////////////////////////////////////////////////
    // ⏱ MINIMUM SERVICE TIME (1 minute)
    //////////////////////////////////////////////////////////

    const elapsedMinutes = (new Date() - booking.serviceStartedAt) / (1000 * 60);

    if (elapsedMinutes < 1) {
      throw Object.assign(
        new Error("Minimum service time has not been met"),
        { status: 403 }
      );
    }

    //////////////////////////////////////////////////////////
    // 💰 VERIFY PAYMENT TRANSACTION EXISTS
    //
    // FIX-3: completeService() must NOT create a new transaction.
    //
    // Industry-correct flow:
    //   confirmBooking()  → creates BOOKING transaction + credits wallet
    //   completeService() → verifies the transaction exists, transitions
    //                       status to COMPLETED, frees the chair
    //
    // Creating a second Transaction.create() here would:
    //   ❌ double-count revenue in SalonEarnings
    //   ❌ double-count commission in reporting
    //   ❌ create a phantom financial record
    //
    // The wallet was credited at payment time. Nothing to credit here.
    //////////////////////////////////////////////////////////

    const paymentTxn = await Transaction.findOne({
      bookingId: booking._id,
      type:      TRANSACTION_TYPE.BOOKING,
      status:    TRANSACTION_STATUS.PAID,
    }).session(session);

    if (!paymentTxn) {
      // Payment transaction missing — this booking was never properly
      // confirmed through the payment flow. Block completion.
      throw Object.assign(
        new Error("Payment record not found — booking cannot be completed"),
        { status: 409 }
      );
    }

    //////////////////////////////////////////////////////////
    // 💰 RELEASE PENDING → AVAILABLE
    // Service is genuinely done now — this is the moment the
    // salon earns the right to withdraw. Money sat in PENDING
    // since payment time; releasing it only here (not at payment
    // time) protects against paid-but-never-delivered scenarios.
    //////////////////////////////////////////////////////////

    await WalletBalanceService.releasePendingToAvailable({
      salonId:        booking.salonRef,
      amountInPaise:  paymentTxn.payoutAmount,
      refType:        "BOOKING",   // ← "Transaction" se badla
      refId:          paymentTxn._id,
      idempotencyKey: `booking:release:${booking._id}`,
      session,
      triggeredBy:    "SYSTEM",
      remarks:        "Service completed — funds released to available balance",
    });

    // Fetch current wallet balance for the response (read-only, no update)
    const currentWallet = await SalonEarnings.findOne({
      salonId: booking.salonRef,
    }).session(session);


    //////////////////////////////////////////////////////////
    // ✅ TRANSITION TO COMPLETED (inside session)
    //////////////////////////////////////////////////////////

    await transitionBookingStatus({ booking, nextStatus: BOOKING_STATUS.COMPLETED, session });

    //////////////////////////////////////////////////////////
    // 📈 SERVICE BOOKING COUNT
    //////////////////////////////////////////////////////////

    if (
      Array.isArray(booking.serviceRefs) &&
      booking.serviceRefs.length
    ) {
      await Service.updateMany(
        {
          _id: { $in: booking.serviceRefs }
        },
        {
          $inc: { bookingCount: 1 }
        },
        { session }
      );
    }

    //////////////////////////////////////////////////////////
    // ✅ COMMIT
    //////////////////////////////////////////////////////////

    await session.commitTransaction();
    session.endSession();

    //////////////////////////////////////////////////////////
    // 🗑️ CACHE INVALIDATION — next-slot label stale after completion
    //////////////////////////////////////////////////////////

    await invalidateNextSlotCache(
      booking.salonRef.toString(),
      booking.startTime.toISOString().split("T")[0]
    );

    //////////////////////////////////////////////////////////
    // 📬 NOTIFICATION (non-blocking, after commit)
    //////////////////////////////////////////////////////////

    await NotificationService.send({
      recipientId:   booking.salonRef,
      recipientType: "SALON",
      templateKey:   NOTIFICATION_EVENTS.SERVICE_COMPLETED_SALON,
      title:         "Service Completed ✅",
      message:       `Service completed. Chair is now free.`,
      type:          "BOOKING",
      priority:      "HIGH",
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    });

    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.SERVICE_COMPLETED_USER,
      title:         "Service Completed",
      message:       "Your service is complete. Thank you for booking with us!",
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    // Review-request — separate from SERVICE_COMPLETED_USER above (own
    // templateKey/title/message/actionType), sent at the same already-
    // guarded post-commit point. Eligibility for this exact booking is
    // guaranteed open right now (ratingEligibility.service.js requires
    // status===COMPLETED, which was only just reached), so no extra
    // eligibility call is needed here.
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.RATING_REQUEST_USER,
      title:         "How was your ZEMISH experience?",
      message:       "Your service is complete. Share your rating and review.",
      type:          "REVIEW",
      priority:      "MEDIUM",
      actionType:    "OPEN_REVIEW",
      actionUrl:     `/ratings/${booking._id}`,
      entityType:    "BOOKING",
      entityId:      booking._id,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);

    //////////////////////////////////////////////////////////
    // 📡 REALTIME — chair freed (after commit)
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:completed",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId:     booking._id,
        chairId:       booking.chairRef,
        status:        BOOKING_STATUS.COMPLETED,
        walletBalance: currentWallet?.availableBalanceInPaise ?? 0,
      },
    });

    return res.status(200).json({
      success:       true,
      bookingId:     booking._id,
      transactionId: paymentTxn._id,
      walletBalance: currentWallet?.availableBalanceInPaise ?? 0,
    });

  } catch (error) {
    // Guarded: post-commit code (cache/socket/notification) runs
    // inside this same try block. If it throws AFTER a successful
    // commit, session.inTransaction() is already false, and calling
    // abortTransaction() unconditionally would itself throw
    // ("Cannot call abortTransaction after calling commitTransaction"),
    // masking the real error. Only abort a still-open transaction.
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error("completeService error:", error);
    return res.status(error.statusCode || error.status || 500).json({
      success: false,
      message: error.message || "Service completion failed",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 6. CANCEL BOOKING — WITH REFUND/PENALTY LOGIC
//////////////////////////////////////////////////////////////

export const cancelBooking = async (req, res) => {
  // Bounded retry, MongoDB's own documented handling for
  // TransientTransactionError (WriteConflict, code 112): two
  // concurrent cancel requests for the same booking legitimately
  // both pass validation against the same pre-cancel snapshot, then
  // collide at the physical write — one transaction is correctly
  // aborted by the storage engine, not corrupted. Retrying lets the
  // loser re-read the now-updated document fresh; it then lands on
  // the *existing* "Invalid booking state: CANCELLED" 400 path
  // (validateBookingTransition below) instead of a raw 500 — no new
  // response shape, no frontend change needed for that case.
  const MAX_ATTEMPTS = 3;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
    const { bookingId } = req.body;

    const booking = await Booking.findById(bookingId).session(session);
    if (!booking) throw Object.assign(new Error("Booking not found"), { status: 404 });

    // USER OWNERSHIP CHECK
    if (booking.userRef.toString() !== req.user._id.toString()) {
      throw Object.assign(new Error("Unauthorized"), { status: 403 });
    }

    // STATE MACHINE VALIDATION
    if (!validateBookingTransition(booking.status, BOOKING_STATUS.CANCELLED)) {
      throw Object.assign(new Error("This booking cannot be cancelled"), { status: 400 });
    }

    //////////////////////////////////////////////////////////
    // 💰 REFUND CALCULATION
    // Based on how far before startTime cancellation happens.
    // Delegated to CancellationPolicyService — the single source of
    // truth for the cancellation refund FRACTION (pure calculation,
    // no side effects; unchanged by the PAN-India Platform Fee + GST
    // architecture). The same fraction is then applied to every
    // refund-eligible component (service, Platform Fee, GST) via the
    // shared splitRefundComponents() helper — the exact same helper
    // ownerCancelBooking and RefundExecutionService use, so all three
    // refund paths can never drift apart.
    //////////////////////////////////////////////////////////

    const now = new Date();

    const { refundPolicy, refundFraction } = CancellationPolicyService.evaluate({ booking, now });

    const {
      serviceRefundPaise,
      commissionRefundPaise,
      gstRefundPaise,
      totalRefundPaise: refundPaise,
    } = splitRefundComponents({
      refundFraction,
      serviceAmountInPaise: booking.serviceAmountInPaise,
      commissionAmountInPaise: booking.commissionAmountInPaise,
      gstAmountInPaise: booking.gstAmountInPaise,
    });

    //////////////////////////////////////////////////////////
    // 💰 WALLET ADJUSTMENT — deduct refund from salon wallet
    // Salon wallet was credited (serviceAmountInPaise, full amount)
    // at confirmBooking time. On refund, only the service-amount
    // portion is deducted from the salon — commission was never the
    // salon's money to begin with, so it's untouched here.
    //////////////////////////////////////////////////////////
    if (refundPaise > 0 && booking.status === BOOKING_STATUS.CONFIRMED) {
      // Salon only ever gets refunded FOR the service-amount portion
      // — commission was never the salon's money, so it's never
      // deducted from the salon's balance. serviceRefundPaise is
      // exactly what the salon's PENDING balance shrinks by — this
      // booking's payment was credited to PENDING at confirmBooking
      // time (via WalletBalanceService.creditPending) and hasn't
      // been released to AVAILABLE yet, so the claw-back must debit
      // PENDING via WalletBalanceService, not a raw SalonEarnings
      // write (WalletBalanceService is the only file allowed to
      // write to SalonEarnings' *InPaise fields — see its header).
      if (serviceRefundPaise > 0) {
        await WalletBalanceService.debitPending({
          salonId:        booking.salonRef,
          amountInPaise:  serviceRefundPaise,
          action:         "REFUND",
          refType:        "BOOKING",
          refId:          booking._id,
          idempotencyKey: `booking:refund:${booking._id}`,
          session,
          triggeredBy:    "SYSTEM",
          remarks:        "Booking cancelled — refund claws back salon's pending balance",
        });
      }

      //////////////////////////////////////////////////////////
      // 💰 CREDIT REFUND TO USER'S WALLET
      // refundPaise = serviceRefundPaise + commissionRefundPaise —
      // the user gets back their full share of both the service
      // amount AND the commission they paid, proportional to the
      // refund policy. The salon only loses serviceRefundPaise
      // (deducted above); commissionRefundPaise was always the
      // platform's money, never the salon's, so it doesn't touch
      // SalonEarnings at all. Idempotency key ties this to the
      // booking so a retried/duplicate cancelBooking call can never
      // double-credit the same refund.
      //////////////////////////////////////////////////////////

      const userBefore = await User.findOne({ _id: booking.userRef, isDeleted: false })
        .select("walletBalance")
        .session(session);

      const refundRupees = refundPaise / 100;
      const balanceBeforeInPaise = Math.round((userBefore?.walletBalance || 0) * 100);

      const updatedUser = await User.findOneAndUpdate(
        { _id: booking.userRef, isDeleted: false },
        { $inc: { walletBalance: refundRupees } },
        { new: true, session }
      ).select("walletBalance");

      await WalletTransaction.create(
        [{
          userId:        booking.userRef,
          bookingId:     booking._id,
          direction:     WALLET_TXN_DIRECTION.CREDIT,
          type:          WALLET_TXN_TYPE.REFUND,
          status:        WALLET_TXN_STATUS.SUCCESS,
          source:        WALLET_TXN_SOURCE.BOOKING,
          amountInPaise: refundPaise,
          requestId:     `refund:${booking._id}`,
          balanceBeforeInPaise,
          balanceAfterInPaise: Math.round((updatedUser?.walletBalance || 0) * 100),
          metadata:      { refundPolicy, bookingId: booking._id.toString(), serviceRefundPaise, commissionRefundPaise, gstRefundPaise },
        }],
        { session }
      );
    }

    // Store cancellation details on booking
    booking.cancellationPolicy  = refundPolicy;
    booking.refundAmountInPaise = refundPaise;
    booking.cancelledAt         = now;

    await transitionBookingStatus({
      booking,
      nextStatus: BOOKING_STATUS.CANCELLED,
      session,
    });

    await session.commitTransaction();
    session.endSession();

    //////////////////////////////////////////////////////////
    // 🗑️ CACHE INVALIDATION — next-slot label stale after cancellation
    //////////////////////////////////////////////////////////

    await invalidateNextSlotCache(
      booking.salonRef.toString(),
      booking.startTime.toISOString().split("T")[0]
    );
    emitBookingEvent(req, {
      event:   "booking:cancelled",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   booking.chairRef,
        startTime: booking.startTime,
        endTime:   booking.endTime,
        status:    BOOKING_STATUS.CANCELLED,
      },
    });

    const refundMsg = refundPaise > 0
      ? ` ₹${Math.round(refundPaise / 100)} has been refunded to your wallet.`
      : "";
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_CANCELLED,
      variables:     { refundMessage: refundMsg },
      title:         "Booking Cancelled",
      message:       `Your booking has been cancelled.${refundMsg}`,
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK"), refundAmountInPaise: refundPaise },
    });

    return res.status(200).json({
      success:            true,
      bookingId:          booking._id,
      refundPolicy,
      refundAmountInPaise: refundPaise,
      refundAmountRupees:  Math.round(refundPaise / 100),
      message:            "Booking cancelled successfully",
    });

    } catch (error) {
    // Guarded: post-commit code (cache/socket/notification) runs
    // inside this same try block. If it throws AFTER a successful
    // commit, session.inTransaction() is already false, and calling
    // abortTransaction() unconditionally would itself throw
    // ("Cannot call abortTransaction after calling commitTransaction"),
    // masking the real error. Only abort a still-open transaction.
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    // Genuine concurrent-write collision (see comment above the
    // retry loop) — retry the whole attempt on a fresh session
    // rather than surface it. Every other error (not found,
    // unauthorized, invalid state, wallet/ledger failures, etc.)
    // falls through unchanged to the existing response below.
    const isTransientConflict =
      typeof error.hasErrorLabel === "function" &&
      error.hasErrorLabel("TransientTransactionError");

    if (isTransientConflict && attempt < MAX_ATTEMPTS) {
      continue;
    }

    if (isTransientConflict) {
      // Exhausted retries on a genuine conflict (rare — would need
      // 3 consecutive collisions). Still not a raw driver error to
      // the client: a clean, retryable 409 the client's own retry
      // (same Idempotency-Key) can safely resolve.
      console.error("cancelBooking error (transient conflict, retries exhausted):", error);
      return res.status(409).json({
        success: false,
        message: "This booking is being updated. Please try again in a moment.",
      });
    }

    // validateBookingTransition (utils/bookingState.machine.js) throws
    // a bare Error (no .status) for "current === next" instead of
    // returning false — the `if (!validateBookingTransition(...))`
    // guard above it is therefore unreachable for this exact case.
    // Surfaces here specifically because a retried attempt (after
    // the concurrency conflict above) legitimately re-validates
    // against the booking's now-current status and finds it's
    // already CANCELLED. Reworded to match checkBookingState
    // middleware's existing "Invalid booking state: <STATUS>" shape
    // (bookingState.middleware.js:19-22) — same message format
    // whether this rejection comes from the middleware (a fresh,
    // sequential duplicate request) or from here (a retried one),
    // so the client's existing handling for that exact string covers
    // both without needing to know which path produced it.
    if (error.message?.startsWith("Booking already in state:")) {
      const status = error.message.replace("Booking already in state: ", "");
      return res.status(400).json({
        success: false,
        message: `Invalid booking state: ${status}`,
      });
    }

    console.error("cancelBooking error:", error);
    return res.status(error.statusCode || error.status || 500).json({
      success: false,
      message: error.message || "Failed to cancel booking",
    });
    }
  }
};

//////////////////////////////////////////////////////////////
// 🚀 6B. OWNER CANCEL BOOKING — FA-15
//
// Separate, standalone controller — NOT a refactor of cancelBooking
// above, which stays byte-for-byte unchanged. Reuses the exact same
// transactional retry pattern, the exact same CancellationPolicyService
// (no new/changed refund percentages, timing thresholds, GST or
// convenience-fee treatment), the exact same wallet/notification/
// socket/cache side effects. The ONLY difference from cancelBooking
// is the authorization check: an Owner is verified against
// booking.salonRef (via their own Salon document) instead of
// booking.userRef. Owner identity/salon ownership is always
// server-derived — never accepted from the client.
//////////////////////////////////////////////////////////////

export const ownerCancelBooking = async (req, res) => {
  // Same bounded-retry rationale as cancelBooking above: two
  // concurrent cancel attempts for the same booking can legitimately
  // collide at the physical write (TransientTransactionError); the
  // loser retries on a fresh session and lands on the normal
  // "Invalid booking state: CANCELLED" 400 path.
  const MAX_ATTEMPTS = 3;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
    const { bookingId, reason } = req.body;

    const booking = await Booking.findById(bookingId).session(session);
    if (!booking) throw Object.assign(new Error("Booking not found"), { status: 404 });

    // OWNER OWNERSHIP CHECK — scoped directly to the booking's own
    // authoritative salonRef, not resolved separately via an unscoped
    // Salon.findOne({ ownerId }). The previous two-step version
    // (findOne({ownerId}) then compare booking.salonRef against
    // whichever salon that returned) broke for an owner with 2+
    // approved salons: Mongoose has no implicit sort, so findOne could
    // return the owner's OTHER salon, wrongly failing the comparison
    // and 403'ing an owner trying to cancel their own booking — a
    // false-negative, not a cross-owner leak, since ownerId was always
    // scoped to the real caller. Confirmed by a reproducing regression
    // test (scripts/e2e/verifyMultiSalonBookingNotificationIsolation.mjs)
    // before this fix, and by the same test asserting success after it.
    //
    // No AMBIGUOUS_SALON/resolveSensitiveOwnerSalon needed here (unlike
    // getSalonBookings/getLiveSchedule/device-token/notification): those
    // endpoints must guess a salon from ownerId alone with no other
    // signal. Here booking.salonRef already names the exact salon, so
    // baking both _id and ownerId into one query removes the ambiguity
    // outright — smaller and more precise than the ambiguity-resolution
    // pattern, not a reuse of it. isDeleted: false matches this
    // codebase's existing soft-delete convention for salon-ownership
    // checks (Salon.isDeleted, used identically in
    // resolveSensitiveOwnerSalon above and in deviceToken/notification
    // controllers) — a salon soft-deleted out from under an owner is no
    // more actionable here than it is for those endpoints.
    const salon = await Salon.findOne({
      _id:       booking.salonRef,
      ownerId:   req.user._id,
      isDeleted: false,
    }).session(session).select("_id");
    if (!salon) throw Object.assign(new Error("Unauthorized"), { status: 403 });

    // STATE MACHINE VALIDATION — identical call, same central rules.
    if (!validateBookingTransition(booking.status, BOOKING_STATUS.CANCELLED)) {
      throw Object.assign(new Error("This booking cannot be cancelled"), { status: 400 });
    }

    //////////////////////////////////////////////////////////
    // 💰 REFUND CALCULATION — identical to cancelBooking, including
    // the shared splitRefundComponents() helper (service/Platform Fee/
    // GST). CancellationPolicyService is the single source of truth
    // for the refund fraction regardless of who initiates the
    // cancellation; this introduces no owner-specific percentage,
    // fee, or penalty.
    //////////////////////////////////////////////////////////

    const now = new Date();

    const { refundPolicy, refundFraction } = CancellationPolicyService.evaluate({ booking, now });

    const {
      serviceRefundPaise,
      commissionRefundPaise,
      gstRefundPaise,
      totalRefundPaise: refundPaise,
    } = splitRefundComponents({
      refundFraction,
      serviceAmountInPaise: booking.serviceAmountInPaise,
      commissionAmountInPaise: booking.commissionAmountInPaise,
      gstAmountInPaise: booking.gstAmountInPaise,
    });

    // 💰 WALLET ADJUSTMENT — identical to cancelBooking (see its
    // comments above for the full rationale: only the service-amount
    // portion is clawed back from the salon's PENDING balance;
    // commission was never the salon's money).
    if (refundPaise > 0 && booking.status === BOOKING_STATUS.CONFIRMED) {
      if (serviceRefundPaise > 0) {
        await WalletBalanceService.debitPending({
          salonId:        booking.salonRef,
          amountInPaise:  serviceRefundPaise,
          action:         "REFUND",
          refType:        "BOOKING",
          refId:          booking._id,
          idempotencyKey: `booking:refund:${booking._id}`,
          session,
          triggeredBy:    "SYSTEM",
          remarks:        "Booking cancelled by salon — refund claws back salon's pending balance",
        });
      }

      const userBefore = await User.findOne({ _id: booking.userRef, isDeleted: false })
        .select("walletBalance")
        .session(session);

      const refundRupees = refundPaise / 100;
      const balanceBeforeInPaise = Math.round((userBefore?.walletBalance || 0) * 100);

      const updatedUser = await User.findOneAndUpdate(
        { _id: booking.userRef, isDeleted: false },
        { $inc: { walletBalance: refundRupees } },
        { new: true, session }
      ).select("walletBalance");

      await WalletTransaction.create(
        [{
          userId:        booking.userRef,
          bookingId:     booking._id,
          direction:     WALLET_TXN_DIRECTION.CREDIT,
          type:          WALLET_TXN_TYPE.REFUND,
          status:        WALLET_TXN_STATUS.SUCCESS,
          source:        WALLET_TXN_SOURCE.BOOKING,
          amountInPaise: refundPaise,
          requestId:     `refund:${booking._id}`,
          balanceBeforeInPaise,
          balanceAfterInPaise: Math.round((updatedUser?.walletBalance || 0) * 100),
          metadata:      { refundPolicy, bookingId: booking._id.toString(), serviceRefundPaise, commissionRefundPaise, gstRefundPaise },
        }],
        { session }
      );
    }

    // Store cancellation + audit details on booking. cancelledBy/
    // cancelReason already exist on the schema (declared, previously
    // unpopulated by either cancellation path) — populated here for
    // the first time, additive only, no schema change.
    booking.cancellationPolicy  = refundPolicy;
    booking.refundAmountInPaise = refundPaise;
    booking.cancelledAt         = now;
    booking.cancelledBy         = req.user._id;
    if (reason) booking.cancelReason = reason;

    await transitionBookingStatus({
      booking,
      nextStatus: BOOKING_STATUS.CANCELLED,
      actor:      req.user._id,
      session,
    });

    // Tag this transition's audit entry with the actor's role — reuses
    // statusHistory's existing Mixed `meta` field, no parallel audit
    // system. transitionBookingStatus doesn't accept a meta param, so
    // it's set directly on the just-pushed history entry before save.
    const lastHistoryEntry = booking.statusHistory[booking.statusHistory.length - 1];
    if (lastHistoryEntry) {
      lastHistoryEntry.meta = { ...(lastHistoryEntry.meta || {}), performedByRole: "OWNER" };
      // meta is a Mixed field inside an array subdocument — Mongoose
      // does not reliably auto-detect a plain property assignment on
      // Mixed, so markModified is required for this second save to
      // actually persist it (isModified("status") is false here, so
      // the pre-save hook itself won't push a duplicate entry).
      booking.markModified("statusHistory");
      await booking.save({ session });
    }

    await session.commitTransaction();
    session.endSession();

    //////////////////////////////////////////////////////////
    // 🗑️ CACHE INVALIDATION — identical to cancelBooking.
    //////////////////////////////////////////////////////////

    await invalidateNextSlotCache(
      booking.salonRef.toString(),
      booking.startTime.toISOString().split("T")[0]
    );
    emitBookingEvent(req, {
      event:   "booking:cancelled",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   booking.chairRef,
        startTime: booking.startTime,
        endTime:   booking.endTime,
        status:    BOOKING_STATUS.CANCELLED,
      },
    });

    const refundMsg = refundPaise > 0
      ? ` ₹${Math.round(refundPaise / 100)} has been refunded to your wallet.`
      : "";
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_CANCELLED,
      variables:     { refundMessage: refundMsg },
      title:         "Booking Cancelled",
      message:       `Your booking has been cancelled by the salon.${refundMsg}`,
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK"), refundAmountInPaise: refundPaise },
    });

    return res.status(200).json({
      success:            true,
      bookingId:          booking._id,
      refundPolicy,
      refundAmountInPaise: refundPaise,
      refundAmountRupees:  Math.round(refundPaise / 100),
      message:            "Booking cancelled successfully",
    });

    } catch (error) {
    // Guarded exactly like cancelBooking — only abort a still-open
    // transaction (post-commit code can throw without this becoming
    // a masking double-abort error).
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    const isTransientConflict =
      typeof error.hasErrorLabel === "function" &&
      error.hasErrorLabel("TransientTransactionError");

    if (isTransientConflict && attempt < MAX_ATTEMPTS) {
      continue;
    }

    if (isTransientConflict) {
      console.error("ownerCancelBooking error (transient conflict, retries exhausted):", error);
      return res.status(409).json({
        success: false,
        message: "This booking is being updated. Please try again in a moment.",
      });
    }

    if (error.message?.startsWith("Booking already in state:")) {
      const status = error.message.replace("Booking already in state: ", "");
      return res.status(400).json({
        success: false,
        message: `Invalid booking state: ${status}`,
      });
    }

    console.error("ownerCancelBooking error:", error);
    return res.status(error.statusCode || error.status || 500).json({
      success: false,
      message: error.message || "Failed to cancel booking",
    });
    }
  }
};


//////////////////////////////////////////////////////////////
// 🚀 7. MARK NO-SHOW
//////////////////////////////////////////////////////////////

export const markNoShow = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { bookingId } = req.body;

    //////////////////////////////////////////////////////////
    // 🔍 FETCH BOOKING (inside session)
    //////////////////////////////////////////////////////////

    const booking = await Booking.findById(bookingId).session(session);

    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    //////////////////////////////////////////////////////////
    // 🔐 SALON OWNERSHIP CHECK
    //////////////////////////////////////////////////////////

    await assertSalonOwnership(booking.salonRef, req.user._id, session);

    //////////////////////////////////////////////////////////
    // 🔁 STATE MACHINE VALIDATION
    //////////////////////////////////////////////////////////

    // CHECKED_IN intentionally excluded — bookingState.machine.js's
    // BOOKING_TRANSITIONS never allowed CHECKED_IN -> NO_SHOW, so this
    // path always failed downstream anyway. Narrowed to match reality.
    if (booking.status !== BOOKING_STATUS.CONFIRMED) {
      throw Object.assign(
        new Error("Only CONFIRMED bookings can be marked as no-show"),
        { status: 400 }
      );
    }

    await transitionBookingStatus({
      booking,
      nextStatus: BOOKING_STATUS.NO_SHOW,
      session,
    });

    await session.commitTransaction();
    session.endSession();

    //////////////////////////////////////////////////////////
    // 📡 REALTIME — chair freed immediately
    //         (after commit — socket never blocks the write)
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:noShow",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   booking.chairRef,
        startTime: booking.startTime,
        endTime:   booking.endTime,
        status:    BOOKING_STATUS.NO_SHOW,
      },
    });

    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_NO_SHOW,
      title:         "Marked as No-Show",
      message:       "You were marked as a no-show for your booking. Contact the salon if this is a mistake.",
      type:          "BOOKING",
      priority:      "HIGH",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    });

    return res.status(200).json({
      success: true,
      message: "Marked as no-show. Chair is now free.",
    });

  } catch (error) {
    // Guarded: post-commit code (cache/socket/notification) runs
    // inside this same try block. If it throws AFTER a successful
    // commit, session.inTransaction() is already false, and calling
    // abortTransaction() unconditionally would itself throw
    // ("Cannot call abortTransaction after calling commitTransaction"),
    // masking the real error. Only abort a still-open transaction.
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error("markNoShow error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Failed to mark no-show",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 8. GET MY BOOKINGS (ALL — paginated)
//////////////////////////////////////////////////////////////

export const getMyBookings = async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.user?._id)) {
      return res.status(401).json({
        success: false,
        message: "Invalid session",
      });
    }

    const userId             = req.user._id;
    const { page, limit, skip } = getPagination(req.query);

    const filter = {
      userRef:   userId,
      isDeleted: false,
    };

    const [bookings, total] = await Promise.all([
      Booking.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate(USER_BOOKING_POPULATE)
        .lean(),
      Booking.countDocuments(filter),
    ]);

    const bookingsWithOtp = bookings.map(b => ({
      ...b,
      checkInOtp: safeDecryptOtp(b.checkInOtpEncrypted),
      checkInOtpEncrypted: undefined,
      friendlyBookingId: toFriendlyId(b._id, "BK"),
    }));

    return res.status(200).json({
      success:  true,
      bookings: bookingsWithOtp,
      pagination: {
        page,
        limit,
        total,
        pages:   Math.ceil(total / limit),
        hasMore: page * limit < total,
      },
    });

  } catch (error) {
    console.error("getMyBookings error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch bookings",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 9. GET UPCOMING BOOKINGS
//////////////////////////////////////////////////////////////

export const getUpcomingBookings = async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.user?._id)) {
      return res.status(401).json({
        success: false,
        message: "Invalid session",
      });
    }

    const userId   = req.user._id;

    const bookings = await Booking.find({
      userRef:   userId,
      isDeleted: false,
      // HOLD deliberately excluded — a HOLD booking has no payment
      // yet (Razorpay or wallet). Showing it as "upcoming" makes an
      // unpaid, un-confirmed slot look like a real booking to the
      // user. HOLD bookings auto-expire via the HoldExpiryJob if the
      // user never completes payment — they should be invisible
      // here until confirmBooking() actually transitions them.
      status: {
        $in: [
          BOOKING_STATUS.CONFIRMED,
          BOOKING_STATUS.CHECKED_IN,
        ],
      },
      startTime: { $gte: new Date() },
    })
      .sort({ startTime: 1 })
      .limit(20)
      .populate(USER_BOOKING_POPULATE)
      .lean();

    const bookingsWithOtp = bookings.map(b => ({
      ...b,
      checkInOtp: safeDecryptOtp(b.checkInOtpEncrypted),
      checkInOtpEncrypted: undefined,
      friendlyBookingId: toFriendlyId(b._id, "BK"),
    }));

    return res.status(200).json({
      success:  true,
      bookings: bookingsWithOtp,
    });

  } catch (error) {
    console.error("getUpcomingBookings error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch upcoming bookings",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 10. GET COMPLETED BOOKINGS (paginated)
//////////////////////////////////////////////////////////////

export const getCompletedBookings = async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.user?._id)) {
      return res.status(401).json({
        success: false,
        message: "Invalid session",
      });
    }

    const userId             = req.user._id;
    const { page, limit, skip } = getPagination(req.query);

    const filter = {
      userRef:   userId,
      isDeleted: false,
      status:    BOOKING_STATUS.COMPLETED,
    };

    const [bookings, total] = await Promise.all([
      Booking.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate(USER_BOOKING_POPULATE)
        .lean(),
      Booking.countDocuments(filter),
    ]);

    const bookingsWithFriendlyId = bookings.map(b => ({
      ...b,
      friendlyBookingId: toFriendlyId(b._id, "BK"),
    }));

    return res.status(200).json({
      success: true,
      bookings: bookingsWithFriendlyId,
      pagination: {
        page,
        limit,
        total,
        pages:   Math.ceil(total / limit),
        hasMore: page * limit < total,
      },
    });

  } catch (error) {
    console.error("getCompletedBookings error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch completed bookings",
    });
  }
};

//////////////////////////////////////////////////////////////
// MULTI-SALON BOOKING/SCHEDULE VISIBILITY — explicit salonId
//
// Resolves which salon a SENSITIVE, booking-scoped read targets.
// Unlike the onboarding wizard's resolver (safe to fall back to
// {ownerId} unconditionally — onboarding only ever touches a DRAFT),
// this must never silently guess among multiple real salons:
//   - salonId supplied: must belong to this owner and not be deleted
//     (ownership baked into the query itself). Invalid/foreign id ->
//     null, surfaced by every call site as the same generic 404 —
//     never discloses whose salon it actually is.
//   - salonId absent: safe ONLY when the owner has exactly one real,
//     bookable (APPROVED — utils/salonReady.guard.js confirms only
//     APPROVED salons can ever have a real booking, so DRAFT/PENDING/
//     REJECTED salons are correctly excluded from this count, not
//     just "non-deleted") salon. Two or more real salons -> AMBIGUOUS,
//     fails closed with a distinct error instead of guessing — this
//     is the exact fix for the confirmed booking-visibility bug
//     (Salon.findOne({ownerId}) could silently resolve to the wrong
//     one of the owner's salons).
//////////////////////////////////////////////////////////////

const resolveSensitiveOwnerSalon = async ({ ownerId, salonId }) => {
  if (salonId) {
    if (!mongoose.Types.ObjectId.isValid(salonId)) return { error: "NOT_FOUND" };
    const salon = await Salon.findOne({ _id: salonId, ownerId, isDeleted: false }).select("_id").lean();
    return salon ? { salon } : { error: "NOT_FOUND" };
  }
  const candidates = await Salon.find({
    ownerId,
    isDeleted: false,
    "approval.status": "APPROVED",
  }).select("_id").limit(2).lean();
  if (candidates.length === 0) return { error: "NOT_FOUND" };
  if (candidates.length > 1) return { error: "AMBIGUOUS" };
  return { salon: candidates[0] };
};

const salonResolutionErrorResponse = (res, error) => {
  if (error === "AMBIGUOUS") {
    return res.status(409).json({
      success: false,
      code: "AMBIGUOUS_SALON",
      message: "You own more than one salon. Specify salonId to select which one.",
    });
  }
  return res.status(404).json({ success: false, message: "Salon not found" });
};

//////////////////////////////////////////////////////////////
// 🚀 11. GET SALON BOOKINGS (OWNER VIEW — paginated)
//////////////////////////////////////////////////////////////

export const getSalonBookings = async (req, res) => {
  try {
    const ownerId            = req.user._id;
    const { status, salonId } = req.query;
    const { page, limit, skip } = getPagination(req.query);

    const { salon, error } = await resolveSensitiveOwnerSalon({ ownerId, salonId });

    if (error) {
      return salonResolutionErrorResponse(res, error);
    }

    const filter = { salonRef: salon._id };
    if (status) filter.status = status;

    const [bookings, total] = await Promise.all([
      Booking.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate("userRef",     "name phone")
        .populate("serviceRefs", "name price duration")
        .populate("chairRef",    "name")
        .lean(),
      Booking.countDocuments(filter),
    ]);

    return res.status(200).json({
      success: true,
      bookings,
      pagination: {
        page,
        limit,
        total,
        pages:   Math.ceil(total / limit),
        hasMore: page * limit < total,
      },
    });

  } catch (error) {
    console.error("getSalonBookings error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch salon bookings",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 12. FORCE COMPLETE (Already Served — barber forgot)
// CHECKED_IN → COMPLETED directly
// body: { bookingId, actualDurationMinutes }
//////////////////////////////////////////////////////////////

export const forceComplete = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const { bookingId, actualDurationMinutes } = req.body;
    const booking = await Booking.findById(bookingId).session(session);
    if (!booking) throw Object.assign(new Error("Booking not found"), { status: 404 });
    await assertSalonOwnership(booking.salonRef, req.user._id, session);
    if (booking.status !== BOOKING_STATUS.CHECKED_IN) {
      throw Object.assign(new Error("Only CHECKED_IN bookings can be force completed"), { status: 400 });
    }
    const paymentTxn = await Transaction.findOne({
      bookingId: booking._id,
      type:      TRANSACTION_TYPE.BOOKING,
      status:    TRANSACTION_STATUS.PAID,
    }).session(session);
    if (!paymentTxn) throw Object.assign(new Error("Payment record not found"), { status: 409 });
    await WalletBalanceService.releasePendingToAvailable({
      salonId:        booking.salonRef,
      amountInPaise:  paymentTxn.payoutAmount,
      refType:        "BOOKING",   // ← "Transaction" se badla
      refId:          paymentTxn._id,
      idempotencyKey: `booking:release:${booking._id}`,
      session,
      triggeredBy:    "SYSTEM",
      remarks:        "Service force-completed — funds released to available balance",
    });
    const now = new Date();
    // actualDurationMinutes has no route-level validation on this
    // endpoint (bookingSchemas.forceComplete's Joi schema exists but
    // isn't wired to this route in booking.routes.js) — a bare
    // `|| 30` fallback only catches falsy input, not a wrong-typed
    // one (e.g. a string, which `"abc" * 60000` turns into NaN).
    // Defensively parse and clamp to the same 5-300 minute range
    // that schema already documents as the intended bound.
    const parsedDuration  = Number(actualDurationMinutes);
    const durationMinutes = (Number.isFinite(parsedDuration) && parsedDuration >= 5 && parsedDuration <= 300)
      ? parsedDuration
      : 30;
    const durationMs = durationMinutes * 60 * 1000;
    booking.serviceStartedAt = new Date(now.getTime() - durationMs);
    booking.status           = BOOKING_STATUS.COMPLETED;
    booking.completedAt      = now;
    booking.statusChangedAt  = now;
    booking.forceCompleted   = true;
    await booking.save({ session });
    const currentWallet = await SalonEarnings.findOne({ salonId: booking.salonRef }).session(session);
    await session.commitTransaction();
    session.endSession();
    await invalidateNextSlotCache(
      booking.salonRef.toString(),
      booking.startTime.toISOString().split("T")[0]
    );
    emitBookingEvent(req, {
      event:   "booking:completed",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: { bookingId: booking._id, chairId: booking.chairRef, status: BOOKING_STATUS.COMPLETED, walletBalance: currentWallet?.availableBalanceInPaise ?? 0 },
    });
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.SERVICE_COMPLETED_USER,
      title:         "Service Completed",
      message:       "Your service is complete. Thank you for booking with us!",
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);
    // Review-request — same rationale as completeService()'s identical
    // addition: separate event, same already-guarded post-commit point,
    // eligibility guaranteed open (booking just reached COMPLETED).
    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.RATING_REQUEST_USER,
      title:         "How was your ZEMISH experience?",
      message:       "Your service is complete. Share your rating and review.",
      type:          "REVIEW",
      priority:      "MEDIUM",
      actionType:    "OPEN_REVIEW",
      actionUrl:     `/ratings/${booking._id}`,
      entityType:    "BOOKING",
      entityId:      booking._id,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    }, [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.PUSH]);
    return res.status(200).json({ success: true, bookingId: booking._id, transactionId: paymentTxn._id, walletBalance: currentWallet?.availableBalanceInPaise ?? 0, message: "Booking marked as completed" });
  } catch (error) {
    // Guarded: post-commit code (cache/socket/notification) runs
    // inside this same try block. If it throws AFTER a successful
    // commit, session.inTransaction() is already false, and calling
    // abortTransaction() unconditionally would itself throw
    // ("Cannot call abortTransaction after calling commitTransaction"),
    // masking the real error. Only abort a still-open transaction.
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();
    return res.status(error.statusCode || error.status || 500).json({ success: false, message: error.message || "Failed to force complete" });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 13. EXTEND SERVICE (Booking Engine V2 — Phase 3)
// PATCH /v1/bookings/admin/extend-service
// body: { bookingId, minutes }
//
// Manual override for an overdue ONGOING booking. Does NOT change
// status, does NOT touch the wallet, does NOT free the chair —
// it only pushes overdueOverrideUntil forward so the (not yet
// built) auto-complete job will skip this booking until then,
// and records a GRACE_EXTENDED timeline event for the UI.
//////////////////////////////////////////////////////////////

export const extendService = async (req, res) => {
  try {
    const { bookingId, minutes } = req.body;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    await assertSalonOwnership(booking.salonRef, req.user._id);

    if (booking.status !== BOOKING_STATUS.ONGOING) {
      throw Object.assign(
        new Error("Only an ONGOING booking's service can be extended"),
        { status: 400 }
      );
    }

    if (!booking.serviceOverdueAt) {
      throw Object.assign(
        new Error("This booking is not overdue yet — nothing to extend"),
        { status: 400 }
      );
    }

    const now                 = new Date();
    const overdueOverrideUntil = new Date(now.getTime() + minutes * 60 * 1000);

    // Atomic — mirrors serviceOverdue.job.js's own atomic-write
    // pattern rather than mutate-then-save, so a concurrent edit
    // to an unrelated field (e.g. rating) is never clobbered.
    const updated = await Booking.findByIdAndUpdate(
      bookingId,
      {
        $set: {
          overdueOverrideUntil,
        },
        $push: {
          timelineEvents: {
            eventType:  "GRACE_EXTENDED",
            occurredAt: now,
            actor:      "SALON",
            meta: {
              minutes,
              extendedBy: req.user._id,
              reason:     "Salon owner requested more time",
            },
          },
        },
      },
      { new: true }
    );

    emitBookingEvent(req, {
      event:   "booking:graceExtended",
      salonId: updated.salonRef.toString(),
      userId:  updated.userRef.toString(),
      payload: {
        bookingId:            updated._id,
        chairId:              updated.chairRef,
        minutes,
        overdueOverrideUntil,
      },
    });

    await NotificationService.send({
      recipientId:   updated.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.SERVICE_EXTENDED_USER,
      title:         "Service Extended",
      message:       "Your service has been extended by the salon.",
      type:          "BOOKING",
      priority:      "LOW",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${updated._id}`,
      meta:          { bookingId: updated._id, minutes, friendlyBookingId: toFriendlyId(updated._id, "BK") },
    });

    await NotificationService.send({
      recipientId:   updated.salonRef,
      recipientType: "SALON",
      templateKey:   NOTIFICATION_EVENTS.SERVICE_EXTENDED_SALON,
      title:         "Service Extended",
      message:       "Service extended successfully.",
      type:          "BOOKING",
      priority:      "LOW",
      meta:          { bookingId: updated._id, minutes },
    });

    return res.status(200).json({
      success:  true,
      bookingId: updated._id,
      overdueOverrideUntil,
      message:  "Service extended successfully",
    });

  } catch (error) {
    console.error("extendService error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Failed to extend service",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 RESEND REMINDER (Booking Engine V2 — Phase 6)
// POST /v1/bookings/admin/resend-reminder
// body: { bookingId }
//
// Manual, on-demand version of what reminder.job.js already sends
// automatically. Same NotificationService, same copy convention.
// Deliberately independent of reminder30MinSentAt/reminder5MinSentAt —
// those only gate the AUTOMATIC sends; a manual request from the
// owner should always work regardless of the automatic timers.
//////////////////////////////////////////////////////////////

export const resendReminder = async (req, res) => {
  try {
    const { bookingId } = req.body;

    const booking = await Booking.findById(bookingId).populate("serviceRefs", "name");
    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    await assertSalonOwnership(booking.salonRef, req.user._id);

    if (booking.status !== BOOKING_STATUS.CONFIRMED) {
      throw Object.assign(
        new Error("Reminder can only be sent for a CONFIRMED booking"),
        { status: 400 }
      );
    }

    const serviceNames = (booking.serviceRefs || []).map(s => s.name).join(", ") || "your service";

    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_REMINDER_MANUAL,
      variables:     { serviceNames },
      title:         "Appointment Reminder",
      message:       `Reminder: your appointment for ${serviceNames} is coming up. Please head to the salon.`,
      type:          "BOOKING",
      priority:      "MEDIUM",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    });

    return res.status(200).json({
      success: true,
      message: "Reminder sent",
    });

  } catch (error) {
    console.error("resendReminder error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Failed to send reminder",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 GENERATE NO-SHOW OTP (Booking Engine V2 — Phase 6)
// POST /v1/bookings/admin/generate-noshow-otp
// body: { bookingId }
//
// Owner taps "Generate OTP" after calling a customer who hasn't
// checked in past the arrival grace window. Generates a fresh OTP,
// SMS's it to the CUSTOMER (same sendOtpSms channel auth already
// uses), stores only its hash on the booking — same hashOtp()
// function and hash-only-on-document pattern as the existing
// check-in OTP, reused for a different purpose.
//////////////////////////////////////////////////////////////

export const generateNoShowOtp = async (req, res) => {
  try {
    const { bookingId } = req.body;

    const booking = await Booking.findById(bookingId).populate("userRef", "phone");
    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    await assertSalonOwnership(booking.salonRef, req.user._id);

    if (booking.status !== BOOKING_STATUS.CONFIRMED) {
      throw Object.assign(
        new Error("OTP can only be generated for a CONFIRMED booking"),
        { status: 400 }
      );
    }

    // Same precondition style as extendService's serviceOverdueAt
    // guard — the owner can only start this flow once the customer
    // has genuinely been flagged delayed by customerArrival.job.js,
    // not before their arrival grace window has even elapsed.
    if (!booking.customerDelayedAt) {
      throw Object.assign(
        new Error("Customer is not yet marked delayed — nothing to confirm"),
        { status: 400 }
      );
    }

    if (!booking.userRef?.phone) {
      throw Object.assign(new Error("Customer phone number not available"), { status: 409 });
    }

    const otp        = generateOtp();
    const otpHashed   = hashOtp(otp);
    const now         = new Date();
    const expiresAt   = new Date(now.getTime() + 5 * 60 * 1000); // 5 min validity

    booking.noShowOtp          = otpHashed;
    booking.noShowOtpExpiresAt = expiresAt;
    await booking.save();

    const smsResult = await dispatchOtpSms({
      phone: booking.userRef.phone,
      otp,
      purpose: OTP_PURPOSE.BOOKING_NOSHOW,
      req,
    });
    if (!smsResult.success) {
      throw Object.assign(new Error("Could not send OTP. Please try again."), { status: 502 });
    }

    return res.status(200).json({
      success: true,
      message: "OTP sent to customer",
      expiresAt,
    });

  } catch (error) {
    console.error("generateNoShowOtp error:", error);
    return res.status(error.status || 500).json({
      success: false,
      message: error.message || "Failed to generate OTP",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 CONFIRM NO-SHOW CANCELLATION (Booking Engine V2 — Phase 6)
// POST /v1/bookings/admin/confirm-noshow
// body: { bookingId, otp }
//
// Owner reads back the OTP the customer gave over the call. On
// match: transitions CONFIRMED → CANCELLED — this is the EXISTING,
// already-allowed transition (cancelBooking/adminCancelBooking
// already use it), NOT NO_SHOW, and NOT markNoShow() — a human
// confirmed this cancellation, it is not a silent no-show.
//
// LOCKED PAYMENT RULE: no refund. The full amount already sitting
// in the salon's PENDING bucket (credited at confirmBooking time)
// is released to AVAILABLE — same shared WalletBalanceService call,
// same idempotency key format, that completeService()/forceComplete()/
// autoComplete.job.js already use. No new wallet math, no
// CancellationPolicyService, no refund API — this function never
// imports or calls either.
//////////////////////////////////////////////////////////////

export const confirmNoShowCancellation = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { bookingId, otp } = req.body;

    const booking = await Booking.findById(bookingId).session(session);
    if (!booking) {
      throw Object.assign(new Error("Booking not found"), { status: 404 });
    }

    await assertSalonOwnership(booking.salonRef, req.user._id, session);

    if (booking.status !== BOOKING_STATUS.CONFIRMED) {
      throw Object.assign(
        new Error("Only a CONFIRMED booking can be cancelled via this flow"),
        { status: 400 }
      );
    }

    if (!booking.noShowOtp || !booking.noShowOtpExpiresAt || booking.noShowOtpExpiresAt < new Date()) {
      throw Object.assign(
        new Error("OTP expired or was never generated — generate a new one"),
        { status: 400 }
      );
    }

    if (hashOtp(otp) !== booking.noShowOtp) {
      throw Object.assign(new Error("Invalid OTP"), { status: 401 });
    }

    //////////////////////////////////////////////////////////
    // 💰 RELEASE PENDING → AVAILABLE — full amount, no refund.
    // Same shared primitive every other completion path uses.
    //////////////////////////////////////////////////////////

    const paymentTxn = await Transaction.findOne({
      bookingId: booking._id,
      type:      TRANSACTION_TYPE.BOOKING,
      status:    TRANSACTION_STATUS.PAID,
    }).session(session);

    if (paymentTxn) {
      await WalletBalanceService.releasePendingToAvailable({
        salonId:        booking.salonRef,
        amountInPaise:  paymentTxn.payoutAmount,
        refType:        "BOOKING",
        refId:          paymentTxn._id,
        idempotencyKey: `booking:release:${booking._id}`,
        session,
        triggeredBy:    "SYSTEM",
        remarks:        "OTP-confirmed cancellation after no-show — full amount retained by salon (no refund)",
      });
    }

    const now = new Date();

    booking.cancelledAt              = now;
    booking.cancelledBy              = req.user._id;
    booking.cancelReason             = "Customer confirmed cancellation via OTP (did not check in)";
    booking.cancelledViaOtpConfirmation = true;
    booking.noShowOtp                = null;
    booking.noShowOtpExpiresAt       = null;

    booking.timelineEvents.push({
      eventType:  "CUSTOMER_CANCELLED_OTP",
      occurredAt: now,
      actor:      "SALON",
      meta:       { verifiedByOwner: req.user._id },
    });

    await transitionBookingStatus({ booking, nextStatus: BOOKING_STATUS.CANCELLED, session });

    await session.commitTransaction();
    session.endSession();

    //////////////////////////////////////////////////////////
    // 📡 REALTIME — chair freed (derived from status, no extra code)
    //////////////////////////////////////////////////////////

    emitBookingEvent(req, {
      event:   "booking:cancelled",
      salonId: booking.salonRef.toString(),
      userId:  booking.userRef.toString(),
      payload: {
        bookingId: booking._id,
        chairId:   booking.chairRef,
        status:    BOOKING_STATUS.CANCELLED,
      },
    });

    await NotificationService.send({
      recipientId:   booking.userRef,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.BOOKING_CANCELLED_NOSHOW,
      title:         "Booking Cancelled",
      message:       "Your booking has been cancelled as confirmed over the call.",
      type:          "BOOKING",
      priority:      "HIGH",
      actionType:    "OPEN_BOOKING",
      actionUrl:     `/bookings/${booking._id}`,
      meta:          { bookingId: booking._id, friendlyBookingId: toFriendlyId(booking._id, "BK") },
    });

    return res.status(200).json({
      success: true,
      bookingId: booking._id,
      status:    booking.status,
      message:   "Booking cancelled. Chair is now free.",
    });

  } catch (error) {
    if (session.inTransaction()) {
      await session.abortTransaction();
    }
    session.endSession();

    console.error("confirmNoShowCancellation error:", error);
    return res.status(error.statusCode || error.status || 500).json({
      success: false,
      message: error.message || "Failed to confirm cancellation",
    });
  }
};

//////////////////////////////////////////////////////////////
// 🚀 PAYMENT HISTORY — all booking payments, regardless of method
// GET /v1/bookings/user/payment-history?page=1&limit=20
//
// Unlike getWalletTransactions (wallet-only ledger), this shows
// every booking Transaction — Razorpay AND wallet-funded — as the
// unified "how much have I paid for bookings" history. Separate
// screen from Wallet History since a Razorpay payment never touches
// the wallet at all.
//////////////////////////////////////////////////////////////

export const getPaymentHistory = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    const page  = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Number(req.query.limit) || 20, 100);
    const skip  = (page - 1) * limit;

    const filter = { userId };

    const [transactions, total] = await Promise.all([
      Transaction.find(filter)
        .sort({ createdAt: -1, _id: -1 })
        .skip(skip)
        .limit(limit)
        .populate({ path: "salonId", select: "basicInfo.shopName" })
        .populate({ path: "bookingId", select: "serviceRefs startTime status", populate: { path: "serviceRefs", select: "name" } })
        .lean(),
      Transaction.countDocuments(filter),
    ]);

    const data = transactions.map((t) => ({
      _id:            t._id,
      friendlyTxnId:  toFriendlyId(t._id, "TXN"),
      bookingId:      t.bookingId?._id || null,
      friendlyBookingId: t.bookingId?._id ? toFriendlyId(t.bookingId._id, "BK") : null,
      amount:         t.amount,
      commission:     t.commission,
      payoutAmount:   t.payoutAmount,
      status:         t.status,
      type:           t.type,
      paymentId:      t.paymentId,
      paymentMethod:  t.paymentMethod || PAYMENT_METHOD.UNKNOWN,
      salonName:      t.salonId?.basicInfo?.shopName || null,
      serviceNames:   (t.bookingId?.serviceRefs || []).map((s) => s.name).filter(Boolean),
      bookingStartTime: t.bookingId?.startTime || null,
      bookingStatus:  t.bookingId?.status || null,
      createdAt:      t.createdAt,
    }));

    return res.json({
      success: true,
      data,
      pagination: { total, page, limit },
    });
  } catch (error) {
    console.error("getPaymentHistory error:", error);
    return res.status(500).json({ success: false, message: "Failed to fetch payment history" });
  }
};