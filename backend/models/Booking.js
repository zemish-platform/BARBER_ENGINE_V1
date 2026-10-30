import mongoose from "mongoose";

//////////////////////////////////////////////////////////////
// 📖 MODEL OVERVIEW
//
// The Booking document is the single source of truth for one
// customer's slot at one salon, from HOLD through its terminal
// state (COMPLETED / CANCELLED / NO_SHOW / EXPIRED). Every status
// transition is driven exclusively through bookingState.machine.js
// (BOOKING_TRANSITIONS + transitionBookingStatus) — this file only
// declares storage shape and data-integrity constraints, it never
// encodes lifecycle rules itself.
//
// Related models, each with a distinct, non-overlapping role:
//   Transaction        — the payment gateway record for this booking
//                         (1:1, unique bookingId)
//   WalletTransaction   — the CUSTOMER's own wallet ledger entry
//                         (top-ups, wallet-funded payments, refunds)
//   WalletLedger        — the SALON's earnings ledger (bucketed:
//                         available/pending/locked/processing),
//                         written exclusively via WalletBalanceService
//   CancellationPolicyService — pure refund-policy calculator; this
//                         model only stores its output
//                         (cancellationPolicy, refundAmountInPaise)
//
// Money is always paise (integer), except `amount` (display-only,
// rupees) and User.walletBalance (rupees) — see inline notes below.
//////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////
// 🔥 BOOKING STATUS ENUM
//////////////////////////////////////////////////////////////

export const BOOKING_STATUS = {
  HOLD:       "HOLD",        // Temporary slot lock — awaiting payment
  CONFIRMED:  "CONFIRMED",   // Payment received — OTP generated
  CHECKED_IN: "CHECKED_IN",  // Customer arrived — OTP verified
  ONGOING:    "ONGOING",     // Service in progress — timer running
  COMPLETED:  "COMPLETED",   // Service finished — wallet credited
  CANCELLED:  "CANCELLED",   // User or salon cancelled before service
  NO_SHOW:    "NO_SHOW",     // Customer did not arrive — chair freed
  EXPIRED:    "EXPIRED",     // HOLD timed out without payment — chair freed

  // ── EXTENSION GUIDE ─────────────────────────────────────
  // Add new statuses here AND update:
  //   1. bookingState.machine.js  — transition rules
  //   2. booking.controller.js    — any new HTTP handlers
  //   3. holdExpiry.job.js        — if new status needs automation
  //   4. socket.js                — if new status emits realtime events
  //
  // Reserved for future phases (DO NOT add until needed):
  //   LATE         — customer arrived after window (needs policy)
  //   OVERDUE      — service running past endTime (needs timer logic)
  //   RESCHEDULED  — moved to another slot (needs reschedule flow)
  //   REFUNDED     — payment reversed (needs Razorpay webhook)
  // ────────────────────────────────────────────────────────
};

//////////////////////////////////////////////////////////////
// 🔥 SCHEMA
//////////////////////////////////////////////////////////////

const BookingSchema = new mongoose.Schema(
  {
    //////////////////////////////////////////////////////////
    // 👤 USER
    //////////////////////////////////////////////////////////
    // immutable: no code path ever reassigns a booking to a different
    // user after creation — locks in a real invariant, not a new rule.
    userRef: {
      type:      mongoose.Schema.Types.ObjectId,
      ref:       "User",
      required:  true,
      index:     true,
      immutable: true,
    },

    //////////////////////////////////////////////////////////
    // 🏪 SALON
    //////////////////////////////////////////////////////////
    // immutable: a booking never moves to a different salon —
    // same rationale as userRef above.
    salonRef: {
      type:      mongoose.Schema.Types.ObjectId,
      ref:       "Salon",
      required:  true,
      index:     true,
      immutable: true,
    },

    //////////////////////////////////////////////////////////
    // 🪑 CHAIR
    //////////////////////////////////////////////////////////
    // NOT marked immutable, deliberately: the Chair Availability
    // Engine's locked business rules include silent chair
    // reassignment when a chair becomes unavailable — chairRef may
    // legitimately change after creation under that flow.
    chairRef: {
      type:     mongoose.Schema.Types.ObjectId,
      ref:      "Chair",
      required: true,
      index:    true,
    },

    //////////////////////////////////////////////////////////
    // 🧑‍🎨 PROFESSIONAL — Phase 5 (Booking Integration)
    //
    // Additive, optional, historical snapshot — NOT required. Stamped
    // at lockSlot() time from the authoritative, transaction-scoped
    // ProfessionalChairAssignment re-validation (services/
    // professionalAvailability.service.js). Legacy bookings (created
    // before this field existed) and any booking made without
    // selecting a professional simply have professionalRef: null
    // forever — never backfilled, never inferred. A later
    // ProfessionalChairAssignment change (reassignment, cancellation,
    // the professional going INACTIVE) must never rewrite this value
    // — it is what was actually selected/validated at booking time,
    // not a live pointer to "whoever is currently assigned".
    //////////////////////////////////////////////////////////
    professionalRef: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     "Staff",
      default: null,
    },

    //////////////////////////////////////////////////////////
    // 💇 SERVICES
    //////////////////////////////////////////////////////////
    serviceRefs: [
      {
        type:     mongoose.Schema.Types.ObjectId,
        ref:      "Service",
        required: true,
      },
    ],

    //////////////////////////////////////////////////////////
    // ⏱ TIMING
    //////////////////////////////////////////////////////////

    bookingDate: {
      type:     String,   // "YYYY-MM-DD" — used for date-only queries
      required: true,
      index:    true,
      trim:     true,
      match:    [/^\d{4}-\d{2}-\d{2}$/, "bookingDate must be in YYYY-MM-DD format"],
    },

    // NOT marked immutable: bookingState.machine.js reserves a future
    // RESCHEDULED status (see EXTENSION GUIDE above) that will need
    // to move a booking to a new startTime/endTime.
    startTime: {
      type:     Date,
      required: true,
      index:    true,
    },

    endTime: {
      type:     Date,
      required: true,
      index:    true,
    },

    serviceDuration: {
      type:     Number, // minutes
      required: true,
      min:      [1, "serviceDuration must be at least 1 minute"],
    },

    bufferTime: {
      type:    Number, // minutes
      default: 0,
      min:     [0, "bufferTime cannot be negative"],
    },

    //////////////////////////////////////////////////////////
    // 🔒 LOCK SYSTEM
    //
    // lockUntil     → slot visibility lock (UI countdown timer)
    // holdExpiresAt → payment timeout (background job expires HOLD)
    //
    // Kept separate so slot UI lock and payment window can have
    // different durations without affecting each other.
    //////////////////////////////////////////////////////////

    lockUntil: {
      type:    Date,
      default: null,
      index:   true,
    },

    // 🔥 HOLD AUTO EXPIRY
    // Set to (now + HOLD_EXPIRY_DURATION) when HOLD is created.
    // The holdExpiry.job.js worker queries on this field every 30s
    // to find and expire stale HOLDs — even if the user closes the app.
    holdExpiresAt: {
      type:    Date,
      default: null,
      index:   true,
    },

    //////////////////////////////////////////////////////////
    // 📊 STATUS
    //////////////////////////////////////////////////////////
    status: {
      type:    String,
      enum:    Object.values(BOOKING_STATUS),
      default: BOOKING_STATUS.HOLD,
      index:   true,
    },

    //////////////////////////////////////////////////////////
    // 💳 PAYMENT
    //
    // totalAmountInPaise  → authoritative amount used by finance engine
    // amount              → legacy / display field (rupees, optional)
    // paymentStatus       → tracks payment gateway state
    //////////////////////////////////////////////////////////
    paymentStatus: {
      type:    String,
      enum:    ["PENDING", "PAID", "FAILED", "REFUNDED"],
      default: "PENDING",
      index:   true,
    },

    // P0-A — the Razorpay order minted for THIS booking (set by
    // POST /payments/create-order, reused on retries). confirmBooking only
    // accepts a payment made against this order; unique so one order can
    // never be attached to two bookings. Null until an order exists.
    razorpayOrderId: {
      type:    String,
      default: null,
    },

    // 🔥 FINANCE FIELD — used by confirmBooking + completeService
    // Stored in paise (₹1 = 100 paise) to avoid floating-point errors.
    // Controller reads booking.totalAmountInPaise for all calculations.
    // MUST be a non-negative integer — decimals (e.g. 100.5 paise) are
    // invalid finance state and rejected at the schema level.
    totalAmountInPaise: {
      type:     Number,
      default:  0,
      min:      [0, "Amount cannot be negative"],
      validate: {
        validator: Number.isInteger,
        message:   "totalAmountInPaise must be a whole number (paise, not rupees)",
      },
    },

    // Breakdown of totalAmountInPaise — needed because the Platform Fee
    // is charged ON TOP of the service price (not deducted from it):
    // totalAmountInPaise = serviceAmountInPaise + commissionAmountInPaise
    //                      + (gstAmountInPaise || 0).
    // The full serviceAmountInPaise goes to the salon on confirm;
    // commissionAmountInPaise and gstAmountInPaise both stay with the
    // platform. Stored per-booking (rather than re-deriving from the
    // current Platform Fee/GST configuration at cancel time) so a later
    // configuration change never alters the split for bookings made
    // under the old configuration.
    //
    // commissionAmountInPaise is ZEMISH's ONE customer-facing Platform
    // Fee (also referred to as "Platform Fee"/"Convenience Fee" in
    // product/business language — never a second, separate charge).
    // As of the area-based Platform Fee architecture, its value is
    // resolved from the salon's authoritative area
    // (Salon.location.territory.areaRef) via
    // services/areaPlatformFee.service.js#resolvePlatformFeeForArea,
    // NOT from CommissionService.js's percentage-of-service calculation
    // (that service is deliberately left unmodified and unused for new
    // bookings — see lockSlot below). The field name is unchanged so
    // every existing downstream reader (Field Agent earning,
    // cancelBooking/ownerCancelBooking, RefundExecutionService, both
    // frontends) keeps working with zero code change — only the source
    // of the value changed. Historical bookings retain whatever value
    // was resolved under the calculation method active at their own
    // lockSlot time; never recalculated.
    serviceAmountInPaise: {
      type:     Number,
      default:  0,
      min:      [0, "Amount cannot be negative"],
      validate: {
          validator: Number.isInteger,
        message:   "serviceAmountInPaise must be a whole number (paise, not rupees)",
      },
    },
    commissionAmountInPaise: {
      type:     Number,
      default:  0,
      min:      [0, "Amount cannot be negative"],
      validate: {
        validator: Number.isInteger,
        message:   "commissionAmountInPaise must be a whole number (paise, not rupees)",
      },
    },

    // GST snapshot — PAN-India Platform Fee + GST architecture.
    // gstRatePercent/gstAmountInPaise default to null (NOT 0) so a
    // booking that predates this feature is distinguishable from one
    // where GST was genuinely computed as zero — same null-guarded
    // convention already established by cancellationPolicy/
    // refundAmountInPaise below. GST base = serviceAmountInPaise +
    // commissionAmountInPaise (locked business rule), resolved once at
    // lockSlot from the currently PUBLISHED GstPolicyVersion and never
    // re-read for an existing booking — a later rate change can never
    // retroactively alter it.
    gstRatePercent: {
      type:    Number,
      default: null,
      min:     [0, "gstRatePercent cannot be negative"],
    },
    gstAmountInPaise: {
      type:    Number,
      default: null,
      validate: {
        validator: (v) => v === null || (Number.isInteger(v) && v >= 0),
        message:   "gstAmountInPaise must be a non-negative whole number (paise) or null",
      },
    },

    // PLATFORM-FEE GST snapshot — the GST charged on the Platform Fee
    // itself (commissionAmountInPaise above). Both values are calculated
    // by services/bookingPricing.service.js from the PUBLISHED
    // GstPolicyVersion's platformFeeGstRatePercent and are passed to
    // Booking.create() by lockSlot; they are already part of
    // totalAmountInPaise (service + commission + gstAmountInPaise +
    // platformFeeGstAmountInPaise). They were not declared here, so
    // Mongoose strict mode silently dropped them on save. This only
    // persists the already-calculated values — it changes no calculation.
    // Same null-vs-zero convention as gstRatePercent/gstAmountInPaise:
    // null means "no value stored" (e.g. a booking saved before this
    // declaration existed), 0 means "computed as zero". Rate is in
    // percent; amount is in whole paise.
    platformFeeGstRatePercent: {
      type:    Number,
      default: null,
      min:     [0, "platformFeeGstRatePercent cannot be negative"],
    },
    platformFeeGstAmountInPaise: {
      type:    Number,
      default: null,
      validate: {
        validator: (v) => v === null || (Number.isInteger(v) && v >= 0),
        message:   "platformFeeGstAmountInPaise must be a non-negative whole number (paise) or null",
      },
    },

    // STEP 8.2 (policy version follow-up) — audit-trail ONLY, never used
    // for any dollar calculation (that stays totalAmountInPaise/
    // serviceAmountInPaise/commissionAmountInPaise/gstAmountInPaise
    // above, all unchanged by this addition). Records exactly which
    // AreaPlatformFeePolicy/GstPolicyVersion document (if any) was
    // PUBLISHED and resolved at this booking's own lockSlot time — null
    // when no policy applied (no area assigned / no GST ever published),
    // same null-vs-zero convention as gstRatePercent/gstAmountInPaise
    // above. Resolved once, never re-read for an existing booking —
    // immutable, exactly like every other pricing-snapshot field on this
    // document. Exists so RevenueSplitIntegrationService.js can copy
    // real traceability onto the RevenueSplit it creates instead of a
    // second, independent config lookup (RevenueSettings) that could
    // silently disagree with what this booking was actually priced at.
    platformFeePolicyRef: {
      type:      mongoose.Schema.Types.ObjectId,
      ref:       "AreaPlatformFeePolicy",
      default:   null,
      immutable: true,
    },
    gstPolicyVersionRef: {
      type:      mongoose.Schema.Types.ObjectId,
      ref:       "GstPolicyVersion",
      default:   null,
      immutable: true,
    },

    // ⚠️  DISPLAY ONLY — NEVER use this for finance logic.
    // All authoritative calculations (commission, payout, wallet)
    // MUST use totalAmountInPaise above.
    // This field exists only for human-readable display (e.g. ₹500).
    amount: {
      type:    Number,
      default: 0,
    },

    // India-only for now — mirrors the identical convention already
    // established in models/WalletTransaction.js. Widen when
    // multi-currency support is actually needed.
    currency: {
      type:    String,
      default: "INR",
      enum:    ["INR"],
    },

    //////////////////////////////////////////////////////////
    // 🔐 CHECK-IN OTP
    //
    // Stored as String — contains an HMAC-SHA256 hex digest.
    // Controller generates a 4-digit numeric OTP, hashes it
    // with hashOtp() before storing:
    //   checkInOtp = HMAC_SHA256(OTP_SECRET, rawOtp) → hex string
    //
    // The raw OTP is returned to the user once via the API
    // response and never stored. On check-in, the incoming
    // raw OTP is hashed again and compared against this field.
    //
    // Both fields are set to null after a successful check-in
    // (see checkInBooking in booking.controller.js) so they
    // don't linger on completed documents.
    //
    // checkInOtpExpiresAt enables future OTP expiry queries:
    //   { checkInOtp: { $exists: true }, checkInOtpExpiresAt: { $lt: now } }
    // A sparse index (defined below in INDEXES) keeps this fast
    // without indexing the majority of docs where OTP is null.
    //////////////////////////////////////////////////////////
    checkInOtp: {
      type: String,   // HMAC-SHA256 hex hash — never the raw 4-digit OTP
    },

    checkInOtpExpiresAt: {
      type: Date,
    },

    // Encrypted raw OTP — AES-256 encrypted, decryptable by server
    // Used for user-facing booking history OTP display
    checkInOtpEncrypted: {
      type:    String,
      default: null,
    },

    //////////////////////////////////////////////////////////
    // ⏱ OPERATIONAL TIMESTAMPS
    // One timestamp per lifecycle state — used by analytics,
    // audit trails, SLA monitoring, and the realtime engine.
    //////////////////////////////////////////////////////////

    checkedInAt: {
      type:    Date,
      default: null,
    },

    serviceStartedAt: {
      type:    Date,
      default: null,
    },

    completedAt: {
      type:    Date,
      default: null,
    },

    cancelledAt: {
      type:    Date,
      default: null,
    },

    expiredAt: {
      type:    Date,
      default: null,
    },

    noShowMarkedAt: {
      type:    Date,
      default: null,
    },

    //////////////////////////////////////////////////////////
    // 🚗 CUSTOMER ARRIVAL ENGINE
    //
    // These 4 fields power the grace period system that lets
    // salon owners make human decisions about late customers
    // rather than relying on rigid automatic NO_SHOW logic.
    //
    // Flow:
    //   CONFIRMED → startTime passes → arrivalGraceUntil window
    //   → customer still not CHECKED_IN → customerDelayedAt set
    //   → salon owner: WAIT (+10 min) | RELEASE (→ NO_SHOW)
    //////////////////////////////////////////////////////////

    // Absolute deadline for customer to arrive.
    // Set to (startTime + maxArrivalWaitMinutes) when booking
    // is CONFIRMED. Queried by customerArrival.job.js every minute.
    arrivalGraceUntil: {
      type:    Date,
      default: null,
      index:   true,        // ← job queries this field every 60s
    },

    // Timestamp when the customer was first flagged as delayed.
    // Null until arrivalGraceUntil passes without a CHECKED_IN.
    // Used for analytics (average delay, peak late-arrival times)
    // and for the salon dashboard "delayed" badge.
    customerDelayedAt: {
      type:    Date,
      default: null,
    },

    // How many times the salon owner extended the grace window.
    // Capped at MAX_GRACE_EXTENSIONS (defined in the controller)
    // to prevent infinite chair-blocking abuse — e.g. cap at 2
    // extensions so max total wait = 15 + 10 + 10 = 35 minutes.
    // Controller MUST enforce: if graceExtensionsUsed >= MAX, reject.
    graceExtensionsUsed: {
      type:    Number,
      default: 0,
      min:     0,
    },

    // Per-booking wait window (minutes). Default 5 (Booking Engine V2 —
    // Phase 6, approved business flow: "customer still not CHECKED_IN
    // after 5 minutes from appointment start"). Previously 15 — changed
    // here only, no other logic touched; existing CONFIRMED bookings
    // keep whatever value was already stored on them (never retroactive).
    //
    // MIGRATION NOTE: when Salon.settings is introduced in a
    // future phase, the lockSlot() controller should read the
    // salon's configured default and write it here at booking
    // creation time. Storing it per-booking (rather than always
    // reading from Salon.settings at runtime) means historical
    // bookings always reflect the policy that was active when
    // they were created — no retroactive policy changes.
    maxArrivalWaitMinutes: {
      type:    Number,
      default: 5,
      min:     0,
    },

    //////////////////////////////////////////////////////////
    // ⭐ RATING
    //////////////////////////////////////////////////////////
    // No default (undefined = "not rated yet", distinct from a real
    // rating value) — validator is null/undefined-guarded so an
    // unrated booking never fails validation on save.
    rating: {
      type: Number,
      min:  1,
      max:  5,
      validate: {
        validator: (v) => v == null || Number.isInteger(v),
        message:   "rating must be a whole number of stars",
      },
    },

    //////////////////////////////////////////////////////////
    // 📊 CANCELLATION META
    //////////////////////////////////////////////////////////
    cancelledBy: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     "User",
      default: null,
    },

    cancelReason: {
      type:      String,
      maxlength: 300,
      trim:      true,
    },

    // Set by cancelBooking (booking.controller.js) — one of
    // "NO_PAYMENT" | "FULL_REFUND" | "HALF_REFUND" | "NO_REFUND".
    // Previously written by the controller but silently dropped
    // (not declared in schema) — added here as additive-only.
    // enum is the exhaustive set CancellationPolicyService.evaluate()
    // can ever return — null included explicitly (never-cancelled
    // bookings), matching WalletTransaction.js's failureCode pattern.
    cancellationPolicy: {
      type:    String,
      default: null,
      enum:    [null, "NO_PAYMENT", "FULL_REFUND", "HALF_REFUND", "NO_REFUND"],
    },

    // Set by cancelBooking (booking.controller.js) — refund amount
    // in paise. Previously written but silently dropped.
    // Validator is explicitly null-guarded — this field defaults to
    // null (empirically confirmed: an un-guarded Number.isInteger
    // check fails Mongoose validation on its own null default,
    // which would break saving every never-cancelled booking).
    refundAmountInPaise: {
      type:    Number,
      default: null,
      validate: {
        validator: (v) => v === null || (Number.isInteger(v) && v >= 0),
        message:   "refundAmountInPaise must be a non-negative whole number (paise) or null",
      },
    },

    //////////////////////////////////////////////////////////
    // 🧾 AUDIT TRAIL
    // Every status transition is appended here automatically
    // by the pre-save hook below. Immutable event log.
    //////////////////////////////////////////////////////////
    statusHistory: [
      {
        status: {
          type: String,
          enum: Object.values(BOOKING_STATUS),
        },

        changedAt: {
          type:    Date,
          default: Date.now,
        },

        // null for SYSTEM-triggered transitions (cron jobs, expiry worker)
        changedBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref:  "User",
        },

        // Freeform extra audit context (e.g. admin cancel reason,
        // performedByRole, source, ip — see adminBooking.controller.js).
        // Previously written but silently dropped (not declared in
        // schema) — added here as additive-only. Not every push sets it.
        meta: {
          type: mongoose.Schema.Types.Mixed,
        },
      },
    ],

    //////////////////////////////////////////////////////////
    // 🔍 LAST STATUS TRANSITION META
    //////////////////////////////////////////////////////////
    statusChangedAt: {
      type:    Date,
      default: null,
    },

    statusChangedBy: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     "User",
      default: null,
    },

    // Set by forceComplete (booking.controller.js) when an operator
    // manually completes a booking outside the normal service-start
    // flow. Previously written but silently dropped (not declared
    // in schema) — added here as additive-only.
    forceCompleted: {
      type:    Boolean,
      default: false,
    },

    //////////////////////////////////////////////////////////
    // ⏰ REMINDER + AUTO-START + OTP-CANCEL (Booking Engine V2 — Phase 6)
    //
    // Additive-only. No new BOOKING_STATUS value — CONFIRMED→CANCELLED
    // is already a legal transition; this phase only adds a
    // SYSTEM/OWNER-triggered caller for it (via OTP confirmation)
    // and two idempotency markers for the reminder job.
    //////////////////////////////////////////////////////////

    // Set once each by reminder.job.js — prevents re-sending the same
    // reminder on a later tick. Same "flag once, never re-fire"
    // pattern as every other job in this codebase.
    reminder30MinSentAt: {
      type:    Date,
      default: null,
    },
    reminder5MinSentAt: {
      type:    Date,
      default: null,
    },

    // Hashed (never plaintext) OTP for the owner-initiated "confirm
    // customer cancellation" flow — same hashOtp() function and
    // hash-on-the-booking-document pattern as the existing
    // checkInOtp field above, reused for a different purpose.
    noShowOtp: {
      type:    String,
      default: null,
    },
    noShowOtpExpiresAt: {
      type:    Date,
      default: null,
    },

    // True only when this booking's CANCELLED status was reached via
    // the OTP-confirmed no-show flow — distinguishes it from a normal
    // pre-appointment cancellation (cancelBooking/adminCancelBooking)
    // for analytics/audit, exactly like autoCompleted/forceCompleted
    // distinguish HOW an existing status was reached without adding
    // a new status value.
    cancelledViaOtpConfirmation: {
      type:    Boolean,
      default: false,
    },

    //////////////////////////////////////////////////////////
    // ⏰ AUTOMATION ENGINE (Booking Engine V2 — Phase 1)
    //
    // Additive-only fields for the upcoming auto-complete /
    // auto-no-show automation. NONE of these are read or written
    // by any controller or job yet — this phase only declares
    // storage shape so later phases have somewhere to write.
    //
    // No new BOOKING_STATUS value is introduced by this feature.
    // ONGOING → COMPLETED and CONFIRMED → NO_SHOW are already
    // legal transitions in bookingState.machine.js — automation
    // only adds a SYSTEM-triggered caller of the existing
    // transitionBookingStatus(), distinguished from a human
    // action via the flags below.
    //////////////////////////////////////////////////////////

    // Set once by the future serviceOverdue.job.js when an ONGOING
    // booking runs past (serviceStartedAt + serviceDuration + grace)
    // and is still not COMPLETED. Flag-only — mirrors the existing
    // customerDelayedAt pattern (Customer Arrival Engine above):
    // it marks the booking as overdue, it never transitions status
    // by itself.
    serviceOverdueAt: {
      type:    Date,
      default: null,
      index:   true,   // future job will query this field on an interval
    },

    // Set by a future salon-facing "Extend N min" action. While
    // this is in the future (> now), any future auto-complete /
    // auto-no-show job MUST skip the booking — a manual extension
    // always takes priority over automation. Mirrors arrivalGraceUntil's
    // role for the Customer Arrival Engine, but for the in-service
    // (ONGOING) phase instead of the pre-service (CONFIRMED) phase.
    overdueOverrideUntil: {
      type:    Date,
      default: null,
    },

    // True only when a future automation job transitions this
    // booking to COMPLETED itself (SYSTEM-triggered), as opposed
    // to a salon owner calling completeService() or forceComplete().
    // Mirrors the existing forceCompleted flag's role: both
    // distinguish HOW a terminal status was reached without adding
    // a new status value.
    autoCompleted: {
      type:    Boolean,
      default: false,
    },

    // True only when a future automation job transitions this
    // booking to NO_SHOW itself (SYSTEM-triggered), as opposed to
    // a salon owner calling the existing markNoShow().
    autoNoShow: {
      type:    Boolean,
      default: false,
    },

    // Append-only operational narrative, separate from statusHistory
    // above. statusHistory records STATUS transitions only (its
    // `status` field is constrained to BOOKING_STATUS). timelineEvents
    // records the richer story a future UI will render — including
    // events that are NOT status transitions at all (e.g. a grace
    // extension, or the moment expected service duration elapses
    // while status is still ONGOING) — so it needs its own, wider
    // eventType enum rather than reusing BOOKING_STATUS.
    //
    // Nothing pushes to this array yet in this phase.
    timelineEvents: [
      {
        eventType: {
          type: String,
          enum: [
            "CONFIRMED",
            "CHECKED_IN",
            "SERVICE_STARTED",
            "SERVICE_TIME_COMPLETED",
            "AUTO_COMPLETED",
            "GRACE_EXTENDED",
            "OVERDUE_FLAGGED",
            "AUTO_NO_SHOW",
            // Booking Engine V2 — Phase 6 — customer confirmed
            // cancellation over a call by reading back a system-
            // generated OTP, after not checking in within the
            // arrival grace window. Distinct from AUTO_NO_SHOW —
            // this is a human-confirmed cancellation, not a silent
            // no-show.
            "CUSTOMER_CANCELLED_OTP",
          ],
          required: true,
        },

        occurredAt: {
          type:    Date,
          default: Date.now,
        },

        // Who/what caused this event. "SYSTEM" for job-triggered
        // events (e.g. OVERDUE_FLAGGED, AUTO_COMPLETED) — no
        // separate changedBy ObjectId needed since these events
        // are never attributable to a specific User document the
        // way statusHistory.changedBy is.
        actor: {
          type: String,
          enum: ["SYSTEM", "SALON", "USER", "ADMIN"],
          required: true,
        },

        // Freeform extra context (e.g. minutesExtended, thresholdUsed)
        // — same Mixed-type pattern as statusHistory.meta above.
        meta: {
          type: mongoose.Schema.Types.Mixed,
        },
      },
    ],

    //////////////////////////////////////////////////////////
    // 🗑 SOFT DELETE
    //////////////////////////////////////////////////////////
    isDeleted: {
      type:    Boolean,
      default: false,
      index:   true,
    },

    //////////////////////////////////////////////////////////
    // 📊 SOURCE TRACKING
    //////////////////////////////////////////////////////////
    source: {
      type:    String,
      enum:    ["APP", "WEB", "ADMIN", "SYSTEM"],
      default: "APP",
    },
  },
  {
    timestamps: true,   // createdAt, updatedAt
    versionKey: false,
  }
);

//////////////////////////////////////////////////////////////
// 🚀 INDEXES
//
// RULE: indexes here must match exactly the query patterns
// used in booking.controller.js and holdExpiry.job.js.
// Unused indexes waste write performance — every index listed
// below has a direct corresponding query in the codebase.
//////////////////////////////////////////////////////////////

// ── Salon dashboard queries ────────────────────────────────
BookingSchema.index({ salonRef: 1, startTime: 1, endTime: 1 });

// ── Salon booking list (getSalonBookings) — filter by salonRef
// (+ optional status, filtered in-memory from this narrowed,
// already-sorted set), sorted by createdAt. Without this, the
// sort has no index support and falls back to an in-memory sort
// that grows with the salon's total booking history.
BookingSchema.index({ salonRef: 1, createdAt: -1 });

// ── Chair overlap queries (conflict detection) ────────────
BookingSchema.index({ chairRef: 1, startTime: 1, endTime: 1 });

// ── HARD CONFLICT PROTECTION (query optimisation) ─────────
// Covers the $and overlap + status $in query in lockSlot()
// and confirmBooking(). Partial filter restricts index size
// to only active bookings.
BookingSchema.index(
  { chairRef: 1, startTime: 1, endTime: 1, status: 1 },
  {
    partialFilterExpression: {
      status: {
        $in: [
          BOOKING_STATUS.HOLD,
          BOOKING_STATUS.CONFIRMED,
          BOOKING_STATUS.CHECKED_IN,
          BOOKING_STATUS.ONGOING,
        ],
      },
    },
  }
);

// ── RACE CONDITION SAFETY NET — unique constraint ──────────
// This is the final hard guarantee that no two active bookings
// can occupy the same chair at the same startTime.
// Layer 1 (application): lockSlot session transaction
// Layer 2 (database):    this unique partial index
// If two requests slip through Layer 1 at the exact same ms,
// MongoDB's unique constraint catches it and returns code 11000,
// which lockSlot() handles as a clean 409 response.
BookingSchema.index(
  { chairRef: 1, startTime: 1 },
  {
    unique: true,
    partialFilterExpression: {
      status: {
        $in: [
          BOOKING_STATUS.HOLD,
          BOOKING_STATUS.CONFIRMED,
          BOOKING_STATUS.CHECKED_IN,
          BOOKING_STATUS.ONGOING,
        ],
      },
    },
  }
);

// ── PROFESSIONAL RACE CONDITION SAFETY NET — unique constraint (Phase C) ──
// Mirrors the chair unique index directly above, keyed on professionalRef
// instead of chairRef. Physical chair count must never become
// professional booking capacity: this is the DB-level backstop for the
// exact-same-millisecond race on top of the primary protection, which is
// the transaction-scoped range-overlap query in
// booking.controller.js::buildProfessionalOverlapFilter (checked inside
// the SAME session as the create, immediately before it). A unique index
// can only match exact key equality, not arbitrary time-range overlap —
// it does NOT by itself catch two DIFFERENT-but-overlapping start times
// for the same professional; that general case is what the transaction
// query above is for. This index only closes the narrow gap where two
// transactions somehow both pass that query for the exact same
// professionalRef + exact same startTime instant.
//
// professionalRef: { $type: "objectId" } is REQUIRED here, unlike the
// chairRef index above — chairRef is always required/non-null on every
// booking, but professionalRef is only sometimes set. Verified against
// the real database before choosing this (Phase C): MongoDB partial
// filter expressions do NOT support $ne/$not at all ("Expression not
// supported in partial index: $not", confirmed via a real createIndex
// call) — only equality, $exists, $gt/$gte/$lt/$lte, $type, and a
// top-level $and are allowed. $exists:true is ALSO wrong here: every
// pre-Phase-5 booking has the field genuinely ABSENT (confirmed via a
// real $type aggregation — 202/202 documents came back "missing", not
// "null"), but lockSlot() explicitly writes `professionalRef: null`
// (not omitting the key) for every future no-professional booking — so
// $exists:true would start wrongly including those going forward.
// $type:"objectId" is the only condition that correctly excludes BOTH
// the "missing" (historical) and "null" (future legacy) shapes, while
// only ever matching a booking where a real professional was actually
// resolved — confirmed accepted by a real (temporary, since-dropped)
// test index against this exact database before being used here.
BookingSchema.index(
  { professionalRef: 1, startTime: 1 },
  {
    unique: true,
    partialFilterExpression: {
      professionalRef: { $type: "objectId" },
      status: {
        $in: [
          BOOKING_STATUS.HOLD,
          BOOKING_STATUS.CONFIRMED,
          BOOKING_STATUS.CHECKED_IN,
          BOOKING_STATUS.ONGOING,
        ],
      },
    },
  }
);

// ── HOLD EXPIRY — used by holdExpiry.job.js every 30s ─────
// Queries: { status: "HOLD", holdExpiresAt: { $lt: now } }
// Partial filter limits the index to HOLD-only documents —
// keeps it tiny even with millions of completed bookings.
BookingSchema.index(
  { status: 1, holdExpiresAt: 1 },
  {
    partialFilterExpression: {
      status: BOOKING_STATUS.HOLD,
    },
  }
);

// ── Payment queries ────────────────────────────────────────
BookingSchema.index({ paymentStatus: 1, createdAt: -1 });

// P0-A — an order belongs to at most one booking (partial: only string ids).
BookingSchema.index(
  { razorpayOrderId: 1 },
  { unique: true, partialFilterExpression: { razorpayOrderId: { $type: "string" } } }
);

// ── Soft delete queries ────────────────────────────────────
BookingSchema.index({ isDeleted: 1, createdAt: -1 });

// ── User booking history ───────────────────────────────────
BookingSchema.index({ userRef: 1, createdAt: -1 });

// ── User upcoming bookings ─────────────────────────────────
BookingSchema.index({ userRef: 1, status: 1, startTime: 1 });

// ── Rating queries (sparse — most bookings have no rating) ─
BookingSchema.index(
  { salonRef: 1, rating: 1 },
  { sparse: true }
);

// ── OTP expiry queries (sparse — only CONFIRMED bookings have OTP) ─
// Used by future OTP cleanup worker:
//   { checkInOtp: { $exists: true }, checkInOtpExpiresAt: { $lt: now } }
// Sparse keeps index tiny — null OTP fields are excluded.
BookingSchema.index(
  { checkInOtpExpiresAt: 1 },
  { sparse: true }
);

// ── CUSTOMER ARRIVAL ENGINE — used by customerArrival.job.js ──
// Exact query the worker runs every 60s:
//   { status: CONFIRMED, arrivalGraceUntil: { $lt: now }, customerDelayedAt: null }
//
// customerDelayedAt added to the index so MongoDB can satisfy
// the full query from the index alone (covered query) without
// fetching the document. At current scale the difference is
// negligible — included now so the index is migration-safe
// when booking volume grows.
//
// Partial filter restricts to CONFIRMED-only — keeps the index
// tiny since most bookings are COMPLETED/CANCELLED/EXPIRED.
BookingSchema.index(
  { status: 1, arrivalGraceUntil: 1, customerDelayedAt: 1 },
  {
    sparse: true,
    partialFilterExpression: {
      status: BOOKING_STATUS.CONFIRMED,
    },
  }
);

// ── FIELD AGENT EARNING ENGINE — used by fieldAgentEarning.job.js ──
// Exact query the worker runs on a compound (completedAt,_id) cursor:
//   { status: COMPLETED, completedAt: {$gt/$gte: cursor} }
//   .sort({ completedAt: 1, _id: 1 })
// Schema-neutral: no field added, no lifecycle/CommissionService
// change — purely a query-performance structure (FA-9 corrected plan
// §O). Partial filter keeps it small since most bookings are not
// COMPLETED at any given time relative to the full historical set.
BookingSchema.index(
  { status: 1, completedAt: 1, _id: 1 },
  {
    partialFilterExpression: {
      status: BOOKING_STATUS.COMPLETED,
    },
  }
);

//////////////////////////////////////////////////////////////
// 🔥 PRE-SAVE: AUTO STATUS HISTORY TRACKING
//
// Fires on every save() where status changed.
// Appends an immutable entry to statusHistory[].
// changedBy is null for SYSTEM-triggered transitions.
//////////////////////////////////////////////////////////////

BookingSchema.pre("save", function (next) {
  if (this.isModified("status")) {
    this.statusHistory.push({
      status:    this.status,
      changedAt: new Date(),
      changedBy: this.statusChangedBy || null,
    });
  }
  next();
});

//////////////////////////////////////////////////////////////
// 🚀 EXPORT
//////////////////////////////////////////////////////////////

export default mongoose.models.Booking ||
  mongoose.model("Booking", BookingSchema);