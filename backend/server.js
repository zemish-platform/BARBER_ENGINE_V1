import "dotenv/config";
import http from "http";
import mongoose from "mongoose"; // ← IMPROVEMENT-2: needed for DB close + health check
import app from "./app.js";
import connectDB from "./config/db.js";
import redis from "./config/redis.js";
import { startAutoCompleteJob } from "./jobs/autoComplete.job.js";
import { startAutoStartJob } from "./jobs/autoStart.job.js";
import { startCustomerArrivalJob } from "./jobs/customerArrival.job.js";
import { startHoldExpiryJob } from "./jobs/holdExpiry.job.js";
import { startReminderJob } from "./jobs/reminder.job.js";
import { startServiceOverdueJob } from "./jobs/serviceOverdue.job.js";
import { startSlaScannerJob } from "./jobs/slaScanner.job.js"; // ← Phase G Step 10 — wires up the Step 6-8 SLA scanner/escalation/notification chain, previously file-only
import { startRatingOutboxJob } from "./jobs/ratingOutbox.job.js"; // ← Rating & Review Engine Phase 2 — distributed-safe RatingEvent outbox consumer
import { startWeeklyScheduleMaterializerJob } from "./jobs/weeklyScheduleMaterializer.job.js"; // ← C4 Phase 2 — converts WeeklyScheduleTemplate into concrete ProfessionalChairAssignment rows for each salon's rolling booking window
import { startBookingReadinessChangeJob } from "./jobs/bookingReadinessChange.job.js"; // ← R4 approved pilot — notifies the Salon Owner on a real READY/NEEDS_ATTENTION/NOT_READY transition, reusing getBookingReadiness() unmodified
import { startFieldAgentKycSyncJob } from "./modules/kyc/jobs/fieldAgentKycSync.job.js"; // ← FA-3.2 consistency layer — durable FieldAgentKycSyncEvent outbox consumer + reconciliation
import { startFraudDetectionJob } from "./modules/fieldAgent/jobs/fraudDetection.job.js"; // ← FA-7.2 — stateless, read-only REFERRAL_VELOCITY/WITHDRAW_RECLAIM_CYCLE detection over one closed hour, writing only advisory FraudSignal evidence
import { startCrossAgentOverlapJob } from "./modules/fieldAgent/jobs/crossAgentOverlap.job.js"; // ← FA-7.3 — stateless, read-only CROSS_AGENT_SALON_CYCLING detection over full AcquisitionClaim history, writing only advisory FraudSignal evidence
import { startTerritoryAssignmentOverlapJob } from "./modules/fieldAgent/jobs/territoryAssignmentOverlap.job.js"; // ← FA-7.4 — stateless, read-only TERRITORY_ASSIGNMENT_CYCLING detection over full TerritoryAssignment history, writing only advisory FraudSignal evidence
import { startFieldAgentEarningJob } from "./modules/fieldAgent/jobs/fieldAgentEarning.job.js"; // ← FA-9 — durable-checkpoint, compound-cursor discovery of newly COMPLETED Bookings, crediting Acquisition/Territory Partner earning via the immutable FieldAgentEarningLedger
import { startOtpAuditOutboxJob } from "./modules/otp/jobs/otpAuditOutbox.job.js"; // ← OTP-2 Part D — drains modules/otp/models/OtpAuditOutbox.js into OtpAuditLog asynchronously (claim/apply/reclaim, same shape as ratingOutbox.job.js)
import { startNotificationRetryJob } from "./modules/notifications/jobs/notificationRetry.job.js"; // ← FA-P2-A — retries FAILED PUSH NotificationDeliveryLog rows (atomic claim via processingStartedAt, same shape as ratingOutbox.job.js)
import { startCashfreePayoutReconcileJob } from "./modules/fieldAgent/jobs/cashfreePayoutReconcile.job.js"; // ← FA-P4-D Step 1 — polls in-flight Cashfree Field Agent payouts whose webhook never arrived; idempotent, multi-instance safe
import { startGenericPayoutReconcileJob } from "./modules/payout/jobs/genericPayoutReconcile.job.js"; // ← STEP 6.4 — polls in-flight RAZORPAY_ROUTE GenericPayoutRequest payouts whose webhook never arrived; idempotent, multi-instance safe; safe no-op when Razorpay Route isn't configured
import { initSocket } from "./socket/index.js";

//////////////////////////////////////////////////////////////
// 🔑 STEP 1: LOAD ENVIRONMENT VARIABLES
//////////////////////////////////////////////////////////////

// FA-15 Phase A — fail-closed startup guardrail. ALLOW_FIXED_OTP
// (utils/otp.helpers.js) makes OTP verification for EVERY role,
// including FIELD_AGENT, accept a hardcoded "123456" — deliberately
// kept independent of NODE_ENV (see that file's own header comment)
// so it can be toggled without touching Razorpay's own
// NODE_ENV-gated verification. That independence means nothing
// previously stopped it from being left on in a real production
// deployment. This is the single authoritative boot-time check for
// that combination — do not duplicate it elsewhere.
if (process.env.NODE_ENV === "production" && process.env.ALLOW_FIXED_OTP === "true") {
  console.error(
    "❌ Refusing to start: ALLOW_FIXED_OTP=true is set while NODE_ENV=production. " +
    "The fixed-OTP bypass must never be enabled in production. " +
    "Unset ALLOW_FIXED_OTP (or set it to \"false\") and restart."
  );
  process.exit(1);
}

//////////////////////////////////////////////////////////////
// 🔑 STEP 2: CONNECT DATABASE (MongoDB)
//////////////////////////////////////////////////////////////

connectDB();

//////////////////////////////////////////////////////////////
// 🔑 STEP 3: REDIS LIFECYCLE LOGGING
//////////////////////////////////////////////////////////////

redis.on("connect",     () => console.log("🧠 Redis Connected (Session Store Ready)"));
redis.on("ready",       () => console.log("⚡ Redis Ready for Operations"));
redis.on("error",  (err) => console.error("❌ Redis Connection Error:", err.message));
redis.on("reconnecting",() => console.warn("🔄 Redis Reconnecting..."));

//////////////////////////////////////////////////////////////
// 🔑 STEP 4: PORT CONFIGURATION
//////////////////////////////////////////////////////////////

const PORT = process.env.PORT || 6060;

//////////////////////////////////////////////////////////////
// 📡 STEP 5: CREATE HTTP SERVER
// Must be created before Socket.IO attaches to it.
//////////////////////////////////////////////////////////////

const httpServer = http.createServer(app);

//////////////////////////////////////////////////////////////
// 📡 STEP 6: INITIALIZE SOCKET.IO — FAIL-FAST SAFE
//
// IMPROVEMENT-4: wrapped in try/catch so a bad socket config
// causes a clean process.exit(1) instead of a silent crash or
// a server that starts without realtime capability.
//////////////////////////////////////////////////////////////

let io;
try {
  io = initSocket(httpServer);
  console.log("✅ Socket.IO initialized");
} catch (err) {
  console.error("❌ Socket.IO init failed:", err.message);
  process.exit(1);
}

//////////////////////////////////////////////////////////////
// 📡 STEP 7: MAKE SOCKET AVAILABLE INSIDE CONTROLLERS
//
// Any controller can now emit via:
//   const io = req.app.get("io");
//   io.to(`salon:${salonId}`).emit("booking:confirmed", payload);
//////////////////////////////////////////////////////////////

app.set("io", io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7b: START HOLD EXPIRY BACKGROUND JOB
//
// Started here (after initSocket) because the job needs the
// io instance to emit realtime events when HOLDs expire.
// Runs once immediately on startup (clears stale HOLDs from
// any downtime) then every 30 seconds on the interval.
//////////////////////////////////////////////////////////////

const holdExpiryJob = startHoldExpiryJob(io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7c: START CUSTOMER ARRIVAL BACKGROUND JOB
//
// Monitors CONFIRMED bookings where the customer has not arrived
// within their grace window (arrivalGraceUntil). Flags them with
// customerDelayedAt and emits booking:customerDelayed so the salon
// dashboard can display the delayed badge and prompt owner action.
//
// Started after holdExpiryJob — both need io, both are independent.
// Returns a { stop } controller used in graceful shutdown.
//////////////////////////////////////////////////////////////

const customerArrivalJob = startCustomerArrivalJob(io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7d: START SERVICE OVERDUE BACKGROUND JOB
//
// Monitors ONGOING bookings running past their expected duration.
// Flag-only — never transitions status. See jobs/serviceOverdue.job.js.
//
// Started after customerArrivalJob — both need io, both independent.
// Returns a { stop } controller used in graceful shutdown.
//////////////////////////////////////////////////////////////

const serviceOverdueJob = startServiceOverdueJob(io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7e: START AUTO COMPLETE BACKGROUND JOB
//
// Automatically completes an ONGOING booking that has been
// overdue long enough with no owner action. Reuses the same
// transitionBookingStatus/WalletBalanceService/NotificationService
// every manual completion uses. See jobs/autoComplete.job.js.
//
// Started after serviceOverdueJob — both need io, both independent.
// Returns a { stop } controller used in graceful shutdown.
//////////////////////////////////////////////////////////////

const autoCompleteJob = startAutoCompleteJob(io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7f: START REMINDER BACKGROUND JOB (Booking Engine V2 — Phase 6)
//
// Sends 30-min and 5-min appointment reminders to the customer.
// No io needed — notification only, no socket emit.
//////////////////////////////////////////////////////////////

const reminderJob = startReminderJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7g: START AUTO START BACKGROUND JOB (Booking Engine V2 — Phase 6)
//
// Auto-transitions a CHECKED_IN booking to ONGOING once startTime
// arrives, if the owner forgot to tap "Start Service".
//////////////////////////////////////////////////////////////

const autoStartJob = startAutoStartJob(io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7h: START SLA SCANNER BACKGROUND JOB (Phase G Step 10)
//
// Periodically discovers SupportTicket records whose first-response
// or resolution SLA has newly reached WARNING/BREACHED, persists each
// newly detected event exactly once (Step 6), escalates newly-
// detected breaches (Step 7), and delivers the IN_APP notification +
// Socket.IO event for all three (Step 8). The job file itself has
// existed since Step 6 but was never registered here — this is the
// only change needed to make Steps 6-8 actually run in a live
// environment; no logic in jobs/slaScanner.job.js changed.
// Needs `io` for its Socket.IO emits, same as serviceOverdueJob/
// holdExpiryJob above.
//////////////////////////////////////////////////////////////

const slaScannerJob = startSlaScannerJob(io);

//////////////////////////////////////////////////////////////
// 🚀 STEP 7i: START RATING OUTBOX CONSUMER (Rating & Review Engine
// Phase 2)
//
// Polls RatingEvent for PENDING (or stale-claimed PROCESSING) rows
// and folds each into the matching RatingAggregate — distributed-
// safe via an atomic claim + idempotent conditional apply (see
// jobs/ratingOutbox.job.js). No io needed — no realtime emit.
//////////////////////////////////////////////////////////////

const ratingOutboxJob = startRatingOutboxJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7j: START WEEKLY SCHEDULE MATERIALIZER (C4 Phase 2)
//
// Converts each salon's WeeklyScheduleTemplate (C4 Phase 1) into
// concrete ProfessionalChairAssignment rows for that salon's rolling
// booking window (Salon.business.bookingWindowDays, default 7). Runs
// once immediately, then daily. No io needed — no realtime emit. Pure
// orchestration — reuses the existing, unmodified
// professionalChairAssignment.service.js::createAssignment() for
// every row it creates (see jobs/weeklyScheduleMaterializer.job.js).
//////////////////////////////////////////////////////////////

const weeklyScheduleMaterializerJob = startWeeklyScheduleMaterializerJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7j2: START BOOKING READINESS CHANGE JOB (R4 — approved pilot)
//
// Every 60s, re-runs the existing, unmodified
// bookingReadiness.service.js::getBookingReadiness() for every
// approved salon and notifies the owner (IN_APP + PUSH) only on a
// genuine READY/NEEDS_ATTENTION/NOT_READY transition or a changed
// first blocking reason code. In-memory dedup cache only — see
// jobs/bookingReadinessChange.job.js's own header for the documented
// restart/multi-instance limitations this pilot accepts. No io
// needed — no realtime emit.
//////////////////////////////////////////////////////////////

const bookingReadinessChangeJob = startBookingReadinessChangeJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7k: START FIELD AGENT KYC SYNC (FA-3.2 Consistency Layer)
//
// Consumer (every 15s) applies FieldAgentKycSyncEvent rows onto the
// FA-2 FieldAgentApplication lifecycle; reconciliation (every 3 min)
// recovers any event the fast path in fieldAgentKyc.service.js failed
// to durably record, using durable VerificationLog evidence. No io
// needed — no realtime emit. See modules/kyc/jobs/fieldAgentKycSync.job.js.
//////////////////////////////////////////////////////////////

const fieldAgentKycSyncJob = startFieldAgentKycSyncJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7l: START FRAUD DETECTION JOB (FA-7.2)
//
// Runs at most hourly, stateless — recomputes the most recently
// closed hour on every tick from Date.now(), never a historical
// backfill. Reads AcquisitionReferral/AcquisitionClaim (frozen FA-5.3)
// read-only; writes only advisory FraudSignal evidence via the
// frozen FA-7.1 recordSignal(). See
// modules/fieldAgent/jobs/fraudDetection.job.js.
//////////////////////////////////////////////////////////////

const fraudDetectionJob = startFraudDetectionJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7m: START CROSS-AGENT OVERLAP JOB (FA-7.3)
//
// Runs at most hourly, stateless — no time-bucket, evaluates the full
// persisted AcquisitionClaim (frozen FA-5.3) history read-only every
// tick. Writes only advisory CROSS_AGENT_SALON_CYCLING FraudSignal
// evidence via the frozen FA-7.1 recordSignal(). Deliberately a
// separate scheduler from the FA-7.2 fraud detection job — see
// modules/fieldAgent/jobs/crossAgentOverlap.job.js for why.
//////////////////////////////////////////////////////////////

const crossAgentOverlapJob = startCrossAgentOverlapJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7n: START TERRITORY ASSIGNMENT OVERLAP JOB (FA-7.4)
//
// Runs at most hourly, stateless — no time-bucket, evaluates the full
// persisted TerritoryAssignment (frozen FA-5.2) history read-only every
// tick, discovered via the small CommercialTerritory master collection.
// Writes only advisory TERRITORY_ASSIGNMENT_CYCLING FraudSignal
// evidence via the frozen FA-7.1 recordSignal(). Deliberately a
// separate scheduler from the FA-7.2/FA-7.3 fraud detection jobs — see
// modules/fieldAgent/jobs/territoryAssignmentOverlap.job.js for why.
//////////////////////////////////////////////////////////////

const territoryAssignmentOverlapJob = startTerritoryAssignmentOverlapJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7o: START FIELD AGENT EARNING JOB (FA-9)
//
// Runs every 30s. Durable-checkpoint, compound (completedAt,_id)
// cursor discovery of newly COMPLETED Bookings (frozen, read-only —
// see the new partial {status,completedAt,_id} index on Booking.js).
// Resolves policy (national CommercialPolicyVersion or geography-scoped
// CommercialPolicyOverride) as-of Booking.completedAt, credits
// Acquisition (atomic, capped) or Territory Partner via the immutable
// FieldAgentEarningLedger. Never mutates Booking, AcquisitionClaim,
// CommercialTerritory, or CommercialPolicyVersion. See
// modules/fieldAgent/jobs/fieldAgentEarning.job.js.
//////////////////////////////////////////////////////////////

const fieldAgentEarningJob = startFieldAgentEarningJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7p: START OTP AUDIT OUTBOX JOB (OTP-2 Part D)
//
// Runs every 5s. Drains modules/otp/models/OtpAuditOutbox.js (the
// fast, fire-and-forget write target every OTP send/verify uses) into
// modules/otp/models/OtpAuditLog.js — atomic per-row claim, stale-claim
// reclaim, never deletes a row on failure (always retryable). See
// modules/otp/jobs/otpAuditOutbox.job.js.
//////////////////////////////////////////////////////////////

const otpAuditOutboxJob = startOtpAuditOutboxJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 7q: START NOTIFICATION RETRY JOB (FA-P2-A)
//
// Runs every 30s. Retries FAILED PUSH NotificationDeliveryLog rows —
// atomic claim via processingStartedAt (no schema/enum change needed;
// this model has carried these fields, documented as unused, since
// Phase 1). After 5 attempts a row moves to FAILED_PERMANENT and is
// never retried again. See modules/notifications/jobs/notificationRetry.job.js.
//////////////////////////////////////////////////////////////

const notificationRetryJob = startNotificationRetryJob();

// FA-P4-D Step 1 — Cashfree auto-payout reconciliation (no-op unless Cashfree is configured
// and a CASHFREE payout is in flight).
const cashfreePayoutReconcileJob = startCashfreePayoutReconcileJob();

// STEP 6.4 — Razorpay Route (GenericPayoutRequest) reconciliation (no-op unless
// Razorpay Route is configured and a RAZORPAY_ROUTE payout is in flight).
const genericPayoutReconcileJob = startGenericPayoutReconcileJob();

//////////////////////////////////////////////////////////////
// 🚀 STEP 8: START SERVER
//////////////////////////////////////////////////////////////

const server = httpServer.listen(PORT, () => {
  console.log("--------------------------------------------------");
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`🗄️  MongoDB:     ${mongoose.connection.readyState === 1 ? "connected" : "connecting..."}`);
  console.log(`🧠 Redis:       ${redis.isReady ? "connected" : "unavailable"}`);
  console.log("📡 Socket.IO:   READY");
  console.log("⚙️  Jobs:        Hold Expiry + Customer Arrival + Service Overdue + Auto Complete + Reminder + Auto Start + SLA Scanner + Rating Outbox + Weekly Schedule Materializer + Field Agent KYC Sync + Fraud Detection + Cross-Agent Overlap + Territory Assignment Overlap + Field Agent Earning + OTP Audit Outbox RUNNING");
  console.log("📡 System Mode: Enterprise Ready (1 Lakh+ Scale)");
  console.log("--------------------------------------------------");
});

//////////////////////////////////////////////////////////////
// 🛑 STEP 9: GRACEFUL SHUTDOWN
//
// Order matters:
//   1. Stop accepting new HTTP connections  (server.close)
//   2. Close Socket.IO — drain open sockets (await io.close)
//   3. Close MongoDB — flush pending writes (await mongoose.connection.close)
//   4. Quit Redis     — flush pending cmds  (await redis.quit)
//   5. Exit cleanly
//
// This order prevents:
//   - New requests landing on a half-shutdown server
//   - Realtime events emitting after DB is closed
//   - Pending DB writes being lost
//   - Container restart issues in Docker / Kubernetes
//////////////////////////////////////////////////////////////

const shutdown = async (signal) => {
  console.log(`\n⚠️  ${signal} received — graceful shutdown initiated...`);

  // Stop accepting new HTTP connections
  server.close(async () => {
    try {

      // Stop background workers first — prevents any in-flight DB
      // writes from racing against MongoDB closing below.
      holdExpiryJob.stop();
      console.log("✅ Hold expiry job stopped");

      customerArrivalJob.stop();
      console.log("✅ Customer arrival job stopped");

      serviceOverdueJob.stop();
      console.log("✅ Service overdue job stopped");

      autoCompleteJob.stop();
      console.log("✅ Auto complete job stopped");

      reminderJob.stop();
      console.log("✅ Reminder job stopped");

      autoStartJob.stop();
      console.log("✅ Auto start job stopped");

      slaScannerJob.stop();
      console.log("✅ SLA scanner job stopped");

      ratingOutboxJob.stop();
      console.log("✅ Rating outbox job stopped");

      weeklyScheduleMaterializerJob.stop();
      console.log("✅ Weekly schedule materializer job stopped");

      bookingReadinessChangeJob.stop();
      console.log("✅ Booking readiness change job stopped");

      fieldAgentKycSyncJob.stop();
      console.log("✅ Field Agent KYC sync job stopped");

      fraudDetectionJob.stop();
      console.log("✅ Fraud detection job stopped");

      crossAgentOverlapJob.stop();
      console.log("✅ Cross-agent overlap job stopped");

      territoryAssignmentOverlapJob.stop();
      console.log("✅ Territory assignment overlap job stopped");

      fieldAgentEarningJob.stop();
      console.log("✅ Field Agent earning job stopped");

      otpAuditOutboxJob.stop();
      console.log("✅ OTP audit outbox job stopped");

      notificationRetryJob.stop();
      cashfreePayoutReconcileJob.stop();
      genericPayoutReconcileJob.stop();
      console.log("✅ Notification retry job stopped");

      // Drain all open sockets before closing the DB — ensures no
      // realtime emit fires against a closed MongoDB connection.
      await new Promise((resolve) => io.close(resolve));
      console.log("✅ Socket.IO closed");

      // IMPROVEMENT-2: close MongoDB — prevents hanging connections
      // and corrupted state on container restart.
      await mongoose.connection.close();
      console.log("✅ MongoDB disconnected");

      // Close Redis last — notifications / caching layer
      await redis.quit();
      console.log("✅ Redis disconnected");

      console.log("✅ Server shutdown complete");
      process.exit(0);

    } catch (err) {
      console.error("❌ Shutdown error:", err.message);
      process.exit(1);
    }
  });

  // Force-kill if graceful shutdown hangs beyond 15 seconds
  // (e.g. stuck DB query, unresponsive Redis)
  setTimeout(() => {
    console.error("❌ Shutdown timed out — forcing exit");
    process.exit(1);
  }, 15_000).unref(); // .unref() so the timer itself doesn't keep the process alive
};

//////////////////////////////////////////////////////////////
// 🛑 HANDLE TERMINATION SIGNALS
//////////////////////////////////////////////////////////////

process.on("SIGINT",  () => shutdown("SIGINT"));   // Ctrl+C in terminal
process.on("SIGTERM", () => shutdown("SIGTERM"));  // Docker / Kubernetes stop

// Catch unhandled promise rejections — log and exit rather than silently hang
process.on("unhandledRejection", (reason) => {
  console.error("❌ Unhandled Rejection:", reason);
  shutdown("unhandledRejection");
});

// Catch uncaught exceptions — always fatal, shutdown cleanly
process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught Exception:", err.message);
  shutdown("uncaughtException");
});