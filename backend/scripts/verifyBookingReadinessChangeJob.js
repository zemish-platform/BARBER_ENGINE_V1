/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyBookingReadinessChangeJob.js
 *
 * Static, file-based regression check for the Booking Readiness
 * Change job (R4 — approved pilot). Same convention as every other
 * verify*.js script in this folder: NO database connection, creates
 * NO salon/booking/notification, sends NO real push — reads the
 * modified/new source files directly off disk and asserts against
 * their literal text.
 *
 * Run:  cd backend && node scripts/verifyBookingReadinessChangeJob.js
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let pass = 0, fail = 0;
const rows = [];
const check = (name, cond) => {
  if (cond) { pass++; rows.push(`  ✅ ${name}`); }
  else      { fail++; rows.push(`  ❌ ${name}`); }
};

const jobPath         = path.resolve(__dirname, "../jobs/bookingReadinessChange.job.js");
const serverPath      = path.resolve(__dirname, "../server.js");
const eventsConstPath = path.resolve(__dirname, "../modules/notifications/constants/notificationEvents.constants.js");
const readinessSvcPath = path.resolve(__dirname, "../services/bookingReadiness.service.js");
const readinessCtrlPath = path.resolve(__dirname, "../controllers/salon.readiness.controller.js");

const salonAppRoot = path.resolve(__dirname, "../../salon-app/src");
const ownerPushPath = path.join(salonAppRoot, "features/notifications/ownerPushNotificationService.js");
const ownerNotifsScreenPath = path.join(salonAppRoot, "features/notifications/screens/NotificationsScreen.js");

const jobSrc          = fs.readFileSync(jobPath, "utf8");
const serverSrc       = fs.readFileSync(serverPath, "utf8");
const eventsConstSrc  = fs.readFileSync(eventsConstPath, "utf8");
const readinessSvcSrc = fs.readFileSync(readinessSvcPath, "utf8");
const readinessCtrlSrc = fs.readFileSync(readinessCtrlPath, "utf8");
const ownerPushSrc    = fs.readFileSync(ownerPushPath, "utf8");
const ownerNotifsSrc  = fs.readFileSync(ownerNotifsScreenPath, "utf8");

// ── 1. New event key — additive only ──────────────────────────────
check(
  "notificationEvents.constants.js: BOOKING_READINESS_CHANGED key added",
  /BOOKING_READINESS_CHANGED:\s*"BOOKING_READINESS_CHANGED"/.test(eventsConstSrc)
);
check(
  "notificationEvents.constants.js: pre-existing SALON_APPROVED/SALON_REJECTED keys untouched",
  eventsConstSrc.includes('SALON_APPROVED: "SALON_APPROVED"') &&
  eventsConstSrc.includes('SALON_REJECTED: "SALON_REJECTED"')
);

// ── 2. Frozen readiness engine/controller NOT modified ─────────────
check(
  "services/bookingReadiness.service.js: untouched (no job-specific reference leaked into the frozen engine)",
  !readinessSvcSrc.includes("bookingReadinessChange") && !readinessSvcSrc.includes("lastKnownBySalon")
);
check(
  "controllers/salon.readiness.controller.js: untouched (still the original unscoped-but-frozen owner resolution, no job reference)",
  !readinessCtrlSrc.includes("bookingReadinessChange") &&
  readinessCtrlSrc.includes("const salon = await Salon.findOne({ ownerId, isDeleted: { $ne: true } })")
);

// ── 3. Job calls getBookingReadiness() unmodified, with explicit salonId ──
check(
  "job: imports getBookingReadiness from the real, unmodified service file",
  /import\s*\{\s*getBookingReadiness\s*\}\s*from\s*"\.\.\/services\/bookingReadiness\.service\.js"/.test(jobSrc)
);
check(
  "job: calls getBookingReadiness({ salonId: salon._id, date }) — no extra/altered params",
  /getBookingReadiness\(\{\s*salonId:\s*salon\._id,\s*date\s*\}\)/.test(jobSrc)
);

// ── 4. Explicit per-salon iteration — never Salon.findOne({ownerId}) ──
// Scoped to the actual executable query-builder function, not the
// whole file — the file's own header comments legitimately mention
// `Salon.findOne({ownerId})` as the OTHER controllers' documented
// pattern this job must NOT repeat; that prose reference must not
// make this check fail.
const buildCandidateSalonQueryBody = (() => {
  const start = jobSrc.indexOf("const buildCandidateSalonQuery = ()");
  const end   = jobSrc.indexOf("\n});", start);
  return start !== -1 ? jobSrc.slice(start, end === -1 ? undefined : end) : "";
})();
check(
  "job: iterates Salon.find(...) by approval.status/isDeleted — never Salon.findOne({ownerId})",
  /Salon\.find\(buildCandidateSalonQuery\(\)\)/.test(jobSrc) &&
  !buildCandidateSalonQueryBody.includes("findOne") &&
  buildCandidateSalonQueryBody.length > 0
);
check(
  'job: candidate query filters approval.status==="APPROVED" and isDeleted!==true',
  /"approval\.status":\s*"APPROVED"/.test(jobSrc) && /isDeleted:\s*\{\s*\$ne:\s*true\s*\}/.test(jobSrc)
);

// ── 5. Silent baseline + dedup-by-(status,reasonCode) ──────────────
// checkOneSalon's own function body only — avoids matching the
// header comment's prose reference to the same variable name.
const checkOneSalonBody = (() => {
  const start = jobSrc.indexOf("const checkOneSalon = async");
  const end   = jobSrc.indexOf("\n};", start);
  return start !== -1 ? jobSrc.slice(start, end === -1 ? undefined : end) : "";
})();
check(
  "job: first-ever sighting of a salon establishes a silent baseline (no notify)",
  /if \(previousKey === undefined\) \{[\s\S]{0,200}return \{ outcome: "baseline" \};/.test(checkOneSalonBody)
);
check(
  "job: unchanged (status,reasonCode) key never re-notifies",
  /if \(previousKey === currentKey\) \{[\s\S]{0,200}return \{ outcome: "unchanged" \};/.test(checkOneSalonBody)
);
check(
  "job: dedup key is built from BOTH status and the first blocking reason code (reason-only change still counts as a transition)",
  /buildKey\s*=\s*\(status,\s*reasonCode\)\s*=>\s*`\$\{status\}::\$\{reasonCode\s*\?\?\s*"NONE"\}`/.test(jobSrc) &&
  jobSrc.includes("readiness.blockingReasons?.[0]?.code ?? null")
);

// ── 6. All 3 statuses have title copy; NEEDS_ATTENTION/NOT_READY use the real humanMessage ──
check(
  "job: STATUS_TITLES covers READY, NEEDS_ATTENTION, and NOT_READY",
  /READY:\s*"Your salon is ready"/.test(jobSrc) &&
  /NEEDS_ATTENTION:\s*"Needs attention"/.test(jobSrc) &&
  /NOT_READY:\s*"Booking not ready"/.test(jobSrc)
);
check(
  "job: NEEDS_ATTENTION/NOT_READY message is the real blockingReasons[0].humanMessage, never invented",
  jobSrc.includes("readiness.blockingReasons?.[0]?.humanMessage")
);
check(
  'job: READY message is the exact existing Dashboard copy ("Your salon is ready to accept bookings.")',
  jobSrc.includes('"Your salon is ready to accept bookings."')
);

// ── 7. Correct recipient + both channels + OPEN_HOME deep link ─────
check(
  "job: recipientId is salon._id, recipientType is \"SALON\"",
  /recipientId:\s*salon\._id,\s*recipientType:\s*"SALON"/.test(jobSrc)
);
check(
  "job: sends [IN_APP, PUSH] — both existing channels",
  /\},\s*\[\s*NOTIFICATION_CHANNEL\.IN_APP\s*,\s*NOTIFICATION_CHANNEL\.PUSH\s*\]\s*\)/.test(jobSrc)
);
check(
  "job: actionType is OPEN_HOME (the pre-existing, previously-dormant enum value) with actionUrl /dashboard",
  jobSrc.includes('actionType:    "OPEN_HOME"') && jobSrc.includes('actionUrl:     "/dashboard"')
);
check(
  "job: templateKey is NOTIFICATION_EVENTS.BOOKING_READINESS_CHANGED",
  jobSrc.includes("templateKey:   NOTIFICATION_EVENTS.BOOKING_READINESS_CHANGED")
);

// ── 8. Per-salon failure isolation + clean stop ─────────────────────
check(
  "job: a per-salon error is caught inside the loop (does not abort the whole run)",
  /for \(const salon of salons\) \{[\s\S]*?try \{[\s\S]*?checkOneSalon\(salon\)[\s\S]*?\} catch \(err\) \{/.test(jobSrc)
);
check(
  "job: exports startBookingReadinessChangeJob returning { stop }",
  jobSrc.includes("export const startBookingReadinessChangeJob = () =>") &&
  /return \{\s*stop:\s*\(\)\s*=>\s*\{\s*clearInterval\(intervalHandle\);/.test(jobSrc)
);

// ── 9. server.js wiring — import, start, stop, alongside existing jobs ──
check(
  "server.js: imports startBookingReadinessChangeJob",
  /import\s*\{\s*startBookingReadinessChangeJob\s*\}\s*from\s*"\.\/jobs\/bookingReadinessChange\.job\.js"/.test(serverSrc)
);
check(
  "server.js: starts the job (const bookingReadinessChangeJob = startBookingReadinessChangeJob();)",
  /const bookingReadinessChangeJob = startBookingReadinessChangeJob\(\);/.test(serverSrc)
);
check(
  "server.js: stops the job in shutdown alongside the other existing jobs",
  /bookingReadinessChangeJob\.stop\(\);/.test(serverSrc)
);
check(
  "server.js: every pre-existing job start call (autoComplete/autoStart/weeklyScheduleMaterializer) still present, untouched",
  serverSrc.includes("const autoCompleteJob = startAutoCompleteJob(io);") &&
  serverSrc.includes("const autoStartJob = startAutoStartJob(io);") &&
  serverSrc.includes("const weeklyScheduleMaterializerJob = startWeeklyScheduleMaterializerJob();")
);

// ── 10. Salon App — OPEN_HOME added, OPEN_BOOKING preserved ─────────
check(
  "ownerPushNotificationService.js: OPEN_HOME maps to ROUTES.DASHBOARD",
  /OPEN_HOME:\s*ROUTES\.DASHBOARD/.test(ownerPushSrc)
);
check(
  "ownerPushNotificationService.js: OPEN_BOOKING still maps to ROUTES.LIVE_SCHEDULE, unchanged",
  /OPEN_BOOKING:\s*ROUTES\.LIVE_SCHEDULE/.test(ownerPushSrc)
);
check(
  "ownerPushNotificationService.js: resolveOwnerDeepLinkTarget/registerOwnerNotificationListeners logic untouched",
  ownerPushSrc.includes("export const resolveOwnerDeepLinkTarget = (data) => {") &&
  ownerPushSrc.includes("export const registerOwnerNotificationListeners = (navigationRef) => {")
);
check(
  "NotificationsScreen.js (salon-app): OPEN_HOME navigates to ROUTES.DASHBOARD under the SYSTEM case",
  /case "SYSTEM":[\s\S]*?item\.actionType === "OPEN_HOME"[\s\S]*?navigation\.navigate\(ROUTES\.DASHBOARD\)/.test(ownerNotifsSrc)
);
check(
  "NotificationsScreen.js (salon-app): pre-existing OPEN_PROFILE/kyc branch and other type cases untouched",
  ownerNotifsSrc.includes('if (item.actionType === "OPEN_PROFILE" && item.actionUrl === "/kyc")') &&
  ownerNotifsSrc.includes('case "BOOKING": return navigation.navigate(ROUTES.BOOKING_HISTORY);')
);

console.log(rows.join("\n"));
console.log(`\nRESULT: ${fail === 0 ? "ALL PASS" : "SOME FAILED"} — ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
