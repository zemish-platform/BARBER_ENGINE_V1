/**
 * BARBER_ENGINE_V1
 * backend/utils/stagingJobAllowlist.js
 *
 * STAGING-ONLY, default-deny control over the background jobs that server.js starts.
 *
 * WHY: every job (booking lifecycle, earnings, payout reconcilers, notification retry ...) scans the
 * WHOLE database it is pointed at and none of them has a staging switch. A staging service that shares a
 * database with other data would run all 19 against it the moment it boots. So on staging NO job starts
 * unless it is named, exactly, in STAGING_ENABLED_JOBS.
 *
 *   STAGING_ENABLED_JOBS   unset / blank  -> no job starts (default-deny)
 *                          "a,b"          -> only jobs a and b start
 *   - comma-separated, whitespace around an entry is trimmed; names are EXACT and CASE-SENSITIVE
 *   - an unknown name, a duplicate, an empty entry (trailing / doubled comma) is a configuration error
 *   - there is no wildcard and no "all": every job must be named
 *   - the whole list is validated BEFORE any job starts, so a bad list can never start a subset
 *
 * Scope: only NODE_ENV === "staging". On production, development, test or an unset NODE_ENV this module is a
 * pass-through and the variable is never read. Pure module: no I/O, no imports.
 *
 * The registered names are the server.js job variables without the trailing "Job", in startup order.
 * scripts/verifyStagingJobAllowlist.js proves they match the 19 start calls in server.js exactly.
 */

export const STAGING_ENABLED_JOBS_VAR = "STAGING_ENABLED_JOBS";

export const REGISTERED_JOB_NAMES = Object.freeze([
  "holdExpiry",
  "customerArrival",
  "serviceOverdue",
  "autoComplete",
  "reminder",
  "autoStart",
  "slaScanner",
  "ratingOutbox",
  "weeklyScheduleMaterializer",
  "bookingReadinessChange",
  "fieldAgentKycSync",
  "fraudDetection",
  "crossAgentOverlap",
  "territoryAssignmentOverlap",
  "fieldAgentEarning",
  "otpAuditOutbox",
  "notificationRetry",
  "cashfreePayoutReconcile",
  "genericPayoutReconcile",
]);

const REGISTERED = new Set(REGISTERED_JOB_NAMES);

const isStaging = (env) => env.NODE_ENV === "staging";

/**
 * parseStagingEnabledJobs(raw) -> { jobs: Set<string>, errors: string[] }
 * Errors carry the entry NUMBER and the rule only — never the offending text.
 */
export const parseStagingEnabledJobs = (raw) => {
  const jobs = new Set();
  const errors = [];
  if (raw === undefined || raw === null) return { jobs, errors };
  if (typeof raw !== "string") {
    errors.push(`${STAGING_ENABLED_JOBS_VAR} must be a string`);
    return { jobs, errors };
  }
  if (raw.trim() === "") return { jobs, errors }; // blank = default-deny, not an error

  raw.split(",").forEach((entry, index) => {
    const n = index + 1;
    const name = entry.trim();
    if (name === "") {
      errors.push(`${STAGING_ENABLED_JOBS_VAR} entry ${n}: empty entry (trailing or doubled comma)`);
    } else if (!REGISTERED.has(name)) {
      errors.push(`${STAGING_ENABLED_JOBS_VAR} entry ${n}: not a registered job name (names are exact and case-sensitive)`);
    } else if (jobs.has(name)) {
      errors.push(`${STAGING_ENABLED_JOBS_VAR} entry ${n}: duplicate job`);
    } else {
      jobs.add(name);
    }
  });
  return { jobs, errors };
};

/**
 * assertStagingJobAllowlist(env) -> string[]   (violations; empty = fine)
 * Used by the boot guard, which runs before app.js / Redis / MongoDB are touched.
 * Returns [] for every NODE_ENV except exactly "staging".
 */
export const assertStagingJobAllowlist = (env = process.env) => {
  if (!isStaging(env)) return [];
  return parseStagingEnabledJobs(env[STAGING_ENABLED_JOBS_VAR]).errors;
};

/**
 * createJobStarter({ env, log }) -> startJob(name, startFn)
 *
 * server.js builds the starter ONCE, before the first job, and starts every job through it:
 *   const holdExpiryJob = startJob("holdExpiry", () => startHoldExpiryJob(io));
 *
 *  - NOT staging: returns a pass-through — startFn() is called immediately and its result returned
 *    unchanged. No validation, the variable is not read.
 *  - staging: the allow-list is parsed and validated HERE, so an invalid list throws before startJob
 *    exists and therefore before any job can start. An enabled name calls startFn(); every other name
 *    is skipped and gets a no-op controller whose stop() is safe to call from the shutdown handler.
 *    A name that is not registered is a programming error and throws.
 */
export const createJobStarter = ({ env = process.env, log = console } = {}) => {
  if (!isStaging(env)) return (name, startFn) => startFn();

  const { jobs, errors } = parseStagingEnabledJobs(env[STAGING_ENABLED_JOBS_VAR]);
  if (errors.length > 0) {
    throw new Error(`invalid ${STAGING_ENABLED_JOBS_VAR}: ${errors.join("; ")}`);
  }

  log.log(
    jobs.size === 0
      ? `🔒 Staging job allow-list: 0 of ${REGISTERED_JOB_NAMES.length} jobs enabled — no background job will run (set ${STAGING_ENABLED_JOBS_VAR} to enable specific jobs)`
      : `🔒 Staging job allow-list: ${jobs.size} of ${REGISTERED_JOB_NAMES.length} jobs enabled (${[...jobs].join(", ")})`
  );

  return (name, startFn) => {
    if (!REGISTERED.has(name)) {
      throw new Error(`startJob: "${name}" is not a registered job name`);
    }
    if (!jobs.has(name)) {
      log.log(`[jobs] ${name} skipped (not in ${STAGING_ENABLED_JOBS_VAR})`);
      return { stop() {} };
    }
    return startFn();
  };
};
