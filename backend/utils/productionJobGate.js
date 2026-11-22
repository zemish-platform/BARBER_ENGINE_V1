/**
 * BARBER_ENGINE_V1
 * backend/utils/productionJobGate.js
 *
 * PRODUCTION hard-off gate for the 19 background jobs that server.js starts.
 *
 * WHY: every job (booking lifecycle, earnings, payout reconcilers, notification retry ...) scans the
 * WHOLE database it is pointed at, and on main nothing could stop them: the production service started
 * all 19 the moment it booted. The founder's rule is that all 19 stay disabled in production until an
 * explicitly approved future change.
 *
 * There is deliberately NO activation list and NO environment variable that enables a job here. Every
 * variable this module reads can only switch the gate ON, never off. When the gate is active, no job's
 * start function is ever called. Enabling any production job requires a reviewed code change to this file.
 *
 * When is the gate active? (fail-closed — ANY one of these is enough)
 *   1. Production service identity, whatever NODE_ENV says (even "staging"). Render sets these on every
 *      service at runtime (render.com/docs/environment-variables, "All runtimes"):
 *        - RENDER_SERVICE_NAME is "zemish-production-api"  (compared trimmed, case-insensitive, "_" = "-")
 *        - RENDER_SERVICE_ID   is "srv-dbfqqn7f3r2c73e79o80" (immutable; survives a rename)
 *        - RENDER_GIT_BRANCH   is "main"                     (release model: main = production)
 *   2. NODE_ENV is "production" (trimmed, case-insensitive).
 *   3. The process runs on Render (RENDER === "true", set on EVERY service) and NODE_ENV is anything other
 *      than exactly "staging" — so a production service with a missing or misspelt NODE_ENV starts no job.
 *
 * When is it a pass-through? (behaviour unchanged)
 *   - NODE_ENV exactly "staging" with no production identity: staging is governed by its own default-deny
 *     allow-list (utils/stagingJobAllowlist.js on develop, STAGING_ENABLED_JOBS). This gate never reads
 *     that variable and never overrides it. RENDER is "true" on the staging service too, which is why
 *     RENDER alone can never activate this gate for NODE_ENV=staging; the staging service's own identity
 *     (name barber-engine-v1, branch develop) matches none of the production identity values.
 *   - local development / test (no Render identity, NODE_ENV not production): every job starts as before.
 *
 * Pure module: no I/O, no imports. Values of the identity variables are never logged — only which rule
 * matched.
 *
 * The registered names are the server.js job variables without the trailing "Job", in startup order —
 * identical to REGISTERED_JOB_NAMES in develop's utils/stagingJobAllowlist.js.
 * scripts/verifyProductionJobGate.js proves they match the 19 start calls in server.js exactly.
 */

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

// The production Render service (verified in the Render dashboard). Same name as PRODUCTION_SERVICE_NAMES
// in develop's utils/environmentIdentity.js.
export const PRODUCTION_SERVICE_NAMES = Object.freeze(["zemish-production-api"]);
export const PRODUCTION_SERVICE_IDS = Object.freeze(["srv-dbfqqn7f3r2c73e79o80"]);
export const PRODUCTION_BRANCH = "main";

const REGISTERED = new Set(REGISTERED_JOB_NAMES);

const normalize = (value) => (typeof value === "string" ? value.trim().toLowerCase() : "");
const normalizeServiceName = (value) => normalize(value).replace(/_/g, "-");

/**
 * productionJobGateReasons(env) -> string[]
 * Every rule that activates the gate (empty = pass-through). Messages name the rule, never a value.
 */
export const productionJobGateReasons = (env = process.env) => {
  const reasons = [];
  if (PRODUCTION_SERVICE_NAMES.includes(normalizeServiceName(env.RENDER_SERVICE_NAME))) {
    reasons.push("RENDER_SERVICE_NAME is the production service");
  }
  if (PRODUCTION_SERVICE_IDS.includes(normalize(env.RENDER_SERVICE_ID))) {
    reasons.push("RENDER_SERVICE_ID is the production service");
  }
  if (normalize(env.RENDER_GIT_BRANCH) === PRODUCTION_BRANCH) {
    reasons.push(`RENDER_GIT_BRANCH is "${PRODUCTION_BRANCH}"`);
  }
  if (env.NODE_ENV !== "staging") {
    if (normalize(env.NODE_ENV) === "production") {
      reasons.push("NODE_ENV is production");
    } else if (normalize(env.RENDER) === "true") {
      reasons.push('running on Render with NODE_ENV not exactly "staging"');
    }
  }
  return reasons;
};

/** isProductionJobGateActive(env) -> boolean */
export const isProductionJobGateActive = (env = process.env) => productionJobGateReasons(env).length > 0;

// Controllers handed out for disabled jobs, so shutdown logging can tell them from real ones.
const disabledControllers = new WeakSet();

/** isDisabledJobController(controller) -> true only for a controller this gate returned for a disabled job */
export const isDisabledJobController = (controller) =>
  typeof controller === "object" && controller !== null && disabledControllers.has(controller);

/**
 * createProductionJobGate({ env, log, onDisabled }) -> startJob(name, startFn)
 *
 * server.js builds the gate ONCE, before the first job, and starts every job through it:
 *   const holdExpiryJob = startJob("holdExpiry", () => startHoldExpiryJob(io));
 *
 *  - a name that is not registered is a programming error and throws, whether or not the gate is active.
 *  - gate active: startFn is NEVER called; onDisabled(name) is called (monitoring) and the job gets a
 *    no-op controller whose stop() is safe to call from the shutdown handler.
 *  - gate inactive: startFn() is called immediately and its result returned unchanged.
 */
export const createProductionJobGate = ({ env = process.env, log = console, onDisabled = () => {} } = {}) => {
  const reasons = productionJobGateReasons(env);
  const active = reasons.length > 0;

  if (active) {
    log.log(
      `🔒 Production job gate: 0 of ${REGISTERED_JOB_NAMES.length} background jobs enabled — ` +
      `all disabled (${reasons.join("; ")}). There is no activation list; enabling a job requires an approved code change.`
    );
  }

  return (name, startFn) => {
    if (!REGISTERED.has(name)) {
      throw new Error(`startJob: "${name}" is not a registered job name`);
    }
    if (active) {
      log.log(`[jobs] ${name} disabled (production job gate)`);
      onDisabled(name);
      const controller = { stop() {} };
      disabledControllers.add(controller);
      return controller;
    }
    return startFn();
  };
};
