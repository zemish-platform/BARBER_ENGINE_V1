/**
 * BARBER_ENGINE_V1
 * backend/utils/environmentIdentity.js
 *
 * Fail-closed detection of "this process is running as the wrong environment".
 *
 * WHY: staging mode is switched on by NODE_ENV === "staging" (utils/stagingGuards.js), but
 * Render sets NODE_ENV=production by default for Node services, so a staging service that
 * nobody explicitly configured silently runs in production mode with every staging check
 * switched off. Render also exposes identity variables the app cannot misconfigure itself
 * (documented defaults: RENDER, RENDER_SERVICE_NAME, RENDER_GIT_BRANCH), so we cross-check NODE_ENV
 * against them. The service name is an editable label, so on its own it is a fail-open signal (a
 * renamed or unlabelled staging service matches nothing); the deployed git branch is a second,
 * independent signal that survives a rename: this repository's release model is develop = staging,
 * main = production.
 *
 * Rules (only ever evaluated when RENDER === "true"; locally and in CI they are inert):
 *   R-ID-1  the service is a known staging service        but NODE_ENV is not exactly "staging"
 *   R-ID-2  the service is a known production service     but NODE_ENV is "staging"
 *   R-ID-3  NODE_ENV is "staging"                          but the service is not a known staging service
 *   R-ID-4  the service deploys branch "develop"           but NODE_ENV is not exactly "staging"
 *           (regardless of the service name — missing, renamed or even a production name)
 *   R-ID-5  NODE_ENV is "staging"                          but the service deploys branch "main"
 *           (contradictory: production's branch running in staging mode)
 *   R-ID-6  any staging-only variable is set               but NODE_ENV is not exactly "staging"
 *           (regardless of service name AND branch — the rename-proof, branch-proof signal)
 *
 * R-ID-6 closes the case the name and branch rules cannot see: a RENAMED staging service deploying
 * a branch other than develop and left on Render's default NODE_ENV=production. From inside the
 * process that is otherwise indistinguishable from a production hotfix deploy, so the only
 * reliable evidence is what the operator configured: the variables below exist ONLY to configure
 * staging (the guard itself reads them in utils/stagingGuards.js) and have no meaning on
 * production. A process that carries one is a staging process, and must run as staging. Only the
 * variable NAMES are ever reported, never values. Operational consequence: production must not
 * carry any of them (it should not — they hold the deny-list of production's own endpoints and the
 * staging test logins).
 *
 * Still NOT detectable, by design: a renamed staging service on another branch with NO staging
 * variable configured at all — it looks exactly like production; prevent it by pinning
 * NODE_ENV=staging in the service configuration (nothing in code can tell it from production).
 *
 * A missing/empty RENDER_GIT_BRANCH (e.g. an image-based deploy) provides no branch signal: R-ID-4/5
 * stay silent rather than refusing, so production cannot be blocked by an absent variable; the
 * service-name rules still apply. Other branches (previews, hotfixes) give no signal either.
 * Branch values are compared trimmed and case-insensitively.
 *
 * Service names are compared case-insensitively with "_" treated as "-" (Render service names
 * are editable labels, e.g. "BARBER_ENGINE_V1"). Production only ever has NODE_ENV=production, so
 * none of these rules can fire there unless the production service were renamed to a staging
 * name or NODE_ENV were set to "staging" on it — both of which SHOULD stop the boot.
 * Adding another staging service means adding its name below in a reviewed change.
 */

export const STAGING_SERVICE_NAMES = Object.freeze(["barber-engine-v1"]);
export const PRODUCTION_SERVICE_NAMES = Object.freeze(["zemish-production-api"]);

// The environment variables that only ever configure staging (all are read in utils/stagingGuards.js;
// a test keeps this list equal to the guard's actual reads).
export const STAGING_MARKER_VARIABLES = Object.freeze([
  "STAGING_TEST_LOGINS",
  "STAGING_FORBIDDEN_MONGO_ENDPOINTS",
  "STAGING_FORBIDDEN_REDIS_ENDPOINTS",
  "STAGING_ACK_SHARED_DEV_DATABASE",
  "STAGING_SMS_OTP_MODE",
  "STAGING_SMS_ALLOWED_PHONES",
]);

export const STAGING_BRANCH = "develop";
export const PRODUCTION_BRANCH = "main";

export const normalizeServiceName = (value) =>
  String(value ?? "").trim().toLowerCase().replace(/_/g, "-");

export const normalizeBranch = (value) => String(value ?? "").trim().toLowerCase();

const isBlank = (value) => typeof value !== "string" || value.trim() === "";

export const isRenderRuntime = (env = process.env) => env.RENDER === "true";

/** assertEnvironmentIdentity(env) -> string[]  (violation messages; empty = consistent) */
export const assertEnvironmentIdentity = (env = process.env) => {
  if (!isRenderRuntime(env)) return [];
  const violations = [];
  const name = normalizeServiceName(env.RENDER_SERVICE_NAME);
  const isStagingService = STAGING_SERVICE_NAMES.includes(name);
  const isProductionService = PRODUCTION_SERVICE_NAMES.includes(name);

  if (isStagingService && env.NODE_ENV !== "staging") {
    violations.push(
      'This Render service is a staging service but NODE_ENV is not exactly "staging" (Render defaults NODE_ENV to production) — set NODE_ENV=staging'
    );
  }
  if (isProductionService && env.NODE_ENV === "staging") {
    violations.push('This Render service is a production service but NODE_ENV is "staging"');
  }
  if (env.NODE_ENV === "staging" && !isStagingService) {
    violations.push('NODE_ENV is "staging" but this Render service is not a known staging service');
  }

  const branch = normalizeBranch(env.RENDER_GIT_BRANCH);
  if (branch === STAGING_BRANCH && env.NODE_ENV !== "staging") {
    violations.push(
      `This Render service deploys branch "${STAGING_BRANCH}" (staging) but NODE_ENV is not exactly "staging" — set NODE_ENV=staging; a service deploying "${STAGING_BRANCH}" must not run in any other mode, whatever its name`
    );
  }
  if (branch === PRODUCTION_BRANCH && env.NODE_ENV === "staging") {
    violations.push(`NODE_ENV is "staging" but this Render service deploys branch "${PRODUCTION_BRANCH}" (production)`);
  }

  if (env.NODE_ENV !== "staging") {
    const present = STAGING_MARKER_VARIABLES.filter((name) => !isBlank(env[name]));
    if (present.length > 0) {
      violations.push(
        `Staging-only configuration is present (${present.join(", ")}) but NODE_ENV is not exactly "staging" — this service is a staging service whatever its name or branch; set NODE_ENV=staging, or remove the staging variables if this is not staging`
      );
    }
  }
  return violations;
};
