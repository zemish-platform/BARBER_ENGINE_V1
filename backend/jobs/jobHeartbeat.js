//////////////////////////////////////////////////////////////
// BARBER_ENGINE_V1 — backend/jobs/jobHeartbeat.js
// P0-4 — Background Job Monitoring / Heartbeat
//
// Pure observability layer over the 9 existing setInterval-based
// background jobs. Does NOT change how any job runs — it only records
// what already happened, so silent job death becomes visible via
// GET /health/ops instead of going unnoticed.
//
// In-memory, module-level registry — sufficient for the current
// single/few-instance deployment (no Redis/distributed state; state
// resets on restart, which self-heals within seconds since every job
// already runs once immediately on startup). Two-instance deployments
// each see only their own local jobs — a known, accepted limitation,
// not something this module tries to solve.
//
// STALE THRESHOLD FORMULA: staleAfterMs = 3 * intervalMs, derived once
// from the interval passed to recordStart()'s metadata — never a
// separate hardcoded per-job table that could drift out of sync with
// the job's real interval.
//////////////////////////////////////////////////////////////

const STALE_MULTIPLIER = 3;
const MAX_FAILURE_MESSAGE_LENGTH = 300;

// name -> {
//   intervalMs, staleAfterMs,
//   isRunning,
//   lastStartedAt, lastSuccessAt, lastFailureAt,
//   lastFailureMessage, consecutiveFailures,
// }
const registry = new Map();

function getOrCreateEntry(name, intervalMs) {
  let entry = registry.get(name);
  if (!entry) {
    entry = {
      intervalMs: intervalMs ?? null,
      staleAfterMs: intervalMs != null ? intervalMs * STALE_MULTIPLIER : null,
      isRunning: false,
      lastStartedAt: null,
      lastSuccessAt: null,
      lastFailureAt: null,
      lastFailureMessage: null,
      consecutiveFailures: 0,
      disabled: false,
    };
    registry.set(name, entry);
  } else if (intervalMs != null && entry.intervalMs == null) {
    entry.intervalMs = intervalMs;
    entry.staleAfterMs = intervalMs * STALE_MULTIPLIER;
  }
  return entry;
}

// Sanitize a failure message down to a short, bounded, stack-free
// string — never expose err.stack, request payloads, DB documents,
// tokens, or any other sensitive detail via this module.
function sanitizeMessage(err) {
  const raw = err?.message ?? String(err ?? "Unknown error");
  return raw.length > MAX_FAILURE_MESSAGE_LENGTH
    ? raw.slice(0, MAX_FAILURE_MESSAGE_LENGTH) + "…"
    : raw;
}

/**
 * Call at the top of a job's tick, inside its existing control flow —
 * i.e. only on ticks that actually proceed past the job's own
 * isRunning guard. `metadata.intervalMs` only needs to be passed once
 * (the job's own INTERVAL_MS constant); subsequent calls may omit it.
 */
export function recordStart(name, metadata = {}) {
  const entry = getOrCreateEntry(name, metadata.intervalMs);
  entry.isRunning = true;
  entry.lastStartedAt = new Date();
}

/**
 * Call ONLY at the point where the job's own OUTER try block completes
 * without throwing — never from inside a per-item/batch-level catch
 * that the job already handles and continues past.
 */
export function recordSuccess(name) {
  const entry = getOrCreateEntry(name);
  entry.isRunning = false;
  entry.lastSuccessAt = new Date();
  entry.consecutiveFailures = 0;
}

/**
 * Call ONLY from a job's OUTER catch block — the same catch that
 * already logs the failure today. Does not alter that existing
 * error handling in any way.
 */
export function recordFailure(name, err) {
  const entry = getOrCreateEntry(name);
  entry.isRunning = false;
  entry.lastFailureAt = new Date();
  entry.lastFailureMessage = sanitizeMessage(err);
  entry.consecutiveFailures += 1;
}

/**
 * Called by server.js (via utils/productionJobGate.js) for a job that was
 * intentionally NOT started. Reported as status "DISABLED", which the
 * overall rollup does not count as STALE / NEVER_RAN / FAILED. A job that
 * nevertheless records a start is reported from its real timings again.
 */
export function recordDisabled(name) {
  const entry = getOrCreateEntry(name);
  entry.disabled = true;
}

function computeStatus(entry, now) {
  if (entry.disabled && !entry.lastStartedAt) return "DISABLED";
  if (!entry.lastStartedAt) return "NEVER_RAN";
  if (entry.isRunning) return "RUNNING";

  const referenceAt = entry.lastSuccessAt ?? entry.lastStartedAt;
  const ageSinceSuccessMs = now.getTime() - referenceAt.getTime();

  if (entry.staleAfterMs != null && ageSinceSuccessMs > entry.staleAfterMs) {
    return "STALE";
  }

  const failedMoreRecentlyThanSucceeded =
    entry.lastFailureAt &&
    (!entry.lastSuccessAt || entry.lastFailureAt > entry.lastSuccessAt);

  return failedMoreRecentlyThanSucceeded ? "FAILED" : "HEALTHY";
}

/**
 * Returns the full per-job status snapshot plus an overall rollup —
 * read-only, safe to call as often as needed (e.g. from GET /health/ops).
 */
export function getStatus() {
  const now = new Date();
  const jobs = [];

  for (const [name, entry] of registry.entries()) {
    const status = computeStatus(entry, now);
    const referenceAt = entry.lastSuccessAt ?? entry.lastStartedAt;
    jobs.push({
      name,
      intervalMs: entry.intervalMs,
      staleAfterMs: entry.staleAfterMs,
      status,
      disabled: entry.disabled,
      isRunning: entry.isRunning,
      lastStartedAt: entry.lastStartedAt ? entry.lastStartedAt.toISOString() : null,
      lastSuccessAt: entry.lastSuccessAt ? entry.lastSuccessAt.toISOString() : null,
      lastFailureAt: entry.lastFailureAt ? entry.lastFailureAt.toISOString() : null,
      consecutiveFailures: entry.consecutiveFailures,
      lastFailureMessage: entry.lastFailureMessage,
      ageSinceSuccessMs: referenceAt ? now.getTime() - referenceAt.getTime() : null,
    });
  }

  const hasStaleOrNeverRan = jobs.some((j) => j.status === "STALE" || j.status === "NEVER_RAN");
  const hasFailed = jobs.some((j) => j.status === "FAILED");

  const overallStatus = hasStaleOrNeverRan ? "UNHEALTHY" : hasFailed ? "DEGRADED" : "HEALTHY";

  return { overallStatus, evaluatedAt: now.toISOString(), jobs };
}
