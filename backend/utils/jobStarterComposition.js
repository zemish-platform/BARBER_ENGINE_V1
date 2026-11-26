/**
 * BARBER_ENGINE_V1
 * backend/utils/jobStarterComposition.js
 *
 * Composes the two background-job controls into the single startJob() that server.js uses:
 *
 *   outer: utils/productionJobGate.js   — production hard-off gate (no activation list; production identity
 *                                         and NODE_ENV=production fail closed)
 *   inner: utils/stagingJobAllowlist.js — staging default-deny allow-list (STAGING_ENABLED_JOBS), a
 *                                         pass-through everywhere except NODE_ENV=staging
 *
 * server.js:
 *   startJob = withProductionJobGate(createJobStarter({ env: process.env }), { env: process.env, onDisabled: recordJobDisabled });
 *
 *  - production gate active: the staging starter is NEVER called, so no environment variable — including
 *    STAGING_ENABLED_JOBS — can start a production job.
 *  - production gate inactive: the staging starter decides exactly as before (same logs, same validation,
 *    same controllers); on local development it is a pass-through, so every job starts as before.
 *  - a job that the staging allow-list skips is reported to onDisabled (GET /health/ops shows it as
 *    DISABLED) and its controller is recognisable via isSkippedJobController() for shutdown logging.
 *
 * Neither module is modified by this composition. Pure module: no I/O.
 */

import { createProductionJobGate, isDisabledJobController } from "./productionJobGate.js";

// Controllers of jobs that the INNER (staging) starter did not start.
const skippedControllers = new WeakSet();

/** isSkippedJobController(controller) -> true only for a job the staging allow-list did not start */
export const isSkippedJobController = (controller) =>
  typeof controller === "object" && controller !== null && skippedControllers.has(controller);

/**
 * withProductionJobGate(innerStarter, { env, log, onDisabled }) -> startJob(name, startFn)
 * innerStarter is the startJob returned by createJobStarter() (utils/stagingJobAllowlist.js).
 */
export const withProductionJobGate = (innerStarter, { env = process.env, log = console, onDisabled = () => {} } = {}) => {
  if (typeof innerStarter !== "function") {
    throw new Error("withProductionJobGate: innerStarter must be the startJob function from createJobStarter()");
  }
  const productionGate = createProductionJobGate({ env, log, onDisabled });

  return (name, startFn) => {
    let started = false;
    const controller = productionGate(name, () => innerStarter(name, () => {
      started = true;
      return startFn();
    }));
    if (!started && !isDisabledJobController(controller)) {
      skippedControllers.add(controller);
      onDisabled(name);
    }
    return controller;
  };
};
