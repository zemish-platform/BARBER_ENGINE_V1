/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyJobStarterComposition.js
 *
 * Behavioural verification of the composed background-job starter (utils/jobStarterComposition.js):
 * the production job gate (utils/productionJobGate.js) wrapped around the staging allow-list
 * (utils/stagingJobAllowlist.js), exactly as server.js builds it:
 *
 *   startJob = withProductionJobGate(createJobStarter({ env }), { env, onDisabled })
 *
 * Proves, for both environments:
 *   - production (and the production Render identity, whatever NODE_ENV says): 0 of 19 start, the staging
 *     starter is never even called, and no value of STAGING_ENABLED_JOBS changes that;
 *   - staging: every decision, log line and controller is EXACTLY what the staging allow-list alone produces;
 *     the actual staging configuration (STAGING_ENABLED_JOBS unset) starts 0 of 19;
 *   - local development: every job starts, as before.
 *
 * Hermetic by design — stub start functions only; never starts the backend, no database, no network.
 *
 *   cd backend && node scripts/verifyJobStarterComposition.js
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createJobStarter, REGISTERED_JOB_NAMES as STAGING_NAMES } from "../utils/stagingJobAllowlist.js";
import { isDisabledJobController, isProductionJobGateActive, REGISTERED_JOB_NAMES } from "../utils/productionJobGate.js";
import { isSkippedJobController, withProductionJobGate } from "../utils/jobStarterComposition.js";
import { getStatus as getHeartbeatStatus, recordDisabled } from "../jobs/jobHeartbeat.js";

// ─── tiny harness ───────────────────────────────────────────────────────────
const results = [];
const test = async (id, name, fn) => {
  try {
    await fn();
    results.push({ id, ok: true });
    console.log(`  ✅ ${id} ${name}`);
  } catch (error) {
    results.push({ id, ok: false });
    console.log(`  ❌ ${id} ${name} — ${String(error?.message || error)}`);
  }
};
const expect = (condition, label) => { if (!condition) throw new Error(label); };
const section = (title) => console.log(`\n── ${title} ──`);
const quietLog = () => { const lines = []; return { lines, log: { log: (m) => lines.push(String(m)) } }; };

const PROD_IDENTITY = { RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", RENDER_SERVICE_ID: "srv-dbfqqn7f3r2c73e79o80", RENDER_GIT_BRANCH: "main" };
const STAGING_IDENTITY = { RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1", RENDER_SERVICE_ID: "srv-d5vl9ssoud1c738ldjmg", RENDER_GIT_BRANCH: "develop" };
const ALL = REGISTERED_JOB_NAMES.join(",");

/**
 * Runs all 19 stub jobs through a starter, in server.js order.
 * compose=false: the staging allow-list alone (develop before this change).
 * compose=true:  the server.js composition.
 * Returns { threw, started[], controllers{}, lines[], disabledReports[], innerCalls[] }.
 */
const run = (env, { compose }) => {
  const { lines, log } = quietLog();
  const disabledReports = [];
  const innerCalls = [];
  const started = [];
  let startJob;
  try {
    const inner = createJobStarter({ env, log });
    const spyInner = (name, fn) => { innerCalls.push(name); return inner(name, fn); };
    startJob = compose ? withProductionJobGate(spyInner, { env, log, onDisabled: (n) => disabledReports.push(n) }) : spyInner;
  } catch (error) {
    return { threw: true, message: error.message, started, controllers: {}, lines, disabledReports, innerCalls };
  }
  const controllers = {};
  for (const name of REGISTERED_JOB_NAMES) {
    const own = { stop() {}, owner: name };
    controllers[name] = startJob(name, () => { started.push(name); return own; });
    if (started.at(-1) === name) expect(controllers[name] === own, `${name}: started controller not returned unchanged`);
  }
  return { threw: false, started, controllers, lines, disabledReports, innerCalls };
};

const STAGING_VALUES = [undefined, "", "   ", "holdExpiry", "reminder, holdExpiry,genericPayoutReconcile", ALL, "otpAuditOutbox", "bad,,", "HoldExpiry", "holdExpiry,holdExpiry", "notAJob"];
const withList = (env, value) => (value === undefined ? { ...env } : { ...env, STAGING_ENABLED_JOBS: value });

console.log("Job starter composition — production gate + staging allow-list (hermetic; stub jobs only; the backend is never started)");

// ═══ R — the two registries agree ═════════════════════════════════════════
section("R  registries");

await test("R1", "production gate and staging allow-list register the same 19 names in the same order", async () => {
  expect(JSON.stringify(REGISTERED_JOB_NAMES) === JSON.stringify(STAGING_NAMES), "registries differ");
  expect(REGISTERED_JOB_NAMES.length === 19, "not 19 names");
});

await test("R2", "withProductionJobGate rejects anything but a starter function", async () => {
  for (const bad of [undefined, null, {}, "startJob"]) {
    let threw = false;
    try { withProductionJobGate(bad, { env: {} }); } catch { threw = true; }
    expect(threw, `${JSON.stringify(bad)} accepted`);
  }
});

// ═══ P — production: always 0 of 19, staging starter never consulted ══════
section("P  production: 0 of 19, whatever STAGING_ENABLED_JOBS says");

const PRODUCTION_ENVS = [
  ["NODE_ENV=production", { NODE_ENV: "production" }],
  ["the production service", { ...PROD_IDENTITY, NODE_ENV: "production" }],
  ["the production service with NODE_ENV unset", { ...PROD_IDENTITY }],
  ["the production service with NODE_ENV=staging (conflict)", { ...PROD_IDENTITY, NODE_ENV: "staging" }],
  ["staging name but branch main, NODE_ENV=staging (conflict)", { ...STAGING_IDENTITY, RENDER_GIT_BRANCH: "main", NODE_ENV: "staging" }],
  ["Render, NODE_ENV misspelt 'Staging'", { ...STAGING_IDENTITY, NODE_ENV: "Staging" }],
];
let n = 0;
for (const [label, env] of PRODUCTION_ENVS) {
  for (const value of STAGING_VALUES) {
    n += 1;
    await test(`P${n}`, `${label}, STAGING_ENABLED_JOBS=${JSON.stringify(value)} → 0 started, or refuses to boot`, async () => {
      const r = run(withList(env, value), { compose: true });
      expect(r.started.length === 0, `started: ${r.started.join(",")}`);
      if (r.threw) return; // the staging allow-list rejected an invalid list before any starter existed (NODE_ENV=staging only)
      expect(isProductionJobGateActive(withList(env, value)), "gate not active");
      expect(r.innerCalls.length === 0, `staging starter consulted for: ${r.innerCalls.join(",")}`);
      expect(r.disabledReports.join(",") === ALL, "not all 19 reported as disabled");
      expect(REGISTERED_JOB_NAMES.every((name) => isDisabledJobController(r.controllers[name])), "a controller is not a gate-disabled controller");
      expect(REGISTERED_JOB_NAMES.every((name) => !isSkippedJobController(r.controllers[name])), "a gate-disabled controller is also flagged skipped");
    });
  }
}

// ═══ S — staging: identical to the staging allow-list alone ═══════════════
section("S  staging: decisions, logs and controllers identical to the allow-list alone");

const STAGING_ENVS = [
  ["the staging service (NODE_ENV=staging + its Render identity)", { ...STAGING_IDENTITY, NODE_ENV: "staging" }],
  ["NODE_ENV=staging, Render, no identity variables", { NODE_ENV: "staging", RENDER: "true" }],
  ["NODE_ENV=staging, off Render", { NODE_ENV: "staging" }],
];
n = 0;
for (const [label, env] of STAGING_ENVS) {
  for (const value of STAGING_VALUES) {
    n += 1;
    await test(`S${n}`, `${label}, STAGING_ENABLED_JOBS=${JSON.stringify(value)}`, async () => {
      const alone = run(withList(env, value), { compose: false });
      const composed = run(withList(env, value), { compose: true });
      expect(alone.threw === composed.threw, "one threw, the other did not");
      if (alone.threw) {
        expect(alone.message === composed.message, "different validation error");
        return;
      }
      expect(alone.started.join(",") === composed.started.join(","), `started differs: ${alone.started} vs ${composed.started}`);
      expect(alone.lines.join("\n") === composed.lines.join("\n"), "log lines differ");
      const skipped = REGISTERED_JOB_NAMES.filter((name) => !composed.started.includes(name));
      expect(composed.disabledReports.join(",") === skipped.join(","), "skipped jobs not reported as disabled");
      for (const name of REGISTERED_JOB_NAMES) {
        expect(!isDisabledJobController(composed.controllers[name]), `${name}: flagged as production-gated on staging`);
        expect(isSkippedJobController(composed.controllers[name]) === skipped.includes(name), `${name}: skipped flag wrong`);
      }
    });
  }
}

await test("S-ACTUAL", "the actual staging configuration (STAGING_ENABLED_JOBS unset) starts 0 of 19", async () => {
  const r = run({ ...STAGING_IDENTITY, NODE_ENV: "staging" }, { compose: true });
  expect(!r.threw && r.started.length === 0, `started: ${r.started.join(",")}`);
  expect(r.lines.some((l) => l.includes("0 of 19 jobs enabled")), "staging allow-list banner missing");
  expect(r.innerCalls.join(",") === ALL, "the staging allow-list did not decide every job");
  expect(r.disabledReports.join(",") === ALL, "not all 19 reported as disabled");
});

// ═══ L — local development unchanged ══════════════════════════════════════
section("L  local development / test: every job starts, nothing reported");

for (const [i, [label, env]] of [["NODE_ENV unset", {}], ["NODE_ENV=development", { NODE_ENV: "development" }], ["NODE_ENV=test", { NODE_ENV: "test" }]].entries()) {
  await test(`L${i + 1}`, label, async () => {
    const r = run(withList(env, "bad,,"), { compose: true }); // the staging variable is ignored off staging
    expect(!r.threw && r.started.join(",") === ALL, `started: ${r.started.join(",")}`);
    expect(r.disabledReports.length === 0 && r.lines.length === 0, "something was reported or logged");
    expect(REGISTERED_JOB_NAMES.every((name) => !isSkippedJobController(r.controllers[name]) && !isDisabledJobController(r.controllers[name])), "a started job is flagged");
  });
}

// ═══ X — exhaustive matrix ════════════════════════════════════════════════
section("X  exhaustive matrix: composed = (gate active ? nothing : staging allow-list alone)");

await test("X1", "NODE_ENV × RENDER × name × branch × STAGING_ENABLED_JOBS (1,320 environments)", async () => {
  const opt = (k, values) => values.map((v) => (v === undefined ? {} : { [k]: v }));
  let count = 0;
  for (const a of opt("NODE_ENV", [undefined, "production", "staging", "Staging", "development"]))
    for (const b of opt("RENDER", [undefined, "true"]))
      for (const c of opt("RENDER_SERVICE_NAME", [undefined, "zemish-production-api", "BARBER_ENGINE_V1"]))
        for (const d of opt("RENDER_GIT_BRANCH", [undefined, "main", "develop", "feature/x"]))
          for (const value of STAGING_VALUES) {
            const env = withList({ ...a, ...b, ...c, ...d }, value);
            count += 1;
            const alone = run(env, { compose: false });
            const composed = run(env, { compose: true });
            if (alone.threw) { expect(composed.threw && composed.started.length === 0, `invalid list not fatal: ${JSON.stringify(env)}`); continue; }
            const expected = isProductionJobGateActive(env) ? "" : alone.started.join(",");
            expect(composed.started.join(",") === expected, `mismatch for ${JSON.stringify(env)}`);
          }
  expect(count === 1320, `expected 1320, got ${count}`);
});

// ═══ U — unregistered names, shutdown classification, monitoring ══════════
section("U  unregistered names, shutdown classification, monitoring");

await test("U1", "an unregistered name throws and starts nothing — production, staging and local", async () => {
  for (const env of [{ NODE_ENV: "production" }, { NODE_ENV: "staging", STAGING_ENABLED_JOBS: ALL }, {}]) {
    const startJob = withProductionJobGate(createJobStarter({ env, log: quietLog().log }), { env, log: quietLog().log });
    let ran = false; let threw = false;
    try { startJob("notAJob", () => { ran = true; }); } catch { threw = true; }
    expect(threw && !ran, `env ${JSON.stringify(env)}: threw=${threw} ran=${ran}`);
  }
});

await test("U2", "staging (actual config): 19 jobs reported DISABLED to GET /health/ops, rollup not UNHEALTHY", async () => {
  const env = { ...STAGING_IDENTITY, NODE_ENV: "staging" };
  const startJob = withProductionJobGate(createJobStarter({ env, log: quietLog().log }), { env, log: quietLog().log, onDisabled: recordDisabled });
  REGISTERED_JOB_NAMES.forEach((name) => startJob(name, () => ({ stop() {} })));
  const { overallStatus, jobs } = getHeartbeatStatus();
  expect(REGISTERED_JOB_NAMES.every((name) => jobs.find((j) => j.name === name)?.status === "DISABLED"), "a job is not DISABLED");
  expect(overallStatus === "HEALTHY", `rollup is ${overallStatus}`);
});

// ═══ W — server.js wiring (read as text) ══════════════════════════════════
section("W  server.js wiring (text inspection only)");

const serverSrc = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "server.js"), "utf8");
const code = serverSrc.split("\n").filter((l) => !/^\s*(\/\/|\*)/.test(l)).join("\n");

await test("W1", "startJob = withProductionJobGate(createJobStarter({ env: process.env }), { env: process.env, onDisabled: recordJobDisabled }) — once, fatal on error", async () => {
  expect(/let startJob;\s*try \{\s*startJob = withProductionJobGate\(createJobStarter\(\{ env: process\.env \}\), \{ env: process\.env, onDisabled: recordJobDisabled \}\);\s*\} catch \(error\) \{\s*console\.error\(`❌ Refusing to start — \$\{error\.message\}`\);\s*process\.exit\(1\);/.test(code), "composition line missing or changed");
  expect((code.match(/\bwithProductionJobGate\(/g) || []).length === 1 && (code.match(/\bcreateJobStarter\(/g) || []).length === 1, "a starter is built more than once");
});

await test("W2", "shutdown logging distinguishes production-gated, staging-skipped and started jobs", async () => {
  const helper = /const logJobShutdown = \(job, label\) =>\s*console\.log\(isDisabledJobController\(job\)\s*\?\s*`⏸️  \$\{label\} job was not running \(disabled by the production job gate\)`\s*:\s*isSkippedJobController\(job\)\s*\?\s*`⏸️  \$\{label\} job was not running \(not enabled in STAGING_ENABLED_JOBS\)`\s*:\s*`✅ \$\{label\} job stopped`\);/;
  expect(helper.test(code), "logJobShutdown does not handle all three cases");
});

await test("W3", "backend-ci.yml runs this script, the staging allow-list verifier and the production gate verifier", async () => {
  const ci = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", ".github/workflows/backend-ci.yml"), "utf8");
  for (const script of ["verifyJobStarterComposition.js", "verifyStagingJobAllowlist.js", "verifyProductionJobGate.js"]) {
    expect(new RegExp(`^\\s+run: node scripts/${script.replace(".", "\\.")}$`, "m").test(ci), `CI does not run ${script}`);
  }
});

// ─── summary ────────────────────────────────────────────────────────────────
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length === 0 ? 0 : 1);
