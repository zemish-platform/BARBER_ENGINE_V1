/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyProductionJobGate.js
 *
 * Behavioural + static verification of the production hard-off background-job gate
 * (utils/productionJobGate.js, wired in server.js; disabled jobs reported by jobs/jobHeartbeat.js;
 * run by .github/workflows/backend-ci.yml).
 *
 * Hermetic by design — it NEVER starts the backend, never calls a real job handler, and never touches a
 * database, Redis or any provider:
 *   - the gate is exercised with STUB start functions (spies);
 *   - server.js and the CI workflow are only READ as text, to prove all 19 start calls are wrapped, in the
 *     right order, that shutdown still stops all 19, and that CI runs this script;
 *   - jobs/jobHeartbeat.js is a pure in-memory registry (no imports), exercised directly.
 *
 *   cd backend && node scripts/verifyProductionJobGate.js
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createProductionJobGate,
  isDisabledJobController,
  isProductionJobGateActive,
  productionJobGateReasons,
  PRODUCTION_BRANCH,
  PRODUCTION_SERVICE_IDS,
  PRODUCTION_SERVICE_NAMES,
  REGISTERED_JOB_NAMES,
} from "../utils/productionJobGate.js";
import { getStatus as getHeartbeatStatus, recordDisabled, recordStart, recordSuccess } from "../jobs/jobHeartbeat.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.resolve(__dirname, "..");
const REPO_DIR = path.resolve(BACKEND_DIR, "..");

// Render identity values (render.com/docs/environment-variables). Production = the service the gate must
// always close for; staging = the existing staging service, which must keep passing through.
const PROD_NAME = "zemish-production-api";
const PROD_ID = "srv-dbfqqn7f3r2c73e79o80";
const STAGING_IDENTITY = { RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1", RENDER_SERVICE_ID: "srv-d5vl9ssoud1c738ldjmg", RENDER_GIT_BRANCH: "develop" };
const PROD_IDENTITY = { RENDER: "true", RENDER_SERVICE_NAME: PROD_NAME, RENDER_SERVICE_ID: PROD_ID, RENDER_GIT_BRANCH: "main" };

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

// One spy per registered job; a spy records its calls and returns a distinct controller object.
const makeSpies = () => {
  const calls = [];
  const controllers = new Map();
  const spies = Object.fromEntries(REGISTERED_JOB_NAMES.map((name) => {
    const controller = { stop: () => { controller.stopped = true; }, stopped: false, owner: name };
    controllers.set(name, controller);
    return [name, () => { calls.push(name); return controller; }];
  }));
  return { calls, controllers, spies };
};
// server.js starts them in registry order; do the same.
const startAll = (startJob, spies) => Object.fromEntries(REGISTERED_JOB_NAMES.map((name) => [name, startJob(name, spies[name])]));
const startFnName = (name) => `start${name[0].toUpperCase()}${name.slice(1)}Job`;

// Every environment that must keep ALL 19 jobs off.
const GATED_ENVS = [
  ["NODE_ENV=production", { NODE_ENV: "production" }],
  ["NODE_ENV=production + RENDER=true", { NODE_ENV: "production", RENDER: "true" }],
  ["NODE_ENV=' Production ' (padded, mixed case)", { NODE_ENV: " Production " }],
  ["NODE_ENV=PRODUCTION", { NODE_ENV: "PRODUCTION" }],
  ["RENDER=true, NODE_ENV unset", { RENDER: "true" }],
  ["RENDER=true, NODE_ENV empty", { RENDER: "true", NODE_ENV: "" }],
  ["RENDER=true, NODE_ENV=development", { RENDER: "true", NODE_ENV: "development" }],
  ["RENDER=true, NODE_ENV=prod (typo)", { RENDER: "true", NODE_ENV: "prod" }],
  ["RENDER=true, NODE_ENV=Staging (not exact)", { RENDER: "true", NODE_ENV: "Staging" }],
  ["RENDER=true, NODE_ENV=' staging' (not exact)", { RENDER: "true", NODE_ENV: " staging" }],
  ["RENDER=' TRUE ', NODE_ENV unset", { RENDER: " TRUE " }],
  ["the production service, NODE_ENV=production", { ...PROD_IDENTITY, NODE_ENV: "production" }],
  ["the production service, NODE_ENV=staging (conflict)", { ...PROD_IDENTITY, NODE_ENV: "staging" }],
  ["production name only, NODE_ENV=staging", { NODE_ENV: "staging", RENDER_SERVICE_NAME: PROD_NAME }],
  ["production name as ' ZEMISH_PRODUCTION_API ', NODE_ENV=staging", { NODE_ENV: "staging", RENDER_SERVICE_NAME: " ZEMISH_PRODUCTION_API " }],
  ["production id only (renamed service), NODE_ENV=staging", { NODE_ENV: "staging", RENDER: "true", RENDER_SERVICE_NAME: "barber-engine-v1", RENDER_SERVICE_ID: PROD_ID }],
  ["branch main, NODE_ENV=staging, staging name", { NODE_ENV: "staging", RENDER: "true", RENDER_SERVICE_NAME: "barber-engine-v1", RENDER_GIT_BRANCH: "main" }],
  ["branch ' MAIN ', NODE_ENV=staging", { NODE_ENV: "staging", RENDER_GIT_BRANCH: " MAIN " }],
  ["staging identity but NODE_ENV=production", { ...STAGING_IDENTITY, NODE_ENV: "production" }],
  ["staging identity but NODE_ENV unset", { ...STAGING_IDENTITY }],
];
// Environments whose behaviour must stay exactly as before (every job starts).
const PASS_THROUGH_ENVS = [
  ["NODE_ENV=staging + RENDER=true (the staging service)", { NODE_ENV: "staging", RENDER: "true" }],
  ["NODE_ENV=staging (off Render)", { NODE_ENV: "staging" }],
  ["local: NODE_ENV unset, no RENDER", {}],
  ["local: NODE_ENV=development", { NODE_ENV: "development" }],
  ["local: NODE_ENV=test", { NODE_ENV: "test" }],
  ["RENDER=false, NODE_ENV=development", { RENDER: "false", NODE_ENV: "development" }],
  ["the staging service: NODE_ENV=staging + its full Render identity", { ...STAGING_IDENTITY, NODE_ENV: "staging" }],
  ["NODE_ENV=staging, identity variables blank", { NODE_ENV: "staging", RENDER: "true", RENDER_SERVICE_NAME: "", RENDER_SERVICE_ID: "", RENDER_GIT_BRANCH: "" }],
  ["NODE_ENV=staging, near-miss production values", { NODE_ENV: "staging", RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api-2", RENDER_SERVICE_ID: "srv-dbfqqn7f3r2c73e79o8", RENDER_GIT_BRANCH: "mainline" }],
];

console.log("Production job gate — behavioural verification (hermetic; stub jobs only; the backend is never started)");

// ═══ R — registry ═══════════════════════════════════════════════════════════
section("R  registry");

await test("R1", "19 registered names: exact, unique, frozen, camelCase", async () => {
  expect(REGISTERED_JOB_NAMES.length === 19, `expected 19 names, got ${REGISTERED_JOB_NAMES.length}`);
  expect(new Set(REGISTERED_JOB_NAMES).size === 19, "duplicate registered name");
  expect(REGISTERED_JOB_NAMES.every((n) => /^[a-z][A-Za-z0-9]*$/.test(n)), "a name is not camelCase");
  expect(Object.isFrozen(REGISTERED_JOB_NAMES), "the registry is not frozen");
});

// ═══ A — activation matrix ══════════════════════════════════════════════════
section("A  when is the gate active");

for (const [i, [label, env]] of GATED_ENVS.entries()) {
  await test(`A${i + 1}`, `active: ${label}`, async () => {
    expect(isProductionJobGateActive(env) === true, "gate is not active");
  });
}
for (const [i, [label, env]] of PASS_THROUGH_ENVS.entries()) {
  await test(`A${GATED_ENVS.length + i + 1}`, `inactive: ${label}`, async () => {
    expect(isProductionJobGateActive(env) === false, "gate is active");
  });
}

const ALLOWED_READS = ["NODE_ENV", "RENDER", "RENDER_SERVICE_NAME", "RENDER_SERVICE_ID", "RENDER_GIT_BRANCH"];
await test(`A${GATED_ENVS.length + PASS_THROUGH_ENVS.length + 1}`, `reads ONLY ${ALLOWED_READS.join(", ")}`, async () => {
  const touched = new Set();
  const env = new Proxy({ NODE_ENV: "production", ...PROD_IDENTITY, STAGING_ENABLED_JOBS: "holdExpiry" }, {
    get: (target, key) => { touched.add(String(key)); return target[key]; },
    has: (target, key) => { touched.add(String(key)); return key in target; },
  });
  const { log } = quietLog();
  isProductionJobGateActive(env);
  const startJob = createProductionJobGate({ env, log });
  REGISTERED_JOB_NAMES.forEach((name) => startJob(name, () => ({ stop() {} })));
  const extra = [...touched].filter((k) => !ALLOWED_READS.includes(k));
  expect(extra.length === 0, `read unexpected variable(s): ${extra.join(", ")}`);
});

// ═══ X — production identity (W1): missing, incorrect, conflicting ═════════
section("X  production identity: fail closed, never enable");

await test("X1", "identity constants are the verified production service (name / id / branch)", async () => {
  expect(JSON.stringify(PRODUCTION_SERVICE_NAMES) === JSON.stringify([PROD_NAME]), "service names differ");
  expect(JSON.stringify(PRODUCTION_SERVICE_IDS) === JSON.stringify([PROD_ID]), "service ids differ");
  expect(PRODUCTION_BRANCH === "main", "branch differs");
  expect(Object.isFrozen(PRODUCTION_SERVICE_NAMES) && Object.isFrozen(PRODUCTION_SERVICE_IDS), "identity lists not frozen");
});

await test("X2", "each production identity signal alone closes the gate, whatever NODE_ENV says", async () => {
  const signals = [{ RENDER_SERVICE_NAME: PROD_NAME }, { RENDER_SERVICE_ID: PROD_ID }, { RENDER_GIT_BRANCH: "main" }];
  for (const signal of signals) {
    for (const nodeEnv of [undefined, "", "staging", "development", "test", "production"]) {
      for (const render of [undefined, "true", "false"]) {
        const env = { ...signal };
        if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
        if (render !== undefined) env.RENDER = render;
        expect(isProductionJobGateActive(env), `not active for ${JSON.stringify(env)}`);
      }
    }
  }
});

await test("X3", "incorrect / near-miss identity values give no production signal", async () => {
  const wrong = [
    { RENDER_SERVICE_NAME: "zemish-production" }, { RENDER_SERVICE_NAME: "zemish-production-api-staging" },
    { RENDER_SERVICE_NAME: "barber-engine-v1" }, { RENDER_SERVICE_ID: "srv-d5vl9ssoud1c738ldjmg" },
    { RENDER_SERVICE_ID: `${PROD_ID}x` }, { RENDER_GIT_BRANCH: "develop" }, { RENDER_GIT_BRANCH: "main-hotfix" },
    { RENDER_GIT_BRANCH: "origin/main" }, { RENDER_SERVICE_NAME: 42 }, { RENDER_GIT_BRANCH: ["main"] },
  ];
  for (const w of wrong) {
    const reasons = productionJobGateReasons({ NODE_ENV: "staging", ...w });
    expect(reasons.length === 0, `unexpected production signal for ${JSON.stringify(w)}: ${reasons.join("; ")}`);
  }
});

await test("X4", "missing identity keeps the previous NODE_ENV/RENDER rules unchanged", async () => {
  expect(isProductionJobGateActive({ RENDER: "true" }), "Render + no NODE_ENV + no identity must be gated");
  expect(isProductionJobGateActive({ NODE_ENV: "production" }), "NODE_ENV=production + no identity must be gated");
  expect(!isProductionJobGateActive({ NODE_ENV: "staging", RENDER: "true" }), "staging + no identity must pass through");
  expect(!isProductionJobGateActive({}), "local + no identity must pass through");
});

await test("X5", "monotonic: adding any production identity to ANY environment can only close the gate", async () => {
  const bases = [{}, { NODE_ENV: "staging" }, { NODE_ENV: "staging", ...STAGING_IDENTITY }, { NODE_ENV: "development" }, { NODE_ENV: "production" }, { RENDER: "true" }];
  for (const base of bases) {
    for (const add of [{ RENDER_SERVICE_NAME: PROD_NAME }, { RENDER_SERVICE_ID: PROD_ID }, { RENDER_GIT_BRANCH: "main" }, PROD_IDENTITY]) {
      expect(isProductionJobGateActive({ ...base, ...add }), `adding ${JSON.stringify(add)} to ${JSON.stringify(base)} left the gate open`);
    }
  }
});

await test("X6", "exhaustive matrix (NODE_ENV × RENDER × name × id × branch = 2400 envs) matches the specification", async () => {
  const norm = (v) => (typeof v === "string" ? v.trim().toLowerCase() : "");
  const spec = (env) =>
    norm(env.RENDER_SERVICE_NAME).replace(/_/g, "-") === PROD_NAME ||
    norm(env.RENDER_SERVICE_ID) === PROD_ID ||
    norm(env.RENDER_GIT_BRANCH) === "main" ||
    (env.NODE_ENV !== "staging" && (norm(env.NODE_ENV) === "production" || norm(env.RENDER) === "true"));
  const opt = (k, values) => values.map((v) => (v === undefined ? {} : { [k]: v }));
  let count = 0;
  for (const a of opt("NODE_ENV", [undefined, "", "production", " PRODUCTION ", "staging", "Staging", "development", "test"]))
    for (const b of opt("RENDER", [undefined, "true", "false"]))
      for (const c of opt("RENDER_SERVICE_NAME", [undefined, PROD_NAME, "BARBER_ENGINE_V1", "other", ""]))
        for (const d of opt("RENDER_SERVICE_ID", [undefined, PROD_ID, "srv-other", " "]))
          for (const e of opt("RENDER_GIT_BRANCH", [undefined, "main", "develop", "feature/x", " Main "])) {
            const env = { ...a, ...b, ...c, ...d, ...e };
            count += 1;
            expect(isProductionJobGateActive(env) === spec(env), `mismatch for ${JSON.stringify(env)}`);
            if (norm(env.NODE_ENV) === "production") expect(isProductionJobGateActive(env), `production open: ${JSON.stringify(env)}`);
          }
  expect(count === 2400, `expected 2400 environments, got ${count}`);
});

await test("X7", "reasons name the rule only — identity values are never echoed", async () => {
  const reasons = productionJobGateReasons({ NODE_ENV: "production", ...PROD_IDENTITY }).join(" ");
  expect(reasons.length > 0, "no reasons");
  expect(!reasons.includes(PROD_ID) && !reasons.includes(PROD_NAME), "a value was echoed");
  const { lines, log } = quietLog();
  createProductionJobGate({ env: { NODE_ENV: "production", ...PROD_IDENTITY }, log });
  expect(!lines[0].includes(PROD_ID) && !lines[0].includes(PROD_NAME), "the banner echoed a value");
});

// ═══ D — default-deny, every job, every gated environment ═══════════════════
section("D  default-deny: no start function is ever called");

for (const [i, [label, env]] of GATED_ENVS.entries()) {
  await test(`D${i + 1}`, `0 of 19 started — ${label}`, async () => {
    const { calls, spies } = makeSpies();
    const { lines, log } = quietLog();
    const started = startAll(createProductionJobGate({ env, log }), spies);
    expect(calls.length === 0, `start function(s) called: ${calls.join(", ")}`);
    expect(lines[0]?.includes("0 of 19 background jobs enabled"), "missing the gate banner");
    for (const name of REGISTERED_JOB_NAMES) {
      expect(lines.includes(`[jobs] ${name} disabled (production job gate)`), `missing the disabled line for ${name}`);
      expect(typeof started[name]?.stop === "function", `${name}: controller has no stop()`);
      started[name].stop(); // shutdown handler path must not throw
    }
    expect(lines.length === 20, `expected 1 banner + 19 disabled lines, got ${lines.length}`);
  });
}

// One named check per job, so the report lists all 19 explicitly.
for (const [i, name] of REGISTERED_JOB_NAMES.entries()) {
  await test(`J${i + 1}`, `${name}: disabled in production, stop() is a safe no-op`, async () => {
    let called = false;
    const { log } = quietLog();
    const startJob = createProductionJobGate({ env: { NODE_ENV: "production", RENDER: "true" }, log });
    const controller = startJob(name, () => { called = true; return { stop() { throw new Error("real controller"); } }; });
    expect(called === false, "start function was called");
    controller.stop();
    controller.stop();
  });
}

// ═══ I — invalid / hostile configuration ════════════════════════════════════
section("I  no variable can enable a production job; invalid use is rejected");

const ALL = REGISTERED_JOB_NAMES.join(",");
const ENABLE_ATTEMPTS = [
  ["STAGING_ENABLED_JOBS = all 19", { STAGING_ENABLED_JOBS: ALL }],
  ["PRODUCTION_ENABLED_JOBS = all 19", { PRODUCTION_ENABLED_JOBS: ALL }],
  ["ENABLED_JOBS = all 19", { ENABLED_JOBS: ALL }],
  ["JOBS_ENABLED = true", { JOBS_ENABLED: "true" }],
  ["ENABLE_JOBS = *", { ENABLE_JOBS: "*" }],
  ["DISABLE_JOBS = false", { DISABLE_JOBS: "false" }],
  ["PRODUCTION_JOB_GATE = off", { PRODUCTION_JOB_GATE: "off" }],
];
for (const [i, [label, extra]] of ENABLE_ATTEMPTS.entries()) {
  await test(`I${i + 1}`, `production + ${label} → still 0 of 19`, async () => {
    const { calls, spies } = makeSpies();
    const { log } = quietLog();
    startAll(createProductionJobGate({ env: { NODE_ENV: "production", RENDER: "true", ...extra }, log }), spies);
    expect(calls.length === 0, `start function(s) called: ${calls.join(", ")}`);
  });
}

const BAD_NAMES = ["HoldExpiry", "holdExpiryJob", " holdExpiry", "", "all", "*", "unknownJob"];
let n = ENABLE_ATTEMPTS.length;
for (const [envLabel, env] of [["active", { NODE_ENV: "production" }], ["inactive", { NODE_ENV: "development" }]]) {
  for (const bad of BAD_NAMES) {
    n += 1;
    await test(`I${n}`, `${envLabel} gate: unregistered name ${JSON.stringify(bad)} throws and starts nothing`, async () => {
      let called = false;
      const { log } = quietLog();
      const startJob = createProductionJobGate({ env, log });
      let threw = false;
      try { startJob(bad, () => { called = true; return { stop() {} }; }); } catch { threw = true; }
      expect(threw, "did not throw");
      expect(!called, "start function was called");
    });
  }
}

// ═══ P — pass-through (staging + local unchanged) ═══════════════════════════
section("P  pass-through: staging and local development unchanged");

for (const [i, [label, env]] of PASS_THROUGH_ENVS.entries()) {
  await test(`P${i + 1}`, `all 19 start once, in order, result returned unchanged — ${label}`, async () => {
    const { calls, controllers, spies } = makeSpies();
    const { lines, log } = quietLog();
    const started = startAll(createProductionJobGate({ env, log }), spies);
    expect(calls.join(",") === REGISTERED_JOB_NAMES.join(","), "start order / count differs");
    for (const name of REGISTERED_JOB_NAMES) expect(started[name] === controllers.get(name), `${name}: controller not returned unchanged`);
    expect(lines.length === 0, "the gate logged something while inactive");
  });
}

await test(`P${PASS_THROUGH_ENVS.length + 1}`, "staging: the gate ignores STAGING_ENABLED_JOBS entirely (left to the staging allow-list)", async () => {
  for (const value of [undefined, "", "holdExpiry", "not,valid,,"]) {
    const { calls, spies } = makeSpies();
    const { log } = quietLog();
    const env = { NODE_ENV: "staging", RENDER: "true" };
    if (value !== undefined) env.STAGING_ENABLED_JOBS = value;
    startAll(createProductionJobGate({ env, log }), spies);
    expect(calls.length === 19, `value ${JSON.stringify(value)}: gate changed what started`);
  }
});

// ═══ H — shutdown logging + monitoring of disabled jobs (W3 / W4) ═══════════
section("H  disabled jobs are distinguishable at shutdown and in GET /health/ops");

await test("H1", "disabled controllers are recognised; real and pass-through controllers are not", async () => {
  const { log } = quietLog();
  const gated = createProductionJobGate({ env: { NODE_ENV: "production" }, log });
  const open = createProductionJobGate({ env: { NODE_ENV: "development" }, log });
  const real = { stop() {} };
  for (const name of REGISTERED_JOB_NAMES) {
    expect(isDisabledJobController(gated(name, () => real)), `${name}: disabled controller not recognised`);
    expect(!isDisabledJobController(open(name, () => real)), `${name}: pass-through controller flagged as disabled`);
  }
  for (const v of [real, { stop() {}, disabled: true }, null, undefined, "x", {}]) {
    expect(!isDisabledJobController(v), `${JSON.stringify(v)} flagged as disabled`);
  }
});

await test("H2", "onDisabled is called once per job, in order, only while the gate is active", async () => {
  const seen = [];
  const { log } = quietLog();
  const gated = createProductionJobGate({ env: { NODE_ENV: "production" }, log, onDisabled: (n) => seen.push(n) });
  REGISTERED_JOB_NAMES.forEach((n) => gated(n, () => ({ stop() {} })));
  expect(seen.join(",") === REGISTERED_JOB_NAMES.join(","), "onDisabled calls differ");
  const open = createProductionJobGate({ env: { NODE_ENV: "staging" }, log, onDisabled: (n) => seen.push(`open:${n}`) });
  REGISTERED_JOB_NAMES.forEach((n) => open(n, () => ({ stop() {} })));
  expect(seen.length === 19, "onDisabled called while the gate was inactive");
});

await test("H3", "heartbeat: 19 disabled jobs are reported as DISABLED and do not make the rollup UNHEALTHY", async () => {
  const { log } = quietLog();
  const gated = createProductionJobGate({ env: { NODE_ENV: "production" }, log, onDisabled: recordDisabled });
  REGISTERED_JOB_NAMES.forEach((n) => gated(n, () => ({ stop() {} })));
  const { overallStatus, jobs } = getHeartbeatStatus();
  for (const name of REGISTERED_JOB_NAMES) {
    const job = jobs.find((j) => j.name === name);
    expect(job?.status === "DISABLED" && job.disabled === true, `${name}: not reported as DISABLED`);
    expect(job.lastStartedAt === null && job.isRunning === false, `${name}: looks like it ran`);
  }
  expect(overallStatus === "HEALTHY", `rollup is ${overallStatus}`);
});

await test("H4", "heartbeat: existing statuses unchanged (NEVER_RAN still UNHEALTHY; real start wins over DISABLED)", async () => {
  const probe = `zzProbe${Date.now()}`;
  recordStart(`${probe}Never`, { intervalMs: 1000 });
  // A registry entry created without a start (e.g. only success recorded) is still NEVER_RAN.
  recordSuccess(`${probe}Ghost`);
  let s = getHeartbeatStatus();
  expect(s.jobs.find((j) => j.name === `${probe}Ghost`).status === "NEVER_RAN", "NEVER_RAN changed");
  expect(s.jobs.find((j) => j.name === `${probe}Ghost`).disabled === false, "a normal job is flagged disabled");
  expect(s.overallStatus === "UNHEALTHY", "NEVER_RAN no longer makes the rollup UNHEALTHY");
  recordDisabled(`${probe}Later`);
  recordStart(`${probe}Later`, { intervalMs: 1000 });
  s = getHeartbeatStatus();
  expect(s.jobs.find((j) => j.name === `${probe}Later`).status === "RUNNING", "a job that really started is still shown DISABLED");
});

// ═══ S — static wiring of server.js ═════════════════════════════════════════
section("S  server.js wiring (read as text)");

const serverSrc = fs.readFileSync(path.join(BACKEND_DIR, "server.js"), "utf8");
const code = serverSrc.split("\n").filter((l) => !/^\s*(\/\/|\*)/.test(l)).join("\n");
// Two supported wirings (this script is identical on both branches):
//   main    — the gate alone:  const startJob = createProductionJobGate({ env: process.env, onDisabled: recordJobDisabled });
//   develop — the gate wraps the staging allow-list (utils/jobStarterComposition.js; behaviour verified by
//             scripts/verifyJobStarterComposition.js):
//             let startJob; try { startJob = withProductionJobGate(createJobStarter({ env: process.env }), { env: process.env, onDisabled: recordJobDisabled }); }
const COMPOSED = /\bwithProductionJobGate\(/.test(code);

await test("S1", `imports the gate and the heartbeat recorder (${COMPOSED ? "develop: composed with the staging allow-list" : "main: gate alone"})`, async () => {
  if (COMPOSED) {
    expect(/^import \{ isDisabledJobController, isProductionJobGateActive \} from "\.\/utils\/productionJobGate\.js";$/m.test(serverSrc), "gate import missing");
    expect(/^import \{ isSkippedJobController, withProductionJobGate \} from "\.\/utils\/jobStarterComposition\.js";$/m.test(serverSrc), "composition import missing");
    expect(/^import \{ createJobStarter \} from "\.\/utils\/stagingJobAllowlist\.js";$/m.test(serverSrc), "staging allow-list import missing");
  } else {
    expect(/^import \{ createProductionJobGate, isDisabledJobController, isProductionJobGateActive \} from "\.\/utils\/productionJobGate\.js";$/m.test(serverSrc), "gate import missing");
  }
  expect(/^import \{ recordDisabled as recordJobDisabled \} from "\.\/jobs\/jobHeartbeat\.js";$/m.test(serverSrc), "heartbeat import missing");
});

await test("S2", "startJob is created exactly once, before the first job, reporting to the heartbeat", async () => {
  const creations = COMPOSED
    ? [...code.matchAll(/let startJob;\s*try \{\s*startJob = withProductionJobGate\(createJobStarter\(\{ env: process\.env \}\), \{ env: process\.env, onDisabled: recordJobDisabled \}\);\s*\} catch \(error\) \{\s*console\.error\([^)]*\);\s*process\.exit\(1\);/g)]
    : [...code.matchAll(/const startJob = createProductionJobGate\(\{ env: process\.env, onDisabled: recordJobDisabled \}\);/g)];
  expect(creations.length === 1, `expected 1 creation, got ${creations.length}`);
  expect((code.match(/\bstartJob\s*=(?!=)/g) || []).length === 1, "startJob is assigned more than once");
  expect((code.match(/\bcreateProductionJobGate\(|\bwithProductionJobGate\(/g) || []).length === 1, "the gate is created more than once");
  const firstJob = code.indexOf('startJob("');
  expect(firstJob > creations[0].index, "a job is started before the gate exists");
});

await test("S3", "exactly 19 wrapped start calls, registry order, matching start functions", async () => {
  const wrapped = [...code.matchAll(/^const (\w+)Job = startJob\("(\w+)", \(\) => (start\w+Job)\((io)?\)\);$/gm)];
  expect(wrapped.length === 19, `expected 19 wrapped calls, got ${wrapped.length}`);
  wrapped.forEach((m, i) => {
    const expected = REGISTERED_JOB_NAMES[i];
    expect(m[2] === expected, `call ${i + 1}: name "${m[2]}" but registry has "${expected}"`);
    expect(m[1] === expected, `call ${i + 1}: variable ${m[1]}Job does not match name "${expected}"`);
    expect(m[3] === startFnName(expected), `call ${i + 1}: ${m[3]} does not match ${startFnName(expected)}`);
  });
});

await test("S4", "no start*Job function is called outside startJob()", async () => {
  const allCalls = [...code.matchAll(/\b(start[A-Z]\w*Job)\(/g)].map((m) => m[1]);
  const wrappedCalls = [...code.matchAll(/\(\) => (start[A-Z]\w*Job)\(/g)].map((m) => m[1]);
  expect(allCalls.length === 19 && wrappedCalls.length === 19, `found ${allCalls.length} calls, ${wrappedCalls.length} wrapped`);
});

await test("S5", "every one of the 19 start functions is imported", async () => {
  for (const name of REGISTERED_JOB_NAMES) {
    expect(new RegExp(`^import \\{ ${startFnName(name)} \\} from "[^"]+";`, "m").test(serverSrc), `${startFnName(name)} not imported`);
  }
});

await test("S6", "the boot banner reports the gate instead of claiming jobs are RUNNING", async () => {
  expect(/isProductionJobGateActive\(process\.env\)\s*\?\s*"⚙️  Jobs:\s+ALL 19 DISABLED \(production job gate\)"/.test(code), "banner is not gated");
});

await test("S7", "shutdown still stops all 19 jobs, in registry order, and logs each through logJobShutdown", async () => {
  const shutdownSrc = code.slice(code.indexOf("const shutdown = async"));
  const stops = [...shutdownSrc.matchAll(/^\s+(\w+)Job\.stop\(\);$/gm)].map((m) => m[1]);
  expect(stops.join(",") === REGISTERED_JOB_NAMES.join(","), `stop() calls differ: ${stops.join(",")}`);
  const logged = [...shutdownSrc.matchAll(/logJobShutdown\((\w+)Job, "[^"]+"\);/g)].map((m) => m[1]);
  expect(logged.join(",") === REGISTERED_JOB_NAMES.join(","), `logJobShutdown calls differ: ${logged.join(",")}`);
  expect(!/job stopped"\)/.test(shutdownSrc), "a hard-coded 'job stopped' line remains");
  expect(/isDisabledJobController\(job\)/.test(code), "logJobShutdown does not consult the gate");
});

// ═══ C — CI wiring (W2) ═════════════════════════════════════════════════════
section("C  CI runs this script");

await test("C1", "backend-ci.yml runs scripts/verifyProductionJobGate.js from backend/ on PRs to main and develop", async () => {
  const ci = fs.readFileSync(path.join(REPO_DIR, ".github/workflows/backend-ci.yml"), "utf8");
  expect(/^\s+run: node scripts\/verifyProductionJobGate\.js$/m.test(ci), "step missing");
  expect(/working-directory: backend/.test(ci), "not run from backend/");
  expect(/pull_request:\s*\n\s+branches: \[main, develop\]/.test(ci), "PR trigger for main/develop missing");
});

// ─── summary ────────────────────────────────────────────────────────────────
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length === 0 ? 0 : 1);
