/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyStagingJobAllowlist.js
 *
 * Behavioural + static verification of the staging-only, default-deny background-job allow-list
 * (utils/stagingJobAllowlist.js, wired in server.js and config/stagingBootGuard.js).
 *
 * Hermetic by design — it NEVER starts the backend, never calls a real job handler, and never touches a
 * database, Redis or any provider:
 *   - the starter is exercised with STUB start functions (spies);
 *   - server.js is only READ as text, to prove all 19 start calls are wrapped, in the right order;
 *   - the boot guard is run in a child process that imports ONLY config/stagingBootGuard.js (a pure
 *     environment check), with unroutable `.invalid` endpoints in its environment.
 *
 *   cd backend && node scripts/verifyStagingJobAllowlist.js
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  assertStagingJobAllowlist,
  createJobStarter,
  parseStagingEnabledJobs,
  REGISTERED_JOB_NAMES,
  STAGING_ENABLED_JOBS_VAR,
} from "../utils/stagingJobAllowlist.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.resolve(__dirname, "..");
const rnd = (bytes) => crypto.randomBytes(bytes).toString("hex");
const SENTINEL = `zz${rnd(5)}`; // an "offending job name" that must never be echoed back

// ─── tiny harness ───────────────────────────────────────────────────────────
const results = [];
const test = async (id, name, fn) => {
  try {
    await fn();
    results.push({ id, ok: true });
    console.log(`  ✅ ${id} ${name}`);
  } catch (error) {
    results.push({ id, ok: false });
    console.log(`  ❌ ${id} ${name} — ${String(error?.message || error).split(SENTINEL).join("<redacted>")}`);
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
const stagingEnv = (value) => (value === undefined ? { NODE_ENV: "staging" } : { NODE_ENV: "staging", [STAGING_ENABLED_JOBS_VAR]: value });

console.log("Staging job allow-list — behavioural verification (hermetic; stub jobs only; the backend is never started)");

// ═══ R — registry ═══════════════════════════════════════════════════════════
section("R  registry");

await test("R1", "19 registered names: exact, unique, frozen, camelCase", async () => {
  expect(REGISTERED_JOB_NAMES.length === 19, `expected 19 names, got ${REGISTERED_JOB_NAMES.length}`);
  expect(new Set(REGISTERED_JOB_NAMES).size === 19, "duplicate registered name");
  expect(REGISTERED_JOB_NAMES.every((n) => /^[a-z][A-Za-z0-9]*$/.test(n)), "a name is not camelCase");
  expect(Object.isFrozen(REGISTERED_JOB_NAMES), "the registry is not frozen");
});

// ═══ P — parsing ════════════════════════════════════════════════════════════
section("P  parsing and validation");

await test("P1", "unset / null / empty / blank → no jobs and NO error (default-deny is not a misconfiguration)", async () => {
  for (const raw of [undefined, null, "", "   ", "\t\n"]) {
    const { jobs, errors } = parseStagingEnabledJobs(raw);
    expect(jobs.size === 0 && errors.length === 0, `'${JSON.stringify(raw)}' was not treated as default-deny`);
  }
});

await test("P2", "valid lists: each single name, several names, all 19; whitespace around entries is trimmed", async () => {
  for (const name of REGISTERED_JOB_NAMES) {
    const { jobs, errors } = parseStagingEnabledJobs(name);
    expect(errors.length === 0 && jobs.size === 1 && jobs.has(name), `single name '${name}' not accepted`);
  }
  const some = parseStagingEnabledJobs("reminder,holdExpiry,otpAuditOutbox");
  expect(some.errors.length === 0 && some.jobs.size === 3 && some.jobs.has("holdExpiry"), "a valid list was rejected");
  const spaced = parseStagingEnabledJobs("  reminder ,  holdExpiry  ");
  expect(spaced.errors.length === 0 && spaced.jobs.size === 2, "surrounding whitespace was not trimmed");
  const all = parseStagingEnabledJobs(REGISTERED_JOB_NAMES.join(","));
  expect(all.errors.length === 0 && all.jobs.size === 19, "the full list was rejected");
});

await test("P3", "rejected: unknown names, WRONG CASE (every registered name), duplicates, empty entries, trailing/leading commas, internal spaces, non-strings", async () => {
  const bad = [
    ["unknown", "holdExpiry,notAJob"],
    ["unknown only", "notAJob"],
    ["wildcard", "*"],
    ["'all'", "all"],
    ["duplicate", "reminder,reminder"],
    ["duplicate far apart", "reminder,holdExpiry,reminder"],
    ["trailing comma", "reminder,"],
    ["leading comma", ",reminder"],
    ["doubled comma", "reminder,,holdExpiry"],
    ["whitespace-only entry", "reminder, ,holdExpiry"],
    ["only a comma", ","],
    ["internal space", "hold Expiry"],
    ["semicolon separator", "reminder;holdExpiry"],
    ["a valid name plus an invalid one", "holdExpiry,reminder,Reminder"],
  ];
  for (const [label, raw] of bad) expect(parseStagingEnabledJobs(raw).errors.length >= 1, `${label}: '${raw}' was ACCEPTED`);
  for (const name of REGISTERED_JOB_NAMES) {
    for (const variant of [name[0].toUpperCase() + name.slice(1), name.toUpperCase(), name.toLowerCase() === name ? `${name}X` : name.toLowerCase()]) {
      if (variant !== name) expect(parseStagingEnabledJobs(variant).errors.length === 1, `wrong-case/variant '${variant}' was accepted`);
    }
  }
  for (const raw of [123, {}, [], true]) expect(parseStagingEnabledJobs(raw).errors.length === 1, `non-string ${JSON.stringify(raw)} was accepted`);
});

await test("P4", "error messages carry the entry number and the rule — never the offending text", async () => {
  const { errors } = parseStagingEnabledJobs(`holdExpiry,${SENTINEL},holdExpiry,,reminder`);
  expect(errors.length === 3, `expected 3 errors, got ${errors.length}`);
  expect(errors.every((e) => e.startsWith(`${STAGING_ENABLED_JOBS_VAR} entry `)), "an error does not name the entry");
  expect(!errors.join("\n").includes(SENTINEL), "the offending text was echoed");
});

// ═══ S — starter behaviour (stub jobs) ═════════════════════════════════════
section("S  starter: default-deny, allowed jobs, invalid config, pass-through");

await test("S1", "STAGING default-deny: unset and blank start ZERO of the 19 jobs; skipped jobs return a working no-op controller", async () => {
  for (const value of [undefined, "", "   "]) {
    const { calls, spies } = makeSpies();
    const { lines, log } = quietLog();
    const startJob = createJobStarter({ env: stagingEnv(value), log });
    const controllers = startAll(startJob, spies);
    expect(calls.length === 0, `'${JSON.stringify(value)}': ${calls.length} job(s) started with nothing enabled`);
    for (const name of REGISTERED_JOB_NAMES) {
      expect(typeof controllers[name].stop === "function", `${name}: no stop()`);
      controllers[name].stop(); controllers[name].stop(); // repeated, like a double shutdown — must never throw
    }
    expect(lines.some((l) => /0 of 19 jobs enabled/.test(l)), "no default-deny confirmation was logged");
  }
});

await test("S2", "STAGING one explicitly allowed job: ONLY that job starts, once; its controller is returned unchanged; the others are skipped", async () => {
  const { calls, controllers, spies } = makeSpies();
  const { lines, log } = quietLog();
  const started = startAll(createJobStarter({ env: stagingEnv("otpAuditOutbox"), log }), spies);
  expect(calls.length === 1 && calls[0] === "otpAuditOutbox", `unexpected jobs started: ${calls.join(",")}`);
  expect(started.otpAuditOutbox === controllers.get("otpAuditOutbox"), "the real controller was not returned unchanged");
  for (const name of REGISTERED_JOB_NAMES.filter((n) => n !== "otpAuditOutbox")) {
    expect(started[name] !== controllers.get(name), `${name}: a skipped job returned its real controller`);
    started[name].stop();
    expect(controllers.get(name).stopped === false, `${name}: the no-op stop() reached the real job`);
  }
  expect(lines.some((l) => /1 of 19 jobs enabled \(otpAuditOutbox\)/.test(l)), "the enabled set was not logged");
});

await test("S3", "STAGING several allowed jobs: exactly that set starts, in server.js order (not list order), each once", async () => {
  const { calls, spies } = makeSpies();
  const { log } = quietLog();
  startAll(createJobStarter({ env: stagingEnv("reminder, holdExpiry,genericPayoutReconcile"), log }), spies);
  expect(JSON.stringify(calls) === JSON.stringify(["holdExpiry", "reminder", "genericPayoutReconcile"]), `unexpected: ${calls.join(",")}`);
  const all = makeSpies();
  startAll(createJobStarter({ env: stagingEnv(REGISTERED_JOB_NAMES.join(",")), log: quietLog().log }), all.spies);
  expect(all.calls.length === 19 && JSON.stringify(all.calls) === JSON.stringify(REGISTERED_JOB_NAMES), "enabling all 19 did not start all 19 in order");
});

await test("S4", "STAGING invalid list: createJobStarter THROWS before startJob exists — not one job can start, not even a valid name listed first", async () => {
  for (const raw of ["holdExpiry,notAJob", `holdExpiry,${SENTINEL}`, "reminder,reminder", "reminder,", "Reminder", "holdExpiry,,autoStart", "holdExpiry,reminder,HoldExpiry"]) {
    const { calls, spies } = makeSpies();
    let startJob = null; let message = "";
    try { startJob = createJobStarter({ env: stagingEnv(raw), log: quietLog().log }); } catch (error) { message = error.message; }
    expect(startJob === null && /STAGING_ENABLED_JOBS/.test(message), `'${raw}': no starter should exist`);
    expect(!message.includes(SENTINEL), `'${raw}': the offending text leaked`);
    expect(calls.length === 0, `'${raw}': ${calls.length} job(s) started`);
    // The server.js pattern: a failed creation leaves startJob undefined, so a later call could not even run.
    let ran = false;
    try { startJob("holdExpiry", spies.holdExpiry); ran = true; } catch { /* TypeError: startJob is not a function */ }
    expect(!ran && calls.length === 0, `'${raw}': a job ran through a missing starter`);
  }
});

await test("S5", "STAGING a startJob call with an UNREGISTERED name throws and starts nothing", async () => {
  const { calls } = makeSpies();
  const startJob = createJobStarter({ env: stagingEnv("holdExpiry"), log: quietLog().log });
  let threw = false;
  try { startJob("notRegistered", () => { calls.push("notRegistered"); }); } catch { threw = true; }
  expect(threw && calls.length === 0, "an unregistered job name was started or silently skipped");
});

await test("S6", "PRODUCTION / DEVELOPMENT / TEST / UNSET NODE_ENV: pure pass-through — all 19 start, return values unchanged, no logging, no validation, the variable is NEVER READ", async () => {
  for (const nodeEnv of ["production", "development", "test", undefined, "", "Staging", "STAGING", "staging "]) {
    for (const value of [undefined, "", "holdExpiry", `${SENTINEL},,Reminder,reminder,reminder`]) {
      const reads = [];
      const env = new Proxy({ ...(nodeEnv === undefined ? {} : { NODE_ENV: nodeEnv }), ...(value === undefined ? {} : { [STAGING_ENABLED_JOBS_VAR]: value }) }, {
        get(target, prop) { if (prop === STAGING_ENABLED_JOBS_VAR) reads.push(prop); return target[prop]; },
      });
      const { calls, controllers, spies } = makeSpies();
      const { lines, log } = quietLog();
      let startJob;
      expect((() => { try { startJob = createJobStarter({ env, log }); return true; } catch { return false; } })(), `NODE_ENV=${nodeEnv}: createJobStarter threw`);
      const started = startAll(startJob, spies);
      expect(calls.length === 19 && JSON.stringify(calls) === JSON.stringify(REGISTERED_JOB_NAMES), `NODE_ENV=${nodeEnv}: not all 19 jobs started in order`);
      expect(REGISTERED_JOB_NAMES.every((n) => started[n] === controllers.get(n)), `NODE_ENV=${nodeEnv}: a return value was altered`);
      expect(lines.length === 0, `NODE_ENV=${nodeEnv}: the starter logged`);
      expect(reads.length === 0, `NODE_ENV=${nodeEnv}: STAGING_ENABLED_JOBS was read`);
    }
  }
  // Same function reference semantics: whatever startFn returns (even undefined) comes back untouched.
  const passthrough = createJobStarter({ env: { NODE_ENV: "production" } });
  expect(passthrough("anything-at-all", () => undefined) === undefined, "a non-staging return value was altered");
});

await test("S7", "boot-guard function: violations only for NODE_ENV=staging; [] for everything else even with a garbage value", async () => {
  expect(assertStagingJobAllowlist(stagingEnv(undefined)).length === 0, "staging + unset reported violations");
  expect(assertStagingJobAllowlist(stagingEnv("  ")).length === 0, "staging + blank reported violations");
  expect(assertStagingJobAllowlist(stagingEnv("holdExpiry,reminder")).length === 0, "staging + a valid list reported violations");
  expect(assertStagingJobAllowlist(stagingEnv("holdExpiry,nope")).length === 1, "staging + an invalid list did not report");
  for (const nodeEnv of ["production", "development", "test", undefined, "Staging"]) {
    const env = { ...(nodeEnv === undefined ? {} : { NODE_ENV: nodeEnv }), [STAGING_ENABLED_JOBS_VAR]: `${SENTINEL},,Reminder` };
    expect(assertStagingJobAllowlist(env).length === 0, `NODE_ENV=${nodeEnv}: the variable was validated`);
  }
});

// ═══ W — static wiring of server.js ════════════════════════════════════════
section("W  server.js wiring (text inspection only — nothing is executed)");

const serverSrc = fs.readFileSync(path.join(BACKEND_DIR, "server.js"), "utf8");
const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
const code = stripComments(serverSrc);
const WRAPPED = /^const (\w+)Job = startJob\("(\w+)", \(\) => (start\w+Job)\(((?:io)?)\)\);[ \t]*$/gm;
const wrapped = [...code.matchAll(WRAPPED)].map((m) => ({ variable: m[1], name: m[2], fn: m[3], arg: m[4] }));
const IO_JOBS = new Set(["holdExpiry", "customerArrival", "serviceOverdue", "autoComplete", "autoStart", "slaScanner"]);

await test("W1", "ALL 19 start calls are wrapped: one per registered name, in registry order, no bare start call left, arguments preserved", async () => {
  expect(wrapped.length === 19, `expected 19 wrapped start calls, found ${wrapped.length}`);
  expect(JSON.stringify(wrapped.map((w) => w.name)) === JSON.stringify(REGISTERED_JOB_NAMES), "wrapped names differ from the registry (or are out of order)");
  for (const w of wrapped) {
    expect(w.variable === w.name, `${w.name}: variable '${w.variable}Job' does not match`);
    expect(w.fn === `start${w.name[0].toUpperCase()}${w.name.slice(1)}Job`, `${w.name}: wraps '${w.fn}'`);
    expect(w.arg === (IO_JOBS.has(w.name) ? "io" : ""), `${w.name}: the argument passed to the start function changed ('${w.arg}')`);
  }
  const bareCalls = [...code.matchAll(/\bstart[A-Z]\w*Job\(/g)].length;
  expect(bareCalls === 19, `${bareCalls} start*Job( call sites in code; expected exactly the 19 inside the wrappers`);
});

await test("W2", "every wrapped start function is imported exactly once and exists (exported) in the file it is imported from", async () => {
  for (const w of wrapped) {
    const imports = [...code.matchAll(new RegExp(`import \\{ ${w.fn} \\} from "([^"]+)";`, "g"))];
    expect(imports.length === 1, `${w.fn}: imported ${imports.length} times`);
    const file = path.resolve(BACKEND_DIR, imports[0][1]);
    const src = fs.readFileSync(file, "utf8");
    expect(new RegExp(`export (const|function) ${w.fn}\\b`).test(src), `${w.fn} is not exported by ${imports[0][1]}`);
  }
});

await test("W3", "shutdown still stops all 19 jobs (the no-op controllers are what make that safe)", async () => {
  for (const w of wrapped) expect(new RegExp(`\\b${w.variable}Job\\.stop\\(\\);`).test(code), `${w.variable}Job.stop() missing from shutdown`);
});

await test("W4", "ORDER in server.js: boot guard first; pre-flight → connectDB → staging gate → starter creation → first job → listen", async () => {
  const at = (needle) => { const i = code.indexOf(needle); expect(i >= 0, `missing in server.js: ${needle}`); return i; };
  const guard = at('import "./config/stagingBootGuard.js"');
  expect(guard < at('import connectDB') && guard < at('from "./app.js"') && guard < at("config/redis"), "the boot guard is not imported before the app, database and Redis modules") ;
  // startJob must come from createJobStarter — and from nowhere else (a stub/pass-through that merely mentions the name would
  // start every job on staging).
  const creation = /let startJob;\s*try \{\s*startJob = createJobStarter\(\{ env: process\.env \}\);/.exec(code);
  expect(creation !== null, "startJob is not created by `startJob = createJobStarter({ env: process.env })` inside the guarded try block");
  expect((code.match(/\bstartJob\s*=(?!=)/g) || []).length === 1, "startJob is assigned more than once");
  expect(!/\b(function startJob|const startJob|var startJob)\b/.test(code), "startJob is declared a second way");
  expect((code.match(/\bcreateJobStarter\(/g) || []).length === 1, "createJobStarter is called more than once, or not at all");
  const order = [at("await runStagingPreflight("), at("const dbConnected = connectDB()"), at("await runStagingStartupGate("), creation.index, at('startJob("holdExpiry"'), at("httpServer.listen(")];
  expect(order.every((n, i) => i === 0 || n > order[i - 1]), `wrong order: ${order.join(",")}`);
  expect(at('startJob("genericPayoutReconcile"') < order[5], "the last job starts after listen");
  expect(/catch \(error\) \{\s*console\.error\(`❌ Refusing to start — \$\{error\.message\}`\);\s*process\.exit\(1\);/.test(code), "an invalid allow-list is not fatal in server.js");
});

await test("W5", "the boot guard runs the allow-list validation alongside the existing guard", async () => {
  const src = fs.readFileSync(path.join(BACKEND_DIR, "config/stagingBootGuard.js"), "utf8");
  expect(/assertStagingJobAllowlist\(process\.env\)/.test(src) && /assertStagingSafety\(process\.env\)/.test(src), "the boot guard does not run both checks");
});

// ═══ B — boot guard in a child process (imports ONLY the boot guard) ═══════
section("B  boot guard (child process; imports only config/stagingBootGuard.js — no app, no Redis, no MongoDB)");

const scheme = (name) => `${name}:` + "//";
const bootEnv = (over = {}) => ({
  NODE_ENV: "staging",
  STAGING_TEST_LOGINS: "6000000011:739415",
  RAZORPAY_KEY_ID: "rzp_test_synthetic1",
  RAZORPAY_KEY_SECRET: rnd(8),
  MONGODB_URI: `${scheme("mongodb+srv")}svc${rnd(3)}:${rnd(10)}@cluster0.${rnd(2)}.invalid/barber_engine_staging?retryWrites=true`,
  REDIS_URL: `${scheme("rediss")}svc${rnd(3)}:${rnd(10)}@redis-${rnd(3)}.invalid:6379`,
  STAGING_FORBIDDEN_MONGO_ENDPOINTS: rnd(8),
  STAGING_FORBIDDEN_REDIS_ENDPOINTS: rnd(8),
  JWT_ACCESS_SECRET: rnd(24), OTP_SECRET: rnd(24), OTP_ENCRYPT_KEY: rnd(24), ADMIN_RESET_PASSWORD: `Adm!${rnd(8)}`,
  ...over,
});
const bootEntry = pathToFileURL(path.join(BACKEND_DIR, "config/stagingBootGuard.js")).href;
const runBoot = (env) => spawnSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(bootEntry)})`], { cwd: os.tmpdir(), env: { PATH: process.env.PATH, ...env }, encoding: "utf8", timeout: 20000 });

await test("B1", "STAGING invalid STAGING_ENABLED_JOBS → exit 1 AT THE BOOT GUARD, before any database/Redis connection or job: names the entry number only, prints nothing else", async () => {
  for (const raw of ["holdExpiry,notAJob", "HoldExpiry", "reminder,reminder", "reminder,,autoStart", "reminder,", `holdExpiry,${SENTINEL}`]) {
    const r = runBoot(bootEnv({ [STAGING_ENABLED_JOBS_VAR]: raw }));
    expect(r.status === 1 && /Refusing to start/.test(r.stderr) && /STAGING_ENABLED_JOBS entry \d/.test(r.stderr), `'${raw}': not refused at boot (exit ${r.status})`);
    expect(r.stdout.trim() === "", `'${raw}': something was printed to stdout before the refusal`);
    expect(!`${r.stdout}${r.stderr}`.includes(SENTINEL), `'${raw}': the offending text leaked`);
    expect(!/mongo|redis|connect/i.test(r.stderr.replace(/STAGING_[A-Z_]*|MONGODB_URI|REDIS_URL/g, "")), `'${raw}': the refusal mentions a connection`);
  }
});

await test("B2", "STAGING valid configurations pass the boot guard silently: unset, blank, one job, several jobs, all 19", async () => {
  for (const raw of [undefined, "", "   ", "holdExpiry", "reminder, otpAuditOutbox", REGISTERED_JOB_NAMES.join(",")]) {
    const r = runBoot(bootEnv(raw === undefined ? {} : { [STAGING_ENABLED_JOBS_VAR]: raw }));
    expect(r.status === 0 && `${r.stdout}${r.stderr}`.trim() === "", `'${raw}': the boot guard refused or printed (exit ${r.status}): ${r.stderr.slice(0, 200)}`);
  }
});

await test("B3", "PRODUCTION / DEVELOPMENT / TEST / UNSET NODE_ENV: the variable is IGNORED — exit 0, no output, even with a garbage list", async () => {
  const base = { RENDER: undefined };
  for (const env of [
    { NODE_ENV: "production" }, { NODE_ENV: "development" }, { NODE_ENV: "test" }, {},
  ]) {
    const r = runBoot({ ...base, ...env, [STAGING_ENABLED_JOBS_VAR]: `${SENTINEL},,Reminder,reminder,reminder` });
    expect(r.status === 0 && `${r.stdout}${r.stderr}`.trim() === "", `NODE_ENV=${env.NODE_ENV}: the boot guard reacted to STAGING_ENABLED_JOBS (exit ${r.status}): ${r.stderr.slice(0, 160)}`);
  }
});

// ─── summary ────────────────────────────────────────────────────────────────
const passed = results.filter((r) => r.ok).length;
const failed = results.length - passed;
console.log(`\n${failed === 0 ? "✅" : "❌"} ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
