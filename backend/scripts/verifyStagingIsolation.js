/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyStagingIsolation.js
 *
 * Behavioural verification of the staging ISOLATION hardening: Render identity vs NODE_ENV,
 * MongoDB URI parsing with the driver's own semantics, the staging database policy, the
 * MongoDB/Redis endpoint deny-lists, the staging-only PRE-FLIGHT (a raw read-only driver check that
 * must pass before mongoose.connect() is ever called) and the staging-only post-connect gate that
 * must finish before any background job starts or the server listens.
 *
 * Hermetic by default: no real database, Redis, provider, production or staging service.
 * The only sockets are loopback ports opened by short-lived `node server.js` child processes
 * whose MongoDB layer is replaced by a generated preload (mongoose.connect is faked; nothing
 * ever connects), and a child that is refused exits before it listens.
 *
 *   cd backend && node scripts/verifyStagingIsolation.js
 *       I  Render identity            M  MongoDB URI parsing (driver semantics)
 *       P  database policy            D  endpoint deny-lists
 *       F  pre-flight (unit)          G  post-connect gate
 *       B  blocking proof: real server.js, faked MongoDB layer (pre-flight, connect, gate, jobs, listen)
 *
 *   cd backend && node scripts/verifyStagingIsolation.js --real-mongo
 *       adds R: a throwaway LOCAL mongod (authentication on, loopback only, temp directory, hard
 *       timeout, guaranteed cleanup). It checks the privilege logic against the REAL
 *       `connectionStatus` replies of scoped / admin / any-database / custom-role users, and runs
 *       the real server.js end to end, asserting that a refused boot creates NO collection (not even
 *       the database) and that the pre-flight issues only `connectionStatus`. Local use only (not run
 *       in CI). It can never reach Atlas, Render, production or staging.
 *
 * All values are synthetic and generated per run; none is printed (messages are redacted).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  assertStagingSafety,
  evaluateStagingDatabasePolicy,
  parseStagingTestLogins,
  STAGING_ALLOWED_DB_NAMES,
  STAGING_DB_NAME,
  STAGING_SHARED_DEV_ACK_VAR,
  STAGING_SHARED_DEV_DB_NAME,
  STAGING_SMS_ALLOWED_PHONES_VAR,
  STAGING_SMS_MODE_VAR,
} from "../utils/stagingGuards.js";
import { assertEnvironmentIdentity, STAGING_MARKER_VARIABLES } from "../utils/environmentIdentity.js";
import {
  endpointFingerprint,
  mongoEndpointIdentity,
  mongoFingerprints,
  parseFingerprintList,
  parseMongoTarget,
  parseRedisTarget,
  redisFingerprint,
} from "../utils/mongoTarget.js";
import { evaluateConnectionStatus, runStagingPreflight, runStagingStartupGate } from "../utils/stagingStartupGate.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BACKEND_DIR = path.resolve(__dirname, "..");
const BACKEND_PKG = path.join(BACKEND_DIR, "package.json");
const require = createRequire(BACKEND_PKG);
const RUN_REAL_MONGO = process.argv.includes("--real-mongo");
const rnd = (bytes) => crypto.randomBytes(bytes).toString("hex");

// ─── Hermetic environment (before anything reads it) ───────────────────────
for (const name of ["REDIS_URL", "MONGODB_URI", "ZEMISH_DIAG_REDIS_URL", "STAGING_TEST_LOGINS", "RENDER", "RENDER_SERVICE_NAME", "RENDER_GIT_BRANCH"]) {
  delete process.env[name];
}
process.env.NODE_ENV = "test";

// ─── Synthetic sentinels (never printed) ───────────────────────────────────
const USER_NAME = `svc${rnd(3)}`;
const USER_PASS = rnd(10);
const ATLAS_STAGING_ID = `s${rnd(2)}`; // fictional `<id>.mongodb.net` labels
const ATLAS_PROD_ID = `p${rnd(2)}`;
const REDIS_STAGING_HOST = `redis-stg-${rnd(3)}.invalid`;
const REDIS_PROD_HOST = `redis-prd-${rnd(3)}.invalid`;
const SENTINELS = [USER_PASS, ATLAS_STAGING_ID, ATLAS_PROD_ID, REDIS_STAGING_HOST, REDIS_PROD_HOST];
const redact = (text) => SENTINELS.reduce((acc, s) => acc.split(s).join("<redacted>"), String(text));

const scheme = (name) => `${name}:` + "//"; // keeps `scheme://user:pass@host` out of this file's text
const mongoUri = (name, rest) => `${scheme(name)}${USER_NAME}:${USER_PASS}@${rest}`;
const atlasSrv = (id, db, query = "?retryWrites=true") => mongoUri("mongodb+srv", `cluster0.${id}.mongodb.net/${db}${query}`);
const atlasSeedList = (id, db) =>
  mongoUri("mongodb", `ac-x-shard-00-00.${id}.mongodb.net:27017,ac-x-shard-00-01.${id}.mongodb.net:27017/${db}?replicaSet=r`);
const redisUri = (host) => mongoUri("rediss", `${host}:6379`);

const FP_PROD_MONGO = mongoFingerprints([`cluster0.${ATLAS_PROD_ID}.mongodb.net`]).join(",");
const FP_PROD_REDIS = redisFingerprint(REDIS_PROD_HOST);

// A tester OTP the guard's OWN strength rules accept (a fixed weak-pattern filter would be flaky).
const SAFE_LOGINS = (() => {
  for (;;) {
    const candidate = `6000000011:${crypto.randomInt(100000, 1000000)}`;
    if (parseStagingTestLogins(candidate).logins.size === 1) return candidate;
  }
})();
// A complete, SAFE staging environment on the dedicated staging database.
const safeEnv = (over = {}) => ({
  NODE_ENV: "staging",
  STAGING_TEST_LOGINS: SAFE_LOGINS,
  RAZORPAY_KEY_ID: "rzp_test_synthetic1",
  RAZORPAY_KEY_SECRET: rnd(8),
  MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, STAGING_DB_NAME),
  REDIS_URL: redisUri(REDIS_STAGING_HOST),
  STAGING_FORBIDDEN_MONGO_ENDPOINTS: FP_PROD_MONGO,
  STAGING_FORBIDDEN_REDIS_ENDPOINTS: FP_PROD_REDIS,
  JWT_ACCESS_SECRET: rnd(24),
  OTP_SECRET: rnd(24),
  OTP_ENCRYPT_KEY: rnd(24),
  ADMIN_RESET_PASSWORD: `Adm!${rnd(8)}`,
  ...over,
});
// The approved strategy: the shared dev database, explicitly acknowledged.
const sharedDevEnv = (over = {}) =>
  safeEnv({ MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, STAGING_SHARED_DEV_DB_NAME), [STAGING_SHARED_DEV_ACK_VAR]: STAGING_SHARED_DEV_DB_NAME, ...over });
const without = (env, ...names) => { const e = { ...env }; for (const n of names) delete e[n]; return e; };

// ─── Tiny harness ──────────────────────────────────────────────────────────
const results = [];
const test = async (id, name, fn) => {
  try {
    await fn();
    results.push({ id, ok: true });
    console.log(`  ✅ ${id} ${name}`);
  } catch (error) {
    results.push({ id, ok: false });
    console.log(`  ❌ ${id} ${name} — ${redact(error?.message || error)}`);
  }
};
const expect = (condition, label) => { if (!condition) throw new Error(label); };
const section = (title) => console.log(`\n── ${title} ──`);
const noLeak = (text, label) => {
  for (const s of SENTINELS) expect(!String(text).includes(s), `${label}: a host/credential leaked`);
  for (const fp of [FP_PROD_MONGO, FP_PROD_REDIS]) expect(!String(text).includes(fp), `${label}: a fingerprint leaked`);
};

console.log("Staging isolation hardening — behavioural verification (hermetic; synthetic values only)");

// ═══ I — Render identity vs NODE_ENV ═══════════════════════════════════════
section("I  Render identity");

await test("I1", "identity matrix: staging service must be NODE_ENV=staging; production service must not be; unknown service cannot claim staging", async () => {
  const cases = [
    // [RENDER, name, NODE_ENV, expected violations]
    ["true", "BARBER_ENGINE_V1", "production", 1],
    ["true", "BARBER_ENGINE_V1", undefined, 1],
    ["true", "BARBER_ENGINE_V1", "development", 1],
    ["true", "barber-engine-v1", "production", 1],
    ["true", "Barber_Engine_V1", "staging", 0],
    ["true", "zemish-production-api", "production", 0],
    ["true", "ZEMISH-PRODUCTION-API", "production", 0],
    ["true", "zemish-production-api", "staging", 2], // production service + staging NODE_ENV, and not a staging service
    ["true", "some-other-service", "production", 0],
    ["true", "some-other-service", "staging", 1],
    ["true", undefined, "staging", 1],
    ["true", undefined, "production", 0],
    [undefined, "BARBER_ENGINE_V1", "production", 0], // not on Render: inert (local / CI)
    ["false", "BARBER_ENGINE_V1", "production", 0],
    ["TRUE", "BARBER_ENGINE_V1", "production", 0], // only the exact value Render sets counts
  ];
  for (const [render, name, nodeEnv, expected] of cases) {
    const env = {};
    if (render !== undefined) env.RENDER = render;
    if (name !== undefined) env.RENDER_SERVICE_NAME = name;
    if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
    const got = assertEnvironmentIdentity(env).length;
    expect(got === expected, `RENDER=${render} name=${name} NODE_ENV=${nodeEnv}: expected ${expected} violation(s), got ${got}`);
  }
});

await test("I2", "the full guard applies the identity rules for production, development and unset NODE_ENV too", async () => {
  const base = { RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1" };
  for (const nodeEnv of ["production", "development", "test", undefined]) {
    const env = { ...base }; if (nodeEnv) env.NODE_ENV = nodeEnv;
    expect(assertStagingSafety(env).length === 1, `staging service with NODE_ENV=${nodeEnv} was not refused`);
  }
  expect(assertStagingSafety(safeEnv({ ...base })).length === 0, "a correctly configured staging service was refused");
  expect(assertStagingSafety({ RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", NODE_ENV: "production" }).length === 0, "the production service was affected");
});

await test("I3", "boot entry (real stagingBootGuard.js in a child process): staging service in production mode exits 1; production unchanged; correct staging passes", async () => {
  const entry = pathToFileURL(path.join(BACKEND_DIR, "config/stagingBootGuard.js")).href;
  const run = (env) => spawnSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(entry)})`], { cwd: os.tmpdir(), env: { PATH: process.env.PATH, ...env }, encoding: "utf8", timeout: 15000 });
  const bad = run({ RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1", NODE_ENV: "production" });
  expect(bad.status === 1 && /Refusing to start/.test(bad.stderr) && /staging service/.test(bad.stderr), "staging service in production mode was not refused");
  const prod = run({ RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", NODE_ENV: "production" });
  expect(prod.status === 0 && `${prod.stdout}${prod.stderr}`.trim() === "", "production boot guard changed (must pass silently)");
  const ok = run(safeEnv({ RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1" }));
  expect(ok.status === 0, "a correctly configured staging service was refused");
  const dev = run({ NODE_ENV: "development" });
  expect(dev.status === 0 && `${dev.stdout}${dev.stderr}`.trim() === "", "local development changed");
  noLeak(`${bad.stdout}${bad.stderr}`, "boot output");
});

await test("I4", "branch identity (RENDER_GIT_BRANCH): a service deploying develop must be NODE_ENV=staging whatever its name; main cannot run as staging; absent/other branches give no signal", async () => {
  const RENAMED = "renamed-service";
  const cases = [
    // [RENDER, service name, branch, NODE_ENV, expected violations, label]
    ["true", "BARBER_ENGINE_V1", "develop", "staging", 0, "correct staging service"],
    ["true", "barber-engine-v1", "develop", "production", 2, "staging name + develop + production mode (name rule AND branch rule)"],
    ["true", RENAMED, "develop", "production", 1, "RENAMED service on develop in production mode (the fail-open case)"],
    ["true", undefined, "develop", "production", 1, "service name MISSING, develop, production mode"],
    ["true", undefined, "develop", undefined, 1, "service name missing, develop, NODE_ENV unset"],
    ["true", RENAMED, "develop", "development", 1, "renamed, develop, development mode"],
    ["true", RENAMED, "develop", "Staging", 1, "NODE_ENV must be EXACTLY staging (case matters)"],
    ["true", RENAMED, "develop", "staging", 1, "renamed + staging mode: still refused by the existing service-name rule"],
    ["true", undefined, "develop", "staging", 1, "name missing + staging mode: still refused by the existing service-name rule"],
    ["true", "zemish-production-api", "develop", "production", 1, "contradictory: production name deploying develop"],
    ["true", "zemish-production-api", "develop", "staging", 2, "production name + staging mode (existing rules only)"],
    ["true", "zemish-production-api", "main", "production", 0, "NORMAL production: main + production name + production mode"],
    ["true", RENAMED, "main", "production", 0, "main + renamed + production: unchanged"],
    ["true", undefined, "main", "production", 0, "main + name missing + production: unchanged"],
    ["true", "BARBER_ENGINE_V1", "main", "staging", 1, "contradictory: staging name + staging mode but deploying main"],
    ["true", "BARBER_ENGINE_V1", "main", "production", 1, "staging name in production mode (existing rule)"],
    ["true", RENAMED, "main", "staging", 2, "main in staging mode, unknown service"],
    ["true", "zemish-production-api", "main", "staging", 3, "production name + main + staging mode"],
    ["true", RENAMED, " DEVELOP ", "production", 1, "branch compared trimmed and case-insensitively"],
    ["true", "zemish-production-api", "Main", "production", 0, "branch Main (case) on production: unchanged"],
    ["true", RENAMED, undefined, "production", 0, "no branch variable: no signal, production unaffected"],
    ["true", RENAMED, "", "production", 0, "empty branch variable: no signal"],
    ["true", "BARBER_ENGINE_V1", undefined, "production", 1, "no branch signal: the service-name rule still applies"],
    ["true", RENAMED, "feature/x", "production", 0, "other branch: no signal"],
    ["true", RENAMED, "feature/x", "staging", 1, "other branch in staging mode: only the service-name rule"],
    ["true", RENAMED, "develop-2", "production", 0, "exact match only (develop-2)"],
    ["true", RENAMED, "developer", "production", 0, "exact match only (developer)"],
    [undefined, RENAMED, "develop", "production", 0, "NOT on Render: inert even with RENDER_GIT_BRANCH=develop"],
    [undefined, "BARBER_ENGINE_V1", "develop", "development", 0, "local dev with develop checked out and a staging-like name: inert"],
    ["false", RENAMED, "develop", "production", 0, "RENDER=false: inert"],
    ["TRUE", RENAMED, "develop", "production", 0, "only the exact value Render sets counts"],
    [undefined, RENAMED, "main", "staging", 0, "not on Render: staging mode locally is not judged by branch"],
  ];
  for (const [render, name, branch, nodeEnv, expected, label] of cases) {
    const env = {};
    if (render !== undefined) env.RENDER = render;
    if (name !== undefined) env.RENDER_SERVICE_NAME = name;
    if (branch !== undefined) env.RENDER_GIT_BRANCH = branch;
    if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
    const got = assertEnvironmentIdentity(env);
    expect(got.length === expected, `${label}: expected ${expected} violation(s), got ${got.length}`);
  }
  // Messages are value-free: neither the service name nor the branch value read from the environment is echoed.
  const unique = `svc-${rnd(4)}`;
  const text = assertEnvironmentIdentity({ RENDER: "true", RENDER_SERVICE_NAME: unique, RENDER_GIT_BRANCH: " develop ", NODE_ENV: "production" }).join("\n");
  expect(text.length > 0 && !text.includes(unique), "the service name was echoed");
});

await test("I5", "boot entry (real stagingBootGuard.js, child process): develop in production mode is refused even with a renamed/missing service name; normal production and plain local development are silent", async () => {
  const entry = pathToFileURL(path.join(BACKEND_DIR, "config/stagingBootGuard.js")).href;
  const run = (env) => spawnSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(entry)})`], { cwd: os.tmpdir(), env: { PATH: process.env.PATH, ...env }, encoding: "utf8", timeout: 15000 });
  for (const env of [
    { RENDER: "true", RENDER_SERVICE_NAME: "renamed-service", RENDER_GIT_BRANCH: "develop", NODE_ENV: "production" },
    { RENDER: "true", RENDER_GIT_BRANCH: "develop", NODE_ENV: "production" },
    { RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", RENDER_GIT_BRANCH: "develop", NODE_ENV: "production" },
  ]) {
    const r = run(env);
    expect(r.status === 1 && /Refusing to start/.test(r.stderr) && /develop/.test(r.stderr), "a service deploying develop in production mode was not refused");
    noLeak(`${r.stdout}${r.stderr}`, "branch refusal output");
  }
  const prod = run({ RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", RENDER_GIT_BRANCH: "main", NODE_ENV: "production" });
  expect(prod.status === 0 && `${prod.stdout}${prod.stderr}`.trim() === "", "normal production boot guard changed");
  const ok = run(safeEnv({ RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1", RENDER_GIT_BRANCH: "develop" }));
  expect(ok.status === 0, "a correct staging service on develop was refused");
  const dev = run({ NODE_ENV: "development", RENDER_GIT_BRANCH: "develop" });
  expect(dev.status === 0 && `${dev.stdout}${dev.stderr}`.trim() === "", "local development with develop checked out changed");
  expect(assertStagingSafety({ RENDER: "true", RENDER_SERVICE_NAME: "renamed-service", RENDER_GIT_BRANCH: "develop", NODE_ENV: "production" }).length === 1, "the full guard does not apply the branch rule");
});

// ─── Staging-only variables as an explicit staging identity (R-ID-6) ───────
const markerValue = (name) => (name === "STAGING_TEST_LOGINS" ? SAFE_LOGINS : name === "STAGING_ACK_SHARED_DEV_DATABASE" ? STAGING_SHARED_DEV_DB_NAME : FP_PROD_MONGO);
const withMarkers = (names) => Object.fromEntries(names.map((n) => [n, markerValue(n)]));

await test("I6", "explicit staging identity (staging-only variables) must run as NODE_ENV=staging whatever the service name or branch; every other identity scenario is unchanged", async () => {
  const ALL = [...STAGING_MARKER_VARIABLES];
  const RENAMED = "renamed-service";
  const cases = [
    // [RENDER, service name, branch, NODE_ENV, marker variables set, expected violations, label]
    ["true", "BARBER_ENGINE_V1", "develop", "staging", ALL, 0, "ACCEPTED: expected staging service on develop, NODE_ENV=staging, fully configured"],
    ["true", "barber-engine-v1", "feature/x", "staging", ALL, 0, "ACCEPTED: staging service on another branch in staging mode"],
    ["true", "BARBER_ENGINE_V1", "develop", "production", ["STAGING_TEST_LOGINS"], 3, "REFUSED: staging service on develop in production mode (name + branch + marker rules all fire)"],
    ["true", RENAMED, "feature/x", "production", ["STAGING_TEST_LOGINS"], 1, "REFUSED (the edge case): RENAMED service, other branch, production mode, staging identity established"],
    ...ALL.map((n) => ["true", RENAMED, "feature/x", "production", [n], 1, `REFUSED: renamed + other branch + production mode with ONLY ${n} set`]),
    ["true", undefined, undefined, "production", ALL, 1, "REFUSED: no name and no branch signal, but staging variables set"],
    ["true", RENAMED, "feature/x", "development", ["STAGING_FORBIDDEN_MONGO_ENDPOINTS"], 1, "REFUSED: staging identity with NODE_ENV=development"],
    ["true", RENAMED, "feature/x", undefined, ["STAGING_FORBIDDEN_MONGO_ENDPOINTS"], 1, "REFUSED: staging identity with NODE_ENV unset"],
    ["true", RENAMED, "feature/x", "Staging", ["STAGING_TEST_LOGINS"], 1, "REFUSED: NODE_ENV must be EXACTLY staging (case matters)"],
    ["true", RENAMED, "feature/x", "staging", ALL, 1, "renamed + staging mode: the new rule is silent, the EXISTING service-name rule still refuses (add the name in a reviewed change)"],
    ["true", "zemish-production-api", "main", "production", ["STAGING_TEST_LOGINS"], 1, "REFUSED (contradictory): production name + main + production mode but staging variables set"],
    ["true", "zemish-production-api", "develop", "production", ["STAGING_TEST_LOGINS"], 2, "REFUSED (contradictory): production name deploying develop with staging variables"],
    ["true", "zemish-production-api", "main", "staging", ALL, 3, "REFUSED (contradictory): production name + main in staging mode (existing rules)"],
    ["true", "BARBER_ENGINE_V1", "main", "staging", ALL, 1, "REFUSED (contradictory): staging name in staging mode but deploying main (existing rule)"],
    // Nothing to see: unchanged behaviour.
    ["true", "zemish-production-api", "main", "production", [], 0, "UNCHANGED: normal production (main + production service + production mode)"],
    ["true", RENAMED, "main", "production", [], 0, "UNCHANGED: production on main under another name"],
    ["true", undefined, undefined, "production", [], 0, "UNCHANGED: no Render identity variables, production mode"],
    ["true", RENAMED, "feature/x", "production", [], 0, "KNOWN RESIDUAL: renamed + other branch + production mode + NO staging variable is indistinguishable from production"],
    [undefined, RENAMED, "feature/x", "production", ALL, 0, "UNCHANGED: not on Render — inert (the existing production-only STAGING_TEST_LOGINS rule is separate)"],
    [undefined, undefined, undefined, "development", ALL, 0, "UNCHANGED: local development with a staging .env copied in"],
    [undefined, undefined, undefined, undefined, ALL, 0, "UNCHANGED: NODE_ENV unset locally"],
    ["false", RENAMED, "feature/x", "production", ALL, 0, "UNCHANGED: RENDER=false"],
    ["TRUE", RENAMED, "feature/x", "production", ALL, 0, "UNCHANGED: only the exact value Render sets counts"],
  ];
  for (const [render, name, branch, nodeEnv, markers, expected, label] of cases) {
    const env = { ...withMarkers(markers) };
    if (render !== undefined) env.RENDER = render;
    if (name !== undefined) env.RENDER_SERVICE_NAME = name;
    if (branch !== undefined) env.RENDER_GIT_BRANCH = branch;
    if (nodeEnv !== undefined) env.NODE_ENV = nodeEnv;
    const got = assertEnvironmentIdentity(env);
    expect(got.length === expected, `${label}: expected ${expected} violation(s), got ${got.length}`);
  }
  // Blank / whitespace values are not a staging identity.
  for (const blank of ["", "   "]) {
    const env = { RENDER: "true", RENDER_SERVICE_NAME: "renamed-service", RENDER_GIT_BRANCH: "feature/x", NODE_ENV: "production", STAGING_TEST_LOGINS: blank, STAGING_FORBIDDEN_MONGO_ENDPOINTS: blank };
    expect(assertEnvironmentIdentity(env).length === 0, "a blank staging variable was treated as staging identity");
  }
  // Messages name the variables, never their values.
  const text = assertEnvironmentIdentity({ RENDER: "true", RENDER_SERVICE_NAME: "renamed-service", RENDER_GIT_BRANCH: "feature/x", NODE_ENV: "production", ...withMarkers(ALL) }).join("\n");
  expect(STAGING_MARKER_VARIABLES.every((n) => text.includes(n)), "the message does not name every variable present");
  for (const n of ALL) expect(!text.includes(markerValue(n)), `the value of ${n} was echoed`);
  noLeak(text, "identity message");
});

await test("I7", "marker list cannot drift: it equals the staging-only variables the guard actually reads; real boot entry refuses the edge case, accepts correct staging, and leaves production and local development untouched", async () => {
  // Static completeness: every STAGING_* env var read in stagingGuards.js is a marker, and every marker is read there.
  const source = fs.readFileSync(path.join(BACKEND_DIR, "utils/stagingGuards.js"), "utf8");
  const read = new Set([...source.matchAll(/\benv\.(STAGING_[A-Z0-9_]+)/g)].map((m) => m[1]));
  read.add(STAGING_SHARED_DEV_ACK_VAR); // read through a named constant, not `env.STAGING_*`
  read.add(STAGING_SMS_MODE_VAR);
  read.add(STAGING_SMS_ALLOWED_PHONES_VAR);
  expect(JSON.stringify([...read].sort()) === JSON.stringify([...STAGING_MARKER_VARIABLES].sort()), `marker list differs from the guard's reads: guard=${[...read].sort()} markers=${[...STAGING_MARKER_VARIABLES].sort()}`);

  const entry = pathToFileURL(path.join(BACKEND_DIR, "config/stagingBootGuard.js")).href;
  const run = (env) => spawnSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(entry)})`], { cwd: os.tmpdir(), env: { PATH: process.env.PATH, ...env }, encoding: "utf8", timeout: 15000 });
  const renamedProd = { RENDER: "true", RENDER_SERVICE_NAME: "renamed-service", RENDER_GIT_BRANCH: "feature/x", NODE_ENV: "production" };
  for (const n of STAGING_MARKER_VARIABLES) {
    const r = run({ ...renamedProd, ...withMarkers([n]) });
    expect(r.status === 1 && /Refusing to start/.test(r.stderr) && r.stderr.includes(n), `${n}: the renamed-service edge case was not refused (exit ${r.status})`);
    expect(!r.stderr.includes(markerValue(n)), `${n}: its value reached the output`);
    noLeak(`${r.stdout}${r.stderr}`, `${n} refusal output`);
  }
  const good = run(safeEnv({ RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1", RENDER_GIT_BRANCH: "develop" }));
  expect(good.status === 0, "a correct, fully configured staging service on develop was refused");
  const prod = run({ RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", RENDER_GIT_BRANCH: "main", NODE_ENV: "production" });
  expect(prod.status === 0 && `${prod.stdout}${prod.stderr}`.trim() === "", "normal production boot guard changed");
  const dev = run({ NODE_ENV: "development", ...withMarkers([...STAGING_MARKER_VARIABLES]) });
  expect(dev.status === 0 && `${dev.stdout}${dev.stderr}`.trim() === "", "local development with staging variables present changed");
  const devUnset = run({ ...withMarkers([...STAGING_MARKER_VARIABLES]) });
  expect(devUnset.status === 0 && `${devUnset.stdout}${devUnset.stderr}`.trim() === "", "NODE_ENV unset locally with staging variables changed");
  // Pre-existing rule (PR #8), untouched: off Render, production mode + STAGING_TEST_LOGINS is still refused with its own message.
  const legacy = run({ NODE_ENV: "production", ...withMarkers(["STAGING_TEST_LOGINS"]) });
  expect(legacy.status === 1 && /STAGING_TEST_LOGINS must not be set when NODE_ENV=production/.test(legacy.stderr), "the pre-existing production rule changed");
});

// ═══ M — MongoDB URI parsing: the driver is the authority ═════════════════
section("M  MongoDB URI parsing (driver semantics)");
const { MongoClient } = require("mongoose").mongo;
const oracleDb = (uri) => { try { return new MongoClient(uri).options.dbName; } catch { return undefined; } };
const sockUri = mongoUri("mongodb", `${encodeURIComponent("/tmp/sock-" + rnd(2))}.sock/barber_engine_v1`);

await test("M1", "accepted URIs: the guard's database name equals the driver's own parse", async () => {
  const accepted = [
    atlasSrv("ab1cd", "barber_engine_staging"),
    atlasSrv("ab1cd", "barber_engine_v1", "?retryWrites=true&w=majority"),
    atlasSeedList("ab1cd", "barber_engine_v1"),
    atlasSrv("ab1cd", "barber%5Fengine%5Fstaging"),
    sockUri,
  ];
  for (const uri of accepted) {
    const target = parseMongoTarget(uri);
    expect(target.ok === true, "an acceptable URI was refused");
    expect(target.dbName === oracleDb(uri), "guard database name differs from the driver's");
    expect(target.hosts.length >= 1, "no hosts extracted");
  }
  expect(parseMongoTarget(atlasSrv("ab1cd", "barber%5Fengine%5Fstaging")).dbName === "barber_engine_staging", "percent-decoding differs");
});

await test("M2", "refused URIs (malformed or ambiguous) — each with a fixed reason code, never text from the URI", async () => {
  const bad = [
    ["no database path", atlasSrv("ab1cd", "", "?retryWrites=true"), "NO_DATABASE_PATH"],
    ["options without a slash", mongoUri("mongodb+srv", `cluster0.ab1cd.mongodb.net?retryWrites=true`), "NO_DATABASE_PATH"],
    ["trailing slash after the name", atlasSrv("ab1cd", "barber_engine_staging/", ""), "AMBIGUOUS_DATABASE"],
    ["fragment", atlasSrv("ab1cd", "barber_engine_staging#frag", ""), "FRAGMENT"],
    ["leading space", ` ${atlasSrv("ab1cd", "barber_engine_staging")}`, "WHITESPACE"],
    ["trailing newline", `${atlasSrv("ab1cd", "barber_engine_staging")}\n`, "WHITESPACE"],
    ["embedded space", atlasSrv("ab1cd", "barber engine"), "WHITESPACE"],
    ["unknown option", atlasSrv("ab1cd", "barber_engine_v1", "?x=barber_engine_staging"), "UNPARSEABLE"],
    ["unescaped slash in the password", `${scheme("mongodb+srv")}${USER_NAME}:pa/ss@cluster0.ab1cd.mongodb.net/barber_engine_staging`, null],
    ["wrong scheme", `http${":" + "//"}cluster0.ab1cd.mongodb.net/barber_engine_staging`, "SCHEME"],
    ["empty", "", "NOT_SET"],
    ["not a string", undefined, "NOT_SET"],
  ];
  for (const [label, uri, reason] of bad) {
    const target = parseMongoTarget(uri);
    expect(target.ok === false, `${label}: was accepted`);
    if (reason) expect(target.reason === reason, `${label}: reason ${target.reason}, expected ${reason}`);
    expect(/^[A-Z_]+$/.test(target.reason), `${label}: reason is not a fixed code`);
    noLeak(JSON.stringify(target), `${label} result`);
  }
});

await test("M3", "ambiguity: a driver-level database override that disagrees with the path is refused, and a trailing slash is a DIFFERENT database to the driver", async () => {
  expect(oracleDb(atlasSrv("ab1cd", "barber_engine_staging/", "")) === "barber_engine_staging/", "driver no longer reads the trailing slash as part of the name — revisit the AMBIGUOUS rule");
  const override = atlasSrv("ab1cd", "barber_engine_staging", "?dbName=barber_engine_v1");
  const t = parseMongoTarget(override);
  if (oracleDb(override) === undefined) expect(t.ok === false, "an override the driver rejects was accepted");
  else if (oracleDb(override) !== "barber_engine_staging") expect(t.ok === false && t.reason === "AMBIGUOUS_DATABASE", "an override that changes the database was accepted");
});

await test("M4", "parsing is offline: no DNS lookup and no socket for mongodb+srv hosts, returns within milliseconds", async () => {
  const before = new Set(process.getActiveResourcesInfo());
  const t0 = Date.now();
  for (let i = 0; i < 25; i += 1) parseMongoTarget(atlasSrv(ATLAS_STAGING_ID, STAGING_DB_NAME));
  const added = process.getActiveResourcesInfo().filter((r) => !before.has(r));
  expect(Date.now() - t0 < 1500, "parsing took suspiciously long (network?)");
  expect(!added.some((r) => /GetAddrInfo|TCPConnect|TCPSocket|DNS/i.test(r)), "a network resource was opened while parsing");
});

await test("M5", "Redis target parsing: scheme/host rules, never echoing the URL", async () => {
  expect(parseRedisTarget(redisUri(REDIS_STAGING_HOST)).ok === true, "valid rediss URL refused");
  expect(parseRedisTarget(mongoUri("redis", "Mixed.Case.INVALID:6380/2")).host === "mixed.case.invalid", "host not normalised");
  for (const bad of [undefined, "", ` ${redisUri("h.invalid")}`, `http${":" + "//"}h.invalid`, "not a url", `${scheme("redis")}`]) {
    const t = parseRedisTarget(bad);
    expect(t.ok === false && /^[A-Z_]+$/.test(t.reason), "a bad Redis URL was accepted or leaked text");
  }
});

// ═══ P — database policy ═══════════════════════════════════════════════════
section("P  staging database policy");

await test("P1", "policy: the dedicated staging DB is always allowed; barber_engine_v1 only with the exact acknowledgment; nothing else", async () => {
  expect(evaluateStagingDatabasePolicy(STAGING_DB_NAME, {}) === null, "staging DB refused");
  expect(typeof evaluateStagingDatabasePolicy(STAGING_SHARED_DEV_DB_NAME, {}) === "string", "shared dev DB allowed without acknowledgment");
  for (const wrong of ["true", "yes", "BARBER_ENGINE_V1", " barber_engine_v1", "barber_engine_staging", ""]) {
    expect(typeof evaluateStagingDatabasePolicy(STAGING_SHARED_DEV_DB_NAME, { [STAGING_SHARED_DEV_ACK_VAR]: wrong }) === "string", `a wrong acknowledgment (${wrong}) was accepted`);
  }
  expect(evaluateStagingDatabasePolicy(STAGING_SHARED_DEV_DB_NAME, { [STAGING_SHARED_DEV_ACK_VAR]: STAGING_SHARED_DEV_DB_NAME }) === null, "the exact acknowledgment was refused");
  for (const other of ["krishna_iptv", "sample_mflix", "test", "admin", "local", "Barber_Engine_V1", "barber_engine_staging_v2", "barber_engine_prod", ""]) {
    expect(typeof evaluateStagingDatabasePolicy(other, { [STAGING_SHARED_DEV_ACK_VAR]: STAGING_SHARED_DEV_DB_NAME }) === "string", `database "${other}" was allowed`);
  }
  expect(JSON.stringify([...STAGING_ALLOWED_DB_NAMES]) === JSON.stringify([STAGING_DB_NAME, STAGING_SHARED_DEV_DB_NAME]), "the allow-list changed");
});

await test("P2", "full guard: approved strategy (barber_engine_v1 + acknowledgment + declared production endpoints) is supported; each missing piece refuses", async () => {
  expect(assertStagingSafety(safeEnv()).length === 0, "dedicated staging database refused");
  expect(assertStagingSafety(sharedDevEnv()).length === 0, "approved shared-dev strategy refused");
  const noAck = assertStagingSafety(without(sharedDevEnv(), STAGING_SHARED_DEV_ACK_VAR));
  expect(noAck.length === 1 && /shared development database/.test(noAck[0]), "barber_engine_v1 accepted without acknowledgment");
  const noMongoList = assertStagingSafety(without(sharedDevEnv(), "STAGING_FORBIDDEN_MONGO_ENDPOINTS"));
  expect(noMongoList.length === 1 && /STAGING_FORBIDDEN_MONGO_ENDPOINTS/.test(noMongoList[0]), "shared-dev database accepted without a declared production Mongo endpoint");
  const noRedisList = assertStagingSafety(without(sharedDevEnv(), "STAGING_FORBIDDEN_REDIS_ENDPOINTS"));
  expect(noRedisList.length === 1 && /STAGING_FORBIDDEN_REDIS_ENDPOINTS/.test(noRedisList[0]), "accepted without a declared production Redis endpoint");
  for (const db of ["krishna_iptv", "sample_mflix", "test"]) {
    const v = assertStagingSafety(safeEnv({ MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, db) }));
    expect(v.length === 1 && /not allowed on staging/.test(v[0]), `database ${db} was accepted`);
  }
});

await test("P3", "shared-dev strategy on a production endpoint is refused: the deny-list is what protects it", async () => {
  const onProd = sharedDevEnv({ MONGODB_URI: atlasSrv(ATLAS_PROD_ID, STAGING_SHARED_DEV_DB_NAME) });
  const v = assertStagingSafety(onProd);
  expect(v.length === 1 && /MONGODB_URI points at an endpoint listed in STAGING_FORBIDDEN_MONGO_ENDPOINTS/.test(v[0]), "barber_engine_v1 on a forbidden cluster was accepted");
  noLeak(v.join("\n"), "policy messages");
});

// ═══ D — endpoint deny-lists ═══════════════════════════════════════════════
section("D  endpoint deny-lists");

await test("D1", "fingerprint formula and normalisation: sha256(kind:identity)[0..16]; SRV and seed-list forms of one Atlas cluster agree; kinds are domain-separated", async () => {
  const ident = mongoEndpointIdentity(`cluster0.${ATLAS_PROD_ID}.mongodb.net`);
  expect(ident === `${ATLAS_PROD_ID}.mongodb.net`, "Atlas identity is not the <id>.mongodb.net label");
  expect(endpointFingerprint("mongo", ident) === crypto.createHash("sha256").update(`mongo:${ident}`).digest("hex").slice(0, 16), "fingerprint formula differs from the documented one");
  const srv = mongoFingerprints(parseMongoTarget(atlasSrv(ATLAS_PROD_ID, "d")).hosts);
  const seed = mongoFingerprints(parseMongoTarget(atlasSeedList(ATLAS_PROD_ID, "d")).hosts);
  expect(JSON.stringify(srv) === JSON.stringify(seed) && srv.length === 1, "SRV and seed-list forms of one cluster give different identities");
  expect(mongoFingerprints(parseMongoTarget(atlasSrv(ATLAS_STAGING_ID, "d")).hosts)[0] !== srv[0], "two clusters share a fingerprint");
  expect(redisFingerprint("Same.Host.Invalid".toLowerCase()) !== endpointFingerprint("mongo", "same.host.invalid"), "kinds are not domain-separated");
  expect(redisFingerprint(parseRedisTarget(mongoUri("redis", "MiXeD.Host.INVALID:1/9")).host) === redisFingerprint("mixed.host.invalid"), "Redis host normalisation differs");
});

await test("D2", "MongoDB deny-list: hit refuses (including the other host form of the same cluster); miss passes", async () => {
  const denyStaging = mongoFingerprints(parseMongoTarget(atlasSrv(ATLAS_STAGING_ID, "d")).hosts).join(",");
  const hitSrv = assertStagingSafety(safeEnv({ STAGING_FORBIDDEN_MONGO_ENDPOINTS: denyStaging }));
  expect(hitSrv.length === 1 && /STAGING_FORBIDDEN_MONGO_ENDPOINTS/.test(hitSrv[0]), "deny-list hit was not refused");
  const hitSeed = assertStagingSafety(safeEnv({ MONGODB_URI: atlasSeedList(ATLAS_STAGING_ID, STAGING_DB_NAME), STAGING_FORBIDDEN_MONGO_ENDPOINTS: denyStaging }));
  expect(hitSeed.length === 1, "the seed-list form of a denied cluster slipped through");
  const mixed = assertStagingSafety(safeEnv({ STAGING_FORBIDDEN_MONGO_ENDPOINTS: `${FP_PROD_MONGO},${denyStaging}` }));
  expect(mixed.length === 1, "a hit among several entries was missed");
  expect(assertStagingSafety(safeEnv()).length === 0, "a deny-list miss was refused");
});

await test("D3", "Redis deny-list: hit refuses; miss passes; host case/port/credentials irrelevant", async () => {
  const hit = assertStagingSafety(safeEnv({ STAGING_FORBIDDEN_REDIS_ENDPOINTS: redisFingerprint(REDIS_STAGING_HOST) }));
  expect(hit.length === 1 && /STAGING_FORBIDDEN_REDIS_ENDPOINTS/.test(hit[0]), "Redis deny-list hit was not refused");
  const sameHostOtherForm = assertStagingSafety(safeEnv({ REDIS_URL: mongoUri("redis", `${REDIS_PROD_HOST.toUpperCase()}:6390/3`) }));
  expect(sameHostOtherForm.length === 1, "the production Redis host in another URL form slipped through");
});

await test("D4", "malformed or missing deny-lists refuse (fail closed) and never echo the value", async () => {
  const ok = FP_PROD_MONGO;
  const badLists = [undefined, "", "   ", "ABCDEF0123456789", ok.slice(0, 15), `${ok}0`, "zz".repeat(8), `${ok},`, `${ok},,${ok}`, ` ${ok}`, `${ok}, ${ok}`, Array.from({ length: 51 }, () => rnd(8)).join(",")];
  for (const list of badLists) {
    for (const [variable, other] of [["STAGING_FORBIDDEN_MONGO_ENDPOINTS", "STAGING_FORBIDDEN_REDIS_ENDPOINTS"], ["STAGING_FORBIDDEN_REDIS_ENDPOINTS", "STAGING_FORBIDDEN_MONGO_ENDPOINTS"]]) {
      const env = safeEnv(); if (list === undefined) delete env[variable]; else env[variable] = list;
      const v = assertStagingSafety(env);
      expect(v.length === 1 && v[0].startsWith(variable), `bad ${variable} (${list === undefined ? "unset" : "value"}) was not refused exactly once`);
      expect(!(list && list.length >= 8 && v.join("\n").includes(list)), "the list value was echoed");
      void other;
    }
  }
  expect(parseFingerprintList(`${ok},${rnd(8)}`).ok === true, "a valid list was refused");
});

await test("D5", "no host, credential or fingerprint appears in ANY guard message for a worst-case environment", async () => {
  const env = safeEnv({
    MONGODB_URI: atlasSrv(ATLAS_PROD_ID, "krishna_iptv"),
    REDIS_URL: redisUri(REDIS_PROD_HOST),
    STAGING_FORBIDDEN_REDIS_ENDPOINTS: `${FP_PROD_REDIS},zz`,
    RENDER: "true", RENDER_SERVICE_NAME: `svc-${ATLAS_STAGING_ID}`,
  });
  const messages = assertStagingSafety(env).join("\n");
  expect(messages.length > 0, "the worst-case environment produced no violations");
  noLeak(messages, "guard messages");
  const hit = assertStagingSafety(sharedDevEnv({ MONGODB_URI: atlasSrv(ATLAS_PROD_ID, STAGING_SHARED_DEV_DB_NAME) })).join("\n");
  noLeak(hit, "deny-list hit message");
});

// ═══ G — post-connect gate ═════════════════════════════════════════════════
section("G  post-connect gate");

// Replies shaped like MongoDB's connectionStatus { showPrivileges: true } (verified against a real mongod with --real-mongo).
const RW_ACTIONS = ["collStats", "createCollection", "createIndex", "dbStats", "dropCollection", "dropIndex", "find", "insert", "killCursors", "listCollections", "listIndexes", "remove", "renameCollectionSameDB", "update"];
const rwPrivileges = (db) => [{ resource: { db, collection: "" }, actions: RW_ACTIONS }, { resource: { db, collection: "system.js" }, actions: ["find", "insert", "remove", "update"] }];
const reply = ({ users = [{ user: "svc", db: "admin" }], roles, privileges }) => ({ authInfo: { authenticatedUsers: users, authenticatedUserRoles: roles, authenticatedUserPrivileges: privileges }, ok: 1 });
const DB = STAGING_SHARED_DEV_DB_NAME;
const scoped = reply({ roles: [{ role: "readWrite", db: DB }], privileges: rwPrivileges(DB) });

await test("G1", "privilege evaluation: scoped users pass; admin, cluster-wide, any-database, cross-database and administrative privileges fail", async () => {
  const pass = [
    ["readWrite scoped to the database", reply({ roles: [{ role: "readWrite", db: DB }], privileges: rwPrivileges(DB) })],
    ["read scoped to the database", reply({ roles: [{ role: "read", db: DB }], privileges: [{ resource: { db: DB, collection: "" }, actions: ["find", "listCollections", "listIndexes"] }] })],
    ["custom role scoped to the database", reply({ roles: [{ role: "stagingApp", db: "admin" }], privileges: rwPrivileges(DB) })],
  ];
  for (const [label, status] of pass) expect(evaluateConnectionStatus({ status, expectedDb: DB }).length === 0, `${label} was refused`);

  const fail = [
    ["root", reply({ roles: [{ role: "root", db: "admin" }], privileges: [{ resource: { anyResource: true }, actions: ["anyAction"] }] })],
    ["atlasAdmin", reply({ roles: [{ role: "atlasAdmin", db: "admin" }], privileges: [{ resource: { cluster: true }, actions: ["listDatabases"] }, ...rwPrivileges(DB)] })],
    ["readWriteAnyDatabase", reply({ roles: [{ role: "readWriteAnyDatabase", db: "admin" }], privileges: [{ resource: { db: "", collection: "" }, actions: RW_ACTIONS }] })],
    ["readAnyDatabase", reply({ roles: [{ role: "readAnyDatabase", db: "admin" }], privileges: [{ resource: { db: "", collection: "" }, actions: ["find"] }] })],
    ["dbAdmin on the database", reply({ roles: [{ role: "dbAdmin", db: DB }], privileges: [{ resource: { db: DB, collection: "" }, actions: ["dropDatabase", "createIndex"] }] })],
    ["dbOwner on the database", reply({ roles: [{ role: "dbOwner", db: DB }], privileges: rwPrivileges(DB) })],
    ["userAdmin on the database", reply({ roles: [{ role: "userAdmin", db: DB }], privileges: [{ resource: { db: DB, collection: "" }, actions: ["createUser", "grantRole"] }] })],
    ["clusterMonitor", reply({ roles: [{ role: "clusterMonitor", db: "admin" }, { role: "readWrite", db: DB }], privileges: [{ resource: { cluster: true }, actions: ["serverStatus"] }, ...rwPrivileges(DB)] })],
    ["scoped plus a second database", reply({ roles: [{ role: "readWrite", db: DB }, { role: "readWrite", db: "krishna_iptv" }], privileges: [...rwPrivileges(DB), ...rwPrivileges("krishna_iptv")] })],
    ["only ANOTHER database", reply({ roles: [{ role: "readWrite", db: "krishna_iptv" }], privileges: rwPrivileges("krishna_iptv") })],
    ["administrative action inside the database", reply({ roles: [{ role: "customAdmin", db: "admin" }], privileges: [{ resource: { db: DB, collection: "" }, actions: ["find", "createUser"] }] })],
    // Isolation fixtures: the ONLY thing wrong is the role / the authentication, so each rule is tested on its own.
    ["dbAdmin role, otherwise innocuous scoped privileges", reply({ roles: [{ role: "dbAdmin", db: DB }], privileges: rwPrivileges(DB) })],
    ["userAdmin role, otherwise innocuous scoped privileges", reply({ roles: [{ role: "userAdmin", db: DB }], privileges: rwPrivileges(DB) })],
    ["clusterAdmin role, otherwise innocuous scoped privileges", reply({ roles: [{ role: "clusterAdmin", db: "admin" }], privileges: rwPrivileges(DB) })],
    ["scoped privileges listed but NO authenticated user", reply({ users: [], roles: [{ role: "readWrite", db: DB }], privileges: rwPrivileges(DB) })],
    ["no privileges at all", reply({ roles: [], privileges: [] })],
    ["unauthenticated connection", reply({ users: [], roles: [], privileges: [] })],
    ["empty reply", {}],
    ["null reply", null],
  ];
  for (const [label, status] of fail) expect(evaluateConnectionStatus({ status, expectedDb: DB }).length >= 1, `${label} was ACCEPTED`);
});

const stubMongoose = ({ name = DB, readyState = 1, command } = {}) => ({
  connection: { readyState, name, db: { admin: () => ({ command: command ?? (async () => reply({ roles: [{ role: "readWrite", db: DB }], privileges: rwPrivileges(DB) })) }) } },
});
const gateEnv = (over = {}) => sharedDevEnv(over);
const runGate = async ({ mongoose = stubMongoose(), env = gateEnv(), dbConnected = Promise.resolve() } = {}) => {
  const logs = []; const exits = [];
  const result = await runStagingStartupGate(dbConnected, { mongoose, env, exit: (c) => exits.push(c), log: { log: (m) => logs.push(`log: ${m}`), error: (m) => logs.push(`error: ${m}`) } });
  return { result, logs: logs.join("\n"), exits };
};

await test("G2", "gate passes for a scoped user on the policy database, prints a value-free confirmation, never exits", async () => {
  const { result, logs, exits } = await runGate();
  expect(result.ok === true && exits.length === 0, "a valid connection was refused");
  expect(/gate passed/.test(logs), "no confirmation line");
  noLeak(logs, "gate log");
});

await test("G3", "gate fails closed — result.ok false and exit(1) exactly once — for every verification failure", async () => {
  const bad = [
    ["connection promise rejects", { dbConnected: Promise.reject(new Error("synthetic")) }],
    ["connection not open", { mongoose: stubMongoose({ readyState: 0 }) }],
    ["connected database name differs from the URI", { mongoose: stubMongoose({ name: "krishna_iptv" }) }],
    ["URI unparseable", { env: gateEnv({ MONGODB_URI: "garbage" }) }],
    ["URI names a database outside the policy", { env: gateEnv({ MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, "krishna_iptv") }), mongoose: stubMongoose({ name: "krishna_iptv" }) }],
    ["shared-dev database without acknowledgment", { env: without(gateEnv(), STAGING_SHARED_DEV_ACK_VAR) }],
    ["connectionStatus command throws", { mongoose: stubMongoose({ command: async () => { throw new Error("synthetic secret-ish text"); } }) }],
    ["root user", { mongoose: stubMongoose({ command: async () => reply({ roles: [{ role: "root", db: "admin" }], privileges: [{ resource: { anyResource: true }, actions: ["anyAction"] }] }) }) }],
    ["any-database user", { mongoose: stubMongoose({ command: async () => reply({ roles: [{ role: "readWriteAnyDatabase", db: "admin" }], privileges: [{ resource: { db: "", collection: "" }, actions: RW_ACTIONS }] }) }) }],
    ["cross-database user", { mongoose: stubMongoose({ command: async () => reply({ roles: [{ role: "readWrite", db: DB }], privileges: [...rwPrivileges(DB), ...rwPrivileges("sample_mflix")] }) }) }],
  ];
  for (const [label, opts] of bad) {
    const { result, logs, exits } = await runGate(opts);
    expect(result.ok === false, `${label}: gate returned ok`);
    expect(exits.length === 1 && exits[0] === 1, `${label}: exit was called ${exits.length} time(s)`);
    expect(/Refusing to start/.test(logs), `${label}: no refusal message`);
    expect(!/synthetic/.test(logs), `${label}: error text from the failure leaked`);
    noLeak(logs, label);
  }
});

await test("G4", "ordering inside the gate: waits for the connection, then checks name, then privileges; stops at the first failure", async () => {
  const order = [];
  let release;
  const dbConnected = new Promise((resolve) => { release = () => { order.push("connected"); resolve(); }; });
  const mongoose = stubMongoose({ command: async () => { order.push("connectionStatus"); return reply({ roles: [{ role: "readWrite", db: DB }], privileges: rwPrivileges(DB) }); } });
  const pending = runGate({ mongoose, dbConnected });
  let resolvedEarly = false; pending.then(() => { resolvedEarly = true; });
  await new Promise((r) => setTimeout(r, 60));
  expect(!resolvedEarly && !order.includes("connectionStatus"), "the gate proceeded before the connection resolved");
  release();
  const { result } = await pending;
  expect(result.ok === true && order.join(">") === "connected>connectionStatus", `unexpected order: ${order.join(">")}`);
  const calls = [];
  await runGate({ mongoose: stubMongoose({ name: "krishna_iptv", command: async () => { calls.push("x"); return {}; } }) });
  expect(calls.length === 0, "privileges were queried after the name check had already failed");
});

// ═══ F — staging pre-flight (unit; stub driver client) ═════════════════════
section("F  staging pre-flight (raw, read-only; runs before Mongoose connects)");

const STATUS_CMD = { connectionStatus: 1, showPrivileges: true };
const SECRETISH = "synthetic secret-ish text";
// A stand-in for the driver's MongoClient that records every call. It exposes ONLY connect / db().admin().command / close,
// so any other call (collection access, writes, ...) would throw and be reported as a refusal.
const makeStubClient = ({ connectError, commandError, closeError, dbName, status } = {}) => {
  const trace = []; const calls = { ctor: [], connect: 0, commands: [], close: 0 };
  class StubClient {
    constructor(uri, options) { calls.ctor.push({ uri, options }); trace.push("construct"); }
    async connect() { calls.connect += 1; trace.push("connect"); if (connectError) throw new Error(SECRETISH); return this; }
    db() { trace.push("db"); return { databaseName: dbName ?? DB, admin: () => ({ command: async (c) => { calls.commands.push(c); trace.push("command"); if (commandError) throw new Error(SECRETISH); return status ?? scoped; } }) }; }
    async close() { calls.close += 1; trace.push("close"); if (closeError) throw new Error(SECRETISH); }
  }
  return { StubClient, calls, trace };
};
const runPre = async ({ env = gateEnv(), ...stub } = {}) => {
  const { StubClient, calls, trace } = makeStubClient(stub);
  const logs = [];
  const result = await runStagingPreflight({ env, MongoClient: StubClient, exit: (c) => trace.push(`exit:${c}`), log: { log: (m) => logs.push(`log: ${m}`), error: (m) => logs.push(`error: ${m}`) } });
  return { result, calls, trace, logs: logs.join("\n") };
};

await test("F1", "pre-flight passes for a scoped user: ONE read-only connectionStatus (showPrivileges), client closed, value-free confirmation, no exit", async () => {
  const env = gateEnv();
  const { result, calls, trace, logs } = await runPre({ env });
  expect(result.ok === true && result.expectedDb === DB, "a valid target was refused");
  expect(trace.join(">") === "construct>connect>db>command>close", `unexpected call sequence: ${trace.join(">")}`);
  expect(calls.commands.length === 1 && JSON.stringify(calls.commands[0]) === JSON.stringify(STATUS_CMD), "the command issued was not exactly { connectionStatus: 1, showPrivileges: true }");
  expect(calls.ctor[0].uri === env.MONGODB_URI, "the client was not built from the configured MONGODB_URI");
  const t = calls.ctor[0].options?.serverSelectionTimeoutMS;
  expect(Number.isFinite(t) && t > 0 && t <= 30000, "the connection attempt is not time-bounded");
  expect(/pre-flight passed/.test(logs), "no confirmation line");
  noLeak(logs, "pre-flight log");
});

await test("F2", "pre-flight fails closed — ok:false, exit(1) exactly once, client closed BEFORE the exit — for every refusal; only connectionStatus is ever issued; nothing from the failure leaks", async () => {
  const root = reply({ roles: [{ role: "root", db: "admin" }], privileges: [{ resource: { anyResource: true }, actions: ["anyAction"] }] });
  const anyDb = reply({ roles: [{ role: "readWriteAnyDatabase", db: "admin" }], privileges: [{ resource: { db: "", collection: "" }, actions: RW_ACTIONS }] });
  const cross = reply({ roles: [{ role: "readWrite", db: DB }], privileges: [...rwPrivileges(DB), ...rwPrivileges("sample_mflix")] });
  const bad = [
    // [label, options, expectClientBuilt]
    ["root user", { status: root }, true],
    ["any-database user", { status: anyDb }, true],
    ["cross-database user", { status: cross }, true],
    ["unauthenticated connection", { status: reply({ users: [], roles: [], privileges: [] }) }, true],
    ["empty reply", { status: {} }, true],
    ["connection failure", { connectError: true }, true],
    ["connectionStatus failure", { commandError: true }, true],
    ["driver selects a different database than the URI names", { dbName: "krishna_iptv" }, true],
    ["root user AND the close also fails", { status: root, closeError: true }, true],
    ["connectionStatus failure AND the close also fails", { commandError: true, closeError: true }, true],
    ["unparseable URI", { env: gateEnv({ MONGODB_URI: "garbage" }) }, false],
    ["URI without a database", { env: gateEnv({ MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, "") }) }, false],
    ["MONGODB_URI missing", { env: without(gateEnv(), "MONGODB_URI") }, false],
    ["database outside the staging policy", { env: gateEnv({ MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, "krishna_iptv") }) }, false],
    ["shared-dev database without the acknowledgment", { env: without(gateEnv(), STAGING_SHARED_DEV_ACK_VAR) }, false],
  ];
  for (const [label, opts, built] of bad) {
    const { result, calls, trace, logs } = await runPre(opts);
    expect(result.ok === false, `${label}: pre-flight returned ok`);
    const exits = trace.filter((t) => t.startsWith("exit:"));
    expect(exits.length === 1 && exits[0] === "exit:1", `${label}: exit was called ${exits.length} time(s)`);
    expect(calls.ctor.length === (built ? 1 : 0), `${label}: client construction mismatch`);
    expect(calls.close === calls.ctor.length, `${label}: the raw client was not closed exactly once (${calls.close} close(s))`);
    if (built) expect(trace.indexOf("close") < trace.indexOf("exit:1"), `${label}: the client was closed AFTER exit (it would be skipped)`);
    expect(calls.commands.every((c) => JSON.stringify(c) === JSON.stringify(STATUS_CMD)), `${label}: a command other than connectionStatus was issued`);
    expect(/Refusing to start — staging database pre-flight failed/.test(logs), `${label}: no refusal message`);
    expect(!logs.includes("synthetic"), `${label}: error text from the failure leaked`);
    noLeak(logs, label);
  }
});

await test("F3", "a failing close() never changes a successful verdict (no exit) and is not retried", async () => {
  const { result, calls, trace } = await runPre({ closeError: true });
  expect(result.ok === true && !trace.some((t) => t.startsWith("exit:")), "a close failure turned a passing check into a refusal/exit");
  expect(calls.close === 1, "close was attempted more than once");
});

await test("F4", "ordering inside the pre-flight: URI, policy, then connect, then the database check, then the privilege command — stops at the first failure", async () => {
  const a = await runPre({ env: gateEnv({ MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, "krishna_iptv") }) });
  expect(a.calls.ctor.length === 0 && a.calls.connect === 0, "the target was contacted although the policy already refused it");
  const b = await runPre({ connectError: true });
  expect(b.calls.commands.length === 0, "a command was issued although the connection failed");
  const c = await runPre({ dbName: "krishna_iptv" });
  expect(c.calls.connect === 1 && c.calls.commands.length === 0, "privileges were queried after the database check had already failed");
});

await test("F5", "server.js wiring (static): the pre-flight is staging-only, uses the driver client, and sits BEFORE connectDB(); config/db.js is not involved", async () => {
  const src = fs.readFileSync(path.join(BACKEND_DIR, "server.js"), "utf8");
  const call = src.indexOf("await runStagingPreflight(");
  const connect = src.indexOf("const dbConnected = connectDB()");
  expect(call > 0 && connect > 0 && call < connect, "the pre-flight does not precede connectDB()");
  const block = src.slice(src.lastIndexOf("if (isStagingEnv())", call), connect);
  expect(/MongoClient:\s*mongoose\.mongo\.MongoClient/.test(block) && /process\.exit\(1\)/.test(block), "the pre-flight block is not staging-guarded / fail-closed");
  expect(src.split("runStagingPreflight(").length === 2, "the pre-flight is invoked more than once or outside the guarded block");
});

// ═══ B — blocking proof: the REAL server.js with the MongoDB layer faked ═══
section("B  blocking proof (real server.js; mongoose.connect faked; no connection ever opens)");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zemish-iso-"));
process.on("exit", () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
const PRELOAD = path.join(tmp, "fakeMongoPreload.mjs");
fs.writeFileSync(PRELOAD, `
import { createRequire } from "node:module";
const require = createRequire(process.env.FAKE_BACKEND_PKG);
const mongoose = require("mongoose");
const mode = process.env.FAKE_DB_MODE || "plain";
const pmode = process.env.FAKE_PREFLIGHT_MODE || "pass";
const real = mongoose.mongo;
// server.js hands mongoose.mongo.MongoClient to the staging pre-flight, so replacing that handle replaces the RAW client.
// Never opens a real connection unless mode === "real" (--real-mongo only).
if (mode !== "real") {
  // The raw pre-flight client: never opens a socket; every call is announced on stdout.
  class FakeClient extends real.MongoClient {
    async connect() { console.log("[fake-db] preflight connect called"); if (pmode === "connectfail") throw new Error("synthetic"); return this; }
    db(...args) {
      const parsed = super.db(...args);
      return { databaseName: process.env.FAKE_PREFLIGHT_DBNAME || parsed.databaseName, admin: () => ({ command: async (cmd) => {
        console.log("[fake-db] preflight command " + JSON.stringify(cmd));
        if (pmode === "statusfail") throw new Error("synthetic");
        return JSON.parse(process.env.FAKE_PREFLIGHT_STATUS);
      } }) };
    }
    async close() { console.log("[fake-db] preflight client closed"); if (pmode === "closefail") throw new Error("synthetic"); }
  }
  mongoose.mongo = Object.create(real, { MongoClient: { value: FakeClient } });
  // "plain": connect() resolves and the connection stays closed (queries buffer).
  // otherwise: the connection LOOKS open with a given name and a canned connectionStatus reply.
  mongoose.connect = async () => {
    console.log("[fake-db] mongoose.connect called");
    if (mode === "plain") return mongoose;
    const conn = mongoose.connection;
    Object.defineProperty(conn, "readyState", { get: () => 1, configurable: true });
    Object.defineProperty(conn, "name", { value: process.env.FAKE_CONNECTION_NAME, writable: true, configurable: true });
    Object.defineProperty(conn, "db", { configurable: true, value: { admin: () => ({ command: async () => {
      console.log("[fake-db] connectionStatus called");
      if (mode === "statusfail") throw new Error("synthetic");
      return JSON.parse(process.env.FAKE_CONNECTION_STATUS);
    } }) } });
    return mongoose;
  };
} else {
  // Passive observers around the REAL driver: same behaviour, plus markers (command NAMES only).
  class Observed extends real.MongoClient {
    constructor(uri, options) { super(uri, { ...options, monitorCommands: true }); this.on("commandStarted", (e) => console.log("[fake-db] preflight command " + e.commandName)); }
    async connect(...a) { console.log("[fake-db] preflight connect called"); return super.connect(...a); }
    async close(...a) { console.log("[fake-db] preflight client closed"); return super.close(...a); }
  }
  mongoose.mongo = Object.create(real, { MongoClient: { value: Observed } });
  const originalConnect = mongoose.connect.bind(mongoose);
  mongoose.connect = (...a) => { console.log("[fake-db] mongoose.connect called"); return originalConnect(...a); };
}
`);

const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const portOpen = (port) => new Promise((resolve) => { const s = net.connect(port, "127.0.0.1"); s.once("connect", () => { s.destroy(); resolve(true); }); s.once("error", () => resolve(false)); });

// Runs the real server.js; resolves when it exits, or ~1.2 s after it printed "Server running".
const runServerOnce = async (env, { fakeMode = "plain", connectionName, connectionStatus, preflight = {} } = {}) => {
  const port = await freePort();
  const child = spawn(process.execPath, ["--import", pathToFileURL(PRELOAD).href, path.join(BACKEND_DIR, "server.js")], {
    cwd: tmp,
    env: {
      PATH: process.env.PATH, PORT: String(port), SKIP_REDIS_AUTOCONNECT: "true",
      RAZORPAY_KEY_ID: "rzp_test_synthetic1", RAZORPAY_KEY_SECRET: rnd(8),
      FAKE_BACKEND_PKG: BACKEND_PKG, FAKE_DB_MODE: fakeMode,
      FAKE_PREFLIGHT_MODE: preflight.mode ?? "pass", FAKE_PREFLIGHT_STATUS: JSON.stringify(preflight.status ?? scoped),
      ...(preflight.dbName ? { FAKE_PREFLIGHT_DBNAME: preflight.dbName } : {}),
      ...(connectionName ? { FAKE_CONNECTION_NAME: connectionName } : {}),
      ...(connectionStatus ? { FAKE_CONNECTION_STATUS: JSON.stringify(connectionStatus) } : {}),
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = ""; let err = ""; let listening = false; let exited = false; let code = null;
  child.stdout.on("data", (d) => { out += d; if (/Server running on port/.test(out)) listening = true; });
  child.stderr.on("data", (d) => { err += d; });
  child.on("exit", (c) => { exited = true; code = c; });
  const started = Date.now();
  while (!exited && Date.now() - started < 30000) {
    await new Promise((r) => setTimeout(r, 100));
    if (listening) { await new Promise((r) => setTimeout(r, 1200)); break; }
  }
  const openWhileRunning = !exited && (await portOpen(port));
  if (!exited) { child.kill("SIGKILL"); await new Promise((r) => child.once("exit", r)); }
  const stdoutLines = out.split("\n");
  const idx = (re) => stdoutLines.findIndex((l) => re.test(l));
  return {
    diag: `exit=${exited ? code : "still running"}; stderr tail: ${redact(err.slice(-400)).replace(/\s+/g, " ")}; stdout tail: ${redact(out.slice(-200)).replace(/\s+/g, " ")}`,
    code: exited ? code : null, out, err, listening, openWhileRunning, portOpenAfter: await portOpen(port),
    gateLine: idx(/Staging startup gate passed/), firstJob: idx(/\bStarted\b/), listenLine: idx(/Server running on port/),
    statusCalls: (out.match(/\[fake-db\] connectionStatus called/g) || []).length,
    jobStarts: (out.match(/\bStarted\b/g) || []).length,
    // pre-flight / connect evidence (markers printed by the preload)
    preflightConnects: (out.match(/\[fake-db\] preflight connect called/g) || []).length,
    preflightCloses: (out.match(/\[fake-db\] preflight client closed/g) || []).length,
    preflightCommands: [...out.matchAll(/\[fake-db\] preflight command (.*)/g)].map((m) => m[1].trim()),
    mongooseConnects: (out.match(/\[fake-db\] mongoose\.connect called/g) || []).length,
    preflightConnectLine: idx(/preflight connect called/), preflightCommandLine: idx(/preflight command/), preflightCloseLine: idx(/preflight client closed/),
    preflightPassLine: idx(/Staging pre-flight passed/), connectLine: idx(/mongoose\.connect called/),
  };
};

// The port comes from binding a throwaway server, closing it and handing the number to the child, which leaves a small window
// in which another process can take it ("listen EADDRINUSE" — reproduced in a stress loop: 1 in 60 concurrent spawns). That is a
// harness race, not server behaviour, so retry with a fresh port when — and ONLY when — that exact error is why the child exited.
// Every other exit (refusals, crashes) is returned untouched.
const runServer = async (env, opts = {}) => {
  let result;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    result = await runServerOnce(env, opts);
    if (!(result.code === 1 && /EADDRINUSE/.test(result.err))) return result;
  }
  return result;
};

const serverStagingEnv = (over = {}) => ({ ...sharedDevEnv({ RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1", RENDER_GIT_BRANCH: "develop" }), ...over });
const jobsOrListenSeen = (r) => r.jobStarts > 0 || r.listening || r.listenLine >= 0 || r.openWhileRunning;

await test("B1", "DEFENSE IN DEPTH — pre-flight passes but the connected user is privileged (root): process exits 1; NO job starts; server NEVER listens; port stays closed", async () => {
  const root = reply({ roles: [{ role: "root", db: "admin" }], privileges: [{ resource: { anyResource: true }, actions: ["anyAction"] }] });
  const r = await runServer(serverStagingEnv(), { fakeMode: "ok", connectionName: DB, connectionStatus: root });
  expect(r.code === 1, `expected exit code 1, got ${r.code}`);
  expect(r.statusCalls === 1, "the privilege check did not run exactly once");
  expect(!jobsOrListenSeen(r) && !r.portOpenAfter, "a job started or the server listened despite the failed gate");
  expect(/Refusing to start — staging database safety gate failed/.test(r.err), "no gate refusal message");
  noLeak(`${r.out}${r.err}`, "B1 output");
});

await test("B2", "DEFENSE IN DEPTH — pre-flight passes but the connected database differs from the URI: exits 1, nothing starts, the privilege command is never even called", async () => {
  const r = await runServer(serverStagingEnv(), { fakeMode: "ok", connectionName: "krishna_iptv", connectionStatus: scoped });
  expect(r.code === 1 && r.statusCalls === 0 && !jobsOrListenSeen(r) && !r.portOpenAfter, "wrong-database connection was not stopped before anything started");
});

await test("B3", "DEFENSE IN DEPTH — pre-flight passes but the post-connect connectionStatus fails: exits 1, nothing starts (fail closed)", async () => {
  const r = await runServer(serverStagingEnv(), { fakeMode: "statusfail", connectionName: DB });
  expect(r.code === 1 && !jobsOrListenSeen(r) && !r.portOpenAfter, "a failed privilege check did not block startup");
  expect(!/synthetic/.test(`${r.out}${r.err}`), "failure text leaked");
});

await test("B4", "DEFENSE IN DEPTH — pre-flight passes but the connected user is any-database / cross-database: exits 1, nothing starts", async () => {
  const anyDb = reply({ roles: [{ role: "readWriteAnyDatabase", db: "admin" }], privileges: [{ resource: { db: "", collection: "" }, actions: RW_ACTIONS }] });
  const cross = reply({ roles: [{ role: "readWrite", db: DB }], privileges: [...rwPrivileges(DB), ...rwPrivileges("sample_mflix")] });
  for (const status of [anyDb, cross]) {
    const r = await runServer(serverStagingEnv(), { fakeMode: "ok", connectionName: DB, connectionStatus: status });
    expect(r.code === 1 && !jobsOrListenSeen(r) && !r.portOpenAfter, "an over-privileged user was not blocked");
  }
});

await test("B5", "STAGING + scoped user: pre-flight (connect, ONE connectionStatus, close) → pre-flight passed → mongoose.connect → post-connect gate → jobs → listen, strictly in that order", async () => {
  const r = await runServer(serverStagingEnv(), { fakeMode: "ok", connectionName: DB, connectionStatus: scoped });
  expect(r.gateLine >= 0, `no gate-passed line (exit ${r.code}); stderr tail: ${redact(r.err.slice(-300))}`);
  expect(r.preflightConnects === 1 && r.preflightCloses === 1 && r.mongooseConnects === 1, "pre-flight / connect counts are not exactly 1 / 1 / 1");
  expect(r.preflightCommands.length === 1 && r.preflightCommands[0] === JSON.stringify(STATUS_CMD), `the pre-flight issued ${JSON.stringify(r.preflightCommands)} instead of exactly one connectionStatus`);
  const order = [r.preflightConnectLine, r.preflightCommandLine, r.preflightCloseLine, r.preflightPassLine, r.connectLine, r.gateLine, r.firstJob, r.listenLine];
  expect(order.every((n) => n >= 0) && order.every((n, i) => i === 0 || n > order[i - 1]), `wrong order of [pre-flight connect, command, close, pass, mongoose.connect, gate, first job, listen]: ${order.join(",")} (${r.diag})`);
  expect(r.statusCalls === 1, "the post-connect gate did not verify exactly once");
  expect(r.jobStarts >= 10, `only ${r.jobStarts} job start lines`);
  expect(r.listening && r.openWhileRunning, "the server did not listen after the gate");
  noLeak(`${r.out}${r.err}`, "B5 output");
});

await test("B5b", "PRE-FLIGHT REFUSALS (post-connect layer would have passed): exit 1; mongoose.connect NEVER called; no gate, no job, no listen; raw client closed; only connectionStatus issued", async () => {
  const root = reply({ roles: [{ role: "root", db: "admin" }], privileges: [{ resource: { anyResource: true }, actions: ["anyAction"] }] });
  const anyDb = reply({ roles: [{ role: "readWriteAnyDatabase", db: "admin" }], privileges: [{ resource: { db: "", collection: "" }, actions: RW_ACTIONS }] });
  const cross = reply({ roles: [{ role: "readWrite", db: DB }], privileges: [...rwPrivileges(DB), ...rwPrivileges("sample_mflix")] });
  const refusals = [
    ["root user", { status: root }],
    ["any-database user", { status: anyDb }],
    ["cross-database user", { status: cross }],
    ["unauthenticated", { status: reply({ users: [], roles: [], privileges: [] }) }],
    ["connection failure", { mode: "connectfail" }],
    ["connectionStatus failure", { mode: "statusfail" }],
    ["driver database differs from the URI", { dbName: "krishna_iptv" }],
    ["root user and the close also fails", { status: root, mode: "closefail" }],
  ];
  for (const [label, preflight] of refusals) {
    // fakeMode "ok" would let the post-connect gate PASS — so only the pre-flight can be what stops the boot.
    const r = await runServer(serverStagingEnv(), { fakeMode: "ok", connectionName: DB, connectionStatus: scoped, preflight });
    expect(r.code === 1, `${label}: expected exit code 1, got ${r.code}`);
    expect(r.mongooseConnects === 0, `${label}: mongoose.connect() WAS called`);
    expect(r.statusCalls === 0 && r.gateLine === -1, `${label}: the post-connect gate was reached`);
    expect(!jobsOrListenSeen(r) && !r.portOpenAfter, `${label}: a job started or the server listened`);
    expect(r.preflightConnects === 1 && r.preflightCloses === 1, `${label}: raw client not built and closed exactly once (${r.preflightConnects}/${r.preflightCloses})`);
    expect(r.preflightCommands.every((c) => c === JSON.stringify(STATUS_CMD)), `${label}: a command other than connectionStatus: ${JSON.stringify(r.preflightCommands)}`);
    expect(/staging database pre-flight failed/.test(r.err), `${label}: no pre-flight refusal message`);
    expect(!/synthetic/.test(`${r.out}${r.err}`), `${label}: failure text leaked`);
    noLeak(`${r.out}${r.err}`, `${label} output`);
  }
});

await test("B5c", "a failing raw close() after a PASSING pre-flight does not block a correct staging boot (verdict unchanged)", async () => {
  const r = await runServer(serverStagingEnv(), { fakeMode: "ok", connectionName: DB, connectionStatus: scoped, preflight: { mode: "closefail" } });
  expect(r.preflightCloses === 1 && r.mongooseConnects === 1 && r.gateLine >= 0 && r.listening, `boot was blocked by a close failure (${r.diag})`);
});

await test("B6", "STAGING service running with NODE_ENV=production (the original failure): exits 1 at the boot guard before ANY application output", async () => {
  const env = { ...sharedDevEnv(), NODE_ENV: "production", RENDER: "true", RENDER_SERVICE_NAME: "BARBER_ENGINE_V1" };
  delete env.STAGING_TEST_LOGINS; // as on a service that was never switched to staging mode
  const r = await runServer(env, { fakeMode: "plain" });
  expect(r.code === 1 && /staging service/.test(r.err), "the mis-modeled staging service was not refused");
  expect(r.out.trim() === "" && !jobsOrListenSeen(r) && !r.portOpenAfter, "application output or listening happened before the refusal");
});

await test("B6b", "RENDER_GIT_BRANCH=develop in production mode is refused at the boot guard — missing, renamed or production-looking service name — before ANY application output, pre-flight or connect", async () => {
  for (const [label, over] of [
    ["renamed service", { RENDER_SERVICE_NAME: "renamed-service" }],
    ["service name missing", { RENDER_SERVICE_NAME: undefined }],
    ["production-looking name (contradictory)", { RENDER_SERVICE_NAME: "zemish-production-api" }],
    ["staging name", { RENDER_SERVICE_NAME: "BARBER_ENGINE_V1" }],
  ]) {
    const env = { ...sharedDevEnv(), NODE_ENV: "production", RENDER: "true", RENDER_GIT_BRANCH: "develop", ...over };
    if (over.RENDER_SERVICE_NAME === undefined) delete env.RENDER_SERVICE_NAME;
    delete env.STAGING_TEST_LOGINS;
    const r = await runServer(env, { fakeMode: "plain" });
    expect(r.code === 1 && /Refusing to start/.test(r.err) && /develop/.test(r.err), `${label}: not refused (exit ${r.code})`);
    expect(r.out.trim() === "" && r.preflightConnects === 0 && r.mongooseConnects === 0 && !jobsOrListenSeen(r) && !r.portOpenAfter, `${label}: output, a connection attempt or listening happened before the refusal`);
    noLeak(`${r.out}${r.err}`, `${label} output`);
  }
  // A renamed service that DID set staging mode is still refused by the existing service-name rule.
  const r = await runServer(serverStagingEnv({ RENDER_SERVICE_NAME: "renamed-service" }), { fakeMode: "plain" });
  expect(r.code === 1 && r.out.trim() === "" && r.mongooseConnects === 0, "a renamed staging-mode service was not refused");
  // Main branch cannot run in staging mode.
  const m = await runServer(serverStagingEnv({ RENDER_GIT_BRANCH: "main" }), { fakeMode: "plain" });
  expect(m.code === 1 && m.out.trim() === "" && m.mongooseConnects === 0 && /main/.test(m.err), "staging mode on branch main was not refused");
});

await test("B6c", "REAL server.js: a RENAMED staging service on another branch in production mode, staging identity established by its staging variables, is refused before ANY application output, pre-flight or connect", async () => {
  const env = { ...sharedDevEnv(), NODE_ENV: "production", RENDER: "true", RENDER_SERVICE_NAME: "renamed-service", RENDER_GIT_BRANCH: "feature/x" };
  const r = await runServer(env, { fakeMode: "plain" });
  expect(r.code === 1 && /Refusing to start/.test(r.err) && /Staging-only configuration is present/.test(r.err), `not refused (exit ${r.code})`);
  expect(r.out.trim() === "" && r.preflightConnects === 0 && r.mongooseConnects === 0 && !jobsOrListenSeen(r) && !r.portOpenAfter, "output, a connection attempt or listening happened before the refusal");
  noLeak(`${r.out}${r.err}`, "B6c output");
});

const prodEnv = () => ({ NODE_ENV: "production", OTP_SECRET: rnd(24), OTP_ENCRYPT_KEY: rnd(24), ADMIN_RESET_PASSWORD: `Adm!${rnd(8)}`, JWT_ACCESS_SECRET: rnd(24), MONGODB_URI: atlasSrv(ATLAS_PROD_ID, "prod_db_fixture"), REDIS_URL: redisUri(REDIS_PROD_HOST) });

await test("B7", "PRODUCTION (zemish-production-api, branch main, NODE_ENV=production) regression: no pre-flight, no gate, no privilege query; mongoose.connect then jobs then listen, exactly as before — with and without RENDER_GIT_BRANCH", async () => {
  for (const [label, extra] of [["branch main", { RENDER_GIT_BRANCH: "main" }], ["no branch variable", {}]]) {
    const r = await runServer({ ...prodEnv(), RENDER: "true", RENDER_SERVICE_NAME: "zemish-production-api", ...extra }, { fakeMode: "plain" });
    expect(r.listening && r.openWhileRunning, `${label}: production did not start (exit ${r.code}); tail: ${redact(r.err.slice(-300))}`);
    expect(r.gateLine === -1 && r.statusCalls === 0, `${label}: the staging gate ran on production`);
    expect(r.preflightConnects === 0 && r.preflightCloses === 0 && r.preflightCommands.length === 0 && r.preflightPassLine === -1, `${label}: the staging pre-flight ran on production`);
    expect(r.mongooseConnects === 1 && r.connectLine < r.firstJob, `${label}: mongoose.connect was not called exactly once before the jobs`);
    expect(r.jobStarts >= 10 && r.firstJob >= 0 && r.firstJob < r.listenLine, `${label}: production job/listen order changed (jobs start before listen)`);
    noLeak(`${r.out}${r.err}`, `${label} output`);
  }
});

await test("B8", "LOCAL DEVELOPMENT regression: no Render variables — no pre-flight, no gate, connect, jobs then listen, as before; a develop checkout (RENDER_GIT_BRANCH set, RENDER not) is not treated as staging", async () => {
  for (const [label, extra] of [
    ["development", {}],
    ["development with RENDER_GIT_BRANCH=develop", { RENDER_GIT_BRANCH: "develop" }],
    ["development with RENDER_GIT_BRANCH=main", { RENDER_GIT_BRANCH: "main" }],
  ]) {
    const r = await runServer({ NODE_ENV: "development", OTP_SECRET: rnd(24), MONGODB_URI: atlasSrv(ATLAS_STAGING_ID, "dev_db_fixture"), ...extra }, { fakeMode: "plain" });
    expect(r.listening && r.openWhileRunning, `${label}: did not start (exit ${r.code})`);
    expect(r.gateLine === -1 && r.statusCalls === 0, `${label}: the staging gate ran`);
    expect(r.preflightConnects === 0 && r.preflightCommands.length === 0 && r.preflightPassLine === -1, `${label}: the staging pre-flight ran`);
    expect(r.mongooseConnects === 1 && r.connectLine < r.firstJob, `${label}: mongoose.connect not called once before the jobs`);
    expect(r.jobStarts >= 10 && r.firstJob < r.listenLine, `${label}: job/listen order changed`);
  }
  // Production-mode flags without Render identity (e.g. a developer running with NODE_ENV=production) are also untouched.
  const r = await runServer({ ...prodEnv(), RENDER_GIT_BRANCH: "develop" }, { fakeMode: "plain" });
  expect(r.listening && r.preflightConnects === 0 && r.mongooseConnects === 1, "NODE_ENV=production off-Render with RENDER_GIT_BRANCH=develop changed behaviour");
});

// ═══ R — real local mongod (opt-in) ════════════════════════════════════════

// ═══ R — real LOCAL mongod (opt-in: --real-mongo) ══════════════════════════
// A throwaway mongod: authentication ON, bound ONLY to a Unix socket in a fresh temp directory (no TCP),
// scrubbed environment, hard timeout, guaranteed cleanup. Verifies the privilege logic against the REAL
// connectionStatus replies and runs the real server.js end to end. Never touches Atlas/Render/production.
const runRealMongo = async () => {
  section("R  real LOCAL mongod (auth on; Unix socket only; temp dir; hard timeout; guaranteed cleanup)");
  const mongodBin = ["/usr/local/bin/mongod", "/opt/homebrew/bin/mongod", "/usr/bin/mongod"].find((p) => fs.existsSync(p))
    ?? (spawnSync("which", ["mongod"], { env: { PATH: process.env.PATH }, encoding: "utf8" }).stdout || "").trim();
  if (!mongodBin) { console.log("  ⏭  R* skipped — no local mongod binary found (not a failure)"); return; }

  const mtmp = fs.mkdtempSync(path.join(os.tmpdir(), "zemish-mongo-"));
  fs.mkdirSync(path.join(mtmp, "db"));
  const sock = path.join(mtmp, "m.sock");
  const mport = await freePort(); // only used by mongod to name the socket; it does NOT listen on TCP
  let mongod = null; let cleaned = false; let timedOut = false;
  const syncCleanup = () => {
    if (cleaned) return;
    try { mongod?.kill("SIGKILL"); } catch { /* ignore */ }
    try { fs.rmSync(mtmp, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  process.on("exit", syncCleanup);
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { syncCleanup(); process.exit(130); });
  const hardTimeout = setTimeout(() => { timedOut = true; syncCleanup(); }, 240_000);

  const pw = () => rnd(10);
  const sockUrl = (user, pass) => `${scheme("mongodb")}${user ? `${user}:${pass}@` : ""}${encodeURIComponent(sock)}/${user ? "?authSource=admin" : ""}`;
  const open = async (user, pass) => { const c = new MongoClient(sockUrl(user, pass), { serverSelectionTimeoutMS: 6000 }); await c.connect(); return c; };
  const clients = [];
  const track = (c) => { clients.push(c); return c; };

  try {
    mongod = spawn(mongodBin, ["--dbpath", path.join(mtmp, "db"), "--port", String(mport), "--bind_ip", sock, "--auth", "--quiet", "--wiredTigerCacheSizeGB", "0.25"], { cwd: mtmp, env: { PATH: process.env.PATH }, stdio: "ignore" });
    const mongodPid = mongod.pid;
    const t0 = Date.now();
    while (!fs.existsSync(sock)) {
      if (Date.now() - t0 > 20000) throw new Error("throwaway mongod did not create its socket");
      await new Promise((r) => setTimeout(r, 100));
    }

    // Bootstrap through the localhost exception (works on the Unix socket), then everything as root.
    const rootUser = "root1"; const rootPw = pw();
    const boot = track(await open());
    await boot.db("admin").command({ createUser: rootUser, pwd: rootPw, roles: [{ role: "root", db: "admin" }] });
    const root = track(await open(rootUser, rootPw));
    const adminDb = root.db("admin");

    await test("R0", "isolation: Unix socket only (no TCP listener), authentication enforced, fresh instance, dbpath inside the temp dir", async () => {
      const lsof = spawnSync("lsof", ["-nP", "-a", "-p", String(mongodPid), "-iTCP", "-sTCP:LISTEN"], { encoding: "utf8" });
      expect(!lsof.error && (lsof.stdout || "").trim() === "", "a TCP listener exists (or lsof is unavailable)");
      const opts = (await adminDb.command({ getCmdLineOpts: 1 })).parsed;
      expect(fs.realpathSync(opts.storage.dbPath) === fs.realpathSync(path.join(mtmp, "db")), "dbPath is outside the temp dir");
      expect(String(opts.net.bindIp) === sock, "not bound to the socket only");
      const anon = track(await open());
      let denied = false; try { await anon.db("barber_engine_v1").collection("x").insertOne({ a: 1 }); } catch { denied = true; }
      expect(denied, "an unauthenticated write was allowed (auth is not enforced)");
      const dbs = (await root.db("admin").admin().listDatabases()).databases.map((d) => d.name).sort();
      expect(JSON.stringify(dbs) === JSON.stringify(["admin", "config", "local"]), "instance is not fresh");
    });

    // Users: each shaped like a credential someone could plausibly put on the staging service.
    const V1 = STAGING_SHARED_DEV_DB_NAME;
    const users = {};
    const mk = async (label, roles) => { const name = `u_${label}`; const pass = pw(); await adminDb.command({ createUser: name, pwd: pass, roles }); users[label] = { name, pass }; };
    await adminDb.command({ createRole: "stagingAppRole", roles: [], privileges: [{ resource: { db: V1, collection: "" }, actions: ["find", "insert", "update", "remove", "createIndex", "createCollection", "listCollections", "listIndexes", "dbStats", "collStats"] }] });
    await mk("scopedRW", [{ role: "readWrite", db: V1 }]);
    await mk("scopedRead", [{ role: "read", db: V1 }]);
    await mk("customScoped", [{ role: "stagingAppRole", db: "admin" }]);
    await mk("anyDb", [{ role: "readWriteAnyDatabase", db: "admin" }]);
    await mk("crossDb", [{ role: "readWrite", db: V1 }, { role: "readWrite", db: "sample_mflix" }]);
    await mk("otherDbOnly", [{ role: "readWrite", db: "krishna_iptv" }]);
    await mk("dbAdminOnV1", [{ role: "dbAdmin", db: V1 }, { role: "readWrite", db: V1 }]);
    await mk("userAdminOnV1", [{ role: "userAdmin", db: V1 }, { role: "readWrite", db: V1 }]);
    await mk("clusterMon", [{ role: "clusterMonitor", db: "admin" }, { role: "readWrite", db: V1 }]);
    users.root = { name: rootUser, pass: rootPw };

    const realStatus = async (label) => {
      const c = track(await open(users[label].name, users[label].pass));
      return c.db(V1).admin().command({ connectionStatus: 1, showPrivileges: true });
    };
    const verdicts = {
      scopedRW: true, scopedRead: true, customScoped: true,
      anyDb: false, crossDb: false, otherDbOnly: false, dbAdminOnV1: false, userAdminOnV1: false, clusterMon: false, root: false,
    };
    await test("R1", "REAL connectionStatus replies: scoped / read-only / custom-role users PASS; root, any-database, cross-database, other-database, dbAdmin, userAdmin, clusterMonitor FAIL", async () => {
      for (const [label, shouldPass] of Object.entries(verdicts)) {
        const problems = evaluateConnectionStatus({ status: await realStatus(label), expectedDb: V1 });
        expect((problems.length === 0) === shouldPass, `${label}: expected ${shouldPass ? "PASS" : "FAIL"}, got ${problems.length === 0 ? "PASS" : "FAIL (" + problems.join("; ") + ")"}`);
        noLeak(problems.join("\n"), `${label} problems`);
      }
    });
    await test("R2", "REAL unauthenticated connection: connectionStatus reports no user, so the gate would refuse", async () => {
      const anon = track(await open());
      const status = await anon.db(V1).admin().command({ connectionStatus: 1, showPrivileges: true });
      expect(evaluateConnectionStatus({ status, expectedDb: V1 }).length >= 1, "an unauthenticated connection passed");
    });
    await test("R3", "REAL gate end to end (runStagingStartupGate with a real mongoose connection): scoped passes, any-database user is refused", async () => {
      const mongooseReal = require("mongoose");
      for (const [label, shouldPass] of [["scopedRW", true], ["anyDb", false]]) {
        const conn = await mongooseReal.createConnection(`${scheme("mongodb")}${users[label].name}:${users[label].pass}@${encodeURIComponent(sock)}/${V1}?authSource=admin`).asPromise();
        const env = { ...sharedDevEnv(), MONGODB_URI: `${scheme("mongodb")}${users[label].name}:${users[label].pass}@${encodeURIComponent(sock)}/${V1}?authSource=admin` };
        const exits = []; const logs = [];
        const result = await runStagingStartupGate(Promise.resolve(), { mongoose: { connection: conn }, env, exit: (c) => exits.push(c), log: { log: (m) => logs.push(m), error: (m) => logs.push(m) } });
        await conn.close();
        expect(result.ok === shouldPass && (exits.length === 0) === shouldPass, `${label}: gate verdict wrong`);
        noLeak(logs.join("\n"), `${label} gate log`);
        expect(!logs.join("\n").includes(users[label].pass), `${label}: a password reached the log`);
      }
    });

    // End to end: the REAL server.js against the throwaway mongod (the preload only OBSERVES: commands are monitored, nothing is faked).
    const uriFor = (name, pass, { anonymous = false } = {}) =>
      `${scheme("mongodb")}${anonymous ? "" : `${name}:${pass}@`}${encodeURIComponent(sock)}/${V1}${anonymous ? "" : "?authSource=admin"}`;
    const e2eEnvFor = (name, pass, opts) => { if (pass) SENTINELS.push(pass); return serverStagingEnv({ MONGODB_URI: uriFor(name, pass, opts) }); };
    const e2eEnv = (label) => e2eEnvFor(users[label].name, users[label].pass);
    const names = (r) => r.preflightCommands.map((c) => (c.startsWith("{") ? Object.keys(JSON.parse(c))[0] : c));
    // The ONLY command the pre-flight code issues is connectionStatus. The driver itself adds `endSessions` (no data, no write) when
    // close() releases the implicit session that command used — so that is the single other name tolerated, and only after it.
    const onlyReadOnlyCommands = (r) => {
      const n = names(r);
      return n.filter((x) => x === "connectionStatus").length <= 1 && n.every((x) => x === "connectionStatus" || x === "endSessions")
        && (!n.includes("endSessions") || n.indexOf("endSessions") > n.indexOf("connectionStatus"));
    };
    const dbExists = async () => (await root.db("admin").admin().listDatabases()).databases.some((d) => d.name === V1);
    const collectionCount = async () => (await root.db(V1).listCollections().toArray()).length;

    // Refused boots run FIRST, on a pristine instance: they must leave NOTHING behind (the whole point of the pre-flight).
    expect(!(await dbExists()) && (await collectionCount()) === 0, "precondition: the target database must not exist yet");
    const refusedOnce = async (label, env) => {
      const r = await runServer(env, { fakeMode: "real" });
      expect(r.code === 1, `${label}: expected exit 1, got ${r.code}; stderr tail: ${redact(r.err.slice(-300))}`);
      expect(r.mongooseConnects === 0, `${label}: mongoose.connect() WAS called`);
      expect(r.jobStarts === 0 && !r.listening && r.listenLine === -1 && !r.openWhileRunning && !r.portOpenAfter, `${label}: a job started or the server listened`);
      expect(r.gateLine === -1, `${label}: the post-connect gate was reached`);
      expect(r.preflightConnects === 1 && r.preflightCloses === 1, `${label}: raw client not opened and closed exactly once (${r.preflightConnects}/${r.preflightCloses})`);
      expect(onlyReadOnlyCommands(r), `${label}: pre-flight issued ${JSON.stringify(names(r))}`);
      expect(/staging database pre-flight failed/.test(r.err), `${label}: no pre-flight refusal message`);
      noLeak(`${r.out}${r.err}`, `${label} output`);
      return r;
    };
    await test("R4", "REAL server.js + over-privileged / mis-scoped credentials (any-database, cross-database, other-database, dbAdmin, userAdmin, clusterMonitor, root): refused by the PRE-FLIGHT — mongoose.connect never called, nothing started, port closed", async () => {
      for (const label of ["anyDb", "crossDb", "otherDbOnly", "dbAdminOnV1", "userAdminOnV1", "clusterMon", "root"]) await refusedOnce(label, e2eEnv(label));
    });
    await test("R5", "REAL server.js + wrong password and anonymous connection: refused by the pre-flight, same guarantees", async () => {
      await refusedOnce("wrong password", e2eEnvFor(users.scopedRW.name, `wrong${rnd(6)}`));
      await refusedOnce("anonymous", e2eEnvFor("", "", { anonymous: true }));
    });
    await test("R6", "REAL refused boots wrote NOTHING: the target database still does not exist and has no collection (previously 15-18 collections were created before the gate could answer)", async () => {
      expect(!(await dbExists()), "the database was created by a refused boot");
      expect((await collectionCount()) === 0, "a collection was created by a refused boot");
    });
    let verifiedBootCollections = null;
    await test("R7", "REAL server.js + scoped user: pre-flight (ONE connectionStatus [+ the driver's endSessions cleanup], closed) → mongoose.connect → gate → jobs → listen, strictly in order", async () => {
      const r = await runServer(e2eEnv("scopedRW"), { fakeMode: "real" });
      expect(r.gateLine >= 0, `gate did not pass (exit ${r.code}); stderr tail: ${redact(r.err.slice(-400))}`);
      expect(r.preflightConnects === 1 && r.preflightCloses === 1 && r.mongooseConnects === 1, "pre-flight / connect counts are not exactly 1 / 1 / 1");
      expect(names(r).filter((n) => n === "connectionStatus").length === 1 && onlyReadOnlyCommands(r), `pre-flight issued ${JSON.stringify(names(r))}`);
      const order = [r.preflightConnectLine, r.preflightCommandLine, r.preflightCloseLine, r.preflightPassLine, r.connectLine, r.gateLine, r.firstJob, r.listenLine];
      expect(order.every((n) => n >= 0) && order.every((n, i) => i === 0 || n > order[i - 1]), `wrong order: ${order.join(",")}`);
      expect(r.listening && r.openWhileRunning && r.jobStarts >= 10, "jobs/listen did not follow the gate");
      noLeak(`${r.out}${r.err}`, "R7 output");
      verifiedBootCollections = await collectionCount();
    });
    console.log(`  ℹ  documented residual (not a pass/fail check): after a VERIFIED boot, autoIndex creates ${verifiedBootCollections ?? "n/a"} collections in ${V1} — only in the allowed database, only after the credentials were proven scoped`);

    // Cleanup with evidence.
    for (const c of clients) { try { await c.close(); } catch { /* ignore */ } }
    const closer = await open(rootUser, rootPw);
    try { await closer.db("admin").command({ shutdown: 1, force: true }); } catch { /* connection drops on shutdown */ }
    await new Promise((resolve) => {
      const started = Date.now();
      const tick = () => { let alive = true; try { process.kill(mongodPid, 0); } catch (e) { alive = e.code !== "ESRCH"; } if (!alive || Date.now() - started > 15000) resolve(); else setTimeout(tick, 200); };
      tick();
    });
    try { mongod.kill("SIGKILL"); } catch { /* ignore */ }
    await test("R8", "cleanup: mongod (recorded PID) exited, socket and temp directory removed, no stray files", async () => {
      let alive = true; try { process.kill(mongodPid, 0); } catch (e) { alive = e.code !== "ESRCH"; }
      expect(!alive, "mongod still running");
      fs.rmSync(mtmp, { recursive: true, force: true });
      cleaned = true;
      expect(!fs.existsSync(mtmp), "temp directory still exists");
    });
    if (timedOut) throw new Error("hard timeout hit");
  } catch (error) {
    results.push({ id: "R-setup", ok: false });
    console.log(`  ❌ R-setup — ${redact(error?.message || error)}`);
  } finally {
    clearTimeout(hardTimeout);
    for (const c of clients) { try { await c.close(); } catch { /* ignore */ } }
    syncCleanup();
  }
};
if (RUN_REAL_MONGO) await runRealMongo();

// ═══ Summary ═══════════════════════════════════════════════════════════════
const passed = results.filter((r) => r.ok).length;
const failed = results.length - passed;
console.log(`\n${failed === 0 ? "✅" : "❌"} ${passed} passed, ${failed} failed${RUN_REAL_MONGO ? "" : " (real-mongod section not requested)"}`);
process.exit(failed === 0 ? 0 : 1);
