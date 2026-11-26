/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyStagingGuards.js
 *
 * Behavioural verification of the staging security guards (see
 * utils/stagingGuards.js). Every check calls REAL code — the boot guard, the OTP
 * service, the login/verify controllers, the mock-payment controllers, the real
 * Express app — with only I/O stubbed. It is NOT a "does this string exist in
 * the file" check.
 *
 * Hermetic by default: no real database, Redis, provider, payment, production or
 * staging API. Loopback HTTP on 127.0.0.1 (ephemeral port) is the only socket.
 *
 *   cd backend && node scripts/verifyStagingGuards.js
 *       G  boot guard (pure) + child-process boot-order proof
 *       O  OTP service  (real sendOtp/verifyOtp/generateOtp, in-memory Redis)
 *       H  handlers     (real controllers; models/session stubbed; zero-mutation counters)
 *       C  CORS / webhook / socket handshake on the real app (loopback)
 *
 *   cd backend && node scripts/verifyStagingGuards.js --real-lua
 *       adds R: the REAL verify Lua against a throwaway local redis-server that
 *       listens on a Unix socket ONLY (no TCP), with no persistence, in a fresh
 *       temp directory, a scrubbed environment, a hard timeout and guaranteed
 *       cleanup. Local use only (not run in CI). It can never reach Render,
 *       production Redis, staging Redis or any external database.
 *
 * All phone numbers and OTPs used here are synthetic and generated per run; none
 * is ever printed (messages are redacted before output).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  assertStagingSafety,
  isStagingEnv,
  isStagingTestPhone,
  isStrictCorsEnv,
  maskPhoneForLog,
  parseStagingTestLogins,
  stagingTestOtpFor,
} from "../utils/stagingGuards.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BACKEND_DIR = path.resolve(__dirname, "..");
const ARGS = process.argv.slice(2);
const IS_LUA_CHILD = ARGS.includes("--real-lua-child");
const RUN_REAL_LUA = ARGS.includes("--real-lua");

// ─── Hermetic environment (set BEFORE any app module is imported) ───────────
const rnd = (bytes) => crypto.randomBytes(bytes).toString("hex");
const SCRUBBED_NAMES = [
  "REDIS_URL", "MONGODB_URI", "ZEMISH_DIAG_REDIS_URL", "ALLOW_FIXED_OTP", "RAZORPAY_ALLOW_TEST_BYPASS",
  "SMS_PROVIDER", "PUSH_PROVIDER", "STAGING_TEST_LOGINS", "RAZORPAY_WEBHOOK_SECRET", "CASHFREE_ENV",
  "STAGING_SMS_OTP_MODE", "STAGING_SMS_ALLOWED_PHONES", "MSG91_AUTH_KEY", "MSG91_TEMPLATE_ID", "MSG91_SENDER_ID",
];
// Remember what the process was LAUNCHED with (for the R0 scrubbed-env proof), then scrub.
const LAUNCH_ENV_SEEN = Object.fromEntries(SCRUBBED_NAMES.map((n) => [n, process.env[n] !== undefined]));
for (const name of SCRUBBED_NAMES) delete process.env[name];
process.env.NODE_ENV = "test";
process.env.SKIP_REDIS_AUTOCONNECT = "true";
process.env.RAZORPAY_KEY_ID = "rzp_test_synthetic_placeholder";
process.env.RAZORPAY_KEY_SECRET = `synthetic-${rnd(8)}`;
process.env.JWT_ACCESS_SECRET = rnd(24);
process.env.CORS_ORIGIN = "https://cors-fixture.invalid"; // test fixture, NOT a deployment origin

// ─── Synthetic sentinels (generated per run, never printed) ─────────────────
const PHONE_L1 = "6000000011";
const PHONE_L2 = "6000000012";
const PHONE_L3 = "6000000013";
const PHONE_L4 = "6000000014";
const PHONE_L5 = "6000000015";
const PHONE_U1 = "6000000099"; // never listed
const LISTED_PHONES = [PHONE_L1, PHONE_L2, PHONE_L3, PHONE_L4, PHONE_L5];
const WRONG_OTP = "654322"; // a deliberately wrong guess; secrets are never allowed to equal it
const makeSecretOtp = (phone) => {
  for (;;) {
    const candidate = String(crypto.randomInt(100000, 1000000));
    if (candidate === WRONG_OTP || candidate === "000001" || candidate === "123456") continue;
    if (parseStagingTestLogins(`${phone}:${candidate}`).logins.size === 1) return candidate;
  }
};
const SECRETS = new Map(LISTED_PHONES.map((p) => [p, makeSecretOtp(p)]));
const loginsValue = (phones = LISTED_PHONES) => phones.map((p) => `${p}:${SECRETS.get(p)}`).join(",");
const ALL_SENTINELS = [...LISTED_PHONES, PHONE_U1, ...SECRETS.values()];

// Credential-bearing connection-string fixtures are assembled at runtime from random parts, so this
// file contains no `scheme://user:pass@host` literal for secret scanners to flag. The boot guard only
// inspects scheme / host / database path, so the behaviour under test is identical.
const URI_USER = `svc${rnd(3)}`;
const URI_PASS = rnd(10);
ALL_SENTINELS.push(URI_PASS);
const uriScheme = (name) => `${name}:` + "//";
const withUserinfo = (name, rest) => `${uriScheme(name)}${URI_USER}:${URI_PASS}@${rest}`;
const redact = (text) => ALL_SENTINELS.reduce((acc, s) => acc.split(s).join("<redacted>"), String(text));

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

// ─── Tiny harness ───────────────────────────────────────────────────────────
const results = [];
const test = async (id, name, fn) => {
  try {
    await fn();
    results.push({ id, name, ok: true });
    console.log(`  ✅ ${id} ${name}`);
  } catch (error) {
    results.push({ id, name, ok: false });
    console.log(`  ❌ ${id} ${name} — ${redact(error?.message || error)}`);
  }
};
const expect = (condition, label) => {
  if (!condition) throw new Error(label);
};
const section = (title) => console.log(`\n── ${title} ──`);

const withEnv = async (overrides, fn) => {
  const saved = {};
  for (const [key, value] of Object.entries(overrides)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
};

// Collect everything that could reach a console/stdout/stderr/logger sink.
const capture = async (fn, logger) => {
  const chunks = [];
  const push = (...args) => {
    for (const a of args) {
      try { chunks.push(typeof a === "string" ? a : JSON.stringify(a)); } catch { chunks.push(String(a)); }
    }
  };
  const saved = {};
  for (const m of ["log", "info", "warn", "error", "debug"]) { saved[`console.${m}`] = console[m]; console[m] = push; }
  const outWrite = process.stdout.write.bind(process.stdout);
  const errWrite = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c, ...r) => { push(String(c)); return true; };
  process.stderr.write = (c, ...r) => { push(String(c)); return true; };
  if (logger) for (const m of ["info", "warn", "error", "debug"]) { saved[`logger.${m}`] = logger[m]; logger[m] = push; }
  try {
    await fn();
  } finally {
    for (const m of ["log", "info", "warn", "error", "debug"]) console[m] = saved[`console.${m}`];
    process.stdout.write = outWrite;
    process.stderr.write = errWrite;
    if (logger) for (const m of ["info", "warn", "error", "debug"]) logger[m] = saved[`logger.${m}`];
  }
  return chunks.join("\n");
};

// ─── In-memory Redis with a faithful JS port of the (unchanged) verify Lua ───
// The port is cross-checked against the REAL Lua in section R (--real-lua).
const portVerify = (api, keys, args) => {
  const [hashKeyName, attemptKeyName] = keys;
  const [suppliedHash, limit, windowSeconds, purpose] = args;
  const attempts = Number((api._alive(attemptKeyName)?.value) ?? 0);
  if (attempts >= Number(limit)) return [0, "TOO_MANY_ATTEMPTS"];
  const raw = api._alive(hashKeyName)?.value;
  if (!raw) return [0, "OTP_EXPIRED"];
  let payload;
  try { payload = JSON.parse(raw); } catch { return [0, "OTP_EXPIRED"]; }
  if (!payload || typeof payload !== "object" || !payload.hash) return [0, "OTP_EXPIRED"];
  if (payload.purpose !== purpose) return [0, "PURPOSE_MISMATCH"];
  if (payload.hash !== suppliedHash) {
    api.store.set(attemptKeyName, { value: String(attempts + 1), exp: Date.now() + Number(windowSeconds) * 1000 });
    return [0, "INVALID_OTP"];
  }
  api.store.delete(hashKeyName);
  api.store.delete(attemptKeyName);
  return [1, "OK"];
};

const makeFakeRedis = ({ evalImpl, failOn } = {}) => {
  const api = {
    store: new Map(),
    evalCalls: [],
    _alive(key) {
      const entry = api.store.get(key);
      if (!entry) return undefined;
      if (entry.exp !== null && entry.exp <= Date.now()) { api.store.delete(key); return undefined; }
      return entry;
    },
    async set(key, value, opts = {}) {
      if (failOn === "set") throw new Error("synthetic redis failure");
      if (opts.NX && api._alive(key)) return null;
      api.store.set(key, { value: String(value), exp: opts.EX ? Date.now() + opts.EX * 1000 : null });
      return "OK";
    },
    async get(key) { return api._alive(key)?.value ?? null; },
    async del(key) { return api.store.delete(key) ? 1 : 0; },
    async ttl(key) {
      const entry = api._alive(key);
      if (!entry) return -2;
      return entry.exp === null ? -1 : Math.ceil((entry.exp - Date.now()) / 1000);
    },
    async eval(_script, { keys, arguments: args }) {
      if (failOn === "eval") throw new Error("synthetic redis failure");
      api.evalCalls.push({ keys, args });
      return evalImpl ? evalImpl({ keys, args }) : portVerify(api, keys, args);
    },
  };
  return api;
};

const keyFor = (role, purpose, phone, suffix) => `otp:${role.toLowerCase()}:${purpose.toLowerCase()}:${phone}:${suffix}`;

// A safe, complete staging environment (all values synthetic).
const safeStagingEnv = () => ({
  NODE_ENV: "staging",
  STAGING_TEST_LOGINS: loginsValue([PHONE_L1, PHONE_L2]),
  RAZORPAY_KEY_ID: "rzp_test_synthetic",
  RAZORPAY_KEY_SECRET: `synthetic-${rnd(6)}`,
  MONGODB_URI: withUserinfo("mongodb+srv", "cluster0.invalid/barber_engine_staging?retryWrites=true&w=majority"),
  REDIS_URL: withUserinfo("rediss", "redis.invalid:6379"),
  // Mandatory deny-lists: fingerprints of FICTIONAL production endpoints (random, match none of the fixtures).
  STAGING_FORBIDDEN_MONGO_ENDPOINTS: rnd(8),
  STAGING_FORBIDDEN_REDIS_ENDPOINTS: rnd(8),
  JWT_ACCESS_SECRET: rnd(24),
  OTP_SECRET: rnd(24),
  OTP_ENCRYPT_KEY: rnd(24),
  ADMIN_RESET_PASSWORD: `Adm!${rnd(8)}`,
  KYC_ENCRYPTION_KEY: rnd(32),
  CORS_ORIGIN: "https://cors-fixture.invalid",
});

// ═════════════════════════════════════════════════════════════════════════════
// R — real Lua against a throwaway local Redis (child + parent orchestration)
// ═════════════════════════════════════════════════════════════════════════════

const ACCEPTED_REDIS_SERVER_PATHS = ["/usr/local/bin/redis-server", "/opt/homebrew/bin/redis-server", "/usr/bin/redis-server"];

const runLuaChildSuite = async () => {
  const sock = process.env.ZEMISH_LUA_SOCKET;
  const resultFile = path.join(path.dirname(sock), "result.json");
  // Scrubbed-environment proof, from INSIDE the test process.
  await test("R0", "scrubbed env: no REDIS_URL / MONGODB_URI / diag URL visible to the test process", async () => {
    expect(LAUNCH_ENV_SEEN.REDIS_URL === false, "REDIS_URL was visible at launch");
    expect(LAUNCH_ENV_SEEN.MONGODB_URI === false, "MONGODB_URI was visible at launch");
    expect(LAUNCH_ENV_SEEN.ZEMISH_DIAG_REDIS_URL === false, "diag URL was visible at launch");
  });

  const { default: mongoose } = await import("mongoose");
  mongoose.set("bufferCommands", false);
  const { createClient } = await import("redis");
  const otpService = await import("../modules/otp/services/otp.service.js");
  const { default: OtpAuditOutbox } = await import("../modules/otp/models/OtpAuditOutbox.js");
  const { OTP_PURPOSE } = await import("../modules/otp/constants/otpPurpose.constants.js");
  const auditRows = [];
  OtpAuditOutbox.create = async (doc) => { auditRows.push(doc); return doc; };

  const client = createClient({ socket: { path: sock, reconnectStrategy: false, connectTimeout: 3000 } });
  client.on("error", () => {});
  await client.connect();
  try {
    const stagingEnv = { NODE_ENV: "staging", STAGING_TEST_LOGINS: loginsValue(), SMS_PROVIDER: undefined, PUSH_PROVIDER: undefined };
    const send = (phone, purpose = OTP_PURPOSE.LOGIN, role = "USER") => otpService.sendOtp({ phone, purpose, role, redis: client });
    const verify = (phone, otp, purpose = OTP_PURPOSE.LOGIN, role = "USER") => otpService.verifyOtp({ phone, purpose, otp, role, redis: client });
    const wrongFor = (phone) => (SECRETS.get(phone) === "000001" ? "000002" : "000001");

    await test("R0b", "throwaway Redis is empty before the suite (DBSIZE = 0)", async () => {
      expect((await client.dbSize()) === 0, "database not empty");
    });

    // R1 — staging policy: 10 failures then a lock, even for the right code; TTL = 7200 s.
    await withEnv(stagingEnv, async () => {
      await test("R1", "staging: 10 wrong guesses → INVALID_OTP ×10, 11th (even correct) → TOO_MANY_ATTEMPTS; counter TTL = 7200", async () => {
        await send(PHONE_L1);
        for (let i = 0; i < 10; i += 1) {
          const r = await verify(PHONE_L1, wrongFor(PHONE_L1));
          expect(r.ok === false && r.code === "INVALID_OTP", `attempt ${i + 1} not INVALID_OTP`);
        }
        const locked = await verify(PHONE_L1, SECRETS.get(PHONE_L1));
        expect(locked.ok === false && locked.code === "TOO_MANY_ATTEMPTS", "11th not locked");
        const ttl = await client.ttl(keyFor("USER", "LOGIN", PHONE_L1, "attempts"));
        expect(ttl > 7190 && ttl <= 7200, "attempt-counter TTL not ~7200");
      });
      await test("R3", "locked calls do not extend the counter TTL", async () => {
        const before = await client.pTTL(keyFor("USER", "LOGIN", PHONE_L1, "attempts"));
        const again = await verify(PHONE_L1, wrongFor(PHONE_L1));
        const after = await client.pTTL(keyFor("USER", "LOGIN", PHONE_L1, "attempts"));
        expect(again.code === "TOO_MANY_ATTEMPTS", "not locked");
        expect(after <= before, "TTL was extended by a locked call");
      });
      await test("R2", "correct secret consumes the hash and clears the counter; reuse → OTP_EXPIRED", async () => {
        await send(PHONE_L3);
        expect((await verify(PHONE_L3, wrongFor(PHONE_L3))).code === "INVALID_OTP", "wrong not INVALID_OTP");
        const ok = await verify(PHONE_L3, SECRETS.get(PHONE_L3));
        expect(ok.ok === true, "correct secret rejected");
        expect((await client.exists(keyFor("USER", "LOGIN", PHONE_L3, "hash"))) === 0, "hash not consumed");
        expect((await client.exists(keyFor("USER", "LOGIN", PHONE_L3, "attempts"))) === 0, "counter not cleared");
        expect((await verify(PHONE_L3, SECRETS.get(PHONE_L3))).code === "OTP_EXPIRED", "reuse not OTP_EXPIRED");
      });
      await test("R4", "payload purpose ≠ requested purpose → PURPOSE_MISMATCH", async () => {
        await client.set(keyFor("USER", "LOGIN", PHONE_L4, "hash"), JSON.stringify({ hash: sha256(SECRETS.get(PHONE_L4)), purpose: "SALON_LOGIN" }), { EX: 300 });
        const r = await verify(PHONE_L4, SECRETS.get(PHONE_L4));
        expect(r.ok === false && r.code === "PURPOSE_MISMATCH", "not PURPOSE_MISMATCH");
      });
      await test("R5", "unlisted phone with a PLANTED matching hash (shared fixed-OTP Redis case): staging → INVALID_OTP", async () => {
        const planted = () => client.set(keyFor("USER", "LOGIN", PHONE_U1, "hash"), JSON.stringify({ hash: sha256("123456"), purpose: "LOGIN" }), { EX: 300 });
        await planted();
        const before = auditRows.length;
        const staged = await verify(PHONE_U1, "123456");
        expect(staged.ok === false && staged.code === "INVALID_OTP", "unlisted phone was not vetoed");
        const row = auditRows[before];
        expect(row && row.status === "VERIFY_FAILED" && row.failureReason === "INVALID_OTP", "veto not audited as a failed verify");
        // Causality: the SAME planted hash verifies in development, so only the veto blocked it.
        await planted();
        await client.del(keyFor("USER", "LOGIN", PHONE_U1, "attempts"));
        const dev = await withEnv({ NODE_ENV: "development" }, () => verify(PHONE_U1, "123456"));
        expect(dev.ok === true, "control: development did not accept the planted hash");
      });
    });

    // R1b — non-staging policy still 5 / 300.
    await test("R1b", "development/test policy unchanged: lock after 5, counter TTL = 300", async () => {
      await client.set(keyFor("USER", "LOGIN", PHONE_L2, "hash"), JSON.stringify({ hash: sha256(SECRETS.get(PHONE_L2)), purpose: "LOGIN" }), { EX: 300 });
      const results5 = [];
      await withEnv({ NODE_ENV: "development" }, async () => {
        for (let i = 0; i < 5; i += 1) results5.push((await verify(PHONE_L2, wrongFor(PHONE_L2))).code);
      });
      expect(results5.every((c) => c === "INVALID_OTP"), "first 5 not INVALID_OTP");
      const ttl = await client.ttl(keyFor("USER", "LOGIN", PHONE_L2, "attempts"));
      expect(ttl > 290 && ttl <= 300, "development counter TTL not ~300");
      const sixth = await withEnv({ NODE_ENV: "development" }, () => verify(PHONE_L2, SECRETS.get(PHONE_L2)));
      expect(sixth.code === "TOO_MANY_ATTEMPTS", "6th not locked in development");
    });

    // R6 — parity: the JS port used by sections O/H must behave exactly like the real Lua.
    await test("R6", "JS port of the Lua matches the REAL Lua over a mixed scenario", async () => {
      const scenario = async (redisLike, phone, flushReal) => {
        const out = [];
        const setHash = (secret, purpose = "LOGIN") =>
          redisLike.set(keyFor("USER", "LOGIN", phone, "hash"), JSON.stringify({ hash: sha256(secret), purpose }), { EX: 300 });
        const run = (otp) => otpService.verifyOtp({ phone, purpose: OTP_PURPOSE.LOGIN, otp, role: "USER", redis: redisLike }).then((r) => `${r.ok}:${r.code ?? "OK"}`);
        out.push(await run("000001"));                 // OTP_EXPIRED (no hash yet)
        await setHash(PARITY_OTP);
        out.push(await run("000001"), await run("000001"), await run(PARITY_OTP)); // 2× wrong, then OK
        out.push(await run(PARITY_OTP));               // OTP_EXPIRED (consumed)
        await setHash(PARITY_OTP, "SALON_LOGIN");
        out.push(await run(PARITY_OTP));               // PURPOSE_MISMATCH
        await setHash(PARITY_OTP);
        for (let i = 0; i < 10; i += 1) out.push(await run("000001"));
        out.push(await run(PARITY_OTP));               // TOO_MANY_ATTEMPTS
        if (flushReal) await flushReal();
        return out;
      };
      const parityPhone = "6000000077";
      const PARITY_OTP = makeSecretOtp(parityPhone);
      const parityEnv = { NODE_ENV: "staging", STAGING_TEST_LOGINS: `${parityPhone}:${PARITY_OTP}` };
      ALL_SENTINELS.push(PARITY_OTP, parityPhone); // keep the redactor aware of this run's extra sentinels
      const real = await withEnv(parityEnv, () => scenario(client, parityPhone));
      const fake = makeFakeRedis();
      const port = await withEnv(parityEnv, () => scenario(fake, parityPhone));
      expect(JSON.stringify(real) === JSON.stringify(port), "real Lua and JS port diverged");
    });
  } finally {
    await client.quit().catch(() => {});
  }

  const pass = results.filter((r) => r.ok).length;
  const fail = results.length - pass;
  fs.writeFileSync(resultFile, JSON.stringify({ pass, fail }));
};

const runRealLuaParent = async () => {
  section("R  real Lua on a throwaway local Redis (Unix socket only)");
  const parentResults = [];
  const ptest = async (id, name, fn) => {
    try { await fn(); parentResults.push(true); console.log(`  ✅ ${id} ${name}`); }
    catch (e) { parentResults.push(false); console.log(`  ❌ ${id} ${name} — ${redact(e?.message || e)}`); }
  };

  const redisBin = ACCEPTED_REDIS_SERVER_PATHS.find((p) => fs.existsSync(p))
    ?? (spawnSync("which", ["redis-server"], { env: { PATH: process.env.PATH }, encoding: "utf8" }).stdout || "").trim();
  if (!redisBin) {
    console.log("  ⏭  R* skipped — no local redis-server binary found (not a failure)");
    return { pass: 0, fail: 0, skipped: true };
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zemish-lua-"));
  const sock = path.join(tmp, "r.sock");
  let proc = null;
  let childProc = null;
  let cleanedUp = false;
  let timedOut = false;

  const killEverything = () => {
    try { childProc?.kill("SIGKILL"); } catch { /* ignore */ }
    try { proc?.kill("SIGKILL"); } catch { /* ignore */ }
  };
  const syncCleanup = () => {
    if (cleanedUp) return;
    killEverything();
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  process.on("exit", syncCleanup);
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { syncCleanup(); process.exit(130); });
  const hardTimeout = setTimeout(() => { timedOut = true; killEverything(); }, 30_000);

  let childSummary = { pass: 0, fail: 1 };
  try {
    proc = spawn(redisBin, [
      "--port", "0", "--unixsocket", sock, "--unixsocketperm", "600",
      "--save", "", "--appendonly", "no", "--dir", tmp, "--daemonize", "no", "--loglevel", "warning",
    ], { env: { PATH: process.env.PATH }, stdio: ["ignore", "ignore", "ignore"] });
    const redisPid = proc.pid;

    const started = Date.now();
    while (!fs.existsSync(sock)) {
      if (Date.now() - started > 5000) throw new Error("throwaway redis-server did not create its socket");
      await new Promise((r) => setTimeout(r, 50));
    }

    const { createClient } = await import("redis");
    const admin = createClient({ socket: { path: sock, reconnectStrategy: false, connectTimeout: 3000 } });
    admin.on("error", () => {});
    await admin.connect();
    try {
      const info = await admin.info("server");
      const cfg = async (name) => (await admin.sendCommand(["CONFIG", "GET", name]))[1];
      await ptest("ISO1", "Unix socket only: INFO reports tcp_port:0", async () => expect(/tcp_port:0\b/.test(info), "TCP listener present"));
      await ptest("ISO2", "standalone mode, fresh instance, DBSIZE = 0", async () => {
        expect(/redis_mode:standalone/.test(info), "not standalone");
        expect((await admin.dbSize()) === 0, "database not empty — wrong instance, aborting");
      });
      await ptest("ISO3", "persistence off (save empty, appendonly no)", async () => {
        expect((await cfg("save")) === "", "RDB save enabled");
        expect((await cfg("appendonly")) === "no", "AOF enabled");
      });
      await ptest("ISO4", "working dir and socket are inside the fresh temp directory", async () => {
        expect(fs.realpathSync(await cfg("dir")) === fs.realpathSync(tmp), "dir is not the temp dir");
        expect(fs.realpathSync(path.dirname(sock)) === fs.realpathSync(tmp), "socket outside temp dir");
        expect((fs.statSync(sock).mode & 0o777) === 0o600, "socket permissions not 600");
      });
      await ptest("ISO5", "no TCP listener for the redis-server process (lsof)", async () => {
        const lsof = spawnSync("lsof", ["-nP", "-a", "-p", String(redisPid), "-iTCP", "-sTCP:LISTEN"], { encoding: "utf8" });
        if (lsof.error) throw new Error("lsof unavailable — UNVERIFIED (INFO tcp_port:0 still proves it)");
        expect((lsof.stdout || "").trim() === "", "a TCP listener exists");
      });
    } finally {
      await admin.quit().catch(() => {});
    }

    // Run the suite in a child with a scrubbed environment.
    childProc = spawn(process.execPath, [__filename, "--real-lua-child"], {
      cwd: tmp,
      env: { PATH: process.env.PATH, NODE_ENV: "test", ZEMISH_LUA_SOCKET: sock, SKIP_REDIS_AUTOCONNECT: "true", JWT_ACCESS_SECRET: rnd(24) },
      stdio: ["ignore", "inherit", "inherit"],
    });
    await new Promise((resolve) => childProc.on("exit", resolve));
    if (timedOut) throw new Error("hard timeout (30 s) hit — everything killed");
    try { childSummary = JSON.parse(fs.readFileSync(path.join(tmp, "result.json"), "utf8")); } catch { childSummary = { pass: 0, fail: 1 }; }

    // Cleanup with evidence.
    const leftovers = fs.readdirSync(tmp).filter((f) => f !== "r.sock" && f !== "result.json");
    await ptest("CLEAN1", "no dump.rdb / append-only / other files were written to the temp directory", async () =>
      expect(leftovers.length === 0, "unexpected files in temp directory"));
    const closer = createClient({ socket: { path: sock, reconnectStrategy: false, connectTimeout: 2000 } });
    closer.on("error", () => {});
    try { await closer.connect(); await closer.sendCommand(["SHUTDOWN", "NOSAVE"]); } catch { /* connection drops on shutdown */ }
    await new Promise((resolve) => {
      if (proc.exitCode !== null) return resolve();
      const t = setTimeout(() => { try { proc.kill("SIGKILL"); } catch { /* ignore */ } resolve(); }, 5000);
      proc.once("exit", () => { clearTimeout(t); resolve(); });
    });
    await ptest("CLEAN2", "redis-server process (recorded PID) has exited", async () => {
      let alive = true;
      try { process.kill(redisPid, 0); } catch (e) { alive = e.code !== "ESRCH"; }
      expect(!alive, "redis-server still running");
    });
    fs.rmSync(tmp, { recursive: true, force: true });
    cleanedUp = true;
    await ptest("CLEAN3", "socket and temp directory removed", async () => expect(!fs.existsSync(tmp), "temp directory still exists"));
  } catch (error) {
    console.log(`  ❌ R-setup — ${redact(error?.message || error)}`);
    parentResults.push(false);
  } finally {
    clearTimeout(hardTimeout);
    syncCleanup();
  }
  const pass = parentResults.filter(Boolean).length + childSummary.pass;
  const fail = parentResults.filter((x) => !x).length + childSummary.fail;
  return { pass, fail, skipped: false };
};

// ═════════════════════════════════════════════════════════════════════════════
// Entry point
// ═════════════════════════════════════════════════════════════════════════════

if (IS_LUA_CHILD) {
  await runLuaChildSuite();
  process.exit(0);
}

console.log("Staging security guards — behavioural verification (hermetic; synthetic values only)");

// ─── G — boot guard (pure) ──────────────────────────────────────────────────
section("G  boot guard");

await test("G1", "a safe staging environment yields zero violations", async () => {
  const v = assertStagingSafety(safeStagingEnv());
  expect(v.length === 0, `expected 0 violations, got ${v.length}: ${v.join(" | ")}`);
});

const mutate = (patch) => ({ ...safeStagingEnv(), ...patch });
const without = (...names) => { const e = safeStagingEnv(); for (const n of names) delete e[n]; return e; };
const G2_CASES = [
  ["missing STAGING_TEST_LOGINS", without("STAGING_TEST_LOGINS"), "STAGING_TEST_LOGINS is not set"],
  ["ALLOW_FIXED_OTP=true", mutate({ ALLOW_FIXED_OTP: "true" }), "ALLOW_FIXED_OTP"],
  ["ALLOW_FIXED_OTP=yes (not an off-flag)", mutate({ ALLOW_FIXED_OTP: "yes" }), "ALLOW_FIXED_OTP"],
  ["RAZORPAY_ALLOW_TEST_BYPASS=true", mutate({ RAZORPAY_ALLOW_TEST_BYPASS: "true" }), "RAZORPAY_ALLOW_TEST_BYPASS"],
  ["live Razorpay key", mutate({ RAZORPAY_KEY_ID: "rzp_live_synthetic" }), "LIVE key"],
  ["non-test Razorpay key", mutate({ RAZORPAY_KEY_ID: "synthetic_key" }), "test-mode key"],
  ["missing Razorpay key id", without("RAZORPAY_KEY_ID"), "RAZORPAY_KEY_ID is not set"],
  ["missing Razorpay key secret", without("RAZORPAY_KEY_SECRET"), "RAZORPAY_KEY_SECRET is not set"],
  ["CASHFREE_ENV=PRODUCTION", mutate({ CASHFREE_ENV: "PRODUCTION" }), "CASHFREE_ENV"],
  ["CASHFREE_ENV=production (case)", mutate({ CASHFREE_ENV: "production" }), "CASHFREE_ENV"],
  ["RAZORPAYX_ROUTE_BASE_URL override", mutate({ RAZORPAYX_ROUTE_BASE_URL: "https://override.invalid" }), "RAZORPAYX_ROUTE_BASE_URL"],
  ["CASHFREE_PAYOUT_BASE_URL override", mutate({ CASHFREE_PAYOUT_BASE_URL: "https://override.invalid" }), "CASHFREE_PAYOUT_BASE_URL"],
  ["SUREPASS_TOKEN set", mutate({ SUREPASS_TOKEN: "synthetic" }), "SUREPASS_TOKEN"],
  ["SMS_PROVIDER=msg91", mutate({ SMS_PROVIDER: "msg91" }), "SMS_PROVIDER"],
  ["MSG91_AUTH_KEY set", mutate({ MSG91_AUTH_KEY: "synthetic" }), "MSG91_*"],
  ["TWILIO_ACCOUNT_SID set", mutate({ TWILIO_ACCOUNT_SID: "synthetic" }), "TWILIO_*"],
  ["PUSH_PROVIDER=fcm", mutate({ PUSH_PROVIDER: "fcm" }), "PUSH_PROVIDER"],
  ["PUSH_PROVIDER=Expo (not the exact value)", mutate({ PUSH_PROVIDER: "Expo" }), "PUSH_PROVIDER"],
  ["EXPO_ACCESS_TOKEN set", mutate({ EXPO_ACCESS_TOKEN: "synthetic" }), "EXPO_ACCESS_TOKEN"],
  ["FIREBASE_PRIVATE_KEY set", mutate({ FIREBASE_PRIVATE_KEY: "synthetic" }), "FIREBASE_PRIVATE_KEY"],
  ["FIREBASE_PROJECT_ID set", mutate({ FIREBASE_PROJECT_ID: "synthetic" }), "FIREBASE_PROJECT_ID"],
  ["FIREBASE_CLIENT_EMAIL set", mutate({ FIREBASE_CLIENT_EMAIL: "synthetic" }), "FIREBASE_CLIENT_EMAIL"],
  ["SMTP_HOST set", mutate({ SMTP_HOST: "smtp.invalid" }), "SMTP_HOST"],
  ["WHATSAPP_PROVIDER set", mutate({ WHATSAPP_PROVIDER: "x" }), "WHATSAPP_PROVIDER"],
  ["CALL_PROVIDER set", mutate({ CALL_PROVIDER: "x" }), "CALL_PROVIDER"],
  ["BOT_PROVIDER set", mutate({ BOT_PROVIDER: "x" }), "BOT_PROVIDER"],
  ["MONGODB_URI missing", without("MONGODB_URI"), "MONGODB_URI is not set"],
  ["MONGODB_URI with no database path", mutate({ MONGODB_URI: withUserinfo("mongodb+srv", "cluster0.invalid/?retryWrites=true") }), "not a valid MongoDB URI"],
  ["MONGODB_URI database barber_engine_v1", mutate({ MONGODB_URI: withUserinfo("mongodb+srv", "cluster0.invalid/barber_engine_v1?retryWrites=true") }), "shared development database"],
  ["MONGODB_URI database test", mutate({ MONGODB_URI: withUserinfo("mongodb", "h1.invalid:27017,h2.invalid:27017/test") }), "not allowed on staging"],
  ["REDIS_URL missing", without("REDIS_URL"), "REDIS_URL is not set"],
  ["REDIS_URL wrong scheme", mutate({ REDIS_URL: "http://redis.invalid:6379" }), "redis:// or rediss://"],
  ["JWT_ACCESS_SECRET missing", without("JWT_ACCESS_SECRET"), "JWT_ACCESS_SECRET"],
  ["JWT_ACCESS_SECRET missing even though JWT_SECRET set", { ...without("JWT_ACCESS_SECRET"), JWT_SECRET: rnd(24) }, "JWT_ACCESS_SECRET"],
  ["JWT_ACCESS_SECRET too short", mutate({ JWT_ACCESS_SECRET: "short" }), "JWT_ACCESS_SECRET"],
  ["OTP_SECRET fallback literal", mutate({ OTP_SECRET: "otp-fallback-secret-change-in-prod" }), "OTP_SECRET"],
  ["OTP_SECRET missing", without("OTP_SECRET"), "OTP_SECRET"],
  ["OTP_ENCRYPT_KEY too short", mutate({ OTP_ENCRYPT_KEY: "short" }), "OTP_ENCRYPT_KEY"],
  ["OTP_ENCRYPT_KEY fallback literal", mutate({ OTP_ENCRYPT_KEY: "barber-engine-otp-key-32-chars!!" }), "OTP_ENCRYPT_KEY"],
  ["ADMIN_RESET_PASSWORD default", mutate({ ADMIN_RESET_PASSWORD: "Admin@12345" }), "ADMIN_RESET_PASSWORD"],
  ["ADMIN_RESET_PASSWORD missing", without("ADMIN_RESET_PASSWORD"), "ADMIN_RESET_PASSWORD"],
  ["KYC_ENCRYPTION_KEY 63 hex", mutate({ KYC_ENCRYPTION_KEY: "a".repeat(63) }), "KYC_ENCRYPTION_KEY"],
  ["KYC_ENCRYPTION_KEY non-hex", mutate({ KYC_ENCRYPTION_KEY: "z".repeat(64) }), "KYC_ENCRYPTION_KEY"],
  ["CORS_ORIGIN with a space", mutate({ CORS_ORIGIN: "https://a.invalid, https://b.invalid" }), "CORS_ORIGIN entry 2"],
  ["CORS_ORIGIN wildcard", mutate({ CORS_ORIGIN: "*" }), "CORS_ORIGIN entry 1"],
  ["CORS_ORIGIN trailing slash", mutate({ CORS_ORIGIN: "https://a.invalid/" }), "CORS_ORIGIN entry 1"],
  ["CORS_ORIGIN http", mutate({ CORS_ORIGIN: "http://a.invalid" }), "CORS_ORIGIN entry 1"],
  ["CORS_ORIGIN localhost", mutate({ CORS_ORIGIN: "https://localhost:3000" }), "CORS_ORIGIN entry 1"],
  ["CORS_ORIGIN with a path", mutate({ CORS_ORIGIN: "https://a.invalid/app" }), "CORS_ORIGIN entry 1"],
];
for (const [i, [label, env, fragment]] of G2_CASES.entries()) {
  await test(`G2.${String(i + 1).padStart(2, "0")}`, `rejects: ${label}`, async () => {
    const v = assertStagingSafety(env);
    expect(v.length >= 1, "no violation reported");
    expect(v.some((m) => m.includes(fragment)), `expected a violation mentioning "${fragment}", got: ${v.join(" | ")}`);
    expect(v.length === 1, `expected exactly one violation, got ${v.length}`);
  });
}

await test("G3", "production: STAGING_TEST_LOGINS refused; clean production, development and test unaffected", async () => {
  expect(assertStagingSafety({ NODE_ENV: "production", STAGING_TEST_LOGINS: loginsValue() }).length === 1, "production + STAGING_TEST_LOGINS not refused");
  expect(assertStagingSafety({ NODE_ENV: "production" }).length === 0, "clean production flagged");
  const unsafeButLocal = { ALLOW_FIXED_OTP: "true", RAZORPAY_ALLOW_TEST_BYPASS: "true", RAZORPAY_KEY_ID: "rzp_live_x", CASHFREE_ENV: "PRODUCTION", SMS_PROVIDER: "msg91", MSG91_AUTH_KEY: "x" };
  for (const nodeEnv of ["development", "test", undefined]) {
    const env = { ...unsafeButLocal }; if (nodeEnv) env.NODE_ENV = nodeEnv;
    expect(assertStagingSafety(env).length === 0, `local/test env (${nodeEnv}) was affected`);
  }
});

await test("G4", 'NODE_ENV that only looks like staging ("Staging", "stage", "STAGING", "staging-2") is refused; "staging" accepted', async () => {
  for (const bad of ["Staging", "stage", "STAGING", "staging-2"]) {
    expect(assertStagingSafety({ ...safeStagingEnv(), NODE_ENV: bad }).length === 1, `"${bad}" not refused`);
  }
  expect(assertStagingSafety(safeStagingEnv()).length === 0, '"staging" refused');
});

await test("G6", "STAGING_TEST_LOGINS parser: invalid entries rejected with index-only messages, valid ones kept", async () => {
  const good = `${PHONE_L1}:${SECRETS.get(PHONE_L1)}`;
  const cases = [
    ["bad phone (9 digits)", "600000001:493827"], ["phone starting 5", "5000000011:493827"], ["+91 prefix", "+916000000011:493827"],
    ["otp 5 digits", `${PHONE_L1}:49382`], ["otp 7 digits", `${PHONE_L1}:4938271`], ["otp letters", `${PHONE_L1}:49a827`],
    ["weak 111111", `${PHONE_L1}:111111`], ["weak 123456", `${PHONE_L1}:123456`], ["weak 654321", `${PHONE_L1}:654321`],
    ["weak 121212", `${PHONE_L1}:121212`], ["weak 123123", `${PHONE_L1}:123123`], ["weak 112233", `${PHONE_L1}:112233`],
    ["otp = last six of phone", `${PHONE_L1}:${PHONE_L1.slice(-6)}`], ["no colon", PHONE_L1], ["extra colon", `${PHONE_L1}:493827:1`],
    ["trailing comma", `${good},`], ["empty entry", `${good},,${PHONE_L2}:${SECRETS.get(PHONE_L2)}`],
    ["duplicate phone", `${good},${PHONE_L1}:${makeSecretOtp(PHONE_L1)}`],
    ["space around colon", `${PHONE_L1} : 493827`],
  ];
  for (const [label, raw] of cases) {
    const { errors } = parseStagingTestLogins(raw);
    expect(errors.length >= 1, `no error for: ${label}`);
    expect(errors.every((e) => /^STAGING_TEST_LOGINS /.test(e) && !/\d{6}/.test(e)), `error for "${label}" is not index-only`);
  }
  const tooMany = Array.from({ length: 26 }, (_, i) => `60000${String(i + 100).padStart(5, "0")}:${makeSecretOtp("6000000000")}`).join(",");
  expect(parseStagingTestLogins(tooMany).errors.some((e) => e.includes("more than 25")), "26 entries not rejected");
  expect(parseStagingTestLogins("").errors.length === 0 && parseStagingTestLogins("").logins.size === 0, "empty value mishandled");
  const ok = parseStagingTestLogins(`  ${good} , ${PHONE_L2}:${SECRETS.get(PHONE_L2)}  `);
  expect(ok.errors.length === 0 && ok.logins.size === 2, "surrounding whitespace around entries should be tolerated");
  expect(parseStagingTestLogins(`${good},${PHONE_L2}:111111`).logins.size === 1, "valid entry dropped, or invalid kept");
});

await test("G8", "drift guard: the in-code fallbacks the boot guard rejects still exist verbatim in the controllers", async () => {
  const booking = fs.readFileSync(path.join(BACKEND_DIR, "controllers/booking.controller.js"), "utf8");
  const district = fs.readFileSync(path.join(BACKEND_DIR, "controllers/district.controller.js"), "utf8");
  expect(booking.includes('"otp-fallback-secret-change-in-prod"'), "OTP_SECRET fallback literal changed — update stagingGuards.js");
  expect(booking.includes('"barber-engine-otp-key-32-chars!!"'), "OTP_ENCRYPT_KEY fallback literal changed — update stagingGuards.js");
  expect(district.includes('"Admin@12345"'), "ADMIN_RESET_PASSWORD default changed — update stagingGuards.js");
});

await test("G5", "server.js: unsafe staging exits 1 BEFORE app/Redis/Mongo side effects (child process; control proves the assertion can fail)", async () => {
  const emptyCwd = fs.mkdtempSync(path.join(os.tmpdir(), "zemish-boot-"));
  try {
    const unsafeEnv = {
      PATH: process.env.PATH, NODE_ENV: "staging", ALLOW_FIXED_OTP: "true",
      MONGODB_URI: "mongodb://unreachable.invalid/barber_engine_v1", REDIS_URL: "redis://unreachable.invalid:6379",
    }; // deliberately NO Razorpay keys: if app.js were imported first it would die with "Razorpay credentials missing"
    const run = (args, env) => spawnSync(process.execPath, args, { cwd: emptyCwd, env, encoding: "utf8", timeout: 15_000 });
    const guarded = run([path.join(BACKEND_DIR, "server.js")], unsafeEnv);
    const guardedOut = `${guarded.stdout}\n${guarded.stderr}`;
    expect(guarded.status === 1, `expected exit code 1, got ${guarded.status}`);
    expect(guardedOut.includes("Refusing to start"), "guard message missing");
    expect(guardedOut.includes("ALLOW_FIXED_OTP"), "violation not reported");
    for (const sideEffect of ["Razorpay credentials missing", "Redis", "MongoDB", "connected"]) {
      expect(!guardedOut.includes(sideEffect), `app side effect leaked before the guard: ${sideEffect}`);
    }
    // Control: importing app.js directly (no guard) with the same env DOES hit the app's own startup error.
    const control = run(["--input-type=module", "-e", `await import(${JSON.stringify(pathToFileURL(path.join(BACKEND_DIR, "app.js")).href)})`], { ...unsafeEnv, SKIP_REDIS_AUTOCONNECT: "true" });
    expect(`${control.stdout}\n${control.stderr}`.includes("Razorpay credentials missing"), "control run did not show the app startup error — the assertion above would be vacuous");
    // Production with a leaked staging variable is refused too.
    const prod = run([path.join(BACKEND_DIR, "server.js")], { PATH: process.env.PATH, NODE_ENV: "production", STAGING_TEST_LOGINS: loginsValue() });
    expect(prod.status === 1 && `${prod.stdout}\n${prod.stderr}`.includes("STAGING_TEST_LOGINS must not be set"), "production + STAGING_TEST_LOGINS not refused at boot");
    expect(!`${prod.stdout}\n${prod.stderr}`.includes(SECRETS.get(PHONE_L1)), "boot output leaked a secret");
  } finally {
    fs.rmSync(emptyCwd, { recursive: true, force: true });
  }
});

// ─── Load real modules for O / H / C ────────────────────────────────────────
const { default: mongoose } = await import("mongoose");
mongoose.set("bufferCommands", false); // any DB call that isn't explicitly stubbed throws instead of hanging
const { default: logger } = await import("../utils/logger.js");
// Run `fn` with ALL app/console output swallowed (logger, console, stdout/stderr) and return its value.
// Used ONLY around code paths that emit EXPECTED noise: the dev-mode OTP logger line (regression cases)
// and the intentional CORS / webhook rejections. Assertion failures and thrown errors still propagate
// untouched, so no test outcome is hidden — only the log lines are.
const quiet = async (fn) => {
  let value;
  await capture(async () => { value = await fn(); }, logger);
  return value;
};
const otpService = await import("../modules/otp/services/otp.service.js");
const { DevLogProvider } = await import("../modules/otp/providers/DevLogProvider.js");
const { default: OtpAuditOutbox } = await import("../modules/otp/models/OtpAuditOutbox.js");
const { OTP_PURPOSE } = await import("../modules/otp/constants/otpPurpose.constants.js");
const auditRows = [];
OtpAuditOutbox.create = async (doc) => { auditRows.push(doc); return doc; };

const STAGING = { NODE_ENV: "staging", STAGING_TEST_LOGINS: loginsValue(), ALLOW_FIXED_OTP: undefined, SMS_PROVIDER: undefined, PUSH_PROVIDER: undefined };
const sendVia = (redis, phone, purpose = OTP_PURPOSE.LOGIN, role = "USER") => otpService.sendOtp({ phone, purpose, role, redis });
const verifyVia = (redis, phone, otp, purpose = OTP_PURPOSE.LOGIN, role = "USER") => otpService.verifyOtp({ phone, purpose, otp, role, redis });
const storedHash = (redis, phone, purpose = "LOGIN", role = "USER") => JSON.parse(redis.store.get(keyFor(role, purpose, phone, "hash")).value).hash;

// ─── O — OTP service ────────────────────────────────────────────────────────
section("O  OTP service (real code, in-memory Redis)");

await test("O1", "listed phone: stored hash = hash of ITS secret; no otp in the result", async () => {
  await withEnv(STAGING, async () => {
    const redis = makeFakeRedis();
    const r = await sendVia(redis, PHONE_L1);
    expect(r.success === true, "send failed");
    expect(!("otp" in r), "otp present in send result");
    expect(storedHash(redis, PHONE_L1) === sha256(SECRETS.get(PHONE_L1)), "stored hash is not the tester's secret");
  });
});

await test("O2", "unlisted phone: same result shape; stored hash matches NONE of the 10^6 six-digit codes", async () => {
  await withEnv(STAGING, async () => {
    const redisL = makeFakeRedis(); const redisU = makeFakeRedis();
    const listed = await sendVia(redisL, PHONE_L1);
    const unlisted = await sendVia(redisU, PHONE_U1);
    expect(unlisted.success === true && !("otp" in unlisted), "unlisted send not success-shaped, or otp present");
    expect(JSON.stringify(Object.keys(listed).sort()) === JSON.stringify(Object.keys(unlisted).sort()), "result shape differs between listed and unlisted");
    const target = storedHash(redisU, PHONE_U1);
    for (let n = 0; n < 1_000_000; n += 1) {
      expect(sha256(String(n).padStart(6, "0")) !== target, "unlisted phone's stored hash matches a six-digit code");
    }
  });
});

await test("O3", "verify veto: matching hash → unlisted INVALID_OTP, listed ok; veto audited as VERIFY_FAILED/INVALID_OTP", async () => {
  await withEnv(STAGING, async () => {
    const match = () => [1, "OK"];
    const before = auditRows.length;
    const unlisted = await verifyVia(makeFakeRedis({ evalImpl: match }), PHONE_U1, "654322");
    expect(unlisted.ok === false && unlisted.code === "INVALID_OTP", "unlisted phone not vetoed");
    expect(auditRows[before].status === "VERIFY_FAILED" && auditRows[before].failureReason === "INVALID_OTP", "veto not audited as a failure");
    const listed = await verifyVia(makeFakeRedis({ evalImpl: match }), PHONE_L1, SECRETS.get(PHONE_L1));
    expect(listed.ok === true, "listed phone rejected");
  });
});

await test("O4", "veto result is identical to a genuine wrong-OTP result (indistinguishable)", async () => {
  await withEnv(STAGING, async () => {
    const vetoed = await verifyVia(makeFakeRedis({ evalImpl: () => [1, "OK"] }), PHONE_U1, "654322");
    const wrong = await verifyVia(makeFakeRedis({ evalImpl: () => [0, "INVALID_OTP"] }), PHONE_L1, "654322");
    expect(JSON.stringify(vetoed) === JSON.stringify(wrong), "veto and wrong-OTP results differ");
  });
});

await test("O5", "attempt policy passed to the Lua: 10/7200 on staging for listed AND unlisted; 5/300 on development, test, production", async () => {
  const argsFor = async (env, phone) => withEnv(env, async () => {
    const redis = makeFakeRedis({ evalImpl: () => [0, "OTP_EXPIRED"] });
    await verifyVia(redis, phone, "654322");
    return redis.evalCalls[0].args;
  });
  for (const phone of [PHONE_L1, PHONE_U1]) {
    const a = await argsFor(STAGING, phone);
    expect(a[1] === "10" && a[2] === "7200", "staging policy is not 10/7200");
  }
  for (const nodeEnv of ["development", "test", "production"]) {
    const a = await argsFor({ NODE_ENV: nodeEnv, STAGING_TEST_LOGINS: undefined }, PHONE_L1);
    expect(a[1] === "5" && a[2] === "300", `${nodeEnv} policy changed`);
  }
});

await test("O5b", "end-to-end policy on staging (port): 10 wrong → INVALID_OTP ×10, then correct secret → TOO_MANY_ATTEMPTS", async () => {
  await withEnv(STAGING, async () => {
    const redis = makeFakeRedis();
    await sendVia(redis, PHONE_L1);
    for (let i = 0; i < 10; i += 1) expect((await verifyVia(redis, PHONE_L1, "654322")).code === "INVALID_OTP", `attempt ${i + 1}`);
    expect((await verifyVia(redis, PHONE_L1, SECRETS.get(PHONE_L1))).code === "TOO_MANY_ATTEMPTS", "not locked after 10");
  });
});

await test("O6", "generateOtp: staging never numeric/fixed for unlisted or phone-less; listed → its secret; dev/prod unchanged", async () => {
  const gen = (env, arg) => withEnv(env, () => otpService.generateOtp(arg));
  for (const arg of [undefined, {}, { phone: PHONE_U1 }, { phone: "not-a-phone" }]) {
    const v = await gen({ ...STAGING, ALLOW_FIXED_OTP: "true" }, arg);
    expect(!/^\d{4,6}$/.test(v) && v !== "123456", "staging produced a guessable code");
  }
  expect((await gen(STAGING, { phone: PHONE_L2 })) === SECRETS.get(PHONE_L2), "listed phone did not get its secret");
  expect((await gen(STAGING, { phone: `+91 ${PHONE_L2}` })) === SECRETS.get(PHONE_L2), "canonical phone lookup failed");
  expect((await gen({ NODE_ENV: "development", ALLOW_FIXED_OTP: "true", STAGING_TEST_LOGINS: loginsValue() }, { phone: PHONE_L2 })) === "123456", "development fixed OTP changed");
  expect((await gen({ NODE_ENV: "development", ALLOW_FIXED_OTP: undefined }, undefined)).length === 6, "development random OTP changed");
  expect(/^\d{6}$/.test(await gen({ NODE_ENV: "production", ALLOW_FIXED_OTP: undefined }, { phone: PHONE_L2 })), "production OTP changed");
});

await test("O7", "echo: staging never returns otp (even with ALLOW_FIXED_OTP=true); development + flag still echoes", async () => {
  const stagingRes = await withEnv({ ...STAGING, ALLOW_FIXED_OTP: "true" }, () => sendVia(makeFakeRedis(), PHONE_L1));
  expect(!("otp" in stagingRes), "staging echoed the OTP");
  // Development really logs "[DEV SMS] OTP for …" here; keep that line out of the test output.
  const devRes = await quiet(() => withEnv({ NODE_ENV: "development", ALLOW_FIXED_OTP: "true", STAGING_TEST_LOGINS: undefined }, () => sendVia(makeFakeRedis(), PHONE_L1)));
  expect(devRes.otp === "123456", "development echo changed");
});

await test("O8", "Redis failure fails closed: send and verify reject, never ok:true", async () => {
  await withEnv(STAGING, async () => {
    let sendFailed = false; let verifyFailed = false;
    try { await sendVia(makeFakeRedis({ failOn: "set" }), PHONE_L1); } catch { sendFailed = true; }
    try { await verifyVia(makeFakeRedis({ failOn: "eval" }), PHONE_L1, SECRETS.get(PHONE_L1)); } catch { verifyFailed = true; }
    expect(sendFailed && verifyFailed, "a Redis failure did not surface as a rejection");
  });
});

await test("O9", "DevLogProvider: staging logs nothing (no OTP/phone); development still logs its dev line", async () => {
  const provider = new DevLogProvider();
  const stagingOut = await capture(async () => {
    const r = await withEnv(STAGING, () => provider.sendOtp(PHONE_L1, SECRETS.get(PHONE_L1)));
    expect(r.success === true && r.provider === "none", "staging send not an honest success no-op");
  }, logger);
  expect(!stagingOut.includes(SECRETS.get(PHONE_L1)) && !stagingOut.includes(PHONE_L1), "staging logged the OTP or phone");
  const devOut = await capture(async () => {
    await withEnv({ NODE_ENV: "development" }, () => provider.sendOtp(PHONE_L1, "654322"));
  }, logger);
  expect(devOut.includes("654322"), "development no longer logs its dev OTP line");
});

await test("O10", "rotation / removal take effect on the next call (no cache)", async () => {
  const newSecret = makeSecretOtp(PHONE_L1);
  await withEnv({ ...STAGING, STAGING_TEST_LOGINS: `${PHONE_L1}:${newSecret}` }, async () => {
    expect(otpService.generateOtp({ phone: PHONE_L1 }) === newSecret, "rotated secret not used");
    expect(otpService.generateOtp({ phone: PHONE_L1 }) !== SECRETS.get(PHONE_L1), "old secret still used");
    expect(isStagingTestPhone(PHONE_L2) === false, "removed tester still listed");
  });
});

await test("O11", "helper regression: strict-CORS and staging predicates, masking", async () => {
  expect(isStrictCorsEnv({ NODE_ENV: "production" }) && isStrictCorsEnv({ NODE_ENV: "staging" }), "strict CORS missing for production/staging");
  expect(!isStrictCorsEnv({ NODE_ENV: "development" }) && !isStrictCorsEnv({ NODE_ENV: "test" }) && !isStrictCorsEnv({}), "dev/test must not be strict");
  expect(isStagingEnv({ NODE_ENV: "staging" }) && !isStagingEnv({ NODE_ENV: "production" }), "isStagingEnv wrong");
  expect(stagingTestOtpFor(PHONE_L1, { STAGING_TEST_LOGINS: undefined }) === null, "listed without config");
  const staged = { NODE_ENV: "staging" };
  expect(maskPhoneForLog(PHONE_L1, staged) === `******${PHONE_L1.slice(-4)}`, "mask format");
  expect(maskPhoneForLog("12", staged) === "******" && maskPhoneForLog(undefined, staged) === "******" && maskPhoneForLog({}, staged) === "******", "mask must not throw on odd input");
  for (const nodeEnv of ["production", "development", "test"]) {
    expect(maskPhoneForLog(PHONE_L1, { NODE_ENV: nodeEnv }) === PHONE_L1, `${nodeEnv} masking must be identity`);
  }
});

await test("G7", "no sentinel OTP/phone reaches any console, stdout, stderr or logger sink across guard + service + provider", async () => {
  // The guard is pure: it RETURNS its violation messages and the boot guard is what prints them. Emit every
  // returned message into the captured sink (exactly what stagingBootGuard.js does with console.error), so
  // the sentinel checks below really inspect the guard's output.
  const emit = (messages) => console.error(messages.join("\n"));
  const out = await capture(async () => {
    emit(parseStagingTestLogins(`${PHONE_L1}:111111,${PHONE_L2}:${SECRETS.get(PHONE_L2)},${PHONE_L1}:${SECRETS.get(PHONE_L1)}`).errors);
    emit(assertStagingSafety({ ...safeStagingEnv(), STAGING_TEST_LOGINS: `${PHONE_L1}:111111,${PHONE_L2}:${SECRETS.get(PHONE_L2)}x` }));
    emit(assertStagingSafety({ ...safeStagingEnv(), MONGODB_URI: withUserinfo("mongodb+srv", "cluster0.invalid/barber_engine_v1") }));
    emit(assertStagingSafety({ NODE_ENV: "production", STAGING_TEST_LOGINS: loginsValue() }));
    await withEnv(STAGING, async () => {
      const redis = makeFakeRedis();
      await sendVia(redis, PHONE_L1); await sendVia(makeFakeRedis(), PHONE_U1);
      await verifyVia(redis, PHONE_L1, SECRETS.get(PHONE_L1)); await verifyVia(makeFakeRedis(), PHONE_U1, "654322");
      await new DevLogProvider().sendOtp(PHONE_L1, SECRETS.get(PHONE_L1));
      otpService.generateOtp({ phone: PHONE_L1 });
    });
  }, logger);
  for (const s of ALL_SENTINELS) expect(!out.includes(s), "a sentinel value reached an output sink");
  expect(!out.includes(URI_PASS), "a connection-string password reached an output sink");

  // Worst-case sweep: every variable the guard inspects gets an UNSAFE value with a unique random token
  // embedded in it (inside a URI's password/host/db, a CORS entry, a key, ...). No violation message may
  // contain any token, so a partial leak is caught as well as a whole-value one. Failures name the
  // variable only, never a value.
  const tokens = {};
  const tok = (name) => (tokens[name] = rnd(8));
  const worst = { NODE_ENV: "staging" };
  for (const name of [
    "ALLOW_FIXED_OTP", "RAZORPAY_ALLOW_TEST_BYPASS", "CASHFREE_ENV", "SUREPASS_TOKEN", "SMS_PROVIDER", "PUSH_PROVIDER",
    "EXPO_ACCESS_TOKEN", "FIREBASE_PROJECT_ID", "FIREBASE_CLIENT_EMAIL", "FIREBASE_PRIVATE_KEY", "SMTP_HOST",
    "WHATSAPP_PROVIDER", "CALL_PROVIDER", "BOT_PROVIDER", "MSG91_AUTH_KEY", "TWILIO_ACCOUNT_SID",
    "RAZORPAYX_ROUTE_BASE_URL", "CASHFREE_PAYOUT_BASE_URL", "RAZORPAY_KEY_SECRET",
    "JWT_ACCESS_SECRET", "OTP_SECRET", "OTP_ENCRYPT_KEY", "KYC_ENCRYPTION_KEY", // 16 chars: too short / not 64 hex
  ]) worst[name] = tok(name);
  worst.STAGING_TEST_LOGINS = `${tok("STAGING_TEST_LOGINS")}:${tokens.STAGING_TEST_LOGINS},${tokens.STAGING_TEST_LOGINS}`;
  worst.RAZORPAY_KEY_ID = `rzp_live_${tok("RAZORPAY_KEY_ID")}`;
  worst.MONGODB_URI = `${uriScheme("mongodb+srv")}${tok("MONGODB_URI")}:${tokens.MONGODB_URI}@${tokens.MONGODB_URI}.invalid/${tokens.MONGODB_URI}`;
  worst.REDIS_URL = `http://${tok("REDIS_URL")}:${tokens.REDIS_URL}@${tokens.REDIS_URL}`;
  worst.CORS_ORIGIN = `*,http://${tok("CORS_ORIGIN")}.invalid,https://${tokens.CORS_ORIGIN}.invalid/path, https://${tokens.CORS_ORIGIN}.invalid`;
  // New staging-isolation variables: malformed deny-lists, an acknowledgment value, and a Render identity.
  worst.STAGING_FORBIDDEN_MONGO_ENDPOINTS = `${tok("STAGING_FORBIDDEN_MONGO_ENDPOINTS")},zz`;
  worst.STAGING_FORBIDDEN_REDIS_ENDPOINTS = `${tok("STAGING_FORBIDDEN_REDIS_ENDPOINTS")},zz`;
  worst.STAGING_ACK_SHARED_DEV_DATABASE = tok("STAGING_ACK_SHARED_DEV_DATABASE");
  worst.RENDER = "true";
  worst.RENDER_SERVICE_NAME = tok("RENDER_SERVICE_NAME");
  const worstMessages = assertStagingSafety(worst);
  expect(worstMessages.length >= 25, "worst-case sweep did not exercise the guard rules (too few violations)");
  const sweepText = [
    worstMessages,
    assertStagingSafety({ ...worst, NODE_ENV: "Staging" }),
    assertStagingSafety({ NODE_ENV: "production", STAGING_TEST_LOGINS: worst.STAGING_TEST_LOGINS }),
  ].map((m) => m.join("\n")).join("\n");
  const leaked = Object.entries(tokens).filter(([, token]) => sweepText.includes(token)).map(([name]) => name);
  expect(leaked.length === 0, `a boot-guard violation message contained a value fragment of: ${leaked.join(", ")}`);
});

// ─── H — handlers ───────────────────────────────────────────────────────────
section("H  handlers (real controllers; models/session stubbed; mutation counters)");

const { default: User } = await import("../models/User.js");
const { default: RefreshToken } = await import("../models/RefreshToken.js");
const { default: Salon } = await import("../models/Salon.js");
const { default: WalletTransaction } = await import("../models/WalletTransaction.js");
const { default: NotificationService } = await import("../services/NotificationService.js");
const { default: sharedRedis } = await import("../config/redis.js");
const authController = await import("../controllers/auth.controller.js");
const { verifyFieldAgentOtp } = await import("../modules/fieldAgent/controllers/fieldAgentAuth.controller.js");
const { verifyFieldAgentOperationalOtp } = await import("../modules/fieldAgent/controllers/fieldAgentOperationalAuth.controller.js");
const { startAssistedOnboarding } = await import("../modules/fieldAgent/services/assistedOnboarding.service.js");
const { mockPayment } = await import("../controllers/payment.controller.js");
const { mockVerifyTopup } = await import("../controllers/wallet.controller.js");

const counters = { userFindOne: 0, userSave: 0, refreshCreate: 0, sessionRedisSet: 0, salonFindOne: 0, startSession: 0, walletFind: 0, userUpdate: 0, walletUpdate: 0, notify: 0 };
const resetCounters = () => { for (const k of Object.keys(counters)) counters[k] = 0; };
const stubUser = () => ({ _id: new mongoose.Types.ObjectId(), role: "USER", status: "ACTIVE", name: "Customer", tokenVersion: 0, adminLevel: null });
User.findOne = () => { counters.userFindOne += 1; return { select: async () => stubUser() }; };
User.findById = () => ({ select: () => ({ lean: async () => ({ phone: "6000000555" }) }) });
User.prototype.save = async function save() { counters.userSave += 1; return this; };
User.findOneAndUpdate = () => { counters.userUpdate += 1; throw new Error("unexpected wallet mutation"); };
RefreshToken.create = async () => { counters.refreshCreate += 1; return {}; };
Salon.findOne = () => { counters.salonFindOne += 1; return { lean: async () => null }; };
WalletTransaction.findOne = () => { counters.walletFind += 1; throw new Error("unexpected wallet read"); };
WalletTransaction.updateOne = () => { counters.walletUpdate += 1; throw new Error("unexpected ledger write"); };
NotificationService.send = async () => { counters.notify += 1; };
sharedRedis.set = async () => { counters.sessionRedisSet += 1; return "OK"; };
const realStartSession = mongoose.startSession.bind(mongoose);
mongoose.startSession = async () => { counters.startSession += 1; throw new Error("SENTINEL_START_SESSION"); };

const makeRes = () => {
  const res = { statusCode: 200, body: null, cookies: [], headers: {} };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; return res; };
  res.cookie = (...a) => { res.cookies.push(a); return res; };
  res.setHeader = (k, v) => { res.headers[k] = v; };
  return res;
};
const makeReq = (body, redis) => ({ body, redis, ip: "127.0.0.1", headers: { "user-agent": "verify-script" }, cookies: {}, connection: {} });
const noMutation = () => counters.userFindOne === 0 && counters.userSave === 0 && counters.refreshCreate === 0 && counters.sessionRedisSet === 0 && counters.salonFindOne === 0;
const matchEval = { evalImpl: () => [1, "OK"] };

await test("H1", "unlisted phone + matching hash: user/owner/field-agent verify → 401 INVALID_OTP; ZERO user lookups/creates, sessions, cookies, tokens", async () => {
  await withEnv(STAGING, async () => {
    for (const [label, call] of [
      ["user", async (res) => authController.verifyUserOtp(makeReq({ phone: PHONE_U1, otp: "654322" }, makeFakeRedis(matchEval)), res)],
      ["owner", async (res) => authController.verifyOtp(makeReq({ phone: PHONE_U1, otp: "654322" }, makeFakeRedis(matchEval)), res)],
      ["field-agent apply", async (res) => verifyFieldAgentOtp(makeReq({ phone: PHONE_U1, otp: "654322" }, makeFakeRedis(matchEval)), res, () => { throw new Error("next() called"); })],
      ["field-agent operational", async (res) => verifyFieldAgentOperationalOtp(makeReq({ phone: PHONE_U1, otp: "654322" }, makeFakeRedis(matchEval)), res, () => { throw new Error("next() called"); })],
    ]) {
      resetCounters();
      const res = makeRes();
      await call(res);
      expect(res.statusCode === 401, `${label}: status ${res.statusCode}, expected 401`);
      const code = res.body?.error?.code ?? res.body?.code;
      expect(code === "INVALID_OTP", `${label}: code is not INVALID_OTP`);
      expect(noMutation(), `${label}: a user/session step was reached`);
      expect(res.cookies.length === 0 && !("accessToken" in (res.body || {})) && !("refreshToken" in (res.body || {})), `${label}: a token/cookie was issued`);
    }
  });
});

await test("H1b", "end-to-end with a PLANTED real hash: staging → 401, same hash in development → 200 (only the veto differs)", async () => {
  const planted = () => { const r = makeFakeRedis(); r.store.set(keyFor("USER", "LOGIN", PHONE_U1, "hash"), { value: JSON.stringify({ hash: sha256("123456"), purpose: "LOGIN" }), exp: Date.now() + 300_000 }); return r; };
  resetCounters();
  const staged = makeRes();
  await withEnv(STAGING, () => authController.verifyUserOtp(makeReq({ phone: PHONE_U1, otp: "123456" }, planted()), staged));
  expect(staged.statusCode === 401 && noMutation(), "staging did not block the planted hash");
  resetCounters();
  const dev = makeRes();
  await withEnv({ NODE_ENV: "development", STAGING_TEST_LOGINS: undefined }, () => authController.verifyUserOtp(makeReq({ phone: PHONE_U1, otp: "123456" }, planted()), dev));
  expect(dev.statusCode === 200 && typeof dev.body.accessToken === "string", "control: development did not log in with the planted hash");
});

await test("H2", "listed phone + its secret: user and owner login succeed (intended test login works)", async () => {
  await withEnv(STAGING, async () => {
    for (const [label, call, role] of [
      ["user", (req, res) => authController.verifyUserOtp(req, res), "USER"],
      ["owner", (req, res) => authController.verifyOtp(req, res), "OWNER"],
    ]) {
      resetCounters();
      const redis = makeFakeRedis();
      const purpose = role === "USER" ? OTP_PURPOSE.LOGIN : OTP_PURPOSE.SALON_LOGIN;
      await sendVia(redis, PHONE_L1, purpose, role);
      const res = makeRes();
      await call(makeReq({ phone: PHONE_L1, otp: SECRETS.get(PHONE_L1) }, redis), res);
      expect(res.statusCode === 200 && res.body?.success === true, `${label}: login failed (${res.statusCode})`);
      expect(typeof res.body.accessToken === "string" && res.cookies.length === 1, `${label}: no token/cookie`);
      expect(counters.userFindOne === 1 && counters.refreshCreate === 1, `${label}: session path not taken exactly once`);
    }
  });
});

await test("H3", "assisted onboarding: unlisted owner phone rejected at OTP verify; no owner lookup/creation", async () => {
  await withEnv(STAGING, async () => {
    resetCounters();
    let threw = false;
    try {
      await startAssistedOnboarding({
        fieldAgentUserId: new mongoose.Types.ObjectId().toString(), phone: PHONE_U1, otp: "654322", createNewBranch: false,
        req: makeReq({}, null), redis: makeFakeRedis(matchEval),
      });
    } catch { threw = true; }
    expect(threw, "assisted onboarding did not reject an unlisted phone");
    expect(counters.userFindOne === 0 && counters.userSave === 0, "an owner lookup/creation was reached");
  });
});

await test("H4", "send-otp for listed vs unlisted: identical status and body keys, no otp field", async () => {
  await withEnv(STAGING, async () => {
    const run = async (phone) => { const res = makeRes(); await authController.sendUserOtp(makeReq({ phone }, makeFakeRedis()), res); return res; };
    const listed = await run(PHONE_L1); const unlisted = await run(PHONE_U1);
    expect(listed.statusCode === 200 && unlisted.statusCode === 200, "send did not return 200 for both");
    expect(JSON.stringify(Object.keys(listed.body).sort()) === JSON.stringify(Object.keys(unlisted.body).sort()), "body keys differ");
    expect(!("otp" in listed.body) && !("otp" in unlisted.body), "otp present in a response");
    expect(listed.body.message === unlisted.body.message, "messages differ");
  });
});

await test("H6", "analytics log: staging masks the phone (last 4 only), keeps role/provider/code; development logs the full phone as before", async () => {
  // `quiet` also swallows the development-mode "[DEV SMS] OTP for …" line this run really produces.
  const runOnce = async (env) => quiet(() => withEnv(env, async () => {
    const lines = [];
    const saved = logger.info; logger.info = (...args) => { lines.push(args); };
    try {
      await authController.sendUserOtp(makeReq({ phone: PHONE_L1 }, makeFakeRedis()), makeRes());
      await authController.verifyUserOtp(makeReq({ phone: PHONE_L1, otp: "654322" }, makeFakeRedis({ evalImpl: () => [0, "INVALID_OTP"] })), makeRes());
    } finally { logger.info = saved; }
    return lines;
  }));
  const staged = await runOnce(STAGING);
  const sent = staged.find((l) => String(l[0]).includes("otp_sent"));
  const failed = staged.find((l) => String(l[0]).includes("otp_verify_failed"));
  expect(sent && failed, "analytics events missing");
  expect(sent[1].phone === `******${PHONE_L1.slice(-4)}` && failed[1].phone === `******${PHONE_L1.slice(-4)}`, "staging phone not masked to last 4");
  expect(sent[1].role === "USER" && typeof sent[1].provider === "string" && failed[1].code === "INVALID_OTP", "troubleshooting fields lost");
  expect(!JSON.stringify(staged).includes(PHONE_L1), "full phone present in staging analytics output");
  const dev = await runOnce({ NODE_ENV: "development", STAGING_TEST_LOGINS: undefined });
  const devSent = dev.find((l) => String(l[0]).includes("otp_sent"));
  expect(devSent && devSent[1].phone === PHONE_L1, "development analytics changed (phone must stay unmasked)");
});

await test("H5", "mock payment / mock top-up: staging & production → 404 with ZERO DB/wallet/ledger/notification calls; development passes the guard", async () => {
  for (const nodeEnv of ["staging", "production"]) {
    await withEnv({ NODE_ENV: nodeEnv }, async () => {
      for (const [label, handler] of [["mockPayment", mockPayment], ["mockVerifyTopup", mockVerifyTopup]]) {
        resetCounters();
        const res = makeRes();
        await handler({ body: { amount: 500, orderId: "order_synthetic" }, user: { id: "synthetic" } }, res);
        expect(res.statusCode === 404 && res.body?.success === false && res.body?.message === "Not found", `${nodeEnv}/${label}: not a 404`);
        expect(counters.startSession === 0 && counters.walletFind === 0 && counters.userUpdate === 0 && counters.walletUpdate === 0 && counters.notify === 0 && counters.userFindOne === 0, `${nodeEnv}/${label}: a DB/wallet/ledger/notification call happened`);
      }
    });
  }
  await withEnv({ NODE_ENV: "development" }, async () => {
    resetCounters();
    const pay = makeRes();
    await mockPayment({ body: { amount: 500 } }, pay);
    expect(pay.body?.success === true && pay.body?.paymentConfirmed === true, "development mockPayment changed");
    let reachedDb = false;
    try { await mockVerifyTopup({ body: { orderId: "order_synthetic" }, user: { id: "synthetic" } }, makeRes()); } catch (e) { reachedDb = e.message === "SENTINEL_START_SESSION"; }
    expect(reachedDb && counters.startSession === 1, "development mockVerifyTopup no longer reaches its DB step (guard over-blocks)");
  });
});
mongoose.startSession = realStartSession;

// ─── C — CORS / webhook / socket on the real app (loopback) ─────────────────
section("C  CORS, webhooks and socket handshake (real app, loopback only)");

const { default: app } = await import("../app.js");
const { initSocket } = await import("../socket/index.js");
const server = http.createServer(app);
const io = initSocket(server);
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const FIXTURE_ORIGIN = "https://cors-fixture.invalid";
const UNAPPROVED_ORIGIN = "https://unapproved.invalid";
const httpRequest = ({ method = "GET", path: p, headers = {}, body }) => new Promise((resolve, reject) => {
  const req = http.request({ host: "127.0.0.1", port, method, path: p, headers }, (res) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
  });
  req.on("error", reject);
  req.setTimeout(8000, () => req.destroy(new Error("request timeout")));
  if (body) req.write(body);
  req.end();
});
const preflight = (origin) => httpRequest({ method: "OPTIONS", path: "/api/auth/user/send-otp", headers: { Origin: origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type" } });
const handshake = (headers) => httpRequest({ path: "/socket.io/?EIO=4&transport=polling", headers });
const acao = (r) => r.headers["access-control-allow-origin"];
// The rejections exercised here are intentional; their stack traces / CORS warnings are expected noise.
const inEnv = (nodeEnv, fn) => withEnv({ NODE_ENV: nodeEnv, RAZORPAY_WEBHOOK_SECRET: undefined }, () => quiet(fn));

await test("C1", "staging preflight from the approved fixture origin → 204 with matching Allow-Origin and credentials", async () => {
  const r = await inEnv("staging", () => preflight(FIXTURE_ORIGIN));
  expect(r.status === 204, `status ${r.status}`);
  expect(acao(r) === FIXTURE_ORIGIN && r.headers["access-control-allow-credentials"] === "true", "headers wrong");
});

await test("C2", "unapproved origin: staging behaves exactly like production (no Allow-Origin; same status) for HTTP preflight and socket handshake", async () => {
  const staging = await inEnv("staging", async () => ({ pre: await preflight(UNAPPROVED_ORIGIN), hs: await handshake({ Origin: UNAPPROVED_ORIGIN }) }));
  const production = await inEnv("production", async () => ({ pre: await preflight(UNAPPROVED_ORIGIN), hs: await handshake({ Origin: UNAPPROVED_ORIGIN }) }));
  expect(acao(staging.pre) === undefined && acao(staging.hs) === undefined, "staging allowed an unapproved origin");
  expect(staging.pre.status === production.pre.status && staging.hs.status === production.hs.status, "staging status differs from production");
});

await test("C3", "no Origin and EMPTY Origin (native mobile / the salon app's socket workaround) pass in staging: /health 200 and socket handshake 200", async () => {
  await inEnv("staging", async () => {
    for (const headers of [{}, { Origin: "" }]) {
      const health = await httpRequest({ path: "/health", headers });
      expect(health.status === 200, `/health ${health.status}`);
      const hs = await handshake(headers);
      expect(hs.status === 200 && hs.body.startsWith("0{") && hs.body.includes('"sid"'), `socket handshake failed (${hs.status})`);
    }
  });
});

await test("C3b", "approved fixture origin gets Allow-Origin on the socket handshake in staging", async () => {
  const hs = await inEnv("staging", () => handshake({ Origin: FIXTURE_ORIGIN }));
  expect(hs.status === 200 && acao(hs) === FIXTURE_ORIGIN, "approved origin not allowed on socket handshake");
});

await test("C4", "development remains open (regression): unapproved origin still gets Allow-Origin", async () => {
  const r = await inEnv("development", () => preflight(UNAPPROVED_ORIGIN));
  expect(acao(r) === UNAPPROVED_ORIGIN, "development CORS is no longer open");
});

await test("C5", "webhook (no Origin) is untouched by strict CORS: 503 when unconfigured, 401 on a bad signature — never a CORS error", async () => {
  for (const nodeEnv of ["staging", "production"]) {
    const unconfigured = await inEnv(nodeEnv, () => httpRequest({ method: "POST", path: "/api/webhooks/razorpay", headers: { "content-type": "application/json" }, body: "{}" }));
    expect(unconfigured.status === 503, `${nodeEnv}: unconfigured webhook returned ${unconfigured.status}`);
    const badSig = await withEnv({ NODE_ENV: nodeEnv, RAZORPAY_WEBHOOK_SECRET: rnd(16) }, () =>
      quiet(() => httpRequest({ method: "POST", path: "/api/webhooks/razorpay", headers: { "content-type": "application/json", "x-razorpay-signature": "bad" }, body: "{}" })));
    expect(badSig.status === 401, `${nodeEnv}: bad signature returned ${badSig.status}`);
  }
});


// ─── S — staging SMS OTP, allowlist mode (real OTP service + real MSG91 provider; fetch is STUBBED) ───────────────
section("S  staging SMS OTP allowlist (real MSG91 provider code; global fetch stubbed — no network, no real SMS)");

const guards = await import("../utils/stagingGuards.js");
const providers = await import("../modules/otp/providers/index.js");
const MSG91_KEY = `key${rnd(8)}`;
ALL_SENTINELS.push(MSG91_KEY);
const SMS_ALLOWED = [PHONE_L1, PHONE_L2];
// A complete SMS-mode staging configuration: no tester logins, MSG91 provider, an explicit recipient list.
const smsVars = (over = {}) => ({
  STAGING_SMS_OTP_MODE: "allowlist", STAGING_SMS_ALLOWED_PHONES: SMS_ALLOWED.join(","), SMS_PROVIDER: "msg91",
  MSG91_AUTH_KEY: MSG91_KEY, MSG91_TEMPLATE_ID: `tpl${rnd(3)}`, MSG91_SENDER_ID: "ZEMSH1", ...over,
});
const smsGuardEnv = (over = {}) => { const e = { ...safeStagingEnv(), ...smsVars(), ...over }; delete e.STAGING_TEST_LOGINS; return { ...e, ...(over.STAGING_TEST_LOGINS ? { STAGING_TEST_LOGINS: over.STAGING_TEST_LOGINS } : {}) }; };
const SMS_RUNTIME = { NODE_ENV: "staging", STAGING_TEST_LOGINS: undefined, ALLOW_FIXED_OTP: undefined, PUSH_PROVIDER: undefined, ...smsVars() };
const withoutKey = (env, ...names) => { const e = { ...env }; for (const n of names) delete e[n]; return e; };

// Replaces global fetch for the duration of fn; records every call; NEVER reaches the network.
const withFetch = async (impl, fn) => {
  const saved = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => { calls.push({ url: String(url), headers: init?.headers }); return impl(String(url)); };
  try { return await fn(calls); } finally { globalThis.fetch = saved; }
};
const okSms = async () => ({ ok: true, status: 200, json: async () => ({ type: "success", request_id: `req-${rnd(3)}` }) });
const failSms = async () => ({ ok: false, status: 400, json: async () => ({ type: "error", message: "synthetic provider rejection" }) });
const throwSms = async () => { throw new Error("synthetic network failure"); };
const otpFromCall = (call) => new URL(call.url).searchParams.get("otp");
const mobileFromCall = (call) => new URL(call.url).searchParams.get("mobile");

await test("S1", "boot guard: allowlist mode accepts a complete config; refuses every ambiguous, partial or unsupported one (fixed OTP stays off)", async () => {
  expect(assertStagingSafety(smsGuardEnv()).length === 0, `a complete allowlist config was refused: ${assertStagingSafety(smsGuardEnv()).join(" | ")}`);
  expect(assertStagingSafety(smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: `${PHONE_L1}, ${PHONE_L2}` })).length === 0, "a space after the comma should be tolerated (entries are trimmed)");
  const twentyFive = Array.from({ length: 25 }, (_, i) => `600000${String(1000 + i)}`).join(",");
  expect(assertStagingSafety(smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: twentyFive })).length === 0, "25 phones should be accepted");
  const base = smsGuardEnv();
  const bad = [
    ["STAGING_TEST_LOGINS also set (ambiguous)", smsGuardEnv({ STAGING_TEST_LOGINS: loginsValue() }), /STAGING_TEST_LOGINS must be unset/],
    ["mode 'open' (not supported)", smsGuardEnv({ STAGING_SMS_OTP_MODE: "open" }), /unset or exactly "allowlist"/],
    ["mode 'Allowlist' (case)", smsGuardEnv({ STAGING_SMS_OTP_MODE: "Allowlist" }), /unset or exactly "allowlist"/],
    ["mode ' allowlist' (whitespace)", smsGuardEnv({ STAGING_SMS_OTP_MODE: " allowlist" }), /unset or exactly "allowlist"/],
    ["mode 'true'", smsGuardEnv({ STAGING_SMS_OTP_MODE: "true" }), /unset or exactly "allowlist"/],
    ["allowlist missing", withoutKey(base, "STAGING_SMS_ALLOWED_PHONES"), /STAGING_SMS_ALLOWED_PHONES is not set/],
    ["allowlist blank", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: "   " }), /STAGING_SMS_ALLOWED_PHONES is not set/],
    ["phone with +91", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: `+91${PHONE_L1}` }), /entry 1: phone must be 10 digits/],
    ["phone too short", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: "60000" }), /entry 1: phone must be 10 digits/],
    ["phone starting 1", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: "1000000011" }), /entry 1: phone must be 10 digits/],
    ["trailing comma", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: `${PHONE_L1},` }), /entry 2: empty entry/],
    ["duplicate phone", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: `${PHONE_L1},${PHONE_L1}` }), /entry 2: duplicate phone/],
    ["26 phones", smsGuardEnv({ STAGING_SMS_ALLOWED_PHONES: `${twentyFive},6000009999` }), /more than 25 entries/],
    ["allowlist set but mode unset", withoutKey(base, "STAGING_SMS_OTP_MODE"), /is set but STAGING_SMS_OTP_MODE is not "allowlist"/],
    ["SMS_PROVIDER missing", withoutKey(base, "SMS_PROVIDER"), /SMS_PROVIDER must be exactly "msg91"/],
    ["SMS_PROVIDER none", smsGuardEnv({ SMS_PROVIDER: "none" }), /SMS_PROVIDER must be exactly "msg91"/],
    ["SMS_PROVIDER MSG91 (case)", smsGuardEnv({ SMS_PROVIDER: "MSG91" }), /SMS_PROVIDER must be exactly "msg91"/],
    ["SMS_PROVIDER twilio", smsGuardEnv({ SMS_PROVIDER: "twilio" }), /SMS_PROVIDER must be exactly "msg91"/],
    ["SMS_PROVIDER aws_sns", smsGuardEnv({ SMS_PROVIDER: "aws_sns" }), /SMS_PROVIDER must be exactly "msg91"/],
    ["MSG91_AUTH_KEY missing", withoutKey(base, "MSG91_AUTH_KEY"), /MSG91_AUTH_KEY must be set/],
    ["MSG91_TEMPLATE_ID missing", withoutKey(base, "MSG91_TEMPLATE_ID"), /MSG91_TEMPLATE_ID must be set/],
    ["MSG91_SENDER_ID blank", smsGuardEnv({ MSG91_SENDER_ID: " " }), /MSG91_SENDER_ID must be set/],
    ["TWILIO_* set", smsGuardEnv({ TWILIO_ACCOUNT_SID: `AC${rnd(4)}` }), /TWILIO_\* variables must be unset/],
    ["ALLOW_FIXED_OTP=true", smsGuardEnv({ ALLOW_FIXED_OTP: "true" }), /ALLOW_FIXED_OTP must be unset or false/],
    ["SUREPASS_TOKEN set", smsGuardEnv({ SUREPASS_TOKEN: rnd(6) }), /SUREPASS_TOKEN must be unset/],
  ];
  for (const [label, env, pattern] of bad) {
    const v = assertStagingSafety(env);
    expect(v.some((m) => pattern.test(m)), `${label}: expected ${pattern}, got ${JSON.stringify(v)}`);
    const text = v.join("\n");
    expect(ALL_SENTINELS.every((x) => !text.includes(x)), `${label}: a phone / key / secret appears in a violation message`);
  }
  // Mode OFF keeps the original rules exactly.
  expect(assertStagingSafety({ ...safeStagingEnv(), SMS_PROVIDER: "msg91" }).some((m) => /SMS_PROVIDER must be unset or "none"/.test(m)), "mode off: SMS_PROVIDER=msg91 was not refused");
  expect(assertStagingSafety({ ...safeStagingEnv(), MSG91_AUTH_KEY: MSG91_KEY }).some((m) => /MSG91_\* variables must be unset/.test(m)), "mode off: MSG91_* was not refused");
  expect(assertStagingSafety(withoutKey(safeStagingEnv(), "STAGING_TEST_LOGINS")).some((m) => /STAGING_TEST_LOGINS is not set/.test(m)), "mode off: missing tester logins was not refused");
  expect(assertStagingSafety(safeStagingEnv()).length === 0, "the original tester-login configuration changed");
  // Production / development: the new variables are inert.
  expect(assertStagingSafety({ NODE_ENV: "production", ...smsVars() }).length === 0, "production is affected by the staging SMS variables");
  expect(assertStagingSafety({ NODE_ENV: "development", ...smsVars() }).length === 0, "development is affected by the staging SMS variables");
});

await test("S2", "helpers: the allowlist matches canonical phones only in allowlist mode; tester logins are switched off in SMS mode", async () => {
  const on = { ...smsVars(), STAGING_TEST_LOGINS: loginsValue() }; // deliberately ambiguous: runtime must still ignore fixed OTPs
  expect(guards.getStagingSmsMode(on) === "allowlist", "mode not detected");
  for (const bad of ["open", "Allowlist", " allowlist", "", undefined]) expect(guards.getStagingSmsMode({ STAGING_SMS_OTP_MODE: bad }) === null, `mode '${bad}' counted as on`);
  for (const phone of [PHONE_L1, `+91${PHONE_L1}`, `+91 ${PHONE_L1}`, `91${PHONE_L1}`, `${PHONE_L2}`]) expect(guards.isStagingSmsPhoneAllowed(phone, on) === true, "an allowlisted phone form was rejected");
  for (const phone of [PHONE_U1, PHONE_L3, "not-a-phone", "", undefined, null, 123, "60000000"]) expect(guards.isStagingSmsPhoneAllowed(phone, on) === false, `'${phone}' was allowed`);
  expect(guards.isStagingSmsPhoneAllowed(PHONE_L1, { ...on, STAGING_SMS_OTP_MODE: undefined }) === false, "allowlist honoured while the mode is off");
  expect(guards.getStagingTestLogins(on).size === 0 && guards.stagingTestOtpFor(PHONE_L1, on) === null, "tester logins stayed active in SMS mode");
  expect(guards.isStagingPermittedPhone(PHONE_L1, on) && !guards.isStagingPermittedPhone(PHONE_U1, on) && !guards.isStagingPermittedPhone(PHONE_L3, on), "permitted-phone logic wrong in SMS mode");
  const off = { STAGING_TEST_LOGINS: loginsValue() };
  expect(guards.isStagingPermittedPhone(PHONE_L3, off) === true && guards.isStagingSmsPhoneAllowed(PHONE_L3, off) === false, "tester-login mode changed");
});

await test("S3", "generateOtp: allowed phone → a real random 6-digit OTP (never the fixed one); every other phone → the unusable token; fixed OTP never used; production/development unchanged", async () => {
  const gen = (env, arg) => withEnv(env, () => otpService.generateOtp(arg));
  const seen = new Set();
  for (let i = 0; i < 40; i += 1) {
    const v = await gen({ ...SMS_RUNTIME, ALLOW_FIXED_OTP: "true" }, { phone: i % 2 ? PHONE_L1 : `+91${PHONE_L2}` });
    expect(/^\d{6}$/.test(v) && v !== "123456", "an allowed phone did not get a random 6-digit OTP");
    seen.add(v);
  }
  expect(seen.size > 25, "OTPs are not random");
  for (const arg of [undefined, {}, { phone: PHONE_U1 }, { phone: PHONE_L3 }, { phone: "not-a-phone" }]) {
    const v = await gen({ ...SMS_RUNTIME, ALLOW_FIXED_OTP: "true" }, arg);
    expect(!/^\d{4,6}$/.test(v) && v !== "123456", "an unlisted phone got a guessable code");
  }
  // Even if tester logins were also (wrongly) present, SMS mode never hands out a fixed tester OTP.
  const withLogins = { ...SMS_RUNTIME, STAGING_TEST_LOGINS: loginsValue() };
  expect(!/^\d{6}$/.test(await gen(withLogins, { phone: PHONE_L3 })), "a tester login still produced a fixed OTP in SMS mode");
  expect(/^\d{6}$/.test(await gen({ NODE_ENV: "production", ALLOW_FIXED_OTP: undefined, ...smsVars() }, { phone: PHONE_U1 })), "production OTP changed");
  expect((await gen({ NODE_ENV: "development", ALLOW_FIXED_OTP: "true", ...smsVars() }, { phone: PHONE_U1 })) === "123456", "development fixed OTP changed");
  expect((await gen({ NODE_ENV: "staging", STAGING_TEST_LOGINS: loginsValue() }, { phone: PHONE_L2 })) === SECRETS.get(PHONE_L2), "tester-login mode changed");
});

await test("S4", "allowed phone: ONE MSG91 call with a normal random OTP; that OTP verifies; wrong OTPs fail; no OTP in the response; 30 s resend lock and 10-attempt lock still hold", async () => {
  await withEnv(SMS_RUNTIME, () => withFetch(okSms, async (calls) => {
    const redis = makeFakeRedis();
    const r = await sendVia(redis, PHONE_L1);
    expect(r.success === true && !("otp" in r), "send failed or echoed the otp");
    expect(calls.length === 1, `expected exactly 1 provider call, got ${calls.length}`);
    expect(mobileFromCall(calls[0]) === `91${PHONE_L1}`, "provider was called for a different number");
    const otp = otpFromCall(calls[0]);
    expect(/^\d{6}$/.test(otp) && otp !== "123456", "the SMS carried a non-random OTP");
    expect(storedHash(redis, PHONE_L1) === sha256(otp), "stored hash is not the hash of the OTP that was sent");
    const again = await sendVia(redis, PHONE_L1);
    expect(again.success === false && again.code === "RESEND_TOO_SOON" && calls.length === 1, "the 30 s resend lock did not stop a second provider call");
    const wrong = otp === WRONG_OTP ? "654323" : WRONG_OTP;
    for (let i = 0; i < 10; i += 1) expect((await verifyVia(redis, PHONE_L1, wrong)).code === "INVALID_OTP", `wrong attempt ${i + 1}`);
    expect((await verifyVia(redis, PHONE_L1, otp)).code === "TOO_MANY_ATTEMPTS", "attempt limit (10) no longer locks");
    const redis2 = makeFakeRedis();
    await sendVia(redis2, PHONE_L2);
    const otp2 = otpFromCall(calls[1]);
    expect((await verifyVia(redis2, PHONE_L2, otp2)).ok === true, "the SMS OTP did not verify");
    expect((await verifyVia(redis2, PHONE_L2, otp2)).ok === false, "an OTP verified twice");
  }));
});

await test("S5", "unlisted / invalid / missing phone: NO provider call at all (fetch never invoked), same success-shaped response, can never verify even against a matching hash", async () => {
  await withEnv(SMS_RUNTIME, () => withFetch(okSms, async (calls) => {
    const redisA = makeFakeRedis(); const redisU = makeFakeRedis();
    const allowed = await sendVia(redisA, PHONE_L1);
    const before = calls.length;
    for (const phone of [PHONE_U1, PHONE_L3, "5000000000", "12345"]) {
      const r = await sendVia(makeFakeRedis(), phone);
      expect(r.success === true && !("otp" in r), `${phone}: not success-shaped`);
      expect(JSON.stringify(Object.keys(r).sort()) === JSON.stringify(Object.keys(allowed).sort()), `${phone}: response shape reveals the allowlist`);
    }
    expect(calls.length === before, "an unlisted phone reached the SMS provider");
    // The veto: even a stored hash that matches a code does not let an unlisted phone through.
    redisU.store.set(keyFor("USER", "LOGIN", PHONE_U1, "hash"), { value: JSON.stringify({ hash: sha256("654321"), purpose: "LOGIN" }), exp: null });
    expect((await verifyVia(redisU, PHONE_U1, "654321")).ok === false, "an unlisted phone verified against a matching hash");
    const redisA2 = makeFakeRedis();
    redisA2.store.set(keyFor("USER", "LOGIN", PHONE_L1, "hash"), { value: JSON.stringify({ hash: sha256("654321"), purpose: "LOGIN" }), exp: null });
    expect((await verifyVia(redisA2, PHONE_L1, "654321")).ok === true, "an allowed phone could not verify");
  }));
});

await test("S6", "provider failures for an ALLOWED phone: HTTP error and network error → SMS_SEND_FAILED, counted by the breaker; unlisted phones never reach or trip it; recovery resets it", async () => {
  await withEnv(SMS_RUNTIME, async () => {
    const stateOf = () => providers.getMsg91CircuitBreakerState().failureCount;
    const base = stateOf();
    await quiet(() => withFetch(failSms, async (calls) => {
      const r = await sendVia(makeFakeRedis(), PHONE_L1);
      expect(r.success === false && r.code === "SMS_SEND_FAILED" && calls.length === 1, "an HTTP error was not reported as SMS_SEND_FAILED");
    }));
    await quiet(() => withFetch(throwSms, async (calls) => {
      const r = await sendVia(makeFakeRedis(), PHONE_L2);
      expect(r.success === false && r.code === "SMS_SEND_FAILED" && calls.length === 1, "a network error was not reported as SMS_SEND_FAILED");
    }));
    expect(stateOf() === base + 2, "real failures were not counted by the circuit breaker");
    await withFetch(okSms, async (calls) => {
      for (let i = 0; i < 12; i += 1) await sendVia(makeFakeRedis(), i % 2 ? PHONE_U1 : PHONE_L3);
      expect(calls.length === 0 && stateOf() === base + 2, "unlisted sends reached the provider or moved the breaker");
      const ok = await sendVia(makeFakeRedis(), PHONE_L1);
      expect(ok.success === true && calls.length === 1 && stateOf() === 0, "a successful send did not reset the breaker");
    });
  });
});

await test("S7", "logging privacy: staging never logs the phone, OTP or MSG91 key (success and failure paths); development logs exactly what it did before", async () => {
  const out = await capture(async () => {
    await withEnv(SMS_RUNTIME, async () => {
      await withFetch(throwSms, async () => { await sendVia(makeFakeRedis(), PHONE_L1); });
      await withFetch(failSms, async () => { await sendVia(makeFakeRedis(), PHONE_L2); });
      await withFetch(okSms, async () => { await sendVia(makeFakeRedis(), PHONE_L1); await sendVia(makeFakeRedis(), PHONE_U1); });
    });
  }, logger);
  expect(out.includes("MSG91 send failed"), "the failure was not logged at all (test is vacuous)");
  for (const secret of [PHONE_L1, PHONE_L2, PHONE_U1, MSG91_KEY]) expect(!out.includes(secret), "staging logged a phone number or the MSG91 key");
  expect(out.includes("******0011") || out.includes("******0012"), "staging did not log the masked phone");
  // Regression: outside staging the phone is logged raw, as before.
  const dev = await capture(async () => {
    await withEnv({ NODE_ENV: "development", SMS_PROVIDER: "msg91", MSG91_AUTH_KEY: MSG91_KEY, MSG91_TEMPLATE_ID: "t", MSG91_SENDER_ID: "s" }, () =>
      withFetch(throwSms, () => otpService.dispatchOtpSms({ phone: PHONE_L1, otp: "654321", purpose: OTP_PURPOSE.LOGIN })));
  }, logger);
  expect(dev.includes(PHONE_L1) && !dev.includes(MSG91_KEY), "development logging changed");
});

await test("S8", "no-show OTP call site (booking controller UNCHANGED): same two entry points, so an unapproved number gets no SMS; an approved number gets the generated OTP", async () => {
  const source = fs.readFileSync(path.join(BACKEND_DIR, "controllers/booking.controller.js"), "utf8");
  expect(/const otp\s*=\s*generateOtp\(\{ phone: booking\.userRef\.phone \}\)/.test(source), "the no-show OTP is no longer generated through generateOtp({ phone })");
  expect(/await dispatchOtpSms\(\{\s*phone: booking\.userRef\.phone,/.test(source), "the no-show OTP is no longer sent through dispatchOtpSms");
  expect(!/Msg91Provider|resolveProvider|SMS_PROVIDER|fetch\(/.test(source), "the booking controller talks to an SMS provider directly");
  await withEnv(SMS_RUNTIME, () => withFetch(okSms, async (calls) => {
    for (const phone of [PHONE_U1, PHONE_L3, "not-a-phone", undefined]) {
      const otp = otpService.generateOtp({ phone });
      const r = await otpService.dispatchOtpSms({ phone, otp, purpose: OTP_PURPOSE.BOOKING_NOSHOW });
      expect(!/^\d{6}$/.test(otp), "an unapproved number got a numeric OTP");
      expect(r.success === true && r.provider === "none", "an unapproved number did not get the staging no-op result");
    }
    expect(calls.length === 0, "the no-show path sent an SMS to an unapproved number");
    const phone = `+91${PHONE_L1}`;
    const otp = otpService.generateOtp({ phone });
    const r = await otpService.dispatchOtpSms({ phone: PHONE_L1, otp, purpose: OTP_PURPOSE.BOOKING_NOSHOW });
    expect(r.success === true && r.provider === "msg91" && calls.length === 1 && otpFromCall(calls[0]) === otp, "an approved number did not get exactly one SMS carrying the generated OTP");
  }));
});

await test("S8b", "REGRESSION: an allowlisted number in +91 form reaches MSG91 as the normalized 10-digit number, and the full phone never appears in staging error logs", async () => {
  const forms = [`+91${PHONE_L1}`, `+91 ${PHONE_L1}`, `91${PHONE_L1}`, PHONE_L1];
  await withEnv(SMS_RUNTIME, async () => {
    // Success path: every accepted form sends exactly once, to the normalized number (E.164 "91…" without "+").
    await withFetch(okSms, async (calls) => {
      for (const phone of forms) {
        const before = calls.length;
        const r = await otpService.dispatchOtpSms({ phone, otp: "654321", purpose: OTP_PURPOSE.BOOKING_NOSHOW });
        expect(r.success === true && r.provider === "msg91", `'${phone}': the allowlisted number was not sent`);
        expect(calls.length === before + 1 && mobileFromCall(calls[before]) === `91${PHONE_L1}`, `'${phone}': the provider did not receive the normalized number`);
      }
      // The protection is intact: the same prefixed forms of an UNLISTED number still never reach the provider.
      const before = calls.length;
      for (const phone of [`+91${PHONE_U1}`, `+91 ${PHONE_U1}`, `91${PHONE_U1}`]) {
        const r = await otpService.dispatchOtpSms({ phone, otp: "654321", purpose: OTP_PURPOSE.BOOKING_NOSHOW });
        expect(r.success === true && r.provider === "none", `'${phone}': unlisted prefixed number did not get the staging no-op`);
      }
      expect(calls.length === before, "an unlisted number in +91 form reached the provider");
    });
    // Failure paths: the number may be sent but MSG91 errors — nothing in the logs may carry the full phone, the OTP or the key.
    const out = await capture(async () => {
      await withFetch(failSms, async () => { await otpService.dispatchOtpSms({ phone: `+91${PHONE_L1}`, otp: "654321", purpose: OTP_PURPOSE.BOOKING_NOSHOW }); });
      await withFetch(throwSms, async () => { await otpService.dispatchOtpSms({ phone: `+91 ${PHONE_L1}`, otp: "654321", purpose: OTP_PURPOSE.BOOKING_NOSHOW }); });
    }, logger);
    expect(out.includes("MSG91 send failed"), "the failure was not logged (test is vacuous)");
    expect(!out.includes(PHONE_L1) && !out.includes("654321") && !out.includes(MSG91_KEY), "a full phone number, the OTP or the key reached the staging log");
    expect(out.includes("******0011"), "the masked phone was not logged");
    // Leave the breaker closed for the tests that follow.
    await withFetch(okSms, () => otpService.dispatchOtpSms({ phone: PHONE_L1, otp: "654321", purpose: OTP_PURPOSE.BOOKING_NOSHOW }));
  });
});

await test("S9", "provider resolver: staging without the mode never reaches a real provider; unsupported provider fails closed; audit rows carry no OTP", async () => {
  // Boot guard would refuse these; this proves the second layer.
  await withEnv({ NODE_ENV: "staging", STAGING_SMS_OTP_MODE: undefined, SMS_PROVIDER: "msg91", MSG91_AUTH_KEY: MSG91_KEY, MSG91_TEMPLATE_ID: "t", MSG91_SENDER_ID: "s", STAGING_TEST_LOGINS: loginsValue() }, () =>
    withFetch(okSms, async (calls) => {
      const r = await otpService.dispatchOtpSms({ phone: PHONE_L1, otp: "x", purpose: OTP_PURPOSE.LOGIN });
      expect(r.success === true && r.provider === "none" && calls.length === 0, "staging without the mode reached MSG91");
    }));
  for (const name of ["twilio", "aws_sns", "unknown_x", undefined]) {
    await quiet(() => withEnv({ ...SMS_RUNTIME, SMS_PROVIDER: name }, () => withFetch(okSms, async (calls) => {
      const r = await otpService.dispatchOtpSms({ phone: PHONE_L1, otp: "x", purpose: OTP_PURPOSE.LOGIN });
      expect(r.success === false && calls.length === 0, `provider '${name}' in allowlist mode did not fail closed`);
    })));
  }
  const rows = JSON.stringify(auditRows);
  expect(!rows.includes(MSG91_KEY), "an audit row contains the MSG91 key");
});

await test("S10", "PRODUCTION and DEVELOPMENT regression: the raw provider is returned (no recipient gate); any phone is texted exactly as before, even with staging SMS variables present", async () => {
  for (const nodeEnv of ["production", "development"]) {
    await quiet(() => withEnv({ NODE_ENV: nodeEnv, SMS_PROVIDER: "msg91", MSG91_AUTH_KEY: MSG91_KEY, MSG91_TEMPLATE_ID: "t", MSG91_SENDER_ID: "s", STAGING_SMS_OTP_MODE: "allowlist", STAGING_SMS_ALLOWED_PHONES: PHONE_L1 }, () =>
      withFetch(okSms, async (calls) => {
        const provider = providers.resolveProvider();
        expect(provider.inner && provider.inner.name === "msg91", `${nodeEnv}: the provider is wrapped or not the circuit breaker`);
        const r = await otpService.dispatchOtpSms({ phone: PHONE_U1, otp: "654321", purpose: OTP_PURPOSE.LOGIN });
        expect(r.success === true && r.provider === "msg91" && calls.length === 1 && mobileFromCall(calls[0]) === `91${PHONE_U1}`, `${nodeEnv}: a phone outside the (inert) staging list was not texted`);
      })));
  }
  await withEnv({ NODE_ENV: "production", SMS_PROVIDER: undefined }, async () => {
    expect(providers.resolveProvider().name === "none", "production default provider changed");
  });
  expect(providers.resolveProvider !== undefined && typeof providers.getMsg91CircuitBreakerState === "function", "provider exports changed");
});

// ─── M — staging SMS OTP, STANDARD mode (derived: SMS_PROVIDER=msg91, no tester logins / SMS mode / allowlist) ─────
section("M  staging SMS OTP standard mode (real controllers + OTP service + MSG91 provider code; fetch STUBBED — no network, no real SMS)");

const FA_ROLE = (await import("../modules/fieldAgent/constants/fieldAgent.constants.js")).FIELD_AGENT_OTP_ROLE;
const { sendFieldAgentOtp } = await import("../modules/fieldAgent/controllers/fieldAgentAuth.controller.js");
const { sendFieldAgentOperationalOtp } = await import("../modules/fieldAgent/controllers/fieldAgentOperationalAuth.controller.js");
const { sendOwnerVerificationOtp } = await import("../modules/fieldAgent/services/assistedOnboarding.service.js");

const STD_MSG91 = { SMS_PROVIDER: "msg91", MSG91_AUTH_KEY: MSG91_KEY, MSG91_TEMPLATE_ID: `tpl${rnd(3)}`, MSG91_SENDER_ID: "ZEMSH1" };
// Complete standard-mode staging config for the boot guard: NO tester logins, NO SMS mode, NO allowlist.
const stdGuardEnv = (over = {}) => { const e = { ...safeStagingEnv(), ...STD_MSG91 }; delete e.STAGING_TEST_LOGINS; return { ...e, ...over }; };
const STD_RUNTIME = {
  NODE_ENV: "staging", STAGING_TEST_LOGINS: undefined, STAGING_SMS_OTP_MODE: undefined, STAGING_SMS_ALLOWED_PHONES: undefined,
  ALLOW_FIXED_OTP: undefined, PUSH_PROVIDER: undefined, ...STD_MSG91,
};
const STD_PHONES = [PHONE_U1, PHONE_L3, "9876543210", "7000000001"]; // none listed anywhere; standard mode must not care
const makeResSet = () => { const r = makeRes(); r.set = (k, v) => { r.headers[k] = v; return r; }; r.nextError = null; return r; };
const nextRec = (res) => (err) => { res.nextError = err; };
const sentOtps = []; // every OTP the stubbed provider was ever handed — used by the privacy sweeps

await test("M1", "boot guard: standard mode (msg91, no tester logins / SMS mode / allowlist) is accepted; every partial, mixed or unsupported variant is refused; all other staging rules still apply", async () => {
  expect(assertStagingSafety(stdGuardEnv()).length === 0, `a complete standard config was refused: ${assertStagingSafety(stdGuardEnv()).join(" | ")}`);
  expect(assertStagingSafety(stdGuardEnv({ ALLOW_FIXED_OTP: "false" })).length === 0, "ALLOW_FIXED_OTP=false should be accepted");
  expect(assertStagingSafety(stdGuardEnv({ STAGING_SMS_OTP_MODE: "  " })).length === 0, "a blank SMS mode should count as unset");
  const base = stdGuardEnv();
  const bad = [
    ["ALLOW_FIXED_OTP=true", stdGuardEnv({ ALLOW_FIXED_OTP: "true" }), /ALLOW_FIXED_OTP must be unset or false/],
    ["MSG91_AUTH_KEY missing", withoutKey(base, "MSG91_AUTH_KEY"), /MSG91_AUTH_KEY must be set/],
    ["MSG91_TEMPLATE_ID missing", withoutKey(base, "MSG91_TEMPLATE_ID"), /MSG91_TEMPLATE_ID must be set/],
    ["MSG91_SENDER_ID blank", stdGuardEnv({ MSG91_SENDER_ID: " " }), /MSG91_SENDER_ID must be set/],
    ["SMS_PROVIDER unset, no tester logins", withoutKey(base, "SMS_PROVIDER"), /STAGING_TEST_LOGINS is not set/],
    ["SMS_PROVIDER none, no tester logins", stdGuardEnv({ SMS_PROVIDER: "none" }), /STAGING_TEST_LOGINS is not set/],
    ["SMS_PROVIDER MSG91 (case)", stdGuardEnv({ SMS_PROVIDER: "MSG91" }), /STAGING_TEST_LOGINS is not set/],
    ["SMS_PROVIDER ' msg91' (whitespace)", stdGuardEnv({ SMS_PROVIDER: " msg91" }), /STAGING_TEST_LOGINS is not set/],
    ["SMS_PROVIDER twilio", stdGuardEnv({ SMS_PROVIDER: "twilio" }), /SMS_PROVIDER must be unset or "none"/],
    ["SMS_PROVIDER aws_sns", stdGuardEnv({ SMS_PROVIDER: "aws_sns" }), /SMS_PROVIDER must be unset or "none"/],
    ["msg91 together with tester logins (mixed)", stdGuardEnv({ STAGING_TEST_LOGINS: loginsValue() }), /SMS_PROVIDER must be unset or "none"/],
    ["unsupported SMS mode 'open' + msg91", stdGuardEnv({ STAGING_SMS_OTP_MODE: "open" }), /unset or exactly "allowlist"/],
    ["SMS mode 'Allowlist' (case) + msg91", stdGuardEnv({ STAGING_SMS_OTP_MODE: "Allowlist" }), /unset or exactly "allowlist"/],
    ["SMS mode 'standard' + msg91", stdGuardEnv({ STAGING_SMS_OTP_MODE: "standard" }), /unset or exactly "allowlist"/],
    ["allowlist phones without the mode + msg91", stdGuardEnv({ STAGING_SMS_ALLOWED_PHONES: PHONE_L1 }), /is set but STAGING_SMS_OTP_MODE is not "allowlist"/],
    ["TWILIO_* set", stdGuardEnv({ TWILIO_ACCOUNT_SID: `AC${rnd(4)}` }), /TWILIO_\* variables must be unset/],
    ["SUREPASS_TOKEN set", stdGuardEnv({ SUREPASS_TOKEN: rnd(6) }), /SUREPASS_TOKEN must be unset/],
    ["PUSH_PROVIDER fcm", stdGuardEnv({ PUSH_PROVIDER: "fcm" }), /PUSH_PROVIDER must be unset, "none" or exactly "expo"/],
    ["live Razorpay key", stdGuardEnv({ RAZORPAY_KEY_ID: "rzp_live_x" }), /LIVE key/],
    ["REDIS_URL missing", withoutKey(base, "REDIS_URL"), /REDIS_URL is not set/],
    ["Mongo deny-list missing", withoutKey(base, "STAGING_FORBIDDEN_MONGO_ENDPOINTS"), /STAGING_FORBIDDEN_MONGO_ENDPOINTS must be set/],
    ["Redis deny-list missing", withoutKey(base, "STAGING_FORBIDDEN_REDIS_ENDPOINTS"), /STAGING_FORBIDDEN_REDIS_ENDPOINTS must be set/],
    ["database not allowed on staging", stdGuardEnv({ MONGODB_URI: withUserinfo("mongodb+srv", "cluster0.invalid/some_other_db?retryWrites=true") }), /database is not allowed on staging/],
    ["OTP_SECRET missing", withoutKey(base, "OTP_SECRET"), /OTP_SECRET must be set/],
  ];
  for (const [label, env, pattern] of bad) {
    const v = assertStagingSafety(env);
    expect(v.some((m) => pattern.test(m)), `${label}: expected ${pattern}, got ${JSON.stringify(v)}`);
    const text = v.join("\n");
    expect(ALL_SENTINELS.every((x) => !text.includes(x)), `${label}: a phone / key / secret appears in a violation message`);
  }
  // The other two modes keep exactly their previous verdicts.
  expect(assertStagingSafety(safeStagingEnv()).length === 0, "the tester-login configuration changed");
  expect(assertStagingSafety(smsGuardEnv()).length === 0, "the allowlist configuration changed");
  expect(assertStagingSafety(withoutKey(safeStagingEnv(), "STAGING_TEST_LOGINS")).some((m) => /STAGING_TEST_LOGINS is not set/.test(m)), "no SMS provider and no tester logins is no longer refused");
  // Production / development: inert (never read), and the production tester-login refusal is unchanged.
  for (const nodeEnv of ["production", "development", "test"]) expect(assertStagingSafety({ NODE_ENV: nodeEnv, ...STD_MSG91 }).length === 0, `${nodeEnv} is affected by the standard-mode rules`);
  expect(assertStagingSafety({ NODE_ENV: "production", STAGING_TEST_LOGINS: loginsValue() }).some((m) => /must not be set when NODE_ENV=production/.test(m)), "production tester-login refusal changed");
});

await test("M2", "helpers: standard mode is exactly NODE_ENV=staging + SMS_PROVIDER=msg91 with nothing restricting it; any phone is then permitted; other modes and other environments are unaffected", async () => {
  const on = { NODE_ENV: "staging", ...STD_MSG91 };
  expect(guards.isStagingStandardSmsMode(on) === true, "standard mode not detected");
  expect(guards.isStagingStandardSmsMode({ ...on, STAGING_SMS_OTP_MODE: "  ", STAGING_TEST_LOGINS: "", STAGING_SMS_ALLOWED_PHONES: " " }) === true, "blank restricting settings should count as unset");
  const off = [
    ["production", { ...on, NODE_ENV: "production" }], ["development", { ...on, NODE_ENV: "development" }], ["test", { ...on, NODE_ENV: "test" }],
    ["NODE_ENV unset", withoutKey(on, "NODE_ENV")], ["'Staging'", { ...on, NODE_ENV: "Staging" }],
    ["provider unset", withoutKey(on, "SMS_PROVIDER")], ["provider none", { ...on, SMS_PROVIDER: "none" }], ["provider MSG91", { ...on, SMS_PROVIDER: "MSG91" }],
    ["provider ' msg91'", { ...on, SMS_PROVIDER: " msg91" }], ["provider twilio", { ...on, SMS_PROVIDER: "twilio" }],
    ["tester logins set", { ...on, STAGING_TEST_LOGINS: loginsValue() }],
    ["allowlist mode", { ...on, STAGING_SMS_OTP_MODE: "allowlist", STAGING_SMS_ALLOWED_PHONES: PHONE_L1 }],
    ["allowlist phones without the mode", { ...on, STAGING_SMS_ALLOWED_PHONES: PHONE_L1 }],
    ["mode 'open'", { ...on, STAGING_SMS_OTP_MODE: "open" }], ["mode 'standard'", { ...on, STAGING_SMS_OTP_MODE: "standard" }],
  ];
  for (const [label, env] of off) expect(guards.isStagingStandardSmsMode(env) === false, `${label}: counted as standard mode`);
  for (const phone of [...STD_PHONES, `+91${PHONE_U1}`, "not-a-phone", "", undefined, null]) expect(guards.isStagingPermittedPhone(phone, on) === true, `'${phone}' not permitted in standard mode`);
  expect(guards.getStagingSmsMode(on) === null && guards.getStagingTestLogins(on).size === 0 && guards.isStagingSmsPhoneAllowed(PHONE_U1, on) === false, "standard mode leaked into the allowlist / tester helpers");
  // Other modes: permission is still per phone.
  const tester = { NODE_ENV: "staging", STAGING_TEST_LOGINS: loginsValue() };
  expect(guards.isStagingPermittedPhone(PHONE_L1, tester) === true && guards.isStagingPermittedPhone(PHONE_U1, tester) === false, "tester-login permission changed");
  const allow = { NODE_ENV: "staging", ...smsVars() };
  expect(guards.isStagingPermittedPhone(PHONE_L1, allow) === true && guards.isStagingPermittedPhone(PHONE_U1, allow) === false, "allowlist permission changed");
});

await test("M3", "generateOtp: every phone gets a real random 6-digit OTP in standard mode (never the fixed one, even with ALLOW_FIXED_OTP=true); look-alike configs still get the unusable token; production/development unchanged", async () => {
  const gen = (env, arg) => withEnv(env, () => otpService.generateOtp(arg));
  const seen = new Set();
  for (let i = 0; i < 60; i += 1) {
    const phone = [...STD_PHONES, `+91${PHONE_U1}`, undefined, {}, "x"][i % 8];
    const v = await gen({ ...STD_RUNTIME, ALLOW_FIXED_OTP: "true" }, phone === undefined ? undefined : { phone });
    expect(/^\d{6}$/.test(v) && v !== "123456", "standard mode did not give a random 6-digit OTP");
    seen.add(v);
  }
  expect(seen.size > 40, "OTPs are not random");
  for (const [label, env] of [
    ["mode 'open'", { ...STD_RUNTIME, STAGING_SMS_OTP_MODE: "open" }],
    ["tester logins present", { ...STD_RUNTIME, STAGING_TEST_LOGINS: loginsValue() }],
    ["phones set without the mode", { ...STD_RUNTIME, STAGING_SMS_ALLOWED_PHONES: PHONE_L1 }],
    ["provider not exactly msg91", { ...STD_RUNTIME, SMS_PROVIDER: "MSG91" }],
  ]) {
    const v = await gen(env, { phone: PHONE_U1 });
    expect(!/^\d{4,6}$/.test(v), `${label}: an unrestricted OTP was issued outside standard mode`);
  }
  expect(/^\d{6}$/.test(await gen({ NODE_ENV: "production", ALLOW_FIXED_OTP: undefined, ...STD_MSG91 }, { phone: PHONE_U1 })), "production OTP changed");
  expect((await gen({ NODE_ENV: "development", ALLOW_FIXED_OTP: "true", ...STD_MSG91 }, { phone: PHONE_U1 })) === "123456", "development fixed OTP changed");
  expect((await gen({ NODE_ENV: "staging", STAGING_TEST_LOGINS: loginsValue(), SMS_PROVIDER: undefined }, { phone: PHONE_L2 })) === SECRETS.get(PHONE_L2), "tester-login mode changed");
});

await test("M4", "any phone: ONE MSG91 call with a random OTP, nothing echoed, that OTP verifies once; 30 s resend lock holds; wrong-OTP policy is the staging 10 / 7200 s one", async () => {
  await withEnv(STD_RUNTIME, () => withFetch(okSms, async (calls) => {
    for (const phone of STD_PHONES) {
      const redis = makeFakeRedis();
      const before = calls.length;
      const r = await sendVia(redis, phone);
      expect(r.success === true && r.provider === "msg91" && !("otp" in r), `${phone}: send failed, not routed to msg91, or echoed the otp`);
      expect(calls.length === before + 1 && mobileFromCall(calls[before]) === `91${phone}`, `${phone}: not exactly one MSG91 call to that number`);
      const otp = otpFromCall(calls[before]); sentOtps.push(otp);
      expect(/^\d{6}$/.test(otp) && otp !== "123456", `${phone}: the SMS carried a non-random OTP`);
      expect(storedHash(redis, phone) === sha256(otp), `${phone}: stored hash is not the hash of the OTP that was sent`);
      const again = await sendVia(redis, phone);
      expect(again.success === false && again.code === "RESEND_TOO_SOON" && calls.length === before + 1, `${phone}: the 30 s resend lock did not stop a second provider call`);
      const wrong = otp === WRONG_OTP ? "654323" : WRONG_OTP;
      expect((await verifyVia(redis, phone, wrong)).code === "INVALID_OTP", `${phone}: a wrong OTP was accepted`);
      expect((await verifyVia(redis, phone, otp)).ok === true, `${phone}: the SMS OTP did not verify`);
      expect((await verifyVia(redis, phone, otp)).ok === false, `${phone}: an OTP verified twice`);
    }
    // Attempt policy handed to the Lua script: staging's 10 failures / 7200 s, unchanged — and the 10th still locks.
    const redis = makeFakeRedis();
    await sendVia(redis, PHONE_U1);
    const otp = otpFromCall(calls[calls.length - 1]); sentOtps.push(otp);
    const wrong = otp === WRONG_OTP ? "654323" : WRONG_OTP;
    for (let i = 0; i < 10; i += 1) expect((await verifyVia(redis, PHONE_U1, wrong)).code === "INVALID_OTP", `wrong attempt ${i + 1}`);
    expect((await verifyVia(redis, PHONE_U1, otp)).code === "TOO_MANY_ATTEMPTS", "the attempt limit no longer locks after 10");
    const args = redis.evalCalls[0].args;
    expect(args[1] === "10" && args[2] === "7200", `verify policy changed (limit ${args[1]}, window ${args[2]})`);
    const ttl = await redis.ttl(keyFor("USER", "LOGIN", PHONE_U1, "attempts"));
    expect(ttl > 7000 && ttl <= 7200, "the attempt window is not 7200 s");
  }));
});

await test("M5", "provider failures for any phone: HTTP error and network error → SMS_SEND_FAILED, counted by the circuit breaker; a success resets it", async () => {
  await withEnv(STD_RUNTIME, async () => {
    const stateOf = () => providers.getMsg91CircuitBreakerState().failureCount;
    const base = stateOf();
    await quiet(() => withFetch(failSms, async (calls) => {
      const r = await sendVia(makeFakeRedis(), PHONE_U1);
      expect(r.success === false && r.code === "SMS_SEND_FAILED" && calls.length === 1, "an HTTP error was not reported as SMS_SEND_FAILED");
    }));
    await quiet(() => withFetch(throwSms, async (calls) => {
      const r = await sendVia(makeFakeRedis(), PHONE_L3);
      expect(r.success === false && r.code === "SMS_SEND_FAILED" && calls.length === 1, "a network error was not reported as SMS_SEND_FAILED");
    }));
    expect(stateOf() === base + 2, "real failures were not counted by the circuit breaker");
    await withFetch(okSms, async (calls) => {
      const ok = await sendVia(makeFakeRedis(), "9876543210");
      expect(ok.success === true && calls.length === 1 && stateOf() === 0, "a successful send did not reset the breaker");
      sentOtps.push(otpFromCall(calls[0]));
    });
  });
});

await test("M6", "role-specific paths via the REAL controllers (user, owner, field-agent apply, field-agent login) and the assisted-onboarding service: unrestricted phone → one MSG91 call, no OTP in the response, resend lock, wrong OTP 401, right OTP passes", async () => {
  const flows = [
    { label: "user", purpose: OTP_PURPOSE.LOGIN, role: "USER", send: (q, s) => authController.sendUserOtp(q, s), verify: (q, s) => authController.verifyUserOtp(q, s), session: true },
    { label: "owner", purpose: OTP_PURPOSE.SALON_LOGIN, role: "OWNER", send: (q, s) => authController.sendOtp(q, s), verify: (q, s) => authController.verifyOtp(q, s), session: true },
    { label: "field-agent apply", purpose: OTP_PURPOSE.FIELD_AGENT_APPLY, role: FA_ROLE, send: (q, s) => sendFieldAgentOtp(q, s, nextRec(s)), verify: (q, s) => verifyFieldAgentOtp(q, s, nextRec(s)), session: false },
    { label: "field-agent login", purpose: OTP_PURPOSE.FIELD_AGENT_LOGIN, role: FA_ROLE, send: (q, s) => sendFieldAgentOperationalOtp(q, s, nextRec(s)), verify: (q, s) => verifyFieldAgentOperationalOtp(q, s, nextRec(s)), session: false },
  ];
  await withEnv(STD_RUNTIME, () => withFetch(okSms, async (calls) => {
    for (const f of flows) {
      const phone = PHONE_U1; // never listed anywhere
      const redis = makeFakeRedis();
      const before = calls.length;
      resetCounters();
      const sent = makeResSet();
      await f.send(makeReq({ phone }, redis), sent);
      expect(sent.statusCode === 200 && sent.body?.success === true && sent.nextError === null, `${f.label}: send did not succeed (${sent.statusCode})`);
      expect(!("otp" in (sent.body || {})), `${f.label}: the OTP was returned in the response`);
      expect(calls.length === before + 1 && mobileFromCall(calls[before]) === `91${phone}`, `${f.label}: not exactly one MSG91 call to the requested number`);
      const otp = otpFromCall(calls[before]); sentOtps.push(otp);
      expect(/^\d{6}$/.test(otp) && otp !== "123456", `${f.label}: non-random OTP`);
      expect(redis.store.has(keyFor(f.role, f.purpose, phone, "hash")), `${f.label}: hash not stored under role ${f.role} / purpose ${f.purpose}`);
      const second = makeResSet();
      await f.send(makeReq({ phone }, redis), second);
      expect(calls.length === before + 1 && !(second.statusCode === 200 && second.body?.success === true), `${f.label}: a rapid second send reached the provider or succeeded`);
      expect(second.statusCode === 429 || second.nextError, `${f.label}: the resend lock produced no 429 / error`);
      const wrongOtp = otp === WRONG_OTP ? "654323" : WRONG_OTP;
      const bad = makeResSet();
      await f.verify(makeReq({ phone, otp: wrongOtp }, redis), bad);
      expect(bad.statusCode === 401 && (bad.body?.error?.code ?? bad.body?.code) === "INVALID_OTP", `${f.label}: a wrong OTP was not a 401 INVALID_OTP`);
      expect(noMutation(), `${f.label}: a wrong OTP reached a user/session step`);
      const good = makeResSet();
      await f.verify(makeReq({ phone, otp }, redis), good);
      const pastOtp = !(good.statusCode === 401 || good.statusCode === 429);
      expect(pastOtp, `${f.label}: the correct SMS OTP was rejected (${good.statusCode})`);
      if (f.session) {
        expect(good.statusCode === 200 && typeof good.body?.accessToken === "string" && good.cookies.length === 1, `${f.label}: login did not complete`);
        expect(counters.userFindOne === 1 && counters.refreshCreate === 1, `${f.label}: session path not taken exactly once`);
      }
    }
    // Assisted onboarding (a Field Agent verifies an OWNER's phone): the real service functions.
    const redis = makeFakeRedis();
    const before = calls.length;
    const r = await sendOwnerVerificationOtp({ phone: PHONE_U1, req: makeReq({}, redis), redis });
    expect(r.phone === PHONE_U1 && r.devOtp === null, "assisted onboarding returned an OTP to the caller");
    expect(calls.length === before + 1 && mobileFromCall(calls[before]) === `91${PHONE_U1}`, "assisted onboarding: not exactly one MSG91 call");
    const otp = otpFromCall(calls[before]); sentOtps.push(otp);
    expect(redis.store.has(keyFor("OWNER", OTP_PURPOSE.ASSISTED_ONBOARDING_OWNER_VERIFY, PHONE_U1, "hash")), "assisted onboarding: hash not stored under its own purpose");
    let resend = null;
    try { await sendOwnerVerificationOtp({ phone: PHONE_U1, req: makeReq({}, redis), redis }); } catch (e) { resend = e; }
    expect(resend && resend.retryAfterSeconds > 0 && calls.length === before + 1, "assisted onboarding: the resend lock did not hold");
    // startAssistedOnboarding reads the agent's profile before it verifies the OTP: stub that one read (restored below).
    const { default: FieldAgentModel } = await import("../modules/fieldAgent/models/FieldAgent.js");
    const { FIELD_AGENT_OPERATIONAL_STATUS, COMMERCIAL_PATH } = await import("../modules/fieldAgent/constants/fieldAgent.constants.js");
    const agentUserId = new mongoose.Types.ObjectId();
    const realFindOne = FieldAgentModel.findOne;
    FieldAgentModel.findOne = () => ({ lean: async () => ({ _id: new mongoose.Types.ObjectId(), userRef: agentUserId, operationalStatus: FIELD_AGENT_OPERATIONAL_STATUS.ACTIVE, commercialPath: COMMERCIAL_PATH.ACQUISITION_AGENT }) });
    try {
    const start = (code) => startAssistedOnboarding({ fieldAgentUserId: agentUserId.toString(), phone: PHONE_U1, otp: code, createNewBranch: false, req: makeReq({}, redis), redis });
    let wrongErr = null;
    try { await start(otp === WRONG_OTP ? "654323" : WRONG_OTP); } catch (e) { wrongErr = e; }
    expect(wrongErr && wrongErr.otpCode === "INVALID_OTP", "assisted onboarding: a wrong OTP was not rejected as INVALID_OTP");
    let rightErr = null;
    try { await quiet(() => start(otp)); } catch (e) { rightErr = e; }
    expect(!(rightErr && rightErr.otpCode), "assisted onboarding: the correct SMS OTP was rejected");
    } finally { FieldAgentModel.findOne = realFindOne; }
  }));
});

await test("M7", "no-show OTP (booking controller UNCHANGED): any customer phone gets exactly one SMS carrying the generated OTP; same provider as login", async () => {
  await withEnv(STD_RUNTIME, () => withFetch(okSms, async (calls) => {
    for (const phone of [PHONE_U1, PHONE_L3, "9876543210"]) { // callers hand the provider bare 10-digit phones, exactly as in production
      const otp = otpService.generateOtp({ phone });
      const before = calls.length;
      const r = await otpService.dispatchOtpSms({ phone, otp, purpose: OTP_PURPOSE.BOOKING_NOSHOW });
      expect(/^\d{6}$/.test(otp), "the no-show OTP is not a random 6-digit code");
      expect(r.success === true && r.provider === "msg91" && calls.length === before + 1 && otpFromCall(calls[before]) === otp, `${phone}: not exactly one SMS carrying the generated OTP`);
      sentOtps.push(otp);
    }
  }));
});

await test("M8", "privacy: standard mode never returns or logs an OTP, a full phone number or the MSG91 key (success, HTTP failure, network failure); audit rows carry none of them", async () => {
  const auditStart = auditRows.length;
  const out = await capture(async () => {
    await withEnv({ ...STD_RUNTIME, ALLOW_FIXED_OTP: "true" }, async () => { // even with the legacy flag on, nothing is echoed
      const bodies = [];
      await withFetch(okSms, async (calls) => {
        for (const phone of STD_PHONES) { const r = await sendVia(makeFakeRedis(), phone); bodies.push(JSON.stringify(r)); }
        for (const c of calls) sentOtps.push(otpFromCall(c));
      });
      await withFetch(failSms, async () => { await sendVia(makeFakeRedis(), PHONE_U1); });
      await withFetch(throwSms, async () => { await sendVia(makeFakeRedis(), PHONE_L3); });
      await withFetch(okSms, async (calls) => { await sendVia(makeFakeRedis(), "9876543210"); sentOtps.push(otpFromCall(calls[0])); }); // close the breaker again
      const joined = bodies.join("\n");
      for (const o of sentOtps) expect(!joined.includes(`"otp":"${o}"`) && !/"otp"\s*:/.test(joined), "an OTP appears in a send result");
    });
  }, logger);
  expect(out.includes("MSG91 send failed"), "the failures were not logged at all (test is vacuous)");
  expect(out.includes("******0099") && out.includes("******0013"), "staging did not log the masked phone");
  for (const secret of [...STD_PHONES, MSG91_KEY, ...sentOtps]) expect(!out.includes(secret), "a phone number, OTP or the MSG91 key reached the staging log");
  const rows = JSON.stringify(auditRows.slice(auditStart));
  for (const secret of [MSG91_KEY, ...sentOtps]) expect(!rows.includes(secret), "an audit row contains an OTP or the key");
  expect(auditRows.slice(auditStart).some((row) => row.provider === "msg91" && row.status === "SENT"), "audit rows were not written for standard-mode sends");
});

await test("M9", "provider resolver: standard mode returns the SAME MSG91 circuit breaker production uses (no recipient gate); look-alike configurations never reach MSG91", async () => {
  const productionProvider = await withEnv({ NODE_ENV: "production", ...STD_MSG91 }, () => providers.resolveProvider());
  const standard = await withEnv(STD_RUNTIME, () => providers.resolveProvider());
  expect(standard === productionProvider && standard.inner && standard.inner.name === "msg91", "standard mode is not the plain production MSG91 provider");
  const lookAlikes = [
    ["mode 'open'", { STAGING_SMS_OTP_MODE: "open", STAGING_TEST_LOGINS: undefined }],
    ["mode 'standard'", { STAGING_SMS_OTP_MODE: "standard", STAGING_TEST_LOGINS: undefined }],
    ["tester logins present", { STAGING_TEST_LOGINS: loginsValue() }],
    ["allowlist phones without the mode", { STAGING_SMS_ALLOWED_PHONES: PHONE_L1 }],
    ["provider MSG91 (case)", { SMS_PROVIDER: "MSG91" }],
    ["provider ' msg91'", { SMS_PROVIDER: " msg91" }],
  ];
  for (const [label, over] of lookAlikes) {
    await withEnv({ ...STD_RUNTIME, ...over }, () => withFetch(okSms, async (calls) => {
      const r = await otpService.dispatchOtpSms({ phone: PHONE_U1, otp: "x", purpose: OTP_PURPOSE.LOGIN });
      expect(r.provider === "none" && calls.length === 0, `${label}: reached a real provider`);
    }));
  }
  // The other two modes keep their own resolution.
  await withEnv({ ...SMS_RUNTIME }, () => withFetch(okSms, async (calls) => {
    await otpService.dispatchOtpSms({ phone: PHONE_U1, otp: "x", purpose: OTP_PURPOSE.LOGIN });
    expect(calls.length === 0, "allowlist mode now texts an unlisted phone");
    const ok = await otpService.dispatchOtpSms({ phone: PHONE_L1, otp: "654321", purpose: OTP_PURPOSE.LOGIN });
    expect(ok.provider === "msg91" && calls.length === 1, "allowlist mode no longer texts a listed phone");
  }));
  await withEnv({ NODE_ENV: "staging", STAGING_TEST_LOGINS: loginsValue(), SMS_PROVIDER: undefined, STAGING_SMS_OTP_MODE: undefined, STAGING_SMS_ALLOWED_PHONES: undefined }, () => withFetch(okSms, async (calls) => {
    const r = await otpService.dispatchOtpSms({ phone: PHONE_L1, otp: "x", purpose: OTP_PURPOSE.LOGIN });
    expect(r.provider === "none" && calls.length === 0, "tester-login mode now sends SMS");
  }));
});

await test("M10", "PRODUCTION and DEVELOPMENT non-regression with msg91 configured: same provider, any phone texted, original attempt policy, OTP echo rules and verify behaviour untouched", async () => {
  for (const nodeEnv of ["production", "development"]) {
    await quiet(() => withEnv({ NODE_ENV: nodeEnv, ALLOW_FIXED_OTP: undefined, STAGING_TEST_LOGINS: undefined, STAGING_SMS_OTP_MODE: undefined, STAGING_SMS_ALLOWED_PHONES: undefined, ...STD_MSG91 }, () =>
      withFetch(okSms, async (calls) => {
        expect(guards.isStagingStandardSmsMode() === false && guards.isStagingEnv() === false, `${nodeEnv}: treated as staging`);
        const redis = makeFakeRedis();
        const r = await sendVia(redis, PHONE_U1);
        expect(r.success === true && r.provider === "msg91" && calls.length === 1 && mobileFromCall(calls[0]) === `91${PHONE_U1}`, `${nodeEnv}: send changed`);
        const otp = otpFromCall(calls[0]);
        expect(/^\d{6}$/.test(otp) && otp !== "123456" && !("otp" in r), `${nodeEnv}: OTP generation / echo changed`);
        expect((await verifyVia(redis, PHONE_U1, WRONG_OTP === otp ? "654323" : WRONG_OTP)).code === "INVALID_OTP", `${nodeEnv}: wrong OTP result changed`);
        expect(redis.evalCalls[0].args[1] === "5" && redis.evalCalls[0].args[2] === "300", `${nodeEnv}: the original 5 / 300 s attempt policy changed`);
        expect((await verifyVia(redis, PHONE_U1, otp)).ok === true, `${nodeEnv}: a correct OTP no longer verifies`);
      })));
  }
  // Development with the legacy flag still echoes the fixed OTP exactly as before; staging standard mode never does.
  const devRes = await quiet(() => withEnv({ NODE_ENV: "development", ALLOW_FIXED_OTP: "true", SMS_PROVIDER: undefined, STAGING_TEST_LOGINS: undefined }, () => sendVia(makeFakeRedis(), PHONE_U1)));
  expect(devRes.otp === "123456", "development fixed-OTP echo changed");
  const stdRes = await withEnv({ ...STD_RUNTIME, ALLOW_FIXED_OTP: "true" }, () => withFetch(okSms, () => sendVia(makeFakeRedis(), PHONE_U1)));
  expect(!("otp" in stdRes), "staging standard mode echoed an OTP");
  // The routes (rate limiters), models and controllers are not part of this change.
  const routes = fs.readFileSync(path.join(BACKEND_DIR, "routes/auth.routes.js"), "utf8");
  for (const needle of ['"/partner/send-otp", partnerOtpLimiter', '"/partner/verify-otp", partnerVerifyLimiter', '"/user/send-otp", userOtpLimiter', '"/user/verify-otp", userVerifyLimiter']) {
    expect(routes.includes(needle), `route rate limiter missing: ${needle}`);
  }
});

// ─── P — staging push: the Expo provider is allowed; nothing else about push or any other rule is relaxed ─────────
section("P  staging Expo push (boot guard rule R7; real PushProvider run in a child process with the Expo SDK send stubbed — no network)");

await test("P1", "boot guard: PUSH_PROVIDER exactly 'expo' is accepted in all three OTP modes; unset / 'none' still accepted", async () => {
  const configs = [
    ["tester-login mode", safeStagingEnv()],
    ["allowlist mode", smsGuardEnv()],
    ["standard MSG91 mode", stdGuardEnv()],
  ];
  for (const [label, env] of configs) {
    expect(assertStagingSafety(env).length === 0, `${label}: the baseline config is not clean`);
    for (const value of ["expo", "none", " none", "NONE", undefined, ""]) {
      const v = assertStagingSafety({ ...env, PUSH_PROVIDER: value });
      expect(v.length === 0, `${label}: PUSH_PROVIDER=${JSON.stringify(value)} was refused: ${v.join(" | ")}`);
    }
  }
});

await test("P2", "boot guard: every other PUSH_PROVIDER value is still refused with exactly one violation that names the variable only; Firebase and the Expo access token stay refused with expo", async () => {
  for (const value of ["fcm", "Expo", "EXPO", " expo", "expo ", "expo,fcm", "firebase", "apns", "true", "1"]) {
    const v = assertStagingSafety({ ...safeStagingEnv(), PUSH_PROVIDER: value });
    expect(v.length === 1 && /^PUSH_PROVIDER must be unset, "none" or exactly "expo"/.test(v[0]), `PUSH_PROVIDER=${JSON.stringify(value)}: expected one PUSH_PROVIDER violation, got ${JSON.stringify(v)}`);
    expect(!v[0].includes(String(value).trim()) || ["expo", "none", "true", "1"].includes(String(value).trim()) , "the violation message echoes the configured value");
  }
  for (const [name, value] of [["EXPO_ACCESS_TOKEN", "synthetic"], ["FIREBASE_PROJECT_ID", "synthetic"], ["FIREBASE_CLIENT_EMAIL", "synthetic"], ["FIREBASE_PRIVATE_KEY", "synthetic"]]) {
    const v = assertStagingSafety({ ...safeStagingEnv(), PUSH_PROVIDER: "expo", [name]: value });
    expect(v.length === 1 && v[0].includes(name), `${name} with PUSH_PROVIDER=expo: expected exactly its own violation, got ${JSON.stringify(v)}`);
  }
});

await test("P3", "'expo' relaxes NOTHING else: every existing rejection case (Cashfree PRODUCTION, live Razorpay, DB / Redis rules, secrets, CORS ...) gives the identical result with PUSH_PROVIDER=expo added; deny-list matches and missing deny-lists are still refused", async () => {
  let compared = 0;
  for (const [label, env] of G2_CASES) {
    if ("PUSH_PROVIDER" in env) continue;
    const without = assertStagingSafety(env);
    const withExpo = assertStagingSafety({ ...env, PUSH_PROVIDER: "expo" });
    expect(JSON.stringify(without) === JSON.stringify(withExpo), `${label}: adding PUSH_PROVIDER=expo changed the verdict`);
    compared += 1;
  }
  expect(compared >= 40, `too few cases compared (${compared})`);
  const mt = await import("../utils/mongoTarget.js");
  const base = { ...safeStagingEnv(), PUSH_PROVIDER: "expo" };
  const mongoFp = mt.mongoFingerprints(mt.parseMongoTarget(base.MONGODB_URI).hosts).join(",");
  const redisFp = mt.redisFingerprint(mt.parseRedisTarget(base.REDIS_URL).host);
  const has = (env, fragment) => assertStagingSafety(env).some((m) => m.includes(fragment));
  expect(has({ ...base, STAGING_FORBIDDEN_MONGO_ENDPOINTS: mongoFp }, "MONGODB_URI points at an endpoint listed in STAGING_FORBIDDEN_MONGO_ENDPOINTS"), "a Mongo deny-list match was not refused with expo");
  expect(has({ ...base, STAGING_FORBIDDEN_REDIS_ENDPOINTS: redisFp }, "REDIS_URL points at an endpoint listed in STAGING_FORBIDDEN_REDIS_ENDPOINTS"), "a Redis deny-list match was not refused with expo");
  expect(has(withoutKey(base, "STAGING_FORBIDDEN_MONGO_ENDPOINTS"), "STAGING_FORBIDDEN_MONGO_ENDPOINTS must be set"), "a missing Mongo deny-list was accepted with expo");
  expect(has(withoutKey(base, "STAGING_FORBIDDEN_REDIS_ENDPOINTS"), "STAGING_FORBIDDEN_REDIS_ENDPOINTS must be set"), "a missing Redis deny-list was accepted with expo");
  expect(has({ ...base, CASHFREE_ENV: "PRODUCTION" }, "CASHFREE_ENV must not be PRODUCTION on staging"), "Cashfree PRODUCTION was accepted with expo");
  expect(!assertStagingSafety({ ...base, CASHFREE_ENV: "SANDBOX" }).length, "a sandbox Cashfree config was refused with expo");
});

await test("P4", "production / development / test are untouched: the staging rule never runs there; the push provider source has no staging branch of its own", async () => {
  for (const nodeEnv of ["production", "development", "test", undefined]) {
    for (const value of ["expo", "fcm", "none", undefined]) {
      const env = { ...(nodeEnv ? { NODE_ENV: nodeEnv } : {}), ...(value ? { PUSH_PROVIDER: value } : {}) };
      expect(assertStagingSafety(env).length === 0, `${nodeEnv}/${value}: the staging push rule fired outside staging`);
    }
  }
  const src = fs.readFileSync(path.join(BACKEND_DIR, "modules/notifications/providers/PushProvider.js"), "utf8");
  expect(!/stagingGuards|isStagingEnv|staging/i.test(src), "PushProvider.js has a staging-specific branch");
});

await test("P5", "runtime: the REAL PushProvider under NODE_ENV=staging + PUSH_PROVIDER=expo hands exactly one message to the Expo SDK for the stored token, identically to production (SDK send stubbed; nothing leaves the machine)", async () => {
  const run = (nodeEnv) => {
    const script = `
      const { Expo } = await import("expo-server-sdk");
      const sent = [];
      Expo.prototype.sendPushNotificationsAsync = async (chunk) => { sent.push(...chunk); return chunk.map(() => ({ status: "ok", id: "synthetic-ticket" })); };
      const { default: DeviceToken } = await import(${JSON.stringify(pathToFileURL(path.join(BACKEND_DIR, "modules/notifications/models/DeviceToken.js")).href)});
      DeviceToken.find = () => ({ lean: async () => [{ token: "ExponentPushToken[abcdefghijklmnopqrstuv]" }] });
      const { default: PushProvider } = await import(${JSON.stringify(pathToFileURL(path.join(BACKEND_DIR, "modules/notifications/providers/PushProvider.js")).href)});
      const r = await PushProvider.send({ recipientType: "USER", recipientId: "000000000000000000000001", title: "synthetic title", message: "synthetic body" });
      console.log("RESULT:" + JSON.stringify({ success: r.success, provider: r.provider, error: r.error, sent: sent.map((m) => ({ to: m.to, title: m.title, body: m.body })) }));
      process.exit(0);`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      cwd: BACKEND_DIR, encoding: "utf8", timeout: 30_000,
      env: { PATH: process.env.PATH, NODE_ENV: nodeEnv, PUSH_PROVIDER: "expo", SKIP_REDIS_AUTOCONNECT: "true" },
    });
    const line = `${r.stdout}`.split("\n").find((l) => l.startsWith("RESULT:"));
    expect(r.status === 0 && line, `${nodeEnv}: the child run failed (exit ${r.status})`);
    return JSON.parse(line.slice("RESULT:".length));
  };
  const staging = run("staging");
  expect(staging.success === true && staging.provider === "expo" && staging.error === null, `staging: push result was ${JSON.stringify(staging)}`);
  expect(staging.sent.length === 1 && staging.sent[0].to === "ExponentPushToken[abcdefghijklmnopqrstuv]" && staging.sent[0].title === "synthetic title", "staging: not exactly one Expo message for the stored token");
  expect(JSON.stringify(staging) === JSON.stringify(run("production")), "staging and production push behaviour differ");
});

await new Promise((resolve) => io.close(() => resolve()));
await new Promise((resolve) => server.close(() => resolve()));

// ─── R — optional real Lua ──────────────────────────────────────────────────
let luaTotals = { pass: 0, fail: 0, skipped: false };
if (RUN_REAL_LUA) luaTotals = await runRealLuaParent();

// ─── Summary ────────────────────────────────────────────────────────────────
const passed = results.filter((r) => r.ok).length + luaTotals.pass;
const failed = results.filter((r) => !r.ok).length + luaTotals.fail;
console.log(`\n${failed === 0 ? "✅" : "❌"} ${passed} passed, ${failed} failed${RUN_REAL_LUA ? (luaTotals.skipped ? " (real-Lua section skipped)" : " (includes real-Lua section)") : " (real-Lua section not requested)"}`);
process.exit(failed === 0 ? 0 : 1);
