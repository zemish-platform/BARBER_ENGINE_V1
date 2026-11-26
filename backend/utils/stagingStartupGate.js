/**
 * BARBER_ENGINE_V1
 * backend/utils/stagingStartupGate.js
 *
 * STAGING-ONLY startup verification, in two layers (server.js runs both only when NODE_ENV === "staging"):
 *
 *   1. runStagingPreflight — BEFORE mongoose.connect() is ever called. A raw driver client connects to
 *      the configured target, issues exactly ONE command (the read-only `connectionStatus` with
 *      showPrivileges) and is closed. WHY: Mongoose registers every model at import and, the moment
 *      its connection opens, runs createCollection + createIndexes for all of them (autoIndex/autoCreate,
 *      config/db.js). Measured on a throwaway mongod: with a realistic round trip (>= 50 ms) dozens of
 *      collection creates were already sent before a post-connect check could answer — so a post-connect
 *      check alone cannot stop writes by credentials it is about to reject. Verifying first means a
 *      refused boot writes NOTHING to the database.
 *   2. runStagingStartupGate — the post-connect gate below, kept as defense in depth. server.js awaits
 *      it after the Socket.IO setup and BEFORE the first background job and before httpServer.listen(),
 *      so a failed check terminates the process while no job has started and nothing accepts requests.
 *
 * It verifies the LIVE connection rather than the URI string:
 *   1. the connection is open and Mongoose's connected database name equals the database the
 *      driver parsed from MONGODB_URI, and that name satisfies the staging database policy;
 *   2. the connection is authenticated;
 *   3. `connectionStatus` (a read-only command available to any authenticated user) reports the
 *      effective roles and privileges, and EVERY privilege is scoped to that one database:
 *        - no administrative / cluster-wide / any-database roles (root, atlasAdmin,
 *          readWriteAnyDatabase, dbAdmin, dbOwner, userAdmin, cluster* ...),
 *        - no `cluster` or `anyResource` resources, no resource on any other database,
 *        - no user/role-management, dropDatabase, shutdown, anyAction ... actions,
 *        - and at least one privilege on the allowed database.
 *   Any failure — including the privilege command erroring — refuses to start (fail closed).
 *
 * Output never contains hosts, fingerprints or connection strings; only rule descriptions and
 * database / role names. Residual (documented in stagingGuards.js): once the pre-flight has PASSED,
 * Mongoose's autoIndex/autoCreate still builds collections and indexes in the allowed database —
 * by then the credentials are proven scoped to it. A REFUSED boot writes nothing at all.
 */

import { evaluateStagingDatabasePolicy } from "./stagingGuards.js";
import { parseMongoTarget } from "./mongoTarget.js";

// Roles that are administrative or wider than a single application database.
const BANNED_ROLES = new Set([
  "root", "atlasAdmin", "__system",
  "readWriteAnyDatabase", "readAnyDatabase", "dbAdminAnyDatabase", "userAdminAnyDatabase",
  "clusterAdmin", "clusterManager", "clusterMonitor", "hostManager", "backup", "restore",
  "dbOwner", "dbAdmin", "userAdmin", "enableSharding",
]);

// Privilege actions that are administrative even when scoped to one database.
const BANNED_ACTIONS = new Set([
  "anyAction", "internal", "shutdown", "dropDatabase", "enableSharding",
  "createUser", "dropUser", "updateUser", "createRole", "dropRole", "updateRole",
  "grantRole", "revokeRole", "changeAnyPassword", "changeCustomData", "viewUser", "viewRole",
  "setParameter", "replSetConfigure", "fsync", "killop", "inprog", "authSchemaUpgrade",
]);

/**
 * evaluateConnectionStatus({ status, expectedDb }) -> string[]   (problems; empty = scoped)
 * `status` is the raw reply of { connectionStatus: 1, showPrivileges: true }.
 */
export const evaluateConnectionStatus = ({ status, expectedDb }) => {
  const problems = new Set();
  const info = status && status.authInfo;
  const users = (info && info.authenticatedUsers) || [];
  const roles = (info && info.authenticatedUserRoles) || [];
  const privileges = (info && info.authenticatedUserPrivileges) || [];

  if (!Array.isArray(users) || users.length === 0) {
    problems.add("the MongoDB connection is not authenticated, so its privileges cannot be verified");
  }
  for (const r of Array.isArray(roles) ? roles : []) {
    if (r && BANNED_ROLES.has(r.role)) {
      problems.add(`the MongoDB user holds role "${r.role}", which is administrative or wider than the staging database`);
    }
  }

  let scopedToExpected = false;
  for (const p of Array.isArray(privileges) ? privileges : []) {
    const resource = (p && p.resource) || {};
    if (resource.cluster === true) {
      problems.add("the MongoDB user has a cluster-wide privilege");
    } else if (resource.anyResource === true) {
      problems.add("the MongoDB user has an any-resource privilege");
    } else if (resource.db === "") {
      problems.add("the MongoDB user has a privilege on every database");
    } else if (resource.db !== expectedDb) {
      problems.add(`the MongoDB user has a privilege on another database ("${String(resource.db)}")`);
    } else {
      scopedToExpected = true;
    }
    for (const action of (p && p.actions) || []) {
      if (BANNED_ACTIONS.has(action)) {
        problems.add(`the MongoDB user can perform administrative action "${action}"`);
      }
    }
  }
  if (!scopedToExpected) {
    problems.add("the MongoDB user has no privilege on the staging database");
  }
  return [...problems];
};

// Bounds the raw pre-flight connection attempt (server selection); a timeout is a refusal.
export const PREFLIGHT_SERVER_SELECTION_TIMEOUT_MS = 15_000;

/**
 * runStagingPreflight({ env, MongoClient, exit, log }) -> Promise<{ ok: boolean, expectedDb?: string }>
 *
 * Called by server.js BEFORE connectDB() on staging. Uses `MongoClient` (the driver class, injected so it
 * can be replaced in tests; server.js passes mongoose.mongo.MongoClient) and issues ONLY
 * { connectionStatus: 1, showPrivileges: true } — read-only. Steps, each failing closed:
 *   URI parses unambiguously (driver semantics) → database satisfies the staging policy → connect →
 *   the client's default database equals the validated name (exactly what Mongoose will use) →
 *   connectionStatus → every effective privilege is scoped to that one database.
 * The raw client is closed on EVERY path (success, refusal, thrown error) BEFORE exit is called, because
 * process.exit() would skip any later cleanup. Output never contains the URI, hosts, fingerprints or the
 * driver's error text.
 */
export const runStagingPreflight = async ({
  env = process.env,
  MongoClient,
  exit = process.exit,
  log = console,
} = {}) => {
  const fail = (problems) => {
    log.error(
      "❌ Refusing to start — staging database pre-flight failed (nothing was written to the database):\n" +
        problems.map((p) => `   - ${p}`).join("\n")
    );
    exit(1);
    return { ok: false };
  };

  const target = parseMongoTarget(env.MONGODB_URI);
  if (!target.ok) return fail(["MONGODB_URI is not a valid, unambiguous MongoDB URI"]);
  const expectedDb = target.dbName;
  const policyViolation = evaluateStagingDatabasePolicy(expectedDb, env);
  if (policyViolation) return fail([policyViolation]);

  let client = null;
  let problems = null;
  try {
    client = new MongoClient(env.MONGODB_URI, { serverSelectionTimeoutMS: PREFLIGHT_SERVER_SELECTION_TIMEOUT_MS });
    await client.connect();
    const database = client.db(); // the default database — the same one Mongoose's connection will use
    if (database.databaseName !== expectedDb) {
      problems = ["the database the driver selects does not match the database named in MONGODB_URI"];
    } else {
      const status = await database.admin().command({ connectionStatus: 1, showPrivileges: true });
      const found = evaluateConnectionStatus({ status, expectedDb });
      if (found.length > 0) problems = found;
    }
  } catch {
    problems = ["the MongoDB target could not be reached or its privileges could not be verified (connection or connectionStatus failed)"];
  } finally {
    if (client) {
      try {
        await client.close();
      } catch {
        /* a failing close never changes the verdict */
      }
    }
  }

  if (problems) return fail(problems);
  log.log(`✅ Staging pre-flight passed — database "${expectedDb}" reachable, credentials scoped to it (checked before Mongoose connects)`);
  return { ok: true, expectedDb };
};

/**
 * runStagingStartupGate(dbConnected, { mongoose, env, exit, log }) -> Promise<{ ok: boolean }>
 * `dbConnected` is the promise returned by connectDB() (it never rejects: connectDB exits on failure).
 * On failure it logs the problems, calls exit(1) and resolves { ok: false } (so a non-exiting test
 * double cannot be mistaken for success; server.js also exits itself if ok is false).
 */
export const runStagingStartupGate = async (
  dbConnected,
  { mongoose, env = process.env, exit = process.exit, log = console } = {}
) => {
  const fail = (problems) => {
    log.error(
      "❌ Refusing to start — staging database safety gate failed:\n" + problems.map((p) => `   - ${p}`).join("\n")
    );
    exit(1);
    return { ok: false };
  };

  try {
    await dbConnected;
  } catch {
    return fail(["the MongoDB connection could not be established"]);
  }

  const target = parseMongoTarget(env.MONGODB_URI);
  if (!target.ok) return fail(["MONGODB_URI is not a valid, unambiguous MongoDB URI"]);
  const expectedDb = target.dbName;
  const policyViolation = evaluateStagingDatabasePolicy(expectedDb, env);
  if (policyViolation) return fail([policyViolation]);

  const connection = mongoose && mongoose.connection;
  if (!connection || connection.readyState !== 1) return fail(["the MongoDB connection is not open"]);
  if (connection.name !== expectedDb) {
    return fail(["the connected MongoDB database does not match the database named in MONGODB_URI"]);
  }

  let status;
  try {
    status = await connection.db.admin().command({ connectionStatus: 1, showPrivileges: true });
  } catch {
    return fail(["the MongoDB user's privileges could not be verified (connectionStatus failed)"]);
  }

  const problems = evaluateConnectionStatus({ status, expectedDb });
  if (problems.length > 0) return fail(problems);

  log.log(`✅ Staging startup gate passed — database "${expectedDb}" verified, credentials scoped to it`);
  return { ok: true };
};
