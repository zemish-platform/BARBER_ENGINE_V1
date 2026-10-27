/**
 * BARBER_ENGINE_V1
 * backend/utils/mongoTarget.js
 *
 * Offline parsing of the MongoDB / Redis targets named by MONGODB_URI / REDIS_URL, plus
 * endpoint fingerprints for the staging deny-list. Pure: no connection is ever opened,
 * nothing is logged, and no URI, host or fingerprint is ever returned inside an error message.
 *
 * ── MongoDB: the driver is the authority ─────────────────────────────────────
 *  config/db.js hands the RAW MONGODB_URI to mongoose.connect(), and Mongoose builds
 *  `new MongoClient(uri)` and uses `client.db()` (mongoose/lib/drivers/node-mongodb-native/
 *  connection.js). So the only reliable answer to "which database will this URI use?" is
 *  the driver's own parse — `new MongoClient(uri).options.dbName` — not a regular expression.
 *  Constructing a MongoClient does not connect and does not resolve DNS (mongodb+srv hosts
 *  are only resolved on connect), and `mongoose.mongo` is Mongoose's public handle on the
 *  bundled driver, so no extra dependency is needed.
 *
 *  A URI is accepted only if ALL of these hold (anything else is "ambiguous" and refused):
 *    - it is the untouched env value (no leading/trailing or embedded whitespace — the
 *      application does not trim it, so neither do we);
 *    - the driver parses it without error (this also rejects unknown options and
 *      unescaped characters);
 *    - it has no `#` fragment;
 *    - it names the database explicitly in the path (no path means the driver silently
 *      uses "test");
 *    - the driver's final dbName equals the decoded path segment (so no option or trailing
 *      character can make the driver pick a different database than the path suggests —
 *      e.g. a trailing slash yields "name/", which is never a valid allowed name).
 *
 * ── Endpoint identity and fingerprints ───────────────────────────────────────
 *  The deny-list stores one-way fingerprints (never hostnames) configured through
 *  environment variables:
 *      fingerprint = first 16 hex chars of sha256("<kind>:<endpoint identity>")
 *  Endpoint identity:
 *    - MongoDB Atlas hosts: the cluster label `<id>.mongodb.net` (last three labels), so the
 *      SRV host (`cluster0.<id>.mongodb.net`) and the shard hosts
 *      (`...-shard-00-00.<id>.mongodb.net`) of one cluster share ONE identity. ASSUMPTION
 *      (to be confirmed in the Atlas UI): that `<id>` identifies a single cluster. If it
 *      identifies a whole project the effect is only to deny more, never less.
 *    - every other host (including Redis): the lowercase hostname, without the port.
 *  Compute fingerprints with scripts/fingerprintEndpoint.js (reads the URI from stdin and
 *  prints only the fingerprint).
 */

import crypto from "node:crypto";
import mongoose from "mongoose";

const { MongoClient } = mongoose.mongo;

export const FINGERPRINT_HEX_LENGTH = 16;
export const MAX_DENY_LIST_ENTRIES = 50;

const ATLAS_SUFFIX = ".mongodb.net";

// ─── MongoDB ────────────────────────────────────────────────────────────────

/**
 * parseMongoTarget(uri) -> { ok: true, dbName, hosts, srv } | { ok: false, reason }
 * `reason` is a fixed code, never text derived from the URI.
 */
export const parseMongoTarget = (uri) => {
  if (typeof uri !== "string" || uri === "") return { ok: false, reason: "NOT_SET" };
  if (/\s/.test(uri)) return { ok: false, reason: "WHITESPACE" };
  if (!/^mongodb(?:\+srv)?:\/\//.test(uri)) return { ok: false, reason: "SCHEME" };
  if (uri.includes("#")) return { ok: false, reason: "FRAGMENT" };

  let options;
  try {
    options = new MongoClient(uri).options; // parse only — no connection, no DNS
  } catch {
    return { ok: false, reason: "UNPARSEABLE" }; // never echo the driver message (it may quote the URI)
  }

  // Explicit database path. The driver already accepted the string, so the authority (which
  // must have userinfo characters percent-encoded) ends at the first "/".
  const pathMatch = /^mongodb(?:\+srv)?:\/\/[^/?#]+\/([^/?#]*)/.exec(uri);
  if (!pathMatch || pathMatch[1] === "") return { ok: false, reason: "NO_DATABASE_PATH" };
  let pathSegment;
  try {
    pathSegment = decodeURIComponent(pathMatch[1]);
  } catch {
    return { ok: false, reason: "BAD_ENCODING" };
  }

  const dbName = options.dbName;
  if (typeof dbName !== "string" || dbName === "" || dbName !== pathSegment) {
    return { ok: false, reason: "AMBIGUOUS_DATABASE" };
  }

  const hosts = options.srvHost
    ? [String(options.srvHost)]
    : (options.hosts || []).map((h) => String(h.host ?? h.socketPath ?? "")).filter(Boolean);
  if (hosts.length === 0) return { ok: false, reason: "NO_HOST" };

  return { ok: true, dbName, hosts: hosts.map((h) => h.toLowerCase()), srv: Boolean(options.srvHost) };
};

/**
 * parseMongoHosts(uri) -> string[] | null
 * Lenient variant for scripts/fingerprintEndpoint.js: the driver's host parse only (a production
 * URI may legitimately lack an explicit database path). null if the driver rejects the string.
 */
export const parseMongoHosts = (uri) => {
  if (typeof uri !== "string" || uri === "" || /\s/.test(uri) || !/^mongodb(?:\+srv)?:\/\//.test(uri)) return null;
  try {
    const options = new MongoClient(uri).options;
    const hosts = options.srvHost
      ? [String(options.srvHost)]
      : (options.hosts || []).map((h) => String(h.host ?? h.socketPath ?? "")).filter(Boolean);
    return hosts.length > 0 ? hosts.map((h) => h.toLowerCase()) : null;
  } catch {
    return null;
  }
};

export const mongoEndpointIdentity = (host) => {
  const h = String(host).toLowerCase().replace(/:\d+$/, "");
  const labels = h.split(".");
  return h.endsWith(ATLAS_SUFFIX) && labels.length >= 3 ? labels.slice(-3).join(".") : h;
};

// ─── Redis ──────────────────────────────────────────────────────────────────

/** parseRedisTarget(url) -> { ok: true, host, tls } | { ok: false, reason } */
export const parseRedisTarget = (url) => {
  if (typeof url !== "string" || url === "") return { ok: false, reason: "NOT_SET" };
  if (/\s/.test(url)) return { ok: false, reason: "WHITESPACE" };
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: "UNPARSEABLE" };
  }
  if (parsed.protocol !== "redis:" && parsed.protocol !== "rediss:") return { ok: false, reason: "SCHEME" };
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "") return { ok: false, reason: "NO_HOST" };
  return { ok: true, host, tls: parsed.protocol === "rediss:" };
};

// ─── Fingerprints and the deny-list ────────────────────────────────────────

export const endpointFingerprint = (kind, identity) =>
  crypto.createHash("sha256").update(`${kind}:${identity}`).digest("hex").slice(0, FINGERPRINT_HEX_LENGTH);

export const mongoFingerprints = (hosts) => [
  ...new Set(hosts.map((h) => endpointFingerprint("mongo", mongoEndpointIdentity(h)))),
];

export const redisFingerprint = (host) => endpointFingerprint("redis", host);

/**
 * parseFingerprintList(raw) -> { ok: true, list: Set<string> } | { ok: false, reason }
 * Required, comma-separated, each exactly 16 lowercase hex characters, at most 50.
 */
export const parseFingerprintList = (raw) => {
  if (typeof raw !== "string" || raw.trim() === "") return { ok: false, reason: "NOT_SET" };
  const entries = raw.split(",");
  if (entries.length > MAX_DENY_LIST_ENTRIES) return { ok: false, reason: "TOO_MANY" };
  const re = new RegExp(`^[0-9a-f]{${FINGERPRINT_HEX_LENGTH}}$`);
  for (const entry of entries) {
    if (!re.test(entry)) return { ok: false, reason: "MALFORMED" };
  }
  return { ok: true, list: new Set(entries) };
};
