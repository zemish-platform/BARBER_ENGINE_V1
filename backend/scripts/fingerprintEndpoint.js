/**
 * BARBER_ENGINE_V1
 * backend/scripts/fingerprintEndpoint.js
 *
 * Prints the deny-list fingerprint of a MongoDB or Redis endpoint WITHOUT revealing it. Used to
 * fill STAGING_FORBIDDEN_MONGO_ENDPOINTS / STAGING_FORBIDDEN_REDIS_ENDPOINTS on the staging service
 * from the PRODUCTION (and any other forbidden) service's connection values.
 *
 *   printf '%s' "$VALUE" | node scripts/fingerprintEndpoint.js mongo
 *   printf '%s' "$VALUE" | node scripts/fingerprintEndpoint.js redis
 *
 * The value is read from STDIN (never argv), so it does not land in shell history or the process
 * list. Only the 16-hex fingerprint is printed — never the host, URI, credentials or error text
 * derived from the value. It opens no connection and touches no file or network.
 * See utils/mongoTarget.js for how an endpoint identity is derived (Atlas hosts of one cluster
 * share one identity, so the SRV and seed-list forms give the same fingerprint).
 */

import {
  mongoFingerprints,
  parseMongoHosts,
  parseRedisTarget,
  redisFingerprint,
} from "../utils/mongoTarget.js";

const kind = process.argv[2];
if (kind !== "mongo" && kind !== "redis") {
  console.error("usage: printf '%s' \"$VALUE\" | node scripts/fingerprintEndpoint.js mongo|redis");
  process.exit(2);
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const value = Buffer.concat(chunks).toString("utf8").replace(/[\r\n]+$/, "");

let fingerprints = null;
if (kind === "mongo") {
  const hosts = parseMongoHosts(value);
  if (hosts) fingerprints = mongoFingerprints(hosts);
} else {
  const target = parseRedisTarget(value);
  if (target.ok) fingerprints = [redisFingerprint(target.host)];
}

if (!fingerprints || fingerprints.length === 0) {
  console.error("Could not read a valid endpoint from the value on stdin (nothing about it is shown).");
  process.exit(1);
}
console.log(fingerprints.join(","));
