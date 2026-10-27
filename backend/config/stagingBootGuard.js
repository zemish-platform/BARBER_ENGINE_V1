/**
 * BARBER_ENGINE_V1
 * backend/config/stagingBootGuard.js
 *
 * Import-time boot guard. server.js imports this module immediately after
 * "dotenv/config" and BEFORE app.js, so ES-module evaluation order guarantees
 * that an unsafe staging configuration terminates the process before the app,
 * Redis (config/redis.js connects eagerly) or Mongo are touched.
 *
 * Messages list rules and variable NAMES only, never values. On production and
 * local development this is a no-op unless a staging-only variable leaked in.
 */

import { assertStagingSafety } from "../utils/stagingGuards.js";

const violations = assertStagingSafety(process.env);

if (violations.length > 0) {
  console.error(
    "❌ Refusing to start — unsafe environment configuration:\n" +
      violations.map((v) => `   - ${v}`).join("\n")
  );
  process.exit(1);
}
