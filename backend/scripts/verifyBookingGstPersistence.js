/**
 * BARBER_ENGINE_V1
 * backend/scripts/verifyBookingGstPersistence.js
 *
 * HERMETIC SERIALIZATION / PERSISTENCE-CONTRACT TEST — this is NOT a real MongoDB integration test.
 *
 * What it proves (all in memory, no database, no network, no files written):
 *   - every key lockSlot hands to Booking.create() is a path declared in the Booking schema, so Mongoose
 *     strict mode cannot silently drop it (the defect this guards: platformFeeGstRatePercent and
 *     platformFeeGstAmountInPaise were passed but not declared);
 *   - the two platform-fee GST fields accept null and zero and reject negative and fractional-paise values;
 *   - a Booking document keeps both GST values and totalAmountInPaise unchanged through BSON
 *     serialize -> deserialize -> hydrate (the representation MongoDB stores and returns);
 *   - an old booking without the fields stays readable (null) and a status-only change does not write them.
 *
 * What it does NOT prove: that a document is actually written to and read back from a MongoDB server, that
 * lockSlot runs, transactions, indexes, or that the Global Platform Fee / GST policy values are configured in
 * any environment. It never calls the pricing engine and never reads or changes any fee or GST configuration;
 * it only checks that already-calculated values would be stored.
 *
 *   cd backend && node scripts/verifyBookingGstPersistence.js
 *
 * Uses only dependencies already present on develop (mongoose); adds none. Exit code 0 = all passed.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import mongoose from "mongoose";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.resolve(__dirname, "..");

// No connection is ever opened: stop Mongoose from queueing collection/index creation for the model below.
mongoose.set("bufferCommands", false);
mongoose.set("autoIndex", false);
mongoose.set("autoCreate", false);

const { default: Booking } = await import("../models/Booking.js");

// ─── Tiny harness (same shape as the other verify scripts) ──────────────────
const results = [];
const test = async (id, name, fn) => {
  try {
    await fn();
    results.push({ id, name, ok: true });
    console.log(`  ✅ ${id} ${name}`);
  } catch (error) {
    results.push({ id, name, ok: false });
    console.log(`  ❌ ${id} ${name} — ${error?.message || error}`);
  }
};
const expect = (condition, label) => {
  if (!condition) throw new Error(label);
};
const section = (title) => console.log(`\n── ${title} ──`);

const GST_FIELDS = ["platformFeeGstRatePercent", "platformFeeGstAmountInPaise"];
const oid = () => new mongoose.Types.ObjectId();

// Sample pricing outputs: service ₹20.00, platform fee ₹3.33, service GST ₹1.00, fee GST 18% of 333 = 60 paise.
// Total = 2000 + 333 + 100 + 60. These are fixed numbers for the persistence contract, not a recalculation.
const SAMPLE = Object.freeze({
  serviceAmountInPaise: 2000,
  commissionAmountInPaise: 333,
  gstRatePercent: 5,
  gstAmountInPaise: 100,
  platformFeeGstRatePercent: 18,
  platformFeeGstAmountInPaise: 60,
  totalAmountInPaise: 2493,
});

const bookingFields = (over = {}) => ({
  userRef: oid(),
  salonRef: oid(),
  chairRef: oid(),
  serviceRefs: [oid()],
  bookingDate: "2026-11-01",
  serviceDuration: 30,
  bufferTime: 0,
  lockUntil: new Date(),
  holdExpiresAt: new Date(),
  status: "HOLD",
  ...SAMPLE,
  ...over,
});

// Validate ONLY the two new paths, so unrelated required-field rules never mask what is under test.
const gstErrors = (over) => {
  const err = new Booking(bookingFields(over)).validateSync(GST_FIELDS);
  return Object.keys((err && err.errors) || {});
};

// ─── Static extraction of lockSlot's Booking.create() payload keys ──────────
const controllerSrc = fs.readFileSync(path.join(BACKEND_DIR, "controllers/booking.controller.js"), "utf8");

const extractLockSlot = (src) => {
  const start = src.indexOf("export const lockSlot = ");
  if (start === -1) throw new Error("lockSlot was not found in controllers/booking.controller.js");
  const rest = src.slice(start + 1);
  const next = rest.search(/\nexport const /);
  return next === -1 ? src.slice(start) : src.slice(start, start + 1 + next);
};

// Blank out // and /* */ comments (string-aware, newlines kept) so a mention of "Booking.create(" inside a comment
// can never be mistaken for the real call.
const stripComments = (s) => {
  let out = "";
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    const two = s.slice(i, i + 2);
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      for (; j < s.length && s[j] !== ch; j += 1) if (s[j] === "\\") j += 1;
      out += s.slice(i, j + 1);
      i = j;
    } else if (two === "//") {
      while (i < s.length && s[i] !== "\n") { out += " "; i += 1; }
      out += "\n";
    } else if (two === "/*") {
      const end = s.indexOf("*/", i + 2);
      const stop = end === -1 ? s.length : end + 2;
      out += s.slice(i, stop).replace(/[^\n]/g, " ");
      i = stop - 1;
    } else {
      out += ch;
    }
  }
  return out;
};

// Return the top-level comma-separated segments of the object literal in `await Booking.create([ { ... } ], opts)`,
// with string contents blanked. Works on comment-stripped source.
const extractCreatePayloadSegments = (codeOnlySrc) => {
  const fnSrc = codeOnlySrc;
  const callAt = fnSrc.indexOf("Booking.create(");
  if (callAt === -1) throw new Error("Booking.create( was not found in lockSlot");
  let i = fnSrc.indexOf("{", fnSrc.indexOf("[", callAt));
  if (i === -1) throw new Error("the Booking.create payload object was not found");
  const segments = [];
  let depth = 0;
  let current = "";
  for (; i < fnSrc.length; i += 1) {
    const ch = fnSrc[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      current += '""';
      for (i += 1; i < fnSrc.length && fnSrc[i] !== quote; i += 1) if (fnSrc[i] === "\\") i += 1;
      continue;
    }
    if (ch === "{" || ch === "[" || ch === "(") {
      depth += 1;
      if (depth > 1) current += ch;
      continue;
    }
    if (ch === "}" || ch === "]" || ch === ")") {
      depth -= 1;
      if (depth === 0) { if (current.trim()) segments.push(current.trim()); break; }
      current += ch;
      continue;
    }
    if (ch === "," && depth === 1) { if (current.trim()) segments.push(current.trim()); current = ""; continue; }
    current += ch;
  }
  return segments;
};

const lockSlotSrc = stripComments(extractLockSlot(controllerSrc));
const payloadSegments = extractCreatePayloadSegments(lockSlotSrc);
const payloadKeys = payloadSegments.map((seg) => {
  if (seg.startsWith("...")) throw new Error(`a spread (${seg.slice(0, 30)}) in the payload cannot be checked statically`);
  const m = /^([A-Za-z_$][\w$]*)\s*(?::|$)/.exec(seg);
  if (!m) throw new Error(`could not read a key from payload segment: ${seg.slice(0, 40)}`);
  return m[1];
});

console.log("Booking GST persistence — HERMETIC serialization / persistence-contract test (NOT a MongoDB integration test)");

// ─── 1. Payload keys vs schema ──────────────────────────────────────────────
section("1  lockSlot payload vs Booking schema (static)");

await test("P1", `the lockSlot Booking.create payload was parsed (${payloadKeys.length} keys; non-vacuous: known keys present, no duplicates)`, async () => {
  expect(payloadKeys.length >= 20, `only ${payloadKeys.length} keys parsed`);
  for (const k of ["userRef", "salonRef", "totalAmountInPaise", "commissionAmountInPaise", "gstAmountInPaise", ...GST_FIELDS, "status"]) {
    expect(payloadKeys.includes(k), `expected payload key "${k}" was not parsed`);
  }
  expect(new Set(payloadKeys).size === payloadKeys.length, "duplicate keys in the payload");
  expect((lockSlotSrc.match(/Booking\.create\(/g) || []).length === 1, "lockSlot no longer has exactly one Booking.create( call");
});

await test("P2", "EVERY key lockSlot passes to Booking.create() is a declared Booking schema path (strict mode drops nothing)", async () => {
  const undeclared = payloadKeys.filter((k) => !Booking.schema.path(k));
  expect(undeclared.length === 0, `undeclared (would be silently dropped): ${undeclared.join(", ")}`);
  expect(Booking.schema.options.strict !== false, "the Booking schema is not in strict mode — this test assumes the default");
});

await test("P3", "negative control: a schema WITHOUT the two fields does drop them (proves the check can fail)", async () => {
  const stripped = Booking.schema.clone();
  stripped.remove(GST_FIELDS);
  const Stripped = mongoose.model("BookingGstPersistenceControl", stripped);
  expect(!stripped.path("platformFeeGstAmountInPaise") && !stripped.path("platformFeeGstRatePercent"), "control schema still declares the fields");
  const o = new Stripped(bookingFields()).toObject();
  expect(o.platformFeeGstAmountInPaise === undefined && o.platformFeeGstRatePercent === undefined, "control did not drop the undeclared fields");
  expect(payloadKeys.filter((k) => !stripped.path(k)).sort().join() === GST_FIELDS.slice().sort().join(), "the undeclared-key check would not flag exactly the two GST fields on the control schema");
});

// ─── 2. Field rules ─────────────────────────────────────────────────────────
section("2  field types, defaults and validators");

await test("F1", "declared as Number with default null, same convention as gstRatePercent/gstAmountInPaise", async () => {
  for (const f of GST_FIELDS) {
    const p = Booking.schema.path(f);
    expect(p && p.instance === "Number", `${f} is not a Number path`);
    expect(p.options.default === null, `${f} default is not null`);
  }
  const fresh = new Booking({}).toObject();
  expect(fresh.platformFeeGstRatePercent === null && fresh.platformFeeGstAmountInPaise === null, "a new empty Booking does not default both fields to null");
});

await test("F2", "both fields accept null and zero (zero stays zero, not null)", async () => {
  expect(gstErrors({ platformFeeGstRatePercent: null, platformFeeGstAmountInPaise: null }).length === 0, "null was rejected");
  expect(gstErrors({ platformFeeGstRatePercent: 0, platformFeeGstAmountInPaise: 0 }).length === 0, "zero was rejected");
  const z = new Booking(bookingFields({ platformFeeGstRatePercent: 0, platformFeeGstAmountInPaise: 0 })).toObject();
  expect(z.platformFeeGstRatePercent === 0 && z.platformFeeGstAmountInPaise === 0, "zero was coerced to another value");
});

await test("F3", "negative values and fractional paise are rejected; a valid sample is accepted", async () => {
  expect(gstErrors({}).length === 0, "the valid sample was rejected");
  expect(gstErrors({ platformFeeGstRatePercent: -1 }).includes("platformFeeGstRatePercent"), "a negative rate was accepted");
  expect(gstErrors({ platformFeeGstAmountInPaise: -1 }).includes("platformFeeGstAmountInPaise"), "a negative amount was accepted");
  expect(gstErrors({ platformFeeGstAmountInPaise: 10.5 }).includes("platformFeeGstAmountInPaise"), "a fractional paise amount was accepted");
  expect(gstErrors({ platformFeeGstAmountInPaise: "abc" }).includes("platformFeeGstAmountInPaise"), "a non-numeric amount was accepted");
});

// ─── 3. Serialization contract ──────────────────────────────────────────────
section("3  BSON serialize -> deserialize -> hydrate (the form MongoDB stores and returns)");

const { BSON } = mongoose.mongo;
const roundTrip = (doc) => Booking.hydrate(BSON.deserialize(BSON.serialize(doc.toObject()))).toObject();

await test("S1", "both GST values and totalAmountInPaise are retained exactly, as numbers", async () => {
  const original = new Booking(bookingFields());
  const o = original.toObject();
  expect(o.platformFeeGstRatePercent === 18 && o.platformFeeGstAmountInPaise === 60 && o.totalAmountInPaise === 2493, "the document did not keep the values on creation");
  const back = roundTrip(original);
  expect(back.platformFeeGstRatePercent === 18, `rate after round trip: ${back.platformFeeGstRatePercent}`);
  expect(back.platformFeeGstAmountInPaise === 60, `amount after round trip: ${back.platformFeeGstAmountInPaise}`);
  expect(back.totalAmountInPaise === 2493 && back.totalAmountInPaise === o.totalAmountInPaise, "totalAmountInPaise changed");
  expect(typeof back.platformFeeGstRatePercent === "number" && typeof back.platformFeeGstAmountInPaise === "number", "a value changed type");
  expect(back.serviceAmountInPaise === 2000 && back.commissionAmountInPaise === 333 && back.gstAmountInPaise === 100, "a sibling pricing field changed");
});

await test("S2", "the stored total still equals service + fee + service GST + fee GST (persisted values are not altered)", async () => {
  const back = roundTrip(new Booking(bookingFields()));
  const sum = back.serviceAmountInPaise + back.commissionAmountInPaise + (back.gstAmountInPaise || 0) + (back.platformFeeGstAmountInPaise || 0);
  expect(sum === back.totalAmountInPaise, `components sum to ${sum}, stored total is ${back.totalAmountInPaise}`);
});

await test("S3", "zero and null survive the round trip distinctly", async () => {
  const zero = roundTrip(new Booking(bookingFields({ platformFeeGstRatePercent: 0, platformFeeGstAmountInPaise: 0 })));
  expect(zero.platformFeeGstRatePercent === 0 && zero.platformFeeGstAmountInPaise === 0, "zero did not survive");
  const nul = roundTrip(new Booking(bookingFields({ platformFeeGstRatePercent: null, platformFeeGstAmountInPaise: null })));
  expect(nul.platformFeeGstRatePercent === null && nul.platformFeeGstAmountInPaise === null, "null did not survive");
});

// ─── 4. Backward compatibility ──────────────────────────────────────────────
section("4  an old booking without the fields");

const oldStoredShape = () => {
  const raw = new Booking(bookingFields()).toObject();
  delete raw.platformFeeGstRatePercent; // shaped like a record saved before the fields were declared
  delete raw.platformFeeGstAmountInPaise;
  return raw;
};

await test("B1", "an old booking reads null/null, is unmodified, and keeps its total", async () => {
  const old = Booking.hydrate(oldStoredShape());
  expect(old.platformFeeGstRatePercent === null && old.platformFeeGstAmountInPaise === null, "an old booking did not read as null");
  expect(old.isModified() === false && old.modifiedPaths().length === 0, "merely loading an old booking marks it modified");
  expect(old.totalAmountInPaise === 2493, "the old booking's total changed");
});

await test("B2", "a status-only change on an old booking does not write the new fields", async () => {
  const old = Booking.hydrate(oldStoredShape());
  old.status = "CONFIRMED";
  expect(JSON.stringify(old.modifiedPaths()) === JSON.stringify(["status"]), `modified paths: ${JSON.stringify(old.modifiedPaths())}`);
  const delta = old.$__delta();
  const written = Object.keys((delta && delta[1] && delta[1].$set) || {});
  expect(written.length === 1 && written[0] === "status", `the update would write: ${written.join(", ")}`);
  expect(!JSON.stringify(delta).includes("platformFeeGst"), "the update mentions a platform-fee GST field");
});

// ─── Summary ────────────────────────────────────────────────────────────────
const passed = results.filter((r) => r.ok).length;
const failed = results.length - passed;
console.log(`\n${failed === 0 ? "✅" : "❌"} ${passed} passed, ${failed} failed (hermetic contract test; no MongoDB server was used)`);
process.exit(failed === 0 ? 0 : 1);
