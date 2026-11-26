////////////////////////////////////////////////////////////
// backend/scripts/seedMasterDistricts.js
// FINAL ENTERPRISE DISTRICT SEEDER (ULTIMATE)
////////////////////////////////////////////////////////////

import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import fs from "fs";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";

import Country from "../models/Country.js";
import District from "../models/District.js";
import State from "../models/State.js";
import User from "../models/User.js";

////////////////////////////////////////////////////////////
// ENV
////////////////////////////////////////////////////////////

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({
  path: path.resolve(__dirname, "../.env"),
});

if (!process.env.MONGODB_URI) {
  console.error("❌ MONGODB_URI missing");
  process.exit(1);
}

const DEFAULT_ADMIN_PASSWORD =
  process.env.SEED_ADMIN_PASSWORD || "Admin@12345";

await mongoose.connect(process.env.MONGODB_URI);
console.log("✅ MongoDB connected");

////////////////////////////////////////////////////////////
// HELPERS
////////////////////////////////////////////////////////////

function generateSlug(name) {
  return name
    .toLowerCase()
    .trim()
    .replace(/\s+/g, "-")
    .replace(/[^\w-]+/g, "");
}

// ✅ ADD THIS HERE 👇
function normalize(str) {
  return str?.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// 🔥 STATE NUMERIC MAP (CRITICAL)
const stateCodeMap = {
  AN: "01", AP: "02", AR: "03", AS: "04", BR: "05",
  CH: "06", CT: "07", DL: "08", GA: "09", GJ: "10",
  HR: "11", HP: "12", JH: "13", KA: "14", KL: "15",
  MP: "16", MH: "17", MN: "18", ML: "19", MZ: "20",
  NL: "21", OR: "22", PB: "23", RJ: "24", SK: "25",
  TN: "26", TG: "27", TR: "28", UP: "29", UK: "30",
  WB: "31"
};

function generateInternalEmail(stateCode, districtCode) {
  return `district-admin-${stateCode}-${districtCode}@internal.local`
    .toLowerCase();
}

// 🔥 GEO FIX
function getDistrictGeo(entry) {
  if (
    entry.coordinates &&
    Array.isArray(entry.coordinates) &&
    entry.coordinates.length === 2
  ) {
    return {
      type: "Point",
      coordinates: entry.coordinates,
    };
  }

  return {
    type: "Point",
    coordinates: [78.9629, 20.5937],
  };
}

////////////////////////////////////////////////////////////
// MAIN
////////////////////////////////////////////////////////////

async function seedDistricts() {
  const summary = {
    processed: 0,
    createdAdmins: 0,
    alreadyExists: 0,
    skipped: 0,
  };

  try {
    ////////////////////////////////////////////////////////////
    // COUNTRY
    ////////////////////////////////////////////////////////////

    const country = await Country.findOne({
      code: "IN",
      isDeleted: false,
    }).lean();

    if (!country) throw new Error("India not found");

    ////////////////////////////////////////////////////////////
    // LOAD JSON
    ////////////////////////////////////////////////////////////

    const jsonPath = path.resolve(
      __dirname,
      "../seeds/data/districts.json"
    );

    const districtsData = JSON.parse(
      fs.readFileSync(jsonPath, "utf-8")
    );

    ////////////////////////////////////////////////////////////
    // PREFETCH STATES
    ////////////////////////////////////////////////////////////

    const states = await State.find({
      countryRef: country._id,
      isDeleted: false,
    }).lean();

    const stateMap = {};
    states.forEach((s) => {
      stateMap[s.code] = s;
    });

    ////////////////////////////////////////////////////////////
    // LOOP
    ////////////////////////////////////////////////////////////

    for (const entry of districtsData) {

      const state = stateMap[entry.stateCode];

      if (!state) {
        console.log("❌ SKIPPING (NO STATE):", entry.name);
        summary.skipped++;
        continue;
      }

      // 🔥 BUILD FULL ADMIN CODE (CRITICAL FIX)
      const stateNumeric = stateCodeMap[entry.stateCode];
      
      // 🔥 SAFE ADMIN2 CODE
      let districtCode = null;

      if (entry.admin2Code !== null && entry.admin2Code !== undefined) {
        districtCode = String(entry.admin2Code).padStart(3, "0");
      }

      // 🔥 FINAL ADMIN CODE
      const adminCode =
        stateNumeric && districtCode
          ? `IN.${stateNumeric}.${districtCode}`
          : null;

      const districtName = entry.name.trim().toUpperCase();

      // 🔥 👉 YAHAN ADD KARNA HAI
      const query = {
        $or: [
          ...(adminCode ? [{ adminCode }] : []),
          {
            name: districtName,
            stateRef: state._id,
            isDeleted: false,
          },
        ],
      };
    
      const slug = generateSlug(entry.name);
      const geo = getDistrictGeo(entry);

      ////////////////////////////////////////////////////////////
      // UPSERT DISTRICT
      ////////////////////////////////////////////////////////////

      const district = await District.findOneAndUpdate(
        query,
        {
          $set: {
            name: districtName,
            code: entry.code,
            slug,
            // ✅ NEW (CRITICAL)
            normalizedName: normalize(entry.name),

            aliases: entry.aliases || [],

            normalizedAliases: (entry.aliases || []).map((a) =>
              normalize(a)
            ),

            capital: entry.hqCityName || entry.name,

            ////////////////////////////////////////////////////////

            geoNameCode: entry.geoNameCode || null, // 🔥 ADD THIS

            // ✅ ADD THIS (CRITICAL)
            admin2Code: entry.admin2Code ?? null,

            // 🔥 ADD THIS (FINAL FIX)
            ...(adminCode && { adminCode }),
            countryRef: country._id,
            stateRef: state._id,
            geo,
            priority: entry.priority ?? 0,
            launchStatus: entry.launchStatus ?? "PRE_LAUNCH",
            isActive: entry.isActive ?? true,
            isDeleted: false,
          },
          $setOnInsert: {
            createdBy: null, // will set below if needed
          },
        },
        { upsert: true, new: true }
      );

      ////////////////////////////////////////////////////////////
      // STATE ADMIN
      ////////////////////////////////////////////////////////////

      const stateAdmin = await User.findOne({
        role: "ADMIN",
        adminLevel: "STATE",
        adminSubRole: "PRIMARY",
        stateRef: state._id,
        isDeleted: false,
      });

      if (!stateAdmin)
        throw new Error(`State admin missing for ${state.code}`);

      ////////////////////////////////////////////////////////////
      // CHECK PRIMARY ADMIN
      ////////////////////////////////////////////////////////////

      const existingPrimary = await User.findOne({
        role: "ADMIN",
        adminLevel: "DISTRICT",
        adminSubRole: "PRIMARY",
        districtRef: district._id,
        isDeleted: false,
      });

      ////////////////////////////////////////////////////////////
      // FINAL HYBRID LOGIC
      ////////////////////////////////////////////////////////////

      if (!existingPrimary) {

        // 🔥 EMAIL COLLISION SAFE
        const email = `${generateInternalEmail(
          state.code,
          entry.code
        )}.${Date.now()}`;

        const hashedPassword = await bcrypt.hash(
          DEFAULT_ADMIN_PASSWORD,
          12
        );

        const primaryAdmin = await User.create({
          name: `${entry.name} DISTRICT ADMIN`,
          phone: null,
          email,
          password: hashedPassword,

          role: "ADMIN",
          adminLevel: "DISTRICT",
          adminSubRole: "PRIMARY",

          countryRef: country._id,
          stateRef: state._id,
          districtRef: district._id,

          permissions: ["DISTRICT_FULL_ACCESS"],

          mustChangePassword: true,
          isEmailVerified: true,
          isPhoneVerified: false,

          createdBy: stateAdmin._id,

          // 🔥 ADD THIS (CRITICAL FIX)
          lastAssignedAt: null,
        });

        await District.updateOne(
          { _id: district._id },
          {
            $set: {
              primaryAdminRef: primaryAdmin._id,
              updatedBy: stateAdmin._id,
            },
            $setOnInsert: {
              createdBy: stateAdmin._id, // ✅ FIXED
            },
          }
        );

        summary.createdAdmins++;

      } else {

        await User.updateOne(
          { _id: existingPrimary._id },
          {
            // Existing account is REUSED as-is: same _id; name, phone, email,
            // password, assignment and enabled/disabled status are never
            // overwritten by a re-run.
            $set: {
              permissions: ["DISTRICT_FULL_ACCESS"],

              // 🔥 ENSURE FIELD EXISTS (SAFE UPDATE)
              lastAssignedAt: existingPrimary.lastAssignedAt ?? null,
            },
          }
        );

        await District.updateOne(
          { _id: district._id },
          {
            $set: {
              primaryAdminRef: existingPrimary._id,
            },
          }
        );

        summary.alreadyExists++;
      }

      summary.processed++;

      console.log(`✔ District: ${entry.name}`);
    }

    ////////////////////////////////////////////////////////////
    // DONE
    ////////////////////////////////////////////////////////////

    console.log("🎉 District Seeding Completed");
    console.table(summary);

    process.exit(0);

  } catch (err) {
    console.error("❌ Seeding failed:", err.message);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
  }
}

seedDistricts();