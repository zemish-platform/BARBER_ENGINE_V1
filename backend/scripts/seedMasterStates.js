import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcryptjs";
import fs from "fs";
import mongoose from "mongoose";

import connectDB from "../config/db.js";
import Country from "../models/Country.js";
import State from "../models/State.js";
import User from "../models/User.js";

const JSON_PATH = "./seeds/data/states.json";

/////////////////////////////////////////////////////
// 🔐 DEFAULT PASSWORD
/////////////////////////////////////////////////////
const DEFAULT_PASSWORD =
  process.env.SEED_ADMIN_PASSWORD || "Admin@12345";

/////////////////////////////////////////////////////
// 📞 PHONE GENERATOR
/////////////////////////////////////////////////////
function generateDeterministicPhone(stateCode) {
  const numericCode = stateCode
    .split("")
    .map((char) => char.charCodeAt(0))
    .join("");

  return (numericCode + "0000000000").slice(0, 10);
}

/////////////////////////////////////////////////////
// 🔗 SLUG
/////////////////////////////////////////////////////
function generateSlug(name) {
  return name
    .toLowerCase()
    .trim()
    .replace(/\s+/g, "-")
    .replace(/[^\w-]+/g, "");
}

/////////////////////////////////////////////////////
// 📧 EMAIL
/////////////////////////////////////////////////////
function generateStateAdminEmail(code) {
  return `state-admin-${code.toLowerCase()}@yourapp.internal`;
}

/////////////////////////////////////////////////////
// 📞 BACKUP ADMIN PHONE GENERATOR (NEW)
// Deliberately different from generateDeterministicPhone() so backup
// admins never collide with primary admins on phone number. Starts
// with "9" (valid per phone regex ^[6-9]\d{9}$) followed by the same
// per-state numeric code used for the primary admin's phone.
/////////////////////////////////////////////////////
function generateBackupAdminPhone(stateCode) {
  const numericCode = stateCode
    .split("")
    .map((char) => char.charCodeAt(0))
    .join("");

  return ("9" + numericCode).padEnd(10, "0").slice(0, 10);
}

/////////////////////////////////////////////////////
// 📧 BACKUP ADMIN EMAIL (NEW)
/////////////////////////////////////////////////////
function generateBackupAdminEmail(code) {
  return `state-backup-admin-${code.toLowerCase()}@yourapp.internal`;
}

/////////////////////////////////////////////////////
// 📍 GEO FIX
/////////////////////////////////////////////////////
function getStateGeo(stateData) {
  if (
    stateData.coordinates &&
    Array.isArray(stateData.coordinates) &&
    stateData.coordinates.length === 2
  ) {
    return {
      type: "Point",
      coordinates: stateData.coordinates,
    };
  }

  return {
    type: "Point",
    coordinates: [78.9629, 20.5937], // fallback
  };
}

/////////////////////////////////////////////////////
// 🚀 MAIN
/////////////////////////////////////////////////////
async function seedStates() {
  try {
    console.log("🔌 Connecting DB...");
    await connectDB();

    //////////////////////////////////////////////////////
    // COUNTRY
    //////////////////////////////////////////////////////
    const india = await Country.findOne({
      code: "IN",
      isDeleted: false,
    });

    if (!india) throw new Error("India country not found.");

    //////////////////////////////////////////////////////
    // SUPER ADMIN
    //////////////////////////////////////////////////////
    const indiaAdmin = await User.findOne({
      role: "ADMIN",
      adminLevel: "INDIA",
      isDeleted: false,
    });

    if (!indiaAdmin)
      throw new Error("India Super Admin not found.");

    //////////////////////////////////////////////////////
    // JSON
    //////////////////////////////////////////////////////
    const rawData = fs.readFileSync(JSON_PATH, "utf-8");
    const statesData = JSON.parse(rawData);

    //////////////////////////////////////////////////////
    // LOOP
    //////////////////////////////////////////////////////
    for (const stateData of statesData) {

      const slug = generateSlug(stateData.name);
      const geo = getStateGeo(stateData);

      //////////////////////////////////////////////////////
      // STATE UPSERT
      //////////////////////////////////////////////////////
      const state = await State.findOneAndUpdate(
        { code: stateData.code.toUpperCase(), countryRef: india._id },
        {
          $set: {
            name: stateData.name.toUpperCase(),
            code: stateData.code.toUpperCase(),
            slug,
            type: stateData.type,
            countryRef: india._id,
            geo,
            geoNameCode: stateData.geoNameCode || null, // ✅ ADD THIS
            launchStatus: stateData.launchStatus ?? "PRE_LAUNCH",
            serviceable: false,
            priority: 0,
            isActive: stateData.isActive ?? true,
            isDeleted: false,
            updatedBy: indiaAdmin._id,
          },
          $setOnInsert: {
            createdBy: indiaAdmin._id,
          },
        },
        { upsert: true, new: true }
      );

      console.log(`✔ State: ${state.code}`);

      //////////////////////////////////////////////////////
      // STATE ADMIN
      //////////////////////////////////////////////////////
      // PRIMARY only — without the sub-role filter this could match the
      // SUPPORT (backup) admin and flip it to PRIMARY.
      const existingStateAdmin = await User.findOne({
        role: "ADMIN",
        adminLevel: "STATE",
        adminSubRole: "PRIMARY",
        stateRef: state._id,
        isDeleted: false,
      });

      if (!existingStateAdmin) {

        //////////////////////////////////////////////////////
        // CREATE ADMIN
        //////////////////////////////////////////////////////
        const hashedPassword = await bcrypt.hash(
          DEFAULT_PASSWORD,
          12
        );

        const systemPhone = generateDeterministicPhone(state.code);
        const email = generateStateAdminEmail(state.code);

        const phoneExists = await User.findOne({
          phone: systemPhone,
          isDeleted: false,
        });

        if (phoneExists)
          throw new Error(`Phone collision for ${state.name}`);

        const emailExists = await User.findOne({
          email,
          isDeleted: false,
        });

        if (emailExists)
          throw new Error(`Email collision for ${state.name}`);

        const admin = await User.create({
          name: `${state.name} STATE ADMIN`,
          email,
          phone: systemPhone,
          password: hashedPassword,

          role: "ADMIN",
          adminLevel: "STATE",
          adminSubRole: "PRIMARY",


          countryRef: india._id,
          stateRef: state._id,

          permissions: ["STATE_FULL_ACCESS"],
          mustChangePassword: true,
          createdBy: indiaAdmin._id,

          isEmailVerified: true,
          isPhoneVerified: true,

          isActive: true,
          isDeleted: false,
        });

        //////////////////////////////////////////////////////
        // 🔥 LINK ADMIN TO STATE (FIX)
        //////////////////////////////////////////////////////
        await State.updateOne(
          { _id: state._id },
          {
            $set: {
              primaryAdminRef: admin._id,
            },
          }
        );

        console.log(`✅ Admin created for ${state.code}`);

      } else {

        //////////////////////////////////////////////////////
        // UPDATE ADMIN (SAFE)
        //////////////////////////////////////////////////////
        // Existing account is REUSED as-is: same _id, and its name, phone,
        // email, password, assignment and enabled/disabled status are never
        // overwritten (an assigned employee must not be renamed back to the
        // placeholder, and a disabled account must stay disabled).
        await User.updateOne(
          { _id: existingStateAdmin._id },
          {
            $set: {
              permissions: ["STATE_FULL_ACCESS"],
            },
          }
        );

        //////////////////////////////////////////////////////
        // 🔥 LINK EXISTING ADMIN (FIX)
        //////////////////////////////////////////////////////
        await State.updateOne(
          { _id: state._id },
          {
            $set: {
              primaryAdminRef: existingStateAdmin._id,
            },
          }
        );

        console.log(`🔄 Admin updated for ${state.code}`);
      }

      //////////////////////////////////////////////////////
      // BACKUP (SUPPORT) STATE ADMIN (NEW)
      //////////////////////////////////////////////////////
      const existingBackupAdmin = await User.findOne({
        role: "ADMIN",
        adminLevel: "STATE",
        adminSubRole: "SUPPORT",
        stateRef: state._id,
        isDeleted: false,
      });

      if (!existingBackupAdmin) {

        //////////////////////////////////////////////////////
        // CREATE BACKUP ADMIN
        //////////////////////////////////////////////////////
        const backupPassword = await bcrypt.hash(DEFAULT_PASSWORD, 12);
        const backupPhone = generateBackupAdminPhone(state.code);
        const backupEmail = generateBackupAdminEmail(state.code);

        const backupPhoneExists = await User.findOne({
          phone: backupPhone,
          isDeleted: false,
        });

        if (backupPhoneExists)
          throw new Error(`Backup phone collision for ${state.name}`);

        const backupEmailExists = await User.findOne({
          email: backupEmail,
          isDeleted: false,
        });

        if (backupEmailExists)
          throw new Error(`Backup email collision for ${state.name}`);

        await User.create({
          name: `${state.name} STATE BACKUP ADMIN`,
          email: backupEmail,
          phone: backupPhone,
          password: backupPassword,

          role: "ADMIN",
          adminLevel: "STATE",
          adminSubRole: "SUPPORT",

          countryRef: india._id,
          stateRef: state._id,

          permissions: ["STATE_FULL_ACCESS"],
          mustChangePassword: true,
          createdBy: indiaAdmin._id,

          isEmailVerified: true,
          isPhoneVerified: true,

          isActive: true,
          isDeleted: false,
        });

        console.log(`✅ Backup admin created for ${state.code}`);

      } else {

        //////////////////////////////////////////////////////
        // UPDATE BACKUP ADMIN (SAFE)
        //////////////////////////////////////////////////////
        // Reused as-is (see the PRIMARY branch above).
        await User.updateOne(
          { _id: existingBackupAdmin._id },
          {
            $set: {
              permissions: ["STATE_FULL_ACCESS"],
            },
          }
        );

        console.log(`🔄 Backup admin updated for ${state.code}`);
      }
    }

    console.log("🎉 State Seeding Completed Successfully");
    process.exit(0);

  } catch (error) {
    console.error("❌ Seeding failed:", error.message);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
  }
}

seedStates();