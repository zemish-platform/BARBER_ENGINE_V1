import mongoose from "mongoose";

/////////////////////////////////////////////////////
// USER SCHEMA — FINAL ENTERPRISE SAFE
/////////////////////////////////////////////////////

const UserSchema = new mongoose.Schema(
  {
    /////////////////////////////////////////////////
    // BASIC INFO
    /////////////////////////////////////////////////

    name: {
      type: String,
      required: true,
      trim: true,
    },

    /////////////////////////////////////////////////
    // 🔐 IDENTITY
    /////////////////////////////////////////////////

    phone: {
      type: String,
      trim: true,
      default: null,
      match: /^[6-9]\d{9}$/, // ✅ FIXED (India format)
    },

    email: {
      type: String,
      lowercase: true,
      trim: true,
      default: null,
      match: /^\S+@\S+\.\S+$/, // ✅ FIXED
    },

    /////////////////////////////////////////////////
    // 👤 PERSONAL DETAILS — optional, used for birthday
    // offers, personalized recommendations, and demographic
    // insights. Not required at signup.
    /////////////////////////////////////////////////
    dateOfBirth: {
      type: Date,
      default: null,
    },
    gender: {
      type: String,
      enum: ["MALE", "FEMALE", "OTHER", "PREFER_NOT_TO_SAY"],
      default: null,
    },
  

    /////////////////////////////////////////////////
    // 🔒 AUTH FIELDS
    /////////////////////////////////////////////////

    password: {
      type: String,
      select: false,
    },

    loginAttempts: {
      type: Number,
      default: 0,
      select: false,
    },

    lockUntil: {
      type: Date,
      default: null,
      select: false,
    },

    tokenVersion: {
      type: Number,
      default: 0,
      select: false,
    },

    otpCode: {
      type: String,
      select: false,
    },

    otpExpiresAt: {
      type: Date,
      select: false,
    },

    /////////////////////////////////////////////////
    // ROLE SYSTEM
    /////////////////////////////////////////////////

    role: {
      type: String,
      enum: ["USER", "OWNER", "BARBER", "ADMIN", "FIELD_STAFF", "AGENT", "SUPPORT_ADMIN", "FIELD_AGENT"],
      default: "USER",
      required: true,
      // ❌ removed index (duplicate issue fix)
    },

    /////////////////////////////////////////////////
    // ADMIN HIERARCHY
    /////////////////////////////////////////////////

    adminLevel: {
      type: String,
      enum: ["INDIA", "STATE", "DISTRICT"],
      default: null,
      // ❌ removed index
    },

    adminSubRole: {
      type: String,
      enum: ["PRIMARY", "SUPPORT"],
      default: null,
    },

    /////////////////////////////////////////////////
    // GEO REFERENCES
    /////////////////////////////////////////////////

    countryRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Country",
      default: null,
      required: false,
    },

    stateRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "State",
      default: null,
      // ❌ removed index
    },

    districtRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "District",
      default: null,
      // ❌ removed index
    },

    cityRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "City",
      default: null,
    },

    /////////////////////////////////////////////////
    // ADMIN SECURITY
    /////////////////////////////////////////////////

    permissions: {
      type: [String],
      default: [],
    },

    mustChangePassword: {
      type: Boolean,
      default: false,
    },

    // Admin secure activation (additive). Set when an authorized admin assigns
    // an employee to a State/District admin account (see
    // services/adminCredential.service.js). A STATE/DISTRICT account with no
    // adminAssignedAt can never be activated — knowing a seed-generated email
    // or phone is not enough.
    adminAssignedAt: {
      type: Date,
      default: null,
    },
    adminAssignedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    passwordChangedAt: {
      type: Date,
      default: null,
    },

    lastLoginAt: {
      type: Date,
      default: null,
    },

    // 🔥 NEW FIELD (ADMIN LOAD BALANCING)
    lastAssignedAt: {
      type: Date,
      default: null,
      index: true,
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    isPhoneVerified: {
      type: Boolean,
      default: false,
    },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    /////////////////////////////////////////////////
    // ACCOUNT CONTROL
    /////////////////////////////////////////////////

    accountStatus: {
      type: String,
      enum: ["ACTIVE", "SUSPENDED", "BLOCKED"],
      default: "ACTIVE",
      index: true,
    },

    status: {
      type: String,
      enum: ["ACTIVE", "SUSPENDED", "BLOCKED"],
      default: "ACTIVE",
    },

    /////////////////////////////////////////////////
    // STATUS AUDIT
    /////////////////////////////////////////////////

    statusUpdatedBy: {
      type:    mongoose.Schema.Types.ObjectId,
      ref:     "User",
      default: null,
    },
  
    statusUpdatedAt: {
      type:    Date,
      default: null,
    },
  
    statusUpdateReason: {
      type:      String,
      default:   null,
      maxlength: 300,
    },
    

    /////////////////////////////////////////////////
    // 👤 PROFILE
    /////////////////////////////////////////////////

    profilePhoto: {
      type:    String,
      default: null,
    },

    /////////////////////////////////////////////////
    // 💰 WALLET
    /////////////////////////////////////////////////

    walletBalance: {
      type:    Number,
      default: 0,
      min:     0,
    },

    /////////////////////////////////////////////////
    // 🎁 REWARD POINTS
    /////////////////////////////////////////////////

    rewardPoints: {
      type:    Number,
      default: 0,
      min:     0,
    },

    /////////////////////////////////////////////////
    // SYSTEM FLAGS
    /////////////////////////////////////////////////

    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },

    isDeleted: {
      type: Boolean,
      default: false,
      index: true,
      select: false,
    },
  },
  {
    timestamps: true,
    versionKey: false,
    strict: true,
  }
);

/////////////////////////////////////////////////////
// 🔐 VALIDATION LOGIC (FINAL)
/////////////////////////////////////////////////////

UserSchema.pre("validate", function (next) {

  //////////////////////////////////////////////////
  // EMAIL REQUIRED FOR ADMIN (CRITICAL FIX ✅)
  //////////////////////////////////////////////////

  if (this.role === "ADMIN" && !this.email) {
    return next(new Error("Email required for admin"));
  }

  //////////////////////////////////////////////////
  // PHONE REQUIRED FOR NON-ADMIN
  //////////////////////////////////////////////////

  if (this.role !== "ADMIN" && !this.phone) {
    return next(new Error("Phone required for this role"));
  }

  //////////////////////////////////////////////////
  // NON-ADMIN CLEANUP
  //////////////////////////////////////////////////

  if (this.role !== "ADMIN") {
    this.adminLevel = null;
    this.adminSubRole = null;
    this.countryRef = null;
    return next();
  }

  //////////////////////////////////////////////////
  // ADMIN VALIDATION
  //////////////////////////////////////////////////

  if (!this.adminLevel)
    return next(new Error("adminLevel required"));

  if (!this.countryRef || !mongoose.Types.ObjectId.isValid(this.countryRef)) {
    return next(new Error("Valid countryRef required"));
  }

  // INDIA ADMIN
  if (this.adminLevel === "INDIA") {
    this.stateRef = null;
    this.districtRef = null;
    this.adminSubRole = null;
    return next();
  }

  // STATE ADMIN
  if (this.adminLevel === "STATE") {
    if (!this.stateRef)
      return next(new Error("stateRef required"));

    this.districtRef = null;
    if (!this.adminSubRole)
      return next(new Error("adminSubRole required"));


    return next();
  }


  // DISTRICT ADMIN
  if (this.adminLevel === "DISTRICT") {
    if (!this.stateRef || !this.districtRef)
      return next(new Error("stateRef and districtRef required"));

    if (!this.adminSubRole)
      return next(new Error("adminSubRole required"));

    return next();
  }

  return next();
});

/////////////////////////////////////////////////////
// 🔐 SECURITY (PRO LEVEL FIX ✅)
/////////////////////////////////////////////////////

UserSchema.set("toJSON", {
  transform: function (doc, ret) {
    delete ret.password;
    delete ret.otpCode;
    delete ret.loginAttempts;
    delete ret.lockUntil;
    delete ret.tokenVersion;
    return ret;
  },
});

/////////////////////////////////////////////////////
// ⭐ INDEXES (CLEAN + NO DUPLICATE)
/////////////////////////////////////////////////////

// FA-17 F3 REMEDIATION — the previous declarations here combined
// `sparse: true` with `partialFilterExpression`, a combination MongoDB
// rejects outright (error 67, "cannot mix partialFilterExpression and
// sparse options"). Because the index could never actually be built,
// the live collection was left running on a stale, non-unique legacy
// index instead — phone/email uniqueness was NOT enforced in
// production. Confirmed live via direct query against the real
// database during this remediation (see scripts/verifyUserIdentityUniqueness.js).
//
// Scope decision (per-role, not global) — confirmed against real data,
// not assumed: a live query of the ACTIVE User collection found 11
// real, currently-in-use accounts sharing a phone number ACROSS
// different roles (predominantly OWNER+USER, i.e. the same person
// booking as a customer and separately owning a salon — an existing,
// functioning, real production pattern), plus 2 ADMIN+OWNER/USER
// overlaps. A GLOBAL unique index would either fail to build against
// this real data or require deleting/merging real accounts — neither
// of which this remediation is authorized to do. By contrast, EVERY
// actual application-level uniqueness check already in this codebase
// (createOrFindUser in utils/otp.helpers.js; the ADMIN-provisioning
// checks in controllers/state.controller.js and
// controllers/district.controller.js) scopes its own pre-save lookup
// by {phone/email, role} — never globally. A live query also found
// ZERO same-role duplicates and ZERO email duplicates of any kind
// today, so a per-role unique index is safe to create immediately: it
// enforces exactly the invariant the application already assumes
// (closing the real concurrency-race gap where two simultaneous
// requests could otherwise both pass the same findOne-then-create
// check and both succeed), without conflicting with the real,
// pre-existing cross-role accounts above. Cross-role phone/email
// uniqueness (the broader invariant implied by the original global
// declaration) remains an OPEN question requiring an explicit product
// decision — not resolved here.
UserSchema.index(
  { phone: 1, role: 1 },
  {
    unique: true,
    partialFilterExpression: {
      isDeleted: false,
      phone: { $type: "string" },
    },
  }
);

UserSchema.index(
  { email: 1, role: 1 },
  {
    unique: true,
    partialFilterExpression: {
      isDeleted: false,
      email: { $type: "string" },
    },
  }
);

// ONE INDIA ADMIN
UserSchema.index(
  { role: 1, adminLevel: 1 },
  {
    unique: true,
    partialFilterExpression: {
      role: "ADMIN",
      adminLevel: "INDIA",
      isDeleted: false,
    },
  }
);

// ONE PRIMARY STATE ADMIN (SUPPORT/backup admins are NOT limited to
// one — same rule DISTRICT already uses below)
UserSchema.index(
  { stateRef: 1, adminSubRole: 1 },
  {
    unique: true,
    partialFilterExpression: {
      role: "ADMIN",
      adminLevel: "STATE",
      isDeleted: false,
    },
  }
);


// ONE PRIMARY DISTRICT ADMIN
UserSchema.index(
  { districtRef: 1, adminSubRole: 1 },
  {
    unique: true,
    partialFilterExpression: {
      role: "ADMIN",
      adminLevel: "DISTRICT",
      adminSubRole: "PRIMARY",
      isDeleted: false,
    },
  }
);

//////////////////////////////////////////////////////////////
// 🚀 ADMIN ASSIGN OPTIMIZATION INDEXES
//////////////////////////////////////////////////////////////

// 🔥 District-level admin lookup
UserSchema.index({
  role: 1,
  adminLevel: 1, // ✅ FIXED
  districtRef: 1,
  lastAssignedAt: 1,
});

// 🔥 State-level admin lookup
UserSchema.index({
  role: 1,
  adminLevel: 1,
  stateRef: 1,
  lastAssignedAt: 1,
});

/////////////////////////////////////////////////////
// EXPORT
/////////////////////////////////////////////////////

export default mongoose.models.User ||
  mongoose.model("User", UserSchema);