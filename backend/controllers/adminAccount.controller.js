/**
 * BARBER_ENGINE_V1
 * backend/controllers/adminAccount.controller.js
 *
 * Admin secure activation — hierarchy-scoped list + assignment of the
 * existing (seeded) State/District admin accounts. Does NOT create or delete
 * accounts: the seed hierarchy and account counts are unchanged.
 *
 *   GET  /api/admin/admin-accounts              list (scoped, no credentials)
 *   POST /api/admin/admin-accounts/:id/assign   { adminName, phone, email, confirmReassign? }
 *
 * Scope (enforced here, server-side):
 *   INDIA    → any STATE or DISTRICT admin account
 *   STATE    → DISTRICT admin accounts in its OWN state only
 *   DISTRICT → nothing (route-level requireAdminLevel("INDIA","STATE"))
 *
 * Assignment never sets a password: the account gets an unusable password,
 * mustChangePassword: true and an assignment marker, every existing session
 * is revoked, and the employee must activate via OTP on the assigned phone
 * (see services/adminCredential.service.js).
 */
import mongoose from "mongoose";
import User from "../models/User.js";
import { AppError, Errors, successResponse } from "../utils/response.js";
import { logAdminAction } from "../utils/auditLog.js";
import { AUDIT_ACTIONS } from "../utils/auditActions.js";
import { revokeAllSessions } from "../services/session.service.js";
import {
  adminAccountStatus,
  markAdminAssigned,
  normalizeAdminPhone,
} from "../services/adminCredential.service.js";

const isValidId = (id) => mongoose.Types.ObjectId.isValid(id);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const maskPhone = (phone) => (phone ? `******${String(phone).slice(-4)}` : null);

/** Mongo filter of the admin accounts the caller may see/assign, or null when none. */
const scopeFilterFor = (caller) => {
  const level = String(caller?.adminLevel || "").toUpperCase();
  if (level === "INDIA") return { adminLevel: { $in: ["STATE", "DISTRICT"] } };
  if (level === "STATE" && caller.stateRef) return { adminLevel: "DISTRICT", stateRef: caller.stateRef };
  return null;
};

const toListItem = (a) => ({
  id: a._id,
  name: a.name,
  email: a.email,
  phone: maskPhone(a.phone),
  adminLevel: a.adminLevel,
  adminSubRole: a.adminSubRole || null,
  stateRef: a.stateRef || null,
  districtRef: a.districtRef || null,
  status: adminAccountStatus(a),
  assignedAt: a.adminAssignedAt || null,
});

// GET /api/admin/admin-accounts?adminLevel=&stateId=&districtId=&status=&page=&limit=
export const listAdminAccounts = async (req, res, next) => {
  try {
    const scope = scopeFilterFor(req.user);
    if (!scope) return next(Errors.forbidden("Insufficient admin privileges"));

    const filter = { role: "ADMIN", isDeleted: { $ne: true }, ...scope };
    const { adminLevel, stateId, districtId, status } = req.query;

    if (adminLevel) {
      const lvl = String(adminLevel).toUpperCase();
      if (!["STATE", "DISTRICT"].includes(lvl)) return next(Errors.badRequest("adminLevel must be STATE or DISTRICT"));
      if (scope.adminLevel === "DISTRICT" && lvl !== "DISTRICT") return next(Errors.forbidden("Insufficient admin privileges"));
      filter.adminLevel = lvl;
    }
    if (stateId) {
      if (!isValidId(stateId)) return next(Errors.badRequest("Invalid stateId"));
      if (scope.stateRef && String(scope.stateRef) !== String(stateId)) return next(Errors.forbidden("Outside your state"));
      filter.stateRef = new mongoose.Types.ObjectId(String(stateId));
    }
    if (districtId) {
      if (!isValidId(districtId)) return next(Errors.badRequest("Invalid districtId"));
      filter.districtRef = new mongoose.Types.ObjectId(String(districtId));
    }
    if (status) {
      const st = String(status).toUpperCase();
      // Same rule as adminAccountStatus(): never-assigned = UNASSIGNED regardless of mustChangePassword.
      if (st === "ACTIVE") Object.assign(filter, { mustChangePassword: { $ne: true }, adminAssignedAt: { $ne: null } });
      else if (st === "PENDING_ACTIVATION") Object.assign(filter, { mustChangePassword: true, adminAssignedAt: { $ne: null } });
      else if (st === "UNASSIGNED") filter.adminAssignedAt = null;
      else return next(Errors.badRequest("status must be UNASSIGNED, PENDING_ACTIVATION or ACTIVE"));
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));

    const [items, total] = await Promise.all([
      User.find(filter)
        .select("name email phone adminLevel adminSubRole stateRef districtRef mustChangePassword adminAssignedAt")
        .sort({ adminLevel: 1, stateRef: 1, districtRef: 1, adminSubRole: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      User.countDocuments(filter),
    ]);

    return successResponse(res, {
      message: "Admin accounts fetched",
      data: { items: items.map(toListItem), page, limit, total },
    });
  } catch (err) {
    next(err);
  }
};

// POST /api/admin/admin-accounts/:id/assign { adminName, phone, email, confirmReassign? }
export const assignAdminAccount = async (req, res, next) => {
  try {
    const scope = scopeFilterFor(req.user);
    if (!scope) return next(Errors.forbidden("Insufficient admin privileges"));
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid admin account ID"));

    let { adminName, phone, email, confirmReassign } = req.body || {};
    adminName = typeof adminName === "string" ? adminName.trim().replace(/\s+/g, " ") : "";
    const cleanPhone = normalizeAdminPhone(typeof phone === "string" ? phone : String(phone ?? ""));
    const cleanEmail = typeof email === "string" ? email.trim().toLowerCase() : "";

    if (adminName.length < 2 || adminName.length > 100) return next(Errors.badRequest("adminName is required (2-100 characters)"));
    if (!cleanPhone) return next(Errors.badRequest("A valid 10-digit mobile number is required"));
    if (!EMAIL_RE.test(cleanEmail)) return next(Errors.badRequest("A valid email is required"));

    const target = await User.findOne({
      _id: req.params.id,
      role: "ADMIN",
      isDeleted: { $ne: true },
    }); // full document: User's pre-validate hook needs role/adminLevel/countryRef on save
    if (!target) return next(Errors.notFound("Admin account not found"));

    // Hierarchy check: target must fall inside the caller's scope.
    const inScope =
      (scope.adminLevel?.$in ? scope.adminLevel.$in.includes(target.adminLevel) : target.adminLevel === scope.adminLevel) &&
      (!scope.stateRef || String(target.stateRef) === String(scope.stateRef));
    if (!inScope) return next(Errors.forbidden("You are not allowed to assign this admin account"));
    if (String(target._id) === String(req.user._id)) return next(Errors.forbidden("You cannot assign your own account"));

    if (adminAccountStatus(target) === "ACTIVE" && confirmReassign !== true) {
      return next(new AppError("Account is already active. Pass confirmReassign: true to hand it to a new employee.", 409, "ACCOUNT_ALREADY_ACTIVE"));
    }

    const [phoneClash, emailClash] = await Promise.all([
      User.exists({ phone: cleanPhone, role: "ADMIN", isDeleted: { $ne: true }, _id: { $ne: target._id } }),
      User.exists({ email: cleanEmail, role: "ADMIN", isDeleted: { $ne: true }, _id: { $ne: target._id } }),
    ]);
    if (phoneClash) return next(Errors.conflict("Phone already linked to another admin account"));
    if (emailClash) return next(Errors.conflict("Email already linked to another admin account"));

    const previousStatus = adminAccountStatus(target);
    target.name = adminName;
    target.phone = cleanPhone;
    target.email = cleanEmail;
    target.isActive = true;
    await markAdminAssigned(target, req.user._id);
    try {
      await target.save();
    } catch (err) {
      if (err?.code === 11000) return next(Errors.conflict("Phone or email already linked to another admin account"));
      throw err;
    }

    // Old credentials and sessions die immediately (tokenVersion bump + refresh tokens revoked).
    await revokeAllSessions(target._id);

    logAdminAction({
      adminId: req.user._id,
      action: AUDIT_ACTIONS.ADMIN_ACCOUNT_ASSIGNED,
      targetType: "ADMIN_ACCOUNT",
      targetId: target._id,
      meta: {
        adminLevel: target.adminLevel,
        adminSubRole: target.adminSubRole || null,
        stateRef: target.stateRef || null,
        districtRef: target.districtRef || null,
        previousStatus,
        phone: maskPhone(cleanPhone),
      },
      req,
    });

    return successResponse(res, {
      message: "Admin account assigned. The employee must now activate it with an OTP sent to the assigned phone.",
      data: { account: toListItem(target) },
    });
  } catch (err) {
    next(err);
  }
};
