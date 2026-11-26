/**
 * BARBER ENGINE V1
 * backend/controllers/state.controller.js
 * State Controller — Location Module — 10/10 FROZEN
 */

import mongoose from "mongoose";
import Area from "../models/Area.js";
import Booking from "../models/Booking.js";
import District from "../models/District.js";
import Salon from "../models/Salon.js";
import State from "../models/State.js";
import User from "../models/User.js";
import { Errors, successResponse } from "../utils/response.js";
import { adminAssignmentFields, markAdminAssigned } from "../services/adminCredential.service.js";
import { revokeAllSessions } from "../services/session.service.js";
import { logAdminAction } from "../utils/auditLog.js";
import { AUDIT_ACTIONS } from "../utils/auditActions.js";

const isValidId   = (id)  => mongoose.Types.ObjectId.isValid(id);
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Admin secure activation: no shared/temporary password exists any more.
// Newly assigned admins get an unusable password and must activate via OTP
// (services/adminCredential.service.js).

const SORT_MAP = {
  name:      { name: 1 },
  newest:    { createdAt: -1 },
  oldest:    { createdAt: 1 },
  districts: { districtCount: -1 },
};

/**
 * POST /api/admin/states
 * Create state + auto-create STATE admin
 */
export const createStateWithAdmin = async (req, res, next) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    const creator = await User.findById(req.user.id).session(session);
    if (!creator) {
      await session.abortTransaction();
      return next(Errors.notFound("Requesting admin account not found"));
    }

    if (creator.role !== "ADMIN" || creator.adminLevel !== "INDIA") {
      await session.abortTransaction();
      return next(Errors.forbidden("Only INDIA admin can create states"));
    }

    if (!creator.countryRef) {
      await session.abortTransaction();
      return next(Errors.badRequest("Admin countryRef missing"));
    }

    let { stateName, adminName, phone, email } = req.body;

    if (!stateName || !adminName || !phone) {
      await session.abortTransaction();
      return next(Errors.badRequest("Required fields: stateName, adminName, phone"));
    }

    stateName = stateName.trim().replace(/\s+/g, " ");
    adminName = adminName.trim().replace(/\s+/g, " ");

    const cleanPhone = phone.replace(/\D/g, "");
    if (cleanPhone.length !== 10) {
      await session.abortTransaction();
      return next(Errors.badRequest("Phone must be exactly 10 digits"));
    }
    phone = cleanPhone;

    const [existingState, existingAdmin] = await Promise.all([
      State.findOne({ name: { $regex: `^${escapeRegex(stateName)}$`, $options: "i" } }).session(session),
      User.findOne({ phone, role: "ADMIN" }).session(session),
    ]);

    if (existingState) {
      await session.abortTransaction();
      return next(Errors.conflict(`State "${stateName}" already exists`));
    }

    if (existingAdmin) {
      await session.abortTransaction();
      return next(Errors.conflict("Phone already linked to another admin account"));
    }

    const [state] = await State.create([{
      name:       stateName,
      countryRef: creator.countryRef,
      createdBy:  creator._id,
      isActive:   true,
    }], { session });

    const [admin] = await User.create([{
      name:              adminName,
      phone,
      email:             email?.trim() || null,
      role:              "ADMIN",
      adminLevel:        "STATE",
      adminSubRole:      "PRIMARY",
      stateRef:          state._id,
      countryRef:        creator.countryRef,
      isVerified:        true,
      ...(await adminAssignmentFields(creator._id)),
    }], { session });

    await session.commitTransaction();

    logAdminAction({
      adminId: creator._id, action: AUDIT_ACTIONS.ADMIN_ACCOUNT_ASSIGNED,
      targetType: "ADMIN_ACCOUNT", targetId: admin._id,
      meta: { adminLevel: "STATE", stateRef: state._id, via: "createStateWithAdmin" },
      req,
    });

    return successResponse(res, {
      message: `State "${stateName}" created with STATE admin`,
      data: {
        state: { id: state._id, name: state.name },
        admin: { id: admin._id, name: admin.name, phone: admin.phone, email: admin.email, adminLevel: admin.adminLevel, activation: "PENDING_ACTIVATION" },
      },
    });
  } catch (err) {
    await session.abortTransaction();
    next(err);
  } finally {
    session.endSession();
  }
};

/**
 * GET /api/admin/states
 * List all states with full stats
 */
export const getStates = async (req, res, next) => {
  try {
    const { page = 1, limit = 20, sort = "name", search = "", isActive } = req.query;

    const pageNum  = Math.max(parseInt(page,  10), 1);
    const limitNum = Math.min(Math.max(parseInt(limit, 10), 1), 100);
    const skip     = (pageNum - 1) * limitNum;
    const sortQ    = SORT_MAP[sort] || SORT_MAP.name;

    const filter = {};
    if (search)   filter.name     = { $regex: escapeRegex(search), $options: "i" };
    if (isActive !== undefined) filter.isActive = isActive === "true";

    if (req.user.adminLevel === "STATE" && req.user.stateRef) {
      filter._id = req.user.stateRef;
    }

    const fetchStatesPage = () => {
      if (sort === "districts") {
        return State.aggregate([
          { $match: filter },
          {
            $lookup: {
              from: "districts",
              let: { stateId: "$_id" },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $and: [
                        { $eq: ["$stateRef", "$$stateId"] },
                        { $eq: ["$isActive", true] },
                        { $ne: ["$isDeleted", true] },
                      ],
                    },
                  },
                },
                { $count: "count" },
              ],
              as: "_districtCountArr",
            },
          },
          {
            $addFields: {
              districtCount: { $ifNull: [{ $arrayElemAt: ["$_districtCountArr.count", 0] }, 0] },
            },
          },
          { $sort: { districtCount: -1 } },
          { $skip: skip },
          { $limit: limitNum },
          {
            $project: {
              name: 1, code: 1, capital: 1, zone: 1, isActive: 1, createdAt: 1, manualTerritoryOverride: 1,
            },
          },
        ]);
      }
      return State.find(filter)
        .select("name code capital zone isActive createdAt manualTerritoryOverride")
        .sort(sortQ)
        .skip(skip)
        .limit(limitNum)
        .lean();
    };

    // NOTE: `allFilteredStates` fetches every state matching the current
    // filters (search/isActive/state-scope) with NO pagination — this is
    // what powers the nationwide summary totals below, independent of
    // which page you're viewing.
    const [states, total, activeCount, inactiveCount, allFilteredStates] = await Promise.all([
      fetchStatesPage(),
      State.countDocuments(filter),
      State.countDocuments({ ...filter, isActive: true }),
      State.countDocuments({ ...filter, isActive: false }),
      State.find(filter).select("_id").lean(),
    ]);

    const stateIds    = states.map(s => s._id);           // current page only — used for per-row stats
    const allStateIds = allFilteredStates.map(s => s._id); // every matching state — used for nationwide totals

    // ✅ Parallel aggregations for all stats (current page — per-row data)
    const [districtAggs, areaAggs, salonAggs, serviceableAggs, adminList] = await Promise.all([
      // District count per state (active only)
      District.aggregate([
        { $match: { stateRef: { $in: stateIds }, isActive: true, isDeleted: { $ne: true } } },
        { $group: { _id: "$stateRef", count: { $sum: 1 } } },
      ]),

      // Area count per state (active only)
      Area.aggregate([
        { $match: { stateRef: { $in: stateIds }, isActive: true } },
        { $group: { _id: "$stateRef", count: { $sum: 1 } } },
      ]),

      // Salon count per state (approved only)
      Salon.aggregate([
        { $match: { "location.territory.stateRef": { $in: stateIds }, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
        { $group: { _id: "$location.territory.stateRef", count: { $sum: 1 } } },
      ]),

      // Serviceable area count per state
      Area.aggregate([
        { $match: { stateRef: { $in: stateIds }, isActive: true, isServiceable: true } },
        { $group: { _id: "$stateRef", count: { $sum: 1 } } },
      ]),

      // State admins
      User.find({
        stateRef:   { $in: stateIds },
        role:       "ADMIN",
        adminLevel: "STATE",
        adminSubRole: "PRIMARY",
      }).select("name phone stateRef").lean(),
    ]);

    // ✅ NEW — nationwide totals for the summary strip, independent of pagination
    const [nationwideDistricts, nationwideAreas, nationwideSalons, nationwideServiceable] = await Promise.all([
      District.aggregate([
        { $match: { stateRef: { $in: allStateIds }, isActive: true, isDeleted: { $ne: true } } },
        { $group: { _id: null, count: { $sum: 1 } } },
      ]),
      Area.aggregate([
        { $match: { stateRef: { $in: allStateIds }, isActive: true } },
        { $group: { _id: null, count: { $sum: 1 } } },
      ]),
      Salon.aggregate([
        { $match: { "location.territory.stateRef": { $in: allStateIds }, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
        { $group: { _id: null, count: { $sum: 1 } } },
      ]),
      Area.aggregate([
        { $match: { stateRef: { $in: allStateIds }, isActive: true, isServiceable: true } },
        { $group: { _id: null, count: { $sum: 1 } } },
      ]),
    ]);

    const totalDistrictsAll   = nationwideDistricts[0]?.count   ?? 0;
    const totalAreasAll       = nationwideAreas[0]?.count       ?? 0;
    const totalSalonsAll      = nationwideSalons[0]?.count      ?? 0;
    const serviceableAreasAll = nationwideServiceable[0]?.count ?? 0;
    const avgCoverageAll      = totalAreasAll > 0
      ? Math.round((serviceableAreasAll / totalAreasAll) * 100)
      : 0;

    // Build maps (current page — per-row data, unchanged)
    const distMap      = Object.fromEntries(districtAggs.map(d    => [String(d._id), d.count]));
    const areaMap      = Object.fromEntries(areaAggs.map(a         => [String(a._id), a.count]));
    const salonMap     = Object.fromEntries(salonAggs.map(s        => [String(s._id), s.count]));
    const serviceMap   = Object.fromEntries(serviceableAggs.map(s  => [String(s._id), s.count]));
    const adminMap     = Object.fromEntries(adminList.map(a        => [String(a.stateRef), a]));

    // Territory status — manual override takes precedence over computed value
    const getTerritoryStatus = (totalAreas, serviceableAreas, override) => {
      if (override) return override;
      if (totalAreas === 0) return "CLOSED";
      const pct = (serviceableAreas / totalAreas) * 100;
      if (pct >= 80) return "OPEN";
      if (pct >= 40) return "PARTIAL";
      return "CLOSED";
    };

    // Unassigned states count
    const unassignedCount = states.filter(s => !adminMap[String(s._id)]).length;

    return successResponse(res, {
      message: "States fetched",
      data: states.map(s => {
        const totalAreas       = areaMap[String(s._id)]    ?? 0;
        const serviceableAreas = serviceMap[String(s._id)] ?? 0;
        const coverage         = totalAreas > 0 ? Math.round((serviceableAreas / totalAreas) * 100) : 0;
        const stateAdmin       = adminMap[String(s._id)];

        return {
          id:             s._id,
          name:           s.name,
          code:           s.code     ?? null,
          capital:        s.capital  ?? null,
          zone:           s.zone     ?? null,
          isActive:       s.isActive,
          districtCount:  distMap[String(s._id)]  ?? 0,
          totalAreas,
          totalSalons:    salonMap[String(s._id)] ?? 0,
          coverage,
          territory:      getTerritoryStatus(totalAreas, serviceableAreas, s.manualTerritoryOverride),
          stateAdmin:     stateAdmin ? { id: stateAdmin._id, name: stateAdmin.name, phone: stateAdmin.phone } : null,
          createdAt:      s.createdAt,
        };
      }),
      pagination:      { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total/limitNum)||1 },
      meta: {
        unassignedCount, activeCount, inactiveCount,
        totalDistricts: totalDistrictsAll,
        totalAreas:     totalAreasAll,
        totalSalons:    totalSalonsAll,
        avgCoverage:    avgCoverageAll,
      },
    });
  } catch (err) { next(err) }
};

/**
 * GET /api/admin/states/:id
 *
 * CHANGED: now also returns activeSalons, avgRating, and an enriched
 * stateAdmin object (status + assignedAt) — needed by StateDetailPage's
 * Overview and Admins tabs.
 */
export const getStateById = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid state ID"));

    const state = await State.findById(req.params.id).lean();
    if (!state) return next(Errors.notFound("State not found"));

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(state._id)) {
      return next(Errors.forbidden("Access denied"));
    }

    const [
      districtCount, adminCount, totalAreas, totalSalons, serviceableAreas,
      activeSalons, ratingAgg, stateAdmin, backupAdmin, bookingAgg,
    ] = await Promise.all([
      District.countDocuments({ stateRef: state._id, isActive: true, isDeleted: { $ne: true } }),
      User.countDocuments({ stateRef: state._id, role: "ADMIN" }),
      Area.countDocuments({ stateRef: state._id, isActive: true }),
      Salon.countDocuments({ "location.territory.stateRef": state._id, "approval.status": "APPROVED", isDeleted: { $ne: true } }),
      Area.countDocuments({ stateRef: state._id, isActive: true, isServiceable: true }),

      // NEW — "Active Salons" = approved AND not suspended AND not force-closed.
      // Deliberately NOT tied to isShopOpen (that flips hourly and would make
      // this dashboard number swing to 0 every night — not a useful KPI).
      Salon.countDocuments({
        "location.territory.stateRef": state._id,
        "approval.status": "APPROVED",
        isDeleted: { $ne: true },
        "business.isSuspended": false,
        "business.isForceClosed": false,
      }),

      // NEW — State-level average rating = weighted average across all
      // approved salons in the state (sum of rating totals / sum of rating
      // counts), NOT a plain average-of-averages (which would wrongly give
      // a salon with 1 review the same weight as one with 500 reviews).
      Salon.aggregate([
        { $match: { "location.territory.stateRef": state._id, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
        { $group: { _id: null, totalRatingSum: { $sum: "$rating.total" }, totalRatingCount: { $sum: "$rating.count" } } },
      ]),

      // NEW — enriched state admin: status + assignedAt.
      // assignedAt reuses the admin User document's createdAt, since a
      // STATE admin is always created at the same time the state is
      // created (see createStateWithAdmin) — no separate field needed.
      User.findOne({ stateRef: state._id, role: "ADMIN", adminLevel: "STATE", adminSubRole: "PRIMARY" })
        .select("name phone email accountStatus createdAt").lean(),

      // NEW — backup admin (SUPPORT). Null if none assigned yet.
      User.findOne({ stateRef: state._id, role: "ADMIN", adminLevel: "STATE", adminSubRole: "SUPPORT" })
        .select("name phone email accountStatus createdAt").lean(),

      // NEW — lifetime totals for the Overview KPI strip (all-time


      // NEW — lifetime totals for the Overview KPI strip (all-time
      // COMPLETED bookings + Gross Booking Value). Bookings don't store
      // stateRef directly, so we join through Salon the same way
      // getStateAnalytics does. This is a separate, all-time figure from
      // the recent-months trend returned by getStateAnalytics.
      Booking.aggregate([
        { $match: { status: "COMPLETED", isDeleted: { $ne: true } } },
        { $lookup: { from: "salons", localField: "salonRef", foreignField: "_id", as: "salon" } },
        { $unwind: "$salon" },
        { $match: { "salon.location.territory.stateRef": state._id } },
        { $group: { _id: null, totalBookings: { $sum: 1 }, totalGbvInPaise: { $sum: "$totalAmountInPaise" } } },
      ]),
    ]);

    const coverage      = totalAreas > 0 ? Math.round((serviceableAreas / totalAreas) * 100) : 0;
    const territory     = state.manualTerritoryOverride
      || (totalAreas === 0 ? "CLOSED" : coverage >= 80 ? "OPEN" : coverage >= 40 ? "PARTIAL" : "CLOSED");
    const ratingData    = ratingAgg[0];
    const avgRating     = ratingData && ratingData.totalRatingCount > 0
      ? Number((ratingData.totalRatingSum / ratingData.totalRatingCount).toFixed(1))
      : 0;
    const bookingData   = bookingAgg[0];
    const totalBookings = bookingData?.totalBookings   ?? 0;
    const totalGbvInPaise = bookingData?.totalGbvInPaise ?? 0;

    return successResponse(res, {
      message: "State fetched",
      data: {
        id:            state._id,
        name:          state.name,
        code:          state.code     ?? null,
        capital:       state.capital  ?? null,
        zone:          state.zone     ?? null,
        timezone:      state.timezone ?? null,
        isActive:      state.isActive,
        isDeleted:     state.isDeleted ?? false,
        deletedAt:     state.deletedAt ?? null,
        districtCount,
        expectedDistrictCount: state.expectedDistrictCount ?? 0,
        adminCount,
        totalAreas,
        targetAreas:   state.targetAreas  ?? 0,
        totalSalons,
        targetSalons:  state.targetSalons ?? 0,
        activeSalons,
        avgRating,
        totalBookings,
        totalGbvInPaise,
        coverage,
        territory,
        manualTerritoryOverride: state.manualTerritoryOverride ?? null,
        notes:         state.notes ?? null,
        stateAdmin:    stateAdmin ? {
          id:         stateAdmin._id,
          name:       stateAdmin.name,
          phone:      stateAdmin.phone,
          email:      stateAdmin.email,
          status:     stateAdmin.accountStatus,
          assignedAt: stateAdmin.createdAt,
        } : null,
        backupAdmin:   backupAdmin ? {
          id:         backupAdmin._id,
          name:       backupAdmin.name,
          phone:      backupAdmin.phone,
          email:      backupAdmin.email,
          status:     backupAdmin.accountStatus,
          assignedAt: backupAdmin.createdAt,
        } : null,
        createdAt:     state.createdAt,
        updatedAt:     state.updatedAt,
      },
    });
  } catch (err) { next(err) }
};
/**
 * PATCH /api/admin/states/:id
 *
 * CHANGED: previously only accepted `name` and `isActive`. Now also
 * accepts: code, capital, zone, timezone, notes, targetAreas,
 * targetSalons, expectedDistrictCount, manualTerritoryOverride.
 */
export const updateState = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid state ID"));

    const {
      name, isActive, code, capital, zone, timezone, notes,
      targetAreas, targetSalons, expectedDistrictCount, manualTerritoryOverride,
    } = req.body;
    const updates = {};

    if (name !== undefined) {
      const trimmed = name.trim().replace(/\s+/g, " ");
      const existing = await State.findOne({
        name: { $regex: `^${escapeRegex(trimmed)}$`, $options: "i" },
        _id: { $ne: req.params.id },
      });
      if (existing) return next(Errors.conflict(`State "${trimmed}" already exists`));
      updates.name = trimmed;
    }

    if (code !== undefined) {
      const trimmedCode = code.trim().toUpperCase();
      if (!/^[A-Z]{2,3}$/.test(trimmedCode)) {
        return next(Errors.badRequest("State code must be 2-3 uppercase letters"));
      }
      const existingCode = await State.findOne({
        code: trimmedCode,
        _id: { $ne: req.params.id },
      });
      if (existingCode) return next(Errors.conflict(`State code "${trimmedCode}" already in use`));
      updates.code = trimmedCode;
    }

    if (capital !== undefined) updates.capital = capital?.trim() || null;

    if (zone !== undefined) {
      const validZones = ["NORTH", "SOUTH", "EAST", "WEST", "CENTRAL", "NE", null];
      if (!validZones.includes(zone)) return next(Errors.badRequest("Invalid zone value"));
      updates.zone = zone;
    }
    if (timezone !== undefined) updates.timezone = timezone?.trim() || "IST (UTC+5:30)";
    if (notes !== undefined)    updates.notes    = notes?.trim() || null;

    if (targetAreas !== undefined) {
      const val = Number(targetAreas);
      if (isNaN(val) || val < 0) return next(Errors.badRequest("targetAreas must be a non-negative number"));
      updates.targetAreas = val;
    }

    if (targetSalons !== undefined) {
      const val = Number(targetSalons);
      if (isNaN(val) || val < 0) return next(Errors.badRequest("targetSalons must be a non-negative number"));
      updates.targetSalons = val;
    }

    if (expectedDistrictCount !== undefined) {
      const val = Number(expectedDistrictCount);
      if (isNaN(val) || val < 0) return next(Errors.badRequest("expectedDistrictCount must be a non-negative number"));
      updates.expectedDistrictCount = val;
    }

    if (manualTerritoryOverride !== undefined) {
      const validTerritories = ["OPEN", "PARTIAL", "CLOSED", null];
      if (!validTerritories.includes(manualTerritoryOverride)) {
        return next(Errors.badRequest("Invalid manualTerritoryOverride value"));
      }
      updates.manualTerritoryOverride = manualTerritoryOverride;
    }

    if (isActive !== undefined) updates.isActive = Boolean(isActive);

    const state = await State.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    );
    if (!state) return next(Errors.notFound("State not found"));

    return successResponse(res, {
      message: "State updated",
      data: {
        id: state._id, name: state.name, code: state.code, capital: state.capital,
        zone: state.zone, timezone: state.timezone, notes: state.notes,
        targetAreas: state.targetAreas, targetSalons: state.targetSalons,
        expectedDistrictCount: state.expectedDistrictCount,
        manualTerritoryOverride: state.manualTerritoryOverride,
        isActive: state.isActive,
      },
    });
  } catch (err) { next(err) }
};


/**
 * DELETE /api/admin/states/:id
 * ARCHIVE — soft, fully reversible. Distinct from Deactivate (PATCH
 * with isActive:false, which keeps the state visible/counted). Archive
 * additionally sets isDeleted, so the state drops out of normal active
 * listings. BUG FIX: previously set `deletedAt` which never existed on
 * the schema before (Mongoose strict mode silently dropped it) — now
 * State.js has deletedAt as a real field, and isDeleted is now
 * correctly flipped to true here too (it never was before).
 */
export const deleteState = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid state ID"));

    const districtCount = await District.countDocuments({ stateRef: req.params.id, isActive: true });
    if (districtCount > 0) {
      return next(Errors.conflict(`Cannot archive — ${districtCount} districts exist`));
    }

    const state = await State.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: false, isDeleted: true, deletedAt: new Date() } },
      { new: true }
    );
    if (!state) return next(Errors.notFound("State not found"));

    return successResponse(res, {
      message: "State archived",
      data: { id: state._id, name: state.name, isActive: state.isActive, isDeleted: state.isDeleted, deletedAt: state.deletedAt },
    });
  } catch (err) { next(err) }
};

/**
 * PATCH /api/admin/states/:id/restore
 * Reverses archiveState/deleteState — clears isDeleted + deletedAt and
 * reactivates the state. New endpoint, no equivalent existed before.
 */
export const restoreState = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid state ID"));

    const state = await State.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: true, isDeleted: false, deletedAt: null } },
      { new: true }
    );
    if (!state) return next(Errors.notFound("State not found"));

    return successResponse(res, {
      message: "State restored",
      data: { id: state._id, name: state.name, isActive: state.isActive, isDeleted: state.isDeleted },
    });
  } catch (err) { next(err) }
};


/**
 * GET /api/admin/states/:id/analytics
 * NEW ENDPOINT — powers StateDetailPage's Analytics tab
 * (booking trend, Gross Booking Value trend, top districts by bookings)
 *
 * Bookings don't store stateRef directly — they only have salonRef.
 * So we join Booking → Salon → read location.territory.stateRef to
 * scope bookings to this state.
 *
 * Only status=COMPLETED bookings are counted, both for the booking
 * count and for GBV — a HOLD/CANCELLED/EXPIRED booking never
 * generated real business, so including it would inflate both
 * "demand" and "revenue" numbers in a misleading way.
 */
export const getStateAnalytics = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid state ID"));

    const state = await State.findById(req.params.id).lean();
    if (!state) return next(Errors.notFound("State not found"));

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(state._id)) {
      return next(Errors.forbidden("Access denied"));
    }

    // How many months of trend to return — default 6, capped 1-12
    const months = Math.min(Math.max(parseInt(req.query.months, 10) || 6, 1), 12);
    const since  = new Date();
    since.setMonth(since.getMonth() - (months - 1));
    since.setDate(1);
    since.setHours(0, 0, 0, 0);

    const baseMatch = {
      status:      "COMPLETED",
      completedAt: { $gte: since },
      isDeleted:   { $ne: true },
    };

    const [bookingTrendRaw, topDistrictsRaw] = await Promise.all([
      // Monthly bookings + GBV trend
      Booking.aggregate([
        { $match: baseMatch },
        { $lookup: { from: "salons", localField: "salonRef", foreignField: "_id", as: "salon" } },
        { $unwind: "$salon" },
        { $match: { "salon.location.territory.stateRef": state._id } },
        {
          $group: {
            _id:        { $dateToString: { format: "%Y-%m", date: "$completedAt" } },
            bookings:   { $sum: 1 },
            gbvInPaise: { $sum: "$totalAmountInPaise" },
          },
        },
        { $sort: { _id: 1 } },
      ]),

      // Top 5 districts by booking volume (within the same window)
      Booking.aggregate([
        { $match: baseMatch },
        { $lookup: { from: "salons", localField: "salonRef", foreignField: "_id", as: "salon" } },
        { $unwind: "$salon" },
        { $match: { "salon.location.territory.stateRef": state._id } },
        {
          $group: {
            _id:        "$salon.location.territory.districtRef",
            bookings:   { $sum: 1 },
            gbvInPaise: { $sum: "$totalAmountInPaise" },
          },
        },
        { $sort: { bookings: -1 } },
        { $limit: 5 },
        { $lookup: { from: "districts", localField: "_id", foreignField: "_id", as: "district" } },
        { $unwind: { path: "$district", preserveNullAndEmptyArrays: true } },
        {
          $project: {
            _id:         0,
            districtId:  "$_id",
            districtName:{ $ifNull: ["$district.name", "Unknown"] },
            bookings:    1,
            gbvInPaise:  1,
          },
        },
      ]),
    ]);

    // NEW — salon count per top district. Kept as a separate small
    // aggregation (rather than folding into the pipeline above) because
    // it queries a different collection (Salon, matched by districtRef)
    // and only needs to run against the ≤5 district IDs already picked —
    // same pattern district.controller.js uses for its own salon counts.
    const topDistrictIds = topDistrictsRaw.map(d => d.districtId).filter(Boolean);
    const topDistrictSalonAggs = topDistrictIds.length > 0
      ? await Salon.aggregate([
          { $match: { "location.territory.districtRef": { $in: topDistrictIds }, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
          { $group: { _id: "$location.territory.districtRef", count: { $sum: 1 } } },
        ])
      : [];
    const topDistrictSalonMap = Object.fromEntries(topDistrictSalonAggs.map(s => [String(s._id), s.count]));

    const topDistricts = topDistrictsRaw.map(d => ({
      ...d,
      salonCount: topDistrictSalonMap[String(d.districtId)] ?? 0,
    }));

    return successResponse(res, {
      message: "State analytics fetched",
      data: {
        stateId:      state._id,
        stateName:    state.name,
        months,
        bookingTrend: bookingTrendRaw.map(b => ({
          month:      b._id,
          bookings:   b.bookings,
          gbvInPaise: b.gbvInPaise,
        })),
        topDistricts,
      },
    });
  } catch (err) { next(err) }
};

/**
 * GET /api/admin/states/:id/summary
 */
export const getStateSummary = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid state ID"));

    const state = await State.findById(req.params.id).lean();
    if (!state) return next(Errors.notFound("State not found"));

    const [districtCount, adminCount, totalAreas, totalSalons, serviceableAreas] = await Promise.all([
      District.countDocuments({ stateRef: state._id, isActive: true, isDeleted: { $ne: true } }),
      User.countDocuments({ stateRef: state._id, role: "ADMIN" }),
      Area.countDocuments({ stateRef: state._id, isActive: true }),
      Salon.countDocuments({ "location.territory.stateRef": state._id, "approval.status": "APPROVED" }),
      Area.countDocuments({ stateRef: state._id, isActive: true, isServiceable: true }),
    ]);

    const coverage  = totalAreas > 0 ? Math.round((serviceableAreas / totalAreas) * 100) : 0;
    const territory = state.manualTerritoryOverride
      || (totalAreas === 0 ? "CLOSED" : coverage >= 80 ? "OPEN" : coverage >= 40 ? "PARTIAL" : "CLOSED");


    return successResponse(res, {
      message: "State summary fetched",
      data: {
        id: state._id, name: state.name, isActive: state.isActive,
        districtCount, adminCount, totalAreas, totalSalons, coverage, territory,
      },
    });
  } catch (err) { next(err) }
};

/**
 * POST /api/admin/states/:id/backup-admin
 * Assign or EDIT the STATE-level backup (SUPPORT) admin.
 *
 * If a backup admin already exists for this state, its details
 * (name/phone/email) are updated IN PLACE — no new document is
 * created, the old one isn't deactivated. Only when no backup admin
 * exists yet does this create a fresh one.
 */
export const assignStateBackupAdmin = async (req, res, next) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    if (!isValidId(req.params.id)) {
      await session.abortTransaction();
      return next(Errors.badRequest("Invalid state ID"));
    }

    const state = await State.findById(req.params.id).session(session);
    if (!state) {
      await session.abortTransaction();
      return next(Errors.notFound("State not found"));
    }

    let { adminName, phone, email } = req.body;

    if (!adminName || !phone) {
      await session.abortTransaction();
      return next(Errors.badRequest("Required fields: adminName, phone"));
    }

    adminName = adminName.trim().replace(/\s+/g, " ");

    const cleanPhone = phone.replace(/\D/g, "");
    if (cleanPhone.length !== 10) {
      await session.abortTransaction();
      return next(Errors.badRequest("Phone must be exactly 10 digits"));
    }
    phone = cleanPhone;

    const existingBackupAdmin = await User.findOne({
      stateRef:     state._id,
      role:         "ADMIN",
      adminLevel:   "STATE",
      adminSubRole: "SUPPORT",
      isDeleted:    { $ne: true },
    }).session(session);

    // Uniqueness checks must exclude the backup admin's own existing
    // record (otherwise editing without changing phone/email would
    // always "collide" with itself).
    const [existingPhone, existingEmail] = await Promise.all([
      User.findOne({
        phone, role: "ADMIN", isDeleted: { $ne: true },
        _id: { $ne: existingBackupAdmin?._id },
      }).session(session),
      email?.trim()
        ? User.findOne({
            email: email.trim(), role: "ADMIN", isDeleted: { $ne: true },
            _id: { $ne: existingBackupAdmin?._id },
          }).session(session)
        : null,
    ]);

    if (existingPhone) {
      await session.abortTransaction();
      return next(Errors.conflict("Phone already linked to another admin account"));
    }

    if (existingEmail) {
      await session.abortTransaction();
      return next(Errors.conflict("Email already linked to another admin account"));
    }

    let admin;
    let credentialsReset = true;

    if (existingBackupAdmin) {
      // EDIT in place — same record, just updated details. A changed phone
      // or email (or a never-assigned seed account) is a new employee: the
      // old credentials are wiped and the new holder must activate via OTP.
      const newEmail = email?.trim() || null;
      credentialsReset =
        existingBackupAdmin.phone !== phone ||
        (existingBackupAdmin.email || null) !== newEmail ||
        !existingBackupAdmin.adminAssignedAt;
      existingBackupAdmin.name  = adminName;
      existingBackupAdmin.phone = phone;
      existingBackupAdmin.email = newEmail;
      if (credentialsReset) await markAdminAssigned(existingBackupAdmin, req.user?._id);
      await existingBackupAdmin.save({ session });
      admin = existingBackupAdmin;
    } else {
      // No backup admin yet — create a new one.
      [admin] = await User.create([{
        name:               adminName,
        phone,
        email:              email?.trim() || null,
        role:               "ADMIN",
        adminLevel:         "STATE",
        adminSubRole:       "SUPPORT",
        stateRef:           state._id,
        countryRef:         state.countryRef,
        isEmailVerified:    true,
        ...(await adminAssignmentFields(req.user?._id)),
      }], { session });
    }

    await session.commitTransaction();

    if (credentialsReset) {
      await revokeAllSessions(admin._id);
      logAdminAction({
        adminId: req.user?._id, action: AUDIT_ACTIONS.ADMIN_ACCOUNT_ASSIGNED,
        targetType: "ADMIN_ACCOUNT", targetId: admin._id,
        meta: { adminLevel: "STATE", adminSubRole: "SUPPORT", stateRef: state._id, via: "assignStateBackupAdmin" },
      req,
      });
    }

    return successResponse(res, {
      message: existingBackupAdmin
        ? `Backup admin updated for "${state.name}"`
        : `Backup admin assigned for "${state.name}"`,
      data: {
        state: { id: state._id, name: state.name },
        admin: {
          id: admin._id, name: admin.name, phone: admin.phone, email: admin.email,
          adminLevel: admin.adminLevel, adminSubRole: admin.adminSubRole,
        },
      },
    });
  } catch (err) {
    await session.abortTransaction();
    next(err);
  } finally {
    session.endSession();
  }
};