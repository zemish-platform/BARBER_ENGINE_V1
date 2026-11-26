/**
 * BARBER ENGINE V1
 * backend/controllers/district.controller.js
 * District Controller — Location Module
 *
 * Fixes applied over previous version:
 * 1. createDistrictWithAdmin — now collects `code` (required by schema)
 *    and treats `geo` as optional input; no longer crashes on create.
 * 2. deleteDistrict — now actually sets isDeleted:true (was only
 *    isActive:false before — archived districts could never be
 *    re-created under the same name/code due to the partial unique
 *    indexes). Renamed intent to "archiveDistrict" in comments.
 * 3. restoreDistrict — NEW. Reverses archiveDistrict.
 * 4. getDistrictById — extended (not rewritten) to also return
 *    territory, coverage, capital, pincodesCount, targets, notes,
 *    admin object, live business KPIs (areas/cities, salons, active
 *    salons, bookings, avgRating, totalGbvInPaise, pendingApprovals).
 * 5. updateDistrict — extended to accept the full editable field set
 *    matching updateState's pattern (capital, notes, targetAreas,
 *    targetSalons, pincodesCount, manualTerritoryOverride, isActive).
 *    `name` logic unchanged from before.
 * 6. getDistrictAnalytics — NEW. Booking trend + GBV trend + top
 *    cities, same Booking→Salon join pattern as getStateAnalytics.
 * 7. getDistrictSummary — NEW. Lightweight KPI card endpoint.
 * 8. assignDistrictAdmin — NEW. Assign/transfer the single primary
 *    district admin (One District = One Admin — no backup/support
 *    concept at this level, unlike State).
 *
 * NOTE — City vs Area: this file queries the `City` model for
 * district-level locality counts/lists (matches the previous
 * version's behavior). Response field names are kept deliberately
 * neutral (`cityCount`, `topCities`) pending final business
 * confirmation of whether the District Detail "Areas" tab should
 * show City-level or Area-level data. If that decision changes,
 * only the model reference needs to change — not the controller
 * shape or the routes.
 */

import mongoose from "mongoose";
import AdminAuditLog from "../models/AdminAuditLog.js";
import Booking from "../models/Booking.js";
import City from "../models/City.js";
import District from "../models/District.js";
import Salon from "../models/Salon.js";
import State from "../models/State.js";
import User from "../models/User.js";
import { AUDIT_ACTIONS } from "../utils/auditActions.js";
import { logAdminAction } from "../utils/auditLog.js";
import { Errors, successResponse } from "../utils/response.js";
import { adminAssignmentFields, markAdminAssigned } from "../services/adminCredential.service.js";
import { revokeAllSessions } from "../services/session.service.js";

const isValidId   = (id)  => mongoose.Types.ObjectId.isValid(id);
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Admin secure activation: no shared/temporary password exists any more.
// Newly assigned admins get an unusable password and must activate via OTP
// (services/adminCredential.service.js).

const SORT_MAP = {
  name:    { name: 1 },
  newest:  { createdAt: -1 },
  oldest:  { createdAt: 1 },
  cities:  { cityCount: -1 },
};

// Shared territory formula — identical rule to State module:
// manual override wins; otherwise derived from coverage %.
const getTerritoryStatus = (totalCities, serviceableCities, override) => {
  if (override) return override;
  if (totalCities === 0) return "CLOSED";
  const pct = (serviceableCities / totalCities) * 100;
  if (pct >= 80) return "OPEN";
  if (pct >= 40) return "PARTIAL";
  return "CLOSED";
};

/**
 * POST /api/districts
 * Create district + auto-create DISTRICT admin
 * INDIA + STATE admin only (STATE admin scoped to own state)
 */
export const createDistrictWithAdmin = async (req, res, next) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    const creator = await User.findById(req.user.id).session(session);
    if (!creator) {
      await session.abortTransaction();
      return next(Errors.notFound("Requesting admin not found"));
    }

    if (creator.role !== "ADMIN" || !["INDIA", "STATE"].includes(creator.adminLevel)) {
      await session.abortTransaction();
      return next(Errors.forbidden("Only INDIA or STATE admin can create districts"));
    }

    let {
      districtName, districtCode, stateId, adminName, phone, email,
      capital, geo, // geo optional: { lat, lng }
    } = req.body;

    // FIX — `districtCode` is now required input (schema requires
    // `code`, which previously was never sent, crashing every create).
    if (!districtName || !districtCode || !stateId || !adminName || !phone || !email?.trim()) {
      await session.abortTransaction();
      return next(Errors.badRequest(
        "Required fields: districtName, districtCode, stateId, adminName, phone, email"
      ));
    }

    if (!isValidId(stateId)) {
      await session.abortTransaction();
      return next(Errors.badRequest("Invalid stateId"));
    }

    districtName = districtName.trim().replace(/\s+/g, " ");
    districtCode = districtCode.trim().toUpperCase();
    adminName    = adminName.trim().replace(/\s+/g, " ");

    if (!/^[A-Z0-9]{2,20}$/.test(districtCode)) {
      await session.abortTransaction();
      return next(Errors.badRequest("District code must be 2-20 alphanumeric characters"));
    }

    const cleanPhone = phone.replace(/\D/g, "");
    if (cleanPhone.length !== 10) {
      await session.abortTransaction();
      return next(Errors.badRequest("Phone must be exactly 10 digits"));
    }
    phone = cleanPhone;

    const state = await State.findById(stateId).session(session);
    if (!state || !state.isActive) {
      await session.abortTransaction();
      return next(Errors.notFound("State not found or inactive"));
    }

    if (creator.adminLevel === "STATE" && String(creator.stateRef) !== String(stateId)) {
      await session.abortTransaction();
      return next(Errors.forbidden("You can only create districts in your own state"));
    }

    const emailFilter = email?.trim()
      ? { $or: [{ phone, role: "ADMIN" }, { email: email.trim(), role: "ADMIN" }] }
      : { phone, role: "ADMIN" };

    const [existingDistrict, existingCode, existingAdmin] = await Promise.all([
      District.findOne({
        name:      { $regex: `^${escapeRegex(districtName)}$`, $options: "i" },
        stateRef:  stateId,
        isDeleted: false,
      }).session(session),
      District.findOne({
        code:      districtCode,
        stateRef:  stateId,
        isDeleted: false,
      }).session(session),
      User.findOne(emailFilter).session(session),
    ]);

    if (existingDistrict) {
      await session.abortTransaction();
      return next(Errors.conflict(`District "${districtName}" already exists in this state`));
    }

    if (existingCode) {
      await session.abortTransaction();
      return next(Errors.conflict(`District code "${districtCode}" already in use in this state`));
    }

    if (existingAdmin) {
      await session.abortTransaction();
      return next(Errors.conflict("Phone already linked to another admin account"));
    }

    // Optional geo — only attach if both lat/lng were actually sent.
    let geoDoc = undefined;
    if (geo && typeof geo.lat === "number" && typeof geo.lng === "number") {
      geoDoc = { type: "Point", coordinates: [geo.lng, geo.lat] };
    }

    const [district] = await District.create([{
      name:       districtName,
      code:       districtCode,
      stateRef:   stateId,
      countryRef: creator.countryRef,
      capital:    capital?.trim() || null,
      geo:        geoDoc,
      createdBy:  creator._id,
      isActive:   true,
    }], { session });

    const [admin] = await User.create([{
      name:              adminName,
      phone,
      email:             email?.trim() || null,
      role:              "ADMIN",
      adminLevel:        "DISTRICT",
      adminSubRole:      "PRIMARY",
      stateRef:          stateId,
      districtRef:       district._id,
      countryRef:        creator.countryRef,
      isEmailVerified:    true,
      ...(await adminAssignmentFields(creator._id)),
    }], { session });

    // Link the new admin back onto the district (primaryAdminRef —
    // enforces the unique-partial-index "one admin per district" rule).
    district.primaryAdminRef = admin._id;
    await district.save({ session });

    await session.commitTransaction();

    logAdminAction({
      adminId: req.user.id,
      action: AUDIT_ACTIONS.DISTRICT_CREATED,
      targetType: "DISTRICT",
      targetId: district._id,
      meta: { name: district.name, code: district.code, stateId: district.stateRef },
      req,
    });
    return successResponse(res, {
      message: `District "${districtName}" created with DISTRICT admin`,
      data: {
        district: {
          id:        district._id,
          name:      district.name,
          code:      district.code,
          stateId:   district.stateRef,
          stateName: state.name,
        },
        admin: {
          id:           admin._id,
          name:         admin.name,
          phone:        admin.phone,
          email:        admin.email,
          adminLevel:   admin.adminLevel,
          activation:   "PENDING_ACTIVATION",
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

/**
 * GET /api/districts
 * REWRITTEN as a single aggregation pipeline (was: separate find() +
 * parallel aggregations). Fixes 3 real gaps vs the original frontend
 * design:
 * 1. Search now matches district name OR the linked district admin's
 *    name (was: district name only).
 * 2. unassignedCount is now computed over the FULL filtered result
 *    set, not just the current page.
 * 3. Territory filter is now applied INSIDE the pipeline, before
 *    pagination — so `total`/`totalPages` are correct even when a
 *    territory filter is active (was: filtered after the fact, so
 *    pagination metadata could be wrong).
 */

export const getDistricts = async (req, res, next) => {
  try {
    const {
      page = 1, limit = 20, sort = "name", search = "",
      stateId, isActive, territory, unassigned,
    } = req.query;

    const pageNum  = Math.max(parseInt(page, 10), 1);
    const limitNum = Math.min(Math.max(parseInt(limit, 10), 1), 100);
    const skip     = (pageNum - 1) * limitNum;

    const baseMatch = { isDeleted: { $ne: true } };
    if (stateId && isValidId(stateId)) baseMatch.stateRef = new mongoose.Types.ObjectId(stateId);
    if (isActive !== undefined) baseMatch.isActive = isActive === "true";



    if (req.user.adminLevel === "STATE") {
      baseMatch.stateRef = new mongoose.Types.ObjectId(req.user.stateRef);
    } else if (req.user.adminLevel === "DISTRICT") {
      baseMatch._id = new mongoose.Types.ObjectId(req.user.districtRef);
    }

    const sortStage = { name: { name: 1 }, newest: { createdAt: -1 }, oldest: { createdAt: 1 } }[sort] || { name: 1 };

    const pipeline = [
      { $match: baseMatch },

      // State (for display + code)
      { $lookup: { from: "states", localField: "stateRef", foreignField: "_id", as: "state" } },
      { $unwind: { path: "$state", preserveNullAndEmptyArrays: true } },

      // District admin (for display + search-by-admin-name)
      {
        $lookup: {
          from: "users",
          let: { adminId: "$primaryAdminRef" },
          pipeline: [
            { $match: { $expr: { $eq: ["$_id", "$$adminId"] }, isDeleted: { $ne: true } } },
            { $project: { name: 1, phone: 1 } },
          ],
          as: "districtAdmin",
        },
      },
      { $unwind: { path: "$districtAdmin", preserveNullAndEmptyArrays: true } },

      // ADDITIVE - unassigned=true means "no REAL admin yet". Seed data
      // gives every district a placeholder admin with phone:null, so
      // primaryAdminRef is never actually empty. Real signal for "still
      // needs a real person assigned" is the linked admin's phone being null.
      ...(unassigned === "true"
        ? [{ $match: { $or: [ { districtAdmin: null }, { "districtAdmin.phone": null } ] } }]
        : []),

      // Cities — total + serviceable, via sub-pipeline counts (no
      // separate round trip, and correctly scoped per-district here).
      {
        $lookup: {
          from: "cities",
          let: { districtId: "$_id" },
          pipeline: [
            { $match: { $expr: { $eq: ["$districtRef", "$$districtId"] }, isActive: { $ne: false } } },
            {
              $group: {
                _id: null,
                total:       { $sum: 1 },
                serviceable: { $sum: { $cond: ["$isServiceable", 1, 0] } },
              },
            },
          ],
          as: "cityStats",
        },
      },
      { $unwind: { path: "$cityStats", preserveNullAndEmptyArrays: true } },

      // Salons — approved count
      {
        $lookup: {
          from: "salons",
          let: { districtId: "$_id" },
          pipeline: [
            { $match: { $expr: { $eq: ["$location.territory.districtRef", "$$districtId"] }, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
            { $count: "count" },
          ],
          as: "salonStats",
        },
      },
      { $unwind: { path: "$salonStats", preserveNullAndEmptyArrays: true } },

      // Derived fields: cityCount, salonCount, coverage, territory
      {
        $addFields: {
          cityCount:  { $ifNull: ["$cityStats.total", 0] },
          salonCount: { $ifNull: ["$salonStats.count", 0] },
          coverage: {
            $cond: [
              { $gt: [{ $ifNull: ["$cityStats.total", 0] }, 0] },
              { $round: [{ $multiply: [{ $divide: [{ $ifNull: ["$cityStats.serviceable", 0] }, "$cityStats.total"] }, 100] }, 0] },
              0,
            ],
          },
        },
      },
      {
        $addFields: {
          territory: {
            $cond: [
              { $ne: ["$manualTerritoryOverride", null] },
              "$manualTerritoryOverride",
              {
                $switch: {
                  branches: [
                    { case: { $eq: ["$cityCount", 0] },   then: "CLOSED" },
                    { case: { $gte: ["$coverage", 80] },  then: "OPEN" },
                    { case: { $gte: ["$coverage", 40] },  then: "PARTIAL" },
                  ],
                  default: "CLOSED",
                },
              },
            ],
          },
        },
      },

      // Search — district name OR district admin's name
      ...(search?.trim()
        ? [{
            $match: {
              $or: [
                { name: { $regex: escapeRegex(search.trim()), $options: "i" } },
                { "districtAdmin.name": { $regex: escapeRegex(search.trim()), $options: "i" } },
              ],
            },
          }]
        : []),

      // Territory filter — now applied BEFORE pagination
      ...(territory && ["OPEN", "PARTIAL", "CLOSED"].includes(territory)
        ? [{ $match: { territory } }]
        : []),
    ];

    // ── Facet: page of data + accurate total + unassignedCount, all
    // computed over the SAME filtered set in one round trip. ──
    const [result] = await District.aggregate([
      ...pipeline,
      {
        $facet: {
          data: [
            { $sort: sortStage },
            { $skip: skip },
            { $limit: limitNum },
            {
              $project: {
                id: "$_id", _id: 0,
                name: 1, code: 1,
                state: { id: "$state._id", name: "$state.name", code: "$state.code" },
                isActive: 1,
                cityCount: 1, salonCount: 1, coverage: 1, territory: 1,
                closedReason: 1,
                districtAdmin: {
                  $cond: [
                    { $ifNull: ["$districtAdmin", false] },
                    { id: "$districtAdmin._id", name: "$districtAdmin.name", phone: "$districtAdmin.phone" },
                    null,
                  ],
                },
                createdAt: 1,
              },
            },
          ],
          totalCount:      [{ $count: "count" }],
          unassignedCount: [{ $match: { primaryAdminRef: null } }, { $count: "count" }],
          statusCounts: [
            {
              $group: {
                _id: null,
                active:   { $sum: { $cond: ["$isActive", 1, 0] } },
                inactive: { $sum: { $cond: ["$isActive", 0, 1] } },
              },
            },
          ],
          citySalonTotals: [
            {
              $group: {
                _id: null,
                totalCities: { $sum: "$cityCount" },
                totalSalons: { $sum: "$salonCount" },
                avgCoverage: { $avg: "$coverage" },
              },
            },
          ],
          territoryCounts: [
            { $group: { _id: "$territory", count: { $sum: 1 } } },
          ],
        },
      },
    ]);

    const total       = result.totalCount[0]?.count ?? 0;
    const unassignedN = result.unassignedCount[0]?.count ?? 0;
    const statusCounts= result.statusCounts[0] ?? { active: 0, inactive: 0 };
    const totals      = result.citySalonTotals[0] ?? { totalCities: 0, totalSalons: 0, avgCoverage: 0 };
    const territoryCounts = Object.fromEntries(
      (result.territoryCounts || []).map(t => [t._id, t.count])
    );

    return successResponse(res, {
      message: "Districts fetched",
        data: result.data,
      pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total / limitNum) || 1 },
      meta: {
        unassignedCount: unassignedN,
        activeCount:     statusCounts.active,
        inactiveCount:   statusCounts.inactive,
        closedTerritoryCount: territoryCounts.CLOSED ?? 0,
        totalCities:     totals.totalCities,
        totalSalons:     totals.totalSalons,
        avgCoverage:     Math.round(totals.avgCoverage || 0),
      },
    });
  } catch (err) { next(err) }
};



/**
 * GET /api/districts/:id
 * EXTENDED (not rewritten) — now also returns territory, coverage,
 * capital, pincodesCount, targets, notes, enriched admin object, and
 * live business KPIs, matching getStateById's shape.
 */
export const getDistrictById = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const district = await District.findById(req.params.id)
      .populate("stateRef", "name code")
      .lean();
    if (!district || district.isDeleted) return next(Errors.notFound("District not found"));

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(district.stateRef?._id)) {
      return next(Errors.forbidden("Access denied"));
    }
    if (req.user.adminLevel === "DISTRICT" && String(req.user.districtRef) !== String(district._id)) {
      return next(Errors.forbidden("Access denied"));
    }

    const [
      totalCities, serviceableCities, totalSalons, activeSalons,
      ratingAgg, districtAdmin, bookingAgg, pendingApprovalCount,
    ] = await Promise.all([
      City.countDocuments({ districtRef: district._id, isActive: { $ne: false } }),
      City.countDocuments({ districtRef: district._id, isActive: { $ne: false }, isServiceable: true }),
      Salon.countDocuments({ "location.territory.districtRef": district._id, "approval.status": "APPROVED", isDeleted: { $ne: true } }),

      Salon.countDocuments({
        "location.territory.districtRef": district._id,
        "approval.status": "APPROVED",
        isDeleted: { $ne: true },
        "business.isSuspended": false,
        "business.isForceClosed": false,
      }),

      Salon.aggregate([
        { $match: { "location.territory.districtRef": district._id, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
        { $group: { _id: null, totalRatingSum: { $sum: "$rating.total" }, totalRatingCount: { $sum: "$rating.count" } } },
      ]),

      User.findOne({ districtRef: district._id, role: "ADMIN", adminLevel: "DISTRICT", isDeleted: { $ne: true } })
        .select("name phone email accountStatus createdAt").lean(),

      Booking.aggregate([
        { $match: { status: "COMPLETED", isDeleted: { $ne: true } } },
        { $lookup: { from: "salons", localField: "salonRef", foreignField: "_id", as: "salon" } },
        { $unwind: "$salon" },
        { $match: { "salon.location.territory.districtRef": district._id } },
        { $group: { _id: null, totalBookings: { $sum: 1 }, totalGbvInPaise: { $sum: "$totalAmountInPaise" } } },
      ]),

      // Pending salon approvals — owned by the Salon/Approval Engine;
      // District just filters by districtRef, never owns this data.
      Salon.countDocuments({
        "location.territory.districtRef": district._id,
        "approval.status": "PENDING",
        isDeleted: { $ne: true },
      }),
    ]);

    const coverage    = totalCities > 0 ? Math.round((serviceableCities / totalCities) * 100) : 0;
    const territory   = getTerritoryStatus(totalCities, serviceableCities, district.manualTerritoryOverride);
    const ratingData  = ratingAgg[0];
    const avgRating   = ratingData && ratingData.totalRatingCount > 0
      ? Number((ratingData.totalRatingSum / ratingData.totalRatingCount).toFixed(1))
      : 0;
    const bookingData = bookingAgg[0];

    return successResponse(res, {
      message: "District fetched",
      data: {
        id:        district._id,
        name:      district.name,
        code:      district.code,
        state:     { id: district.stateRef?._id, name: district.stateRef?.name, code: district.stateRef?.code },
        capital:   district.capital ?? null,
        isActive:  district.isActive,
        pincodesCount: district.pincodesCount ?? 0,
        targetCities:  district.targetAreas  ?? 0, // NOTE: field named targetAreas in schema — see City/Area note at top
        targetSalons:  district.targetSalons ?? 0,
        notes:     district.notes ?? null,

        cityCount:     totalCities,
        totalSalons,
        activeSalons,
        pendingApprovalCount,
        totalBookings: bookingData?.totalBookings   ?? 0,
        totalGbvInPaise: bookingData?.totalGbvInPaise ?? 0,
        avgRating,
        coverage,
        territory,
        manualTerritoryOverride: district.manualTerritoryOverride ?? null,

        districtAdmin: districtAdmin ? {
          id:         districtAdmin._id,
          name:       districtAdmin.name,
          phone:      districtAdmin.phone,
          email:      districtAdmin.email,
          status:     districtAdmin.accountStatus,
          assignedAt: districtAdmin.createdAt,
        } : null,

        createdAt: district.createdAt,
        updatedAt: district.updatedAt,
      },
    });
  } catch (err) { next(err) }
};

/**
 * PATCH /api/districts/:id
 * EXTENDED — now accepts the full editable field set (was: name,
 * isActive only). `name` uniqueness-check logic unchanged from
 * before; new fields follow updateState's validation pattern.
 */
export const updateDistrict = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const district = await District.findById(req.params.id).lean();
    if (!district || district.isDeleted) return next(Errors.notFound("District not found"));

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(district.stateRef)) {
      return next(Errors.forbidden("You can only update districts in your own state"));
    }
    if (req.user.adminLevel === "DISTRICT" && String(req.user.districtRef) !== String(district._id)) {
      return next(Errors.forbidden("You can only update your own district"));
    }

    const {
      name, code, isActive, capital, notes, closedReason,
      pincodesCount, targetAreas, targetSalons, manualTerritoryOverride,
    } = req.body;
    const updates = {};

    if (name !== undefined) {
      const trimmed = name.trim().replace(/\s+/g, " ");
      const existing = await District.findOne({
        name:      { $regex: `^${escapeRegex(trimmed)}$`, $options: "i" },
        stateRef:  district.stateRef,
        isDeleted: false,
        _id:       { $ne: req.params.id },
      });
      if (existing) return next(Errors.conflict(`District "${trimmed}" already exists in this state`));
      updates.name = trimmed;
    }

    // District code — belongs to the "Transfer District" concept, not
    // a casual field edit, per the locked hierarchy rule. Kept
    // editable here ONLY because it's still state-scoped (does not
    // change stateRef) — renaming the code within the same state is
    // safe; MOVING a district to a different state is intentionally
    // NOT supported by this endpoint (stateRef is immutable via PATCH).
    if (code !== undefined) {
      const trimmedCode = code.trim().toUpperCase();
      if (!/^[A-Z0-9]{2,20}$/.test(trimmedCode)) {
        return next(Errors.badRequest("District code must be 2-20 alphanumeric characters"));
      }
      const existingCode = await District.findOne({
        code:      trimmedCode,
        stateRef:  district.stateRef,
        isDeleted: false,
        _id:       { $ne: req.params.id },
      });
      if (existingCode) return next(Errors.conflict(`District code "${trimmedCode}" already in use in this state`));
      updates.code = trimmedCode;
    }

    if (capital !== undefined) updates.capital = capital?.trim() || null;
    if (notes   !== undefined) updates.notes   = notes?.trim()   || null;

    if (pincodesCount !== undefined) {
      const val = Number(pincodesCount);
      if (isNaN(val) || val < 0) return next(Errors.badRequest("pincodesCount must be a non-negative number"));
      updates.pincodesCount = val;
    }

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

    if (manualTerritoryOverride !== undefined) {
      const validValues = ["OPEN", "PARTIAL", "CLOSED", null];
      if (!validValues.includes(manualTerritoryOverride)) {
        return next(Errors.badRequest("Invalid manualTerritoryOverride value"));
      }
      updates.manualTerritoryOverride = manualTerritoryOverride;
    }

    if (closedReason !== undefined) {          // ← YAHI SAHI JAGAH HAI
      updates.closedReason = closedReason?.trim() || null;
    }

    if (isActive !== undefined) updates.isActive = Boolean(isActive);

    updates.updatedBy = req.user.id;

    const updated = await District.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).populate("stateRef", "name code");

    if (!updated) return next(Errors.notFound("District not found"));

    logAdminAction({
      adminId: req.user.id,
      action: AUDIT_ACTIONS.DISTRICT_UPDATED,
      targetType: "DISTRICT",
      targetId: updated._id,
      meta: { changedFields: Object.keys(updates).filter(k => k !== "updatedBy") },
      req,
    });  
    return successResponse(res, {
      message: "District updated",
      data: {
        id: updated._id, name: updated.name, code: updated.code,
        state: { id: updated.stateRef?._id, name: updated.stateRef?.name },
        capital: updated.capital, notes: updated.notes, closedReason: updated.closedReason,
        pincodesCount: updated.pincodesCount,
        targetAreas: updated.targetAreas, targetSalons: updated.targetSalons,
        manualTerritoryOverride: updated.manualTerritoryOverride,
        isActive: updated.isActive,
      },
    });
  } catch (err) { next(err) }
};

/**
 * DELETE /api/districts/:id
 * ARCHIVE — soft, fully reversible. FIX: previously only set
 * isActive:false; isDeleted was never flipped, so the partial-unique
 * indexes on name/code/slug/normalizedName would permanently block
 * re-creating a district under the same name/code even after
 * "deleting" it. Now correctly sets isDeleted:true + deletedAt,
 * matching the fix already applied to State.
 */
export const deleteDistrict = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const districtToDelete = await District.findById(req.params.id).lean();
    if (!districtToDelete || districtToDelete.isDeleted) return next(Errors.notFound("District not found"));

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(districtToDelete.stateRef)) {
      return next(Errors.forbidden("You can only archive districts in your own state"));
    }

    const cityCount = await City.countDocuments({ districtRef: req.params.id, isActive: { $ne: false } });
    if (cityCount > 0) {
      return next(Errors.conflict(`Cannot archive — ${cityCount} cities exist in this district`));
    }

    const district = await District.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: false, isDeleted: true, deletedAt: new Date(), updatedBy: req.user.id } },
      { new: true }
    );
    if (!district) return next(Errors.notFound("District not found"));

    logAdminAction({
      adminId: req.user.id,
      action: AUDIT_ACTIONS.DISTRICT_ARCHIVED,
      targetType: "DISTRICT",
      targetId: district._id,
      meta: { name: district.name },
      req,
    });

    return successResponse(res, {
      message: "District archived",
      data: {
        id: district._id, name: district.name,
        isActive: district.isActive, isDeleted: district.isDeleted, deletedAt: district.deletedAt,
      },
    });
  } catch (err) { next(err) }
};

/**
 * PATCH /api/districts/:id/restore
 * NEW — reverses deleteDistrict/archiveDistrict. No equivalent
 * existed before. Mirrors restoreState exactly.
 */
export const restoreDistrict = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const district = await District.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: true, isDeleted: false, deletedAt: null, updatedBy: req.user.id } },
      { new: true }
    );
    if (!district) return next(Errors.notFound("District not found"));

    logAdminAction({
      adminId: req.user.id,
      action: AUDIT_ACTIONS.DISTRICT_RESTORED,
      targetType: "DISTRICT",
      targetId: district._id,
      meta: { name: district.name },
      req,
    });

    return successResponse(res, {
      message: "District restored",
      data: { id: district._id, name: district.name, isActive: district.isActive, isDeleted: district.isDeleted },
    });
  } catch (err) { next(err) }
};

/**
 * GET /api/districts/:id/summary
 * NEW — lightweight KPI card, mirrors getStateSummary.
 */
export const getDistrictSummary = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const district = await District.findById(req.params.id).lean();
    if (!district || district.isDeleted) return next(Errors.notFound("District not found"));

    const [totalCities, totalSalons, serviceableCities, districtAdmin] = await Promise.all([
      City.countDocuments({ districtRef: district._id, isActive: { $ne: false } }),
      Salon.countDocuments({ "location.territory.districtRef": district._id, "approval.status": "APPROVED" }),
      City.countDocuments({ districtRef: district._id, isActive: { $ne: false }, isServiceable: true }),
      User.findOne({ districtRef: district._id, role: "ADMIN", adminLevel: "DISTRICT", isDeleted: { $ne: true } }).select("name phone").lean(),
    ]);

    const coverage  = totalCities > 0 ? Math.round((serviceableCities / totalCities) * 100) : 0;
    const territory = getTerritoryStatus(totalCities, serviceableCities, district.manualTerritoryOverride);

    return successResponse(res, {
      message: "District summary fetched",
      data: {
        id: district._id, name: district.name, isActive: district.isActive,
        cityCount: totalCities, totalSalons, coverage, territory,
        districtAdmin: districtAdmin ? { id: districtAdmin._id, name: districtAdmin.name, phone: districtAdmin.phone } : null,
      },
    });
  } catch (err) { next(err) }
};

/**
 * GET /api/districts/:id/analytics
 * NEW — powers District Dashboard/Analytics tab: booking trend, GBV
 * trend, top cities by booking volume. Same Booking→Salon join
 * pattern as getStateAnalytics; only status=COMPLETED bookings count
 * (a HOLD/CANCELLED/EXPIRED booking never generated real business).
 */
export const getDistrictAnalytics = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const district = await District.findById(req.params.id).lean();
    if (!district || district.isDeleted) return next(Errors.notFound("District not found"));

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(district.stateRef)) {
      return next(Errors.forbidden("Access denied"));
    }
    if (req.user.adminLevel === "DISTRICT" && String(req.user.districtRef) !== String(district._id)) {
      return next(Errors.forbidden("Access denied"));
    }

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

    const [bookingTrendRaw, topCitiesRaw] = await Promise.all([
      Booking.aggregate([
        { $match: baseMatch },
        { $lookup: { from: "salons", localField: "salonRef", foreignField: "_id", as: "salon" } },
        { $unwind: "$salon" },
        { $match: { "salon.location.territory.districtRef": district._id } },
        {
          $group: {
            _id:        { $dateToString: { format: "%Y-%m", date: "$completedAt" } },
            bookings:   { $sum: 1 },
            gbvInPaise: { $sum: "$totalAmountInPaise" },
          },
        },
        { $sort: { _id: 1 } },
      ]),

      Booking.aggregate([
        { $match: baseMatch },
        { $lookup: { from: "salons", localField: "salonRef", foreignField: "_id", as: "salon" } },
        { $unwind: "$salon" },
        { $match: { "salon.location.territory.districtRef": district._id } },
        {
          $group: {
            _id:        "$salon.location.territory.cityRef",
            bookings:   { $sum: 1 },
            gbvInPaise: { $sum: "$totalAmountInPaise" },
          },
        },
        { $sort: { bookings: -1 } },
        { $limit: 5 },
        { $lookup: { from: "cities", localField: "_id", foreignField: "_id", as: "city" } },
        { $unwind: { path: "$city", preserveNullAndEmptyArrays: true } },
        {
          $project: {
            _id: 0, cityId: "$_id",
            cityName: { $ifNull: ["$city.name", "Unknown"] },
            bookings: 1, gbvInPaise: 1,
          },
        },
      ]),
    ]);

    const topCityIds = topCitiesRaw.map(c => c.cityId).filter(Boolean);
    const topCitySalonAggs = topCityIds.length > 0
      ? await Salon.aggregate([
          { $match: { "location.territory.cityRef": { $in: topCityIds }, "approval.status": "APPROVED", isDeleted: { $ne: true } } },
          { $group: { _id: "$location.territory.cityRef", count: { $sum: 1 } } },
        ])
      : [];
    const topCitySalonMap = Object.fromEntries(topCitySalonAggs.map(s => [String(s._id), s.count]));

    const topCities = topCitiesRaw.map(c => ({
      ...c,
      salonCount: topCitySalonMap[String(c.cityId)] ?? 0,
    }));

    return successResponse(res, {
      message: "District analytics fetched",
      data: {
        districtId:   district._id,
        districtName: district.name,
        months,
        bookingTrend: bookingTrendRaw.map(b => ({
          month: b._id, bookings: b.bookings, gbvInPaise: b.gbvInPaise,
        })),
        topCities,
      },
    });
  } catch (err) { next(err) }
};

/**
 * POST /api/districts/:id/admin
 * NEW — Assign or TRANSFER the single primary district admin.
 *
 * Unlike State's SUPPORT-role backup admin, District has exactly one
 * admin (One District = One District Admin — no backup, no duplicate
 * ownership). This endpoint therefore behaves as a strict
 * assign-or-replace:
 *   - No existing admin  → create a new DISTRICT admin user, link it.
 *   - Existing admin      → the old admin user is deactivated
 *                            (accountStatus set to INACTIVE, districtRef
 *                            cleared) and a new admin user is created
 *                            and linked. This preserves a clean audit
 *                            trail (old user record still exists, just
 *                            no longer active/linked) rather than
 *                            silently overwriting the old admin's name/
 *                            phone/email on the same user document —
 *                            which would falsify who actually held the
 *                            role historically.
 */
export const assignDistrictAdmin = async (req, res, next) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    if (!isValidId(req.params.id)) {
      await session.abortTransaction();
      return next(Errors.badRequest("Invalid district ID"));
    }

    const district = await District.findById(req.params.id).session(session);
    if (!district || district.isDeleted) {
      await session.abortTransaction();
      return next(Errors.notFound("District not found"));
    }

    if (req.user.adminLevel === "STATE" && String(req.user.stateRef) !== String(district.stateRef)) {
      await session.abortTransaction();
      return next(Errors.forbidden("You can only assign admins in your own state"));
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

    const existingAdmin = district.primaryAdminRef
      ? await User.findById(district.primaryAdminRef).session(session)
      : null;

    const [existingPhone, existingEmail] = await Promise.all([
      User.findOne({
        phone, role: "ADMIN", isDeleted: { $ne: true },
        _id: { $ne: existingAdmin?._id },
      }).session(session),
      email?.trim()
        ? User.findOne({
            email: email.trim(), role: "ADMIN", isDeleted: { $ne: true },
            _id: { $ne: existingAdmin?._id },
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

    // Is the existing admin a placeholder (seed-time ghost, phone
    // never set) or a real person (genuine transfer)? Placeholder
    // admins get UPDATED in place -- their ID already exists and is
    // already linked to this district, so overwriting is correct and
    // avoids leaving 778 orphaned SUSPENDED user records behind.
    // Real transfers keep the old create-new + deactivate-old
    // behavior, to preserve who genuinely held the role historically.
    const isPlaceholder = existingAdmin && !existingAdmin.phone;


    let newAdmin;
    let wasPlaceholderConversion = false;

    if (isPlaceholder) {
      // Convert placeholder in place -- no new ID, no orphaned record.
      existingAdmin.name               = adminName;
      existingAdmin.phone              = phone;
      existingAdmin.email              = email?.trim() || null;
      existingAdmin.accountStatus      = "ACTIVE";
      existingAdmin.isEmailVerified    = true;
      await markAdminAssigned(existingAdmin, req.user.id);
      await existingAdmin.save({ session });
      newAdmin = existingAdmin;
      wasPlaceholderConversion = true;
    } else {
      // Real transfer (existing admin already had a real phone) OR
      // no existing admin at all -- original create-new behavior.
      if (existingAdmin) {
        existingAdmin.accountStatus = "SUSPENDED";
        existingAdmin.isDeleted     = true;
        await existingAdmin.save({ session });
      }

      [newAdmin] = await User.create([{
        name:              adminName,
        phone,
        email:             email?.trim() || null,
        role:              "ADMIN",
        adminLevel:        "DISTRICT",
        adminSubRole:      "PRIMARY",
        stateRef:          district.stateRef,
        districtRef:       district._id,
        countryRef:        district.countryRef,
        isEmailVerified:    true,
        ...(await adminAssignmentFields(req.user.id)),
      }], { session });
    }

    district.primaryAdminRef = newAdmin._id;
    district.updatedBy = req.user.id;
    await district.save({ session });

    await session.commitTransaction();

    // Kill any session held by the converted account or the previous holder.
    await revokeAllSessions(newAdmin._id);
    if (existingAdmin && !isPlaceholder) await revokeAllSessions(existingAdmin._id);

    logAdminAction({
      adminId: req.user.id,
      action: AUDIT_ACTIONS.DISTRICT_ADMIN_ASSIGNED,
      targetType: "DISTRICT",
      targetId: district._id,
      meta: {
        newAdminId: newAdmin._id, newAdminName: newAdmin.name,
        previousAdminId: wasPlaceholderConversion ? null : (existingAdmin?._id || null),
        wasTransfer: !isPlaceholder && !!existingAdmin,
        wasPlaceholderConversion,
      },
      req,
    });

    return successResponse(res, {
      message: (!isPlaceholder && existingAdmin)
        ? `District admin transferred for "${district.name}"`
        : `District admin assigned for "${district.name}"`,
      data: {
        district: { id: district._id, name: district.name },
        admin: {
          id: newAdmin._id, name: newAdmin.name, phone: newAdmin.phone,
          email: newAdmin.email, adminLevel: newAdmin.adminLevel,
          activation: "PENDING_ACTIVATION",
        },
        previousAdmin: (!isPlaceholder && existingAdmin)
          ? { id: existingAdmin._id, name: existingAdmin.name, status: "DEACTIVATED" }
          : null,
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
 * GET /api/districts/:id/audit
 * NEW — powers the District Detail Audit tab. Reads AdminAuditLog
 * entries scoped to this district (targetType: "DISTRICT",
 * targetId: this district's _id). Read-only, immutable — no
 * update/delete endpoint exists or will exist for this collection.
 */
export const getDistrictAuditLog = async (req, res, next) => {
  try {
    if (!isValidId(req.params.id)) return next(Errors.badRequest("Invalid district ID"));

    const district = await District.findById(req.params.id).select("_id isDeleted").lean();
    if (!district || district.isDeleted) return next(Errors.notFound("District not found"));

    const { page = 1, limit = 20 } = req.query;
    const pageNum  = Math.max(parseInt(page, 10), 1);
    const limitNum = Math.min(Math.max(parseInt(limit, 10), 1), 100);
    const skip     = (pageNum - 1) * limitNum;

    const filter = { targetType: "DISTRICT", targetId: district._id };

    const [logs, total] = await Promise.all([
      AdminAuditLog.find(filter)
        .populate("adminId", "name adminLevel")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean(),
      AdminAuditLog.countDocuments(filter),
    ]);

    return successResponse(res, {
      message: "Audit log fetched",
      data: logs.map(l => ({
        id:        l._id,
        action:    l.action,
        admin:     l.adminId ? { id: l.adminId._id, name: l.adminId.name, adminLevel: l.adminId.adminLevel } : null,
        meta:      l.meta,
        ip:        l.ip,
        createdAt: l.createdAt,
      })),
      pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total / limitNum) || 1 },
    });
  } catch (err) { next(err) }
};