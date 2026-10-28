/**
 * ============================================================
 * 📡 SOCKET.IO INFRASTRUCTURE
 * ============================================================
 *
 * ARCHITECTURE OVERVIEW
 * ─────────────────────
 * This file exports a single `initSocket(server)` function.
 * Call it in server.js after creating the HTTP server:
 *
 *   import { initSocket } from "./socket.js";
 *   const io = initSocket(server);
 *   app.set("io", io);          ← makes io available in controllers
 *
 * ROOMS
 * ─────
 *   salon:{salonId}       — owner dashboard, chair grid, booking list
 *   user:{userId}         — customer app, booking status updates;
 *                           also every AGENT's own room (agents are
 *                           User documents too) for ticket events
 *                           scoped to "assigned to me"
 *   admin                 — platform-level monitoring (optional)
 *   supportAdmin          — Phase F.3.8: SUPPORT_ADMIN role, global
 *                           Support ticket lifecycle visibility
 *   supportTeam:{teamId}  — Phase F.3.8: joined by an AGENT who leads
 *                           that SupportTeam (SupportTeam.teamLeadRef),
 *                           resolved once at connection time via the
 *                           same query adminSupport.controller.js's
 *                           resolveAdminScope() already uses
 *
 * AUTH
 * ────
 *   Every socket connection must present a valid JWT in either:
 *     handshake.auth.token       (preferred — sent by socket client)
 *     handshake.headers.authorization  (Bearer fallback)
 *
 *   Invalid JWT → socket immediately disconnected (401).
 *   Valid JWT   → socket.data.userId, socket.data.role, socket.data.salonId
 *                 are populated and used to auto-join the correct rooms.
 *
 * RECONNECT RECOVERY
 * ──────────────────
 *   On reconnect the client sends "sync:request" with the last known
 *   booking status. The server replies with the current truth from DB.
 *   This covers Indian network instability (2G drops, backgrounded app).
 *
 * EVENTS EMITTED BY SERVER → CLIENT
 * ───────────────────────────────────
 *   booking:hold           — new HOLD placed on chair
 *   booking:confirmed      — payment done, booking confirmed
 *   booking:checkedIn      — customer checked in
 *   booking:serviceStarted — service timer started
 *   booking:completed      — service done, chair freed, wallet credited
 *                            (also emitted to the "admin" room, with
 *                            autoCompleted:true, for system-triggered
 *                            completions — see jobs/autoComplete.job.js)
 *   booking:cancelled      — booking cancelled, chair freed
 *   booking:noShow         — no-show marked, chair freed
 *   booking:expired        — HOLD expired, chair freed
 *   booking:serviceOverdue — ONGOING service past expected duration (salon room only)
 *   booking:graceExtended  — salon owner extended an overdue service
 *   sync:response          — reply to sync:request (reconnect recovery)
 *   error:auth             — authentication failure (client should re-login)
 *
 *   Phase F.3.8 — Support ticket lifecycle (emitted from
 *   supportTicket.service.js / the Support controllers, never from
 *   here — this file only owns rooms/auth, not Support business
 *   events):
 *   support:ticket:created       — user room only
 *   support:ticket:statusChanged — user room + (when relevant)
 *                                  supportTeam/supportAdmin rooms
 *   support:ticket:assigned      — assigned agent's own user room +
 *                                  supportTeam + supportAdmin (never
 *                                  the customer — agent identity is
 *                                  internal data)
 *   support:ticket:reassigned    — old + new agent's own user rooms +
 *                                  supportTeam + supportAdmin
 *   support:ticket:unassigned    — previous agent's own user room +
 *                                  supportTeam + supportAdmin
 *   support:message:new          — user room (customer-visible replies
 *                                  only — never an INTERNAL note)
 *   support:ticket:internalNote  — assigned agent + supportTeam +
 *                                  supportAdmin ONLY, never the
 *                                  customer's user room under any
 *                                  circumstance
 *
 * EVENTS RECEIVED BY SERVER ← CLIENT
 * ────────────────────────────────────
 *   sync:request { bookingId, lastKnownStatus }
 *                          — fetch fresh booking state after reconnect
 *   ping                   — client keepalive (server replies "pong")
 *
 * ============================================================
 */

import { Server }  from "socket.io";
import jwt         from "jsonwebtoken";
import mongoose    from "mongoose";
import Booking from "../models/Booking.js";
import User    from "../models/User.js";
import SupportTeam from "../modules/support/models/SupportTeam.js";

//////////////////////////////////////////////////////////////
// 🔥 CONFIG
//////////////////////////////////////////////////////////////

const JWT_SECRET          = process.env.JWT_SECRET;
const CLIENT_ORIGIN       = process.env.CLIENT_ORIGIN || "http://localhost:3000";

// How long a socket can stay connected without being verified (ms)
const AUTH_TIMEOUT_MS     = 10_000;

// Rate-limit: max sync:request events per socket per window
const SYNC_RATE_LIMIT     = 10;
const SYNC_RATE_WINDOW_MS = 60_000;

//////////////////////////////////////////////////////////////
// 🧠 INTERNAL HELPERS
//////////////////////////////////////////////////////////////

/**
 * Extract JWT string from socket handshake.
 * Supports both auth.token and Authorization header.
 */
const extractToken = (socket) => {
  if (socket.handshake.auth?.token) {
    return socket.handshake.auth.token;
  }
  const authHeader = socket.handshake.headers?.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }
  return null;
};

/**
 * Verify JWT and return decoded payload.
 * Returns null on any failure — never throws.
 */
const verifyToken = (token) => {
  // Same secret + fallback convention as middlewares/auth.middleware.js —
  // access tokens are signed with JWT_ACCESS_SECRET (services/token.service.js).
  const secret = process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;
  if (!token || !secret) {
    console.warn("[Socket] Missing token or secret");
    return null;
  }
  try {
    return jwt.verify(token, secret);
  } catch (err) {
    console.warn("[Socket] JWT verification failed:", err.message);
    return null;
  }
};

/**
 * Per-socket sync rate limiter.
 * Stored on socket.data to avoid a global Map.
 */
const checkSyncRateLimit = (socket) => {
  const now = Date.now();

  if (!socket.data.syncRateLimit) {
    socket.data.syncRateLimit = { count: 0, windowStart: now };
  }

  const rl = socket.data.syncRateLimit;

  if (now - rl.windowStart > SYNC_RATE_WINDOW_MS) {
    // Reset window
    rl.count       = 0;
    rl.windowStart = now;
  }

  rl.count += 1;
  return rl.count <= SYNC_RATE_LIMIT;
};

//////////////////////////////////////////////////////////////
// 🔐 AUTH MIDDLEWARE
//////////////////////////////////////////////////////////////

/**
 * Runs BEFORE the connection is accepted.
 * Populates socket.data with verified identity.
 * Rejects unauthenticated connections immediately.
 */
const authMiddleware = async (socket, next) => {
  const token   = extractToken(socket);
  const payload = verifyToken(token);

  if (!payload) {
    // Reject connection — client will receive a connect_error event
    return next(new Error("AUTH_FAILED"));
  }

  const userId = payload._id || payload.id || payload.userId;
  if (!userId) {
    return next(new Error("AUTH_FAILED"));
  }

  // Same guarantee REST protect() enforces before granting access: a
  // stale tokenVersion (post logout-all) or a suspended/deleted account
  // must not connect, even with a cryptographically-valid, unexpired
  // JWT. One indexed lookup per connection (not per event) — no
  // refresh-token round trip, since the socket handshake has no cookie
  // flow to do a real verifySession() with.
  let user;
  try {
    user = await User.findById(userId).select("tokenVersion isActive isDeleted accountStatus");
  } catch (err) {
    console.warn("[Socket] User lookup failed during auth:", err.message);
    return next(new Error("AUTH_FAILED"));
  }

  if (!user || !user.isActive || user.isDeleted) {
    return next(new Error("AUTH_FAILED"));
  }

  // SECURITY (P0-2): same restriction check as REST protect() — a
  // suspended/blocked account must not be able to open a NEW socket
  // connection, even with a cryptographically-valid, unexpired JWT.
  if (user.accountStatus === "SUSPENDED" || user.accountStatus === "BLOCKED") {
    return next(new Error("AUTH_FAILED"));
  }

  if (Number(payload.tokenVersion ?? 0) !== Number(user.tokenVersion ?? 0)) {
    return next(new Error("AUTH_FAILED"));
  }

  // Populate verified identity — available throughout the session
  socket.data.userId   = userId;
  socket.data.role     = payload.role  || "USER";  // USER | OWNER | ADMIN
  socket.data.salonId  = payload.salonId || null;  // set for OWNER tokens
  socket.data.verified = true;

  next();
};

//////////////////////////////////////////////////////////////
// 🚀 MAIN EXPORT
//////////////////////////////////////////////////////////////

/**
 * Initialise Socket.IO, attach auth middleware, wire all events.
 * Returns the io instance so server.js can pass it to Express.
 *
 * @param {import("http").Server} httpServer
 * @returns {import("socket.io").Server}
 */
export const initSocket = (httpServer) => {

  // Same allowlist convention as app.js's Express CORS (CORS_ORIGIN,
  // comma-separated) — kept as an independent local copy rather than
  // importing from app.js, so this file doesn't depend on it.
  const allowedOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(",")
    : [];

  const io = new Server(httpServer, {
    cors: {
      origin: (origin, callback) => {
        // No Origin header (native mobile clients, server-to-server) —
        // same allowance app.js's Express CORS already makes.
        if (!origin) return callback(null, true);
        if (process.env.NODE_ENV !== "production") return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        console.warn(`🚫 [Socket] CORS blocked: ${origin}`);
        return callback(new Error("Not allowed by CORS"));
      },
      methods:     ["GET", "POST"],
      credentials: false,
    },

    // Prefer WebSocket, fall back to long-polling for poor networks
    transports: ["websocket", "polling"],

    // Ping/pong — detects dead connections faster on unstable networks
    pingTimeout:  20_000,
    pingInterval: 10_000,

    // Max event payload (bytes) — prevents oversized messages
    maxHttpBufferSize: 1e5,
    allowEIO3: true, // 100 KB
  });

  //////////////////////////////////////////////////////////////
  // 🔐 ATTACH AUTH MIDDLEWARE
  //////////////////////////////////////////////////////////////

  io.use(authMiddleware);

  //////////////////////////////////////////////////////////////
  // 🔌 CONNECTION HANDLER
  //////////////////////////////////////////////////////////////

  io.on("connection", async (socket) => {
    const { userId, role, salonId } = socket.data;

    //////////////////////////////////////////////////////////
    // 🏠 AUTO-JOIN ROOMS BASED ON ROLE
    //////////////////////////////////////////////////////////

    // Every authenticated user joins their personal room
    socket.join(`user:${userId}`);

    if (role === "OWNER" && salonId) {
      // Salon owner joins their salon's operational room
      socket.join(`salon:${salonId}`);
    }

    if (role === "ADMIN") {
      socket.join("admin");
    }

    // Phase F.3.8 — Support platform rooms. SUPPORT_ADMIN is a
    // distinct role from ADMIN (confirmed during F.3.7's audit — two
    // separate role checks, not a fallthrough of the block above).
    // A plain token-payload check, same zero-cost pattern as the
    // ADMIN branch — no DB read.
    if (role === "SUPPORT_ADMIN") {
      socket.join("supportAdmin");
    }

    // Team Lead is derived, never a role (F.3.7 decision #5) — the
    // only role that can ever lead a SupportTeam is AGENT, so this
    // query only runs for AGENT-role sockets, never unconditionally
    // for every connection. Same query adminSupport.controller.js's
    // resolveAdminScope() already runs per-request; here it runs once
    // per socket connection instead. A lookup failure must never
    // block the connection — same fail-open philosophy already used
    // for sync:request's presence reads elsewhere in this file.
    if (role === "AGENT") {
      try {
        const ledTeams = await SupportTeam.find({ teamLeadRef: userId, isDeleted: false })
          .select("_id")
          .lean();
        for (const team of ledTeams) {
          socket.join(`supportTeam:${team._id}`);
        }
      } catch (err) {
        console.warn("[Socket] SupportTeam lead lookup failed (non-critical):", err.message);
      }
    }

    console.info(
      `[Socket] connected  | id=${socket.id} | userId=${userId} | role=${role}` +
      (salonId ? ` | salon=${salonId}` : "")
    );

    //////////////////////////////////////////////////////////
    // 🔄 RECONNECT RECOVERY — sync:request
    //
    // Client sends this after reconnecting to get the current
    // truth for a specific booking it was watching.
    // Handles: app backgrounded, network dropped, 2G flicker.
    //////////////////////////////////////////////////////////

    socket.on("sync:request", async ({ bookingId, lastKnownStatus } = {}) => {

      // Rate limit — prevent DB spam on rapid reconnects
      if (!checkSyncRateLimit(socket)) {
        socket.emit("sync:response", {
          success: false,
          error:   "Rate limit exceeded. Please wait before syncing again.",
        });
        return;
      }

      // Validate bookingId format before hitting DB
      if (!bookingId || !mongoose.Types.ObjectId.isValid(bookingId)) {
        socket.emit("sync:response", {
          success: false,
          error:   "Invalid booking ID",
        });
        return;
      }

      try {
        const booking = await Booking.findById(bookingId)
          .select("status startTime endTime chairRef salonRef userRef lockUntil serviceStartedAt")
          .lean();

        if (!booking) {
          socket.emit("sync:response", {
            success: false,
            error:   "Booking not found",
          });
          return;
        }

        // Security: only the booking's user or the booking's salon owner
        // can request a sync for this booking
        const isOwner = role === "OWNER" && salonId &&
                        booking.salonRef.toString() === salonId.toString();
        const isUser  = booking.userRef.toString() === userId.toString();

        if (!isOwner && !isUser && role !== "ADMIN") {
          socket.emit("sync:response", {
            success: false,
            error:   "Unauthorized",
          });
          return;
        }

        const statusChanged = booking.status !== lastKnownStatus;

        socket.emit("sync:response", {
          success: true,
          bookingId,
          currentStatus:   booking.status,
          lastKnownStatus,
          statusChanged,
          booking: {
            status:           booking.status,
            startTime:        booking.startTime,
            endTime:          booking.endTime,
            chairId:          booking.chairRef,
            lockUntil:        booking.lockUntil,
            serviceStartedAt: booking.serviceStartedAt,
          },
        });

      } catch (err) {
        console.error("[Socket] sync:request error:", err.message);
        socket.emit("sync:response", {
          success: false,
          error:   "Sync failed. Please try again.",
        });
      }
    });

    //////////////////////////////////////////////////////////
    // 🏓 KEEPALIVE PING
    // Client sends "ping" periodically on poor networks to
    // detect whether the connection is truly alive.
    //////////////////////////////////////////////////////////

    socket.on("ping", () => {
      socket.emit("pong", { ts: Date.now() });
    });

    //////////////////////////////////////////////////////////
    // 🔌 DISCONNECT
    //////////////////////////////////////////////////////////

    socket.on("disconnect", (reason) => {
      console.info(
        `[Socket] disconnected | id=${socket.id} | userId=${userId} | reason=${reason}`
      );
    });

    //////////////////////////////////////////////////////////
    // ⚠️ ERROR
    //////////////////////////////////////////////////////////

    socket.on("error", (err) => {
      console.error(`[Socket] error | id=${socket.id} | userId=${userId}`, err.message);
    });
  });

  //////////////////////////////////////////////////////////////
  // ⚠️ AUTH FAILURE HANDLER
  // connect_error fires on the CLIENT when authMiddleware calls
  // next(new Error("AUTH_FAILED")).
  // On the server side we just log it — no action needed.
  //////////////////////////////////////////////////////////////

  io.engine.on("connection_error", (err) => {
    if (err.message !== "AUTH_FAILED") {
      console.error("[Socket] engine connection_error:", err.message);
    }
  });

  console.info("[Socket] Socket.IO server initialised ✅");
  return io;
};

//////////////////////////////////////////////////////////////
// 🧰 UTILITY — emit a booking event from outside a request context
//
// Use this from cron jobs / background workers that don't have
// access to req.app. Import io directly instead of going via req.
//
// Example (in a cron job):
//   import { emitToRoom } from "./socket.js";
//   emitToRoom(io, `salon:${salonId}`, "booking:expired", payload);
//////////////////////////////////////////////////////////////

export const emitToRoom = (io, room, event, payload) => {
  try {
    if (!io) return;
    io.to(room).emit(event, payload);
  } catch (err) {
    console.warn(`[Socket] emitToRoom failed [${event}] → ${room}:`, err.message);
  }
};