/**
 * BARBER ENGINE V1
 * backend/routes/adminAuth.routes.js — FINAL
 */

import express from "express";
import rateLimit from "express-rate-limit";

import {
  adminLogin,
  adminLogout,
  adminMe,
  adminRefresh,
  adminActivationRequestOtp,
  adminActivationComplete,
  adminPasswordResetRequestOtp,
  adminPasswordResetComplete,
} from "../controllers/adminAuth.controller.js";

import { protect } from "../middlewares/auth.middleware.js";

const router = express.Router();

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      20,
  message: {
    success: false,
    message: "Too many login attempts. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders:   false,
});

// Secure activation / password reset (OTP). Per-IP limiter on top of the OTP
// engine's own per-phone attempt limit + resend cooldown.
const adminCredentialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  message: {
    success: false,
    message: "Too many requests. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders:   false,
});

// POST /api/admin-auth/activation/request-otp     { phone }
router.post("/activation/request-otp",     adminCredentialLimiter, adminActivationRequestOtp);
// POST /api/admin-auth/activation/complete        { phone, otp, newPassword }
router.post("/activation/complete",        adminCredentialLimiter, adminActivationComplete);
// POST /api/admin-auth/password-reset/request-otp { phone }
router.post("/password-reset/request-otp", adminCredentialLimiter, adminPasswordResetRequestOtp);
// POST /api/admin-auth/password-reset/complete    { phone, otp, newPassword }
router.post("/password-reset/complete",    adminCredentialLimiter, adminPasswordResetComplete);

// POST /api/admin-auth/login
router.post("/login",   adminLoginLimiter, adminLogin);

// POST /api/admin-auth/refresh  (no protect — expired token ke baad bhi kaam kare)
router.post("/refresh", adminRefresh);

// POST /api/admin-auth/logout
router.post("/logout",  protect, adminLogout);

// GET /api/admin-auth/me
router.get("/me",       protect, adminMe);

export default router;