import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import mongoose from "mongoose";
import Booking from "../models/Booking.js";
import NotificationService from "../services/NotificationService.js";
import { NOTIFICATION_EVENTS } from "../modules/notifications/constants/notificationEvents.constants.js";
import User from "../models/User.js";
import WalletTransaction, {
    WALLET_TXN_DIRECTION,
    WALLET_TXN_FAILURE_CODE,
    WALLET_TXN_SOURCE,
    WALLET_TXN_STATUS,
    WALLET_TXN_TYPE,
} from "../models/WalletTransaction.js";
import {
    createRazorpayOrder,
    fetchRazorpayPayment,
    verifyRazorpaySignature,
} from "../services/Razorpay.service.js";
import { toFriendlyId } from "../utils/friendlyId.js";
import logger from "../utils/logger.js";

//////////////////////////////////////////////////////////////
// CONSTANTS
//////////////////////////////////////////////////////////////

const MIN_TOPUP_RUPEES = 10;
const MAX_TOPUP_RUPEES = 50000;

// Razorpay payment statuses that count as "money actually received".
// A valid signature alone doesn't mean this — status must be checked
// separately (see fetchRazorpayPayment call in verifyTopup below).
const CAPTURED_PAYMENT_STATUSES = ["captured", "authorized"];

//////////////////////////////////////////////////////////////
// RATE LIMITER — payment-related endpoints, exported for routes
//////////////////////////////////////////////////////////////

export const walletTopupLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => `wallet_topup_${ipKeyGenerator(req)}_${req.user?.id || "anon"}`,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many wallet requests. Please try again later.",
  },
});

//////////////////////////////////////////////////////////////
// 1. CREATE TOP-UP ORDER
// POST /api/v1/wallet/add-money/create-order
// Body: { amount }  — amount in RUPEES (matches User.walletBalance's
// existing unit — see note in WalletTransaction.js)
//
// FIX: Razorpay order is created FIRST. The WalletTransaction row is
// only written once Razorpay confirms the order — so a Razorpay
// outage never leaves an orphan PENDING row with no order_id behind
// it. If Mongo write fails after a successful Razorpay call, that's
// a genuine 500 (rare, and the order is simply never paid against —
// no wallet-side inconsistency either way).
//////////////////////////////////////////////////////////////

export const createTopupOrder = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    const amount = Number(req.body.amount);

    if (!Number.isFinite(amount) || amount < MIN_TOPUP_RUPEES || amount > MAX_TOPUP_RUPEES) {
      return res.status(400).json({
        success: false,
        message: `Amount must be between ₹${MIN_TOPUP_RUPEES} and ₹${MAX_TOPUP_RUPEES}`,
      });
    }

    const amountInPaise = Math.round(amount * 100);

    // Razorpay receipt has a hard 40-char limit — a full ObjectId +
    // timestamp blows past that, so we use a short random suffix
    // instead. The real linkage to userId lives in `notes`, not the
    // receipt string, so this stays fully traceable.
    const receipt = `wtu_${Date.now().toString(36)}`;

    const order = await createRazorpayOrder({
      amountInPaise,
      receipt,
      notes: { userId: String(userId) },
    });

    const txn = await WalletTransaction.create({
      userId,
      direction: WALLET_TXN_DIRECTION.CREDIT,
      type: WALLET_TXN_TYPE.TOPUP,
      status: WALLET_TXN_STATUS.PENDING,
      source: WALLET_TXN_SOURCE.RAZORPAY,
      amountInPaise,
      razorpayOrderId: order.id,
      requestId: `topup:${order.id}`,
    });

    return res.json({
      success: true,
      orderId: order.id,
      amount: order.amount, // paise — RazorpayCheckout expects paise
      currency: order.currency,
      walletTxnId: txn._id,
    });
  } catch (error) {
    logger.error("WALLET CREATE TOPUP ORDER ERROR", { message: error.message, stack: error.stack });
    return res.status(500).json({ success: false, message: "Could not start top-up" });
  }
};

//////////////////////////////////////////////////////////////
// 2. VERIFY TOP-UP PAYMENT
// POST /api/v1/wallet/add-money/verify
// Body: { orderId, paymentId, signature }
//
// Sequence: signature verify → duplicate paymentId check → fetch
// live payment status from Razorpay (captured/authorized required,
// not just a valid signature) → atomic PENDING→SUCCESS transition →
// credit wallet — all inside one Mongo session.
//////////////////////////////////////////////////////////////

export const verifyTopup = async (req, res) => {
  const session = await mongoose.startSession();
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    const { orderId, paymentId, signature } = req.body;

    if (!orderId || !paymentId || !signature) {
      return res.status(400).json({
        success: false,
        message: "orderId, paymentId and signature are all required",
      });
    }

    const txn = await WalletTransaction.findOne({ razorpayOrderId: orderId, userId });
    if (!txn) {
      return res.status(404).json({ success: false, message: "Top-up order not found" });
    }

    // Idempotency — already verified once (e.g. client retried after
    // a slow response). Safe no-op.
    if (txn.status === WALLET_TXN_STATUS.SUCCESS) {
      return res.json({ success: true, message: "Already credited" });
    }

    // Explicit duplicate check — this exact paymentId must not be
    // attached to any OTHER transaction (defense in depth on top of
    // the model's unique index, with a clean 409 instead of a raw
    // Mongo E11000 bubbling up).
    const existingForPayment = await WalletTransaction.findOne({
      razorpayPaymentId: paymentId,
      _id: { $ne: txn._id },
    }).lean();
    if (existingForPayment) {
      return res.status(409).json({ success: false, message: "This payment has already been processed" });
    }

    const isValid = verifyRazorpaySignature({ orderId, paymentId, signature });
    if (!isValid) {
      await WalletTransaction.updateOne(
        { _id: txn._id, status: WALLET_TXN_STATUS.PENDING },
        {
          status: WALLET_TXN_STATUS.FAILED,
          failureCode: WALLET_TXN_FAILURE_CODE.SIGNATURE_INVALID,
          failureReason: "Signature verification failed",
        }
      );
      return res.status(400).json({ success: false, message: "Invalid payment signature" });
    }

    // Signature valid ≠ money received — confirm with Razorpay's own
    // record of the payment before crediting anything.
    const payment = await fetchRazorpayPayment(paymentId);
    if (!CAPTURED_PAYMENT_STATUSES.includes(payment?.status)) {
      await WalletTransaction.updateOne(
        { _id: txn._id, status: WALLET_TXN_STATUS.PENDING },
        {
          status: WALLET_TXN_STATUS.FAILED,
          failureCode: WALLET_TXN_FAILURE_CODE.PAYMENT_FAILED,
          failureReason: `Payment status was "${payment?.status}", not captured`,
        }
      );
      return res.status(400).json({ success: false, message: "Payment was not captured" });
    }

    const amountRupees = txn.amountInPaise / 100;
    let updatedUser;
    let balanceBeforeInPaise;

    await session.withTransaction(async () => {
      const currentUser = await User.findOne({ _id: userId, isDeleted: false })
        .select("walletBalance")
        .session(session);
      if (!currentUser) throw new Error("User not found");
      balanceBeforeInPaise = Math.round((currentUser.walletBalance || 0) * 100);

      updatedUser = await User.findOneAndUpdate(
        { _id: userId, isDeleted: false },
        { $inc: { walletBalance: amountRupees } },
        { new: true, session }
      ).select("walletBalance");

      // Atomic PENDING→SUCCESS transition — the filter itself
      // requires status still be PENDING, so a concurrent duplicate
      // call for the same txn can never both succeed (second call's
      // matchedCount is 0, caught below).
      const transitionResult = await WalletTransaction.updateOne(
        { _id: txn._id, status: WALLET_TXN_STATUS.PENDING },
        {
          status: WALLET_TXN_STATUS.SUCCESS,
          source: WALLET_TXN_SOURCE.RAZORPAY,
          razorpayPaymentId: paymentId,
          razorpaySignature: signature,
          balanceBeforeInPaise,
          balanceAfterInPaise: Math.round(updatedUser.walletBalance * 100),
        },
        { session }
      );

      if (transitionResult.matchedCount === 0) {
        // Another concurrent request already transitioned this txn —
        // abort so the wallet $inc above rolls back with the session.
        throw new Error("Transaction already processed concurrently");
      }
    });

    await NotificationService.send({
      recipientId:   userId,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.WALLET_CREDIT,
      variables:     { amount: Math.round(amountRupees) },
      title:         "Wallet Credited",
      message:       `₹${Math.round(amountRupees)} has been added to your wallet.`,
      type:          "PAYMENT",
      priority:      "MEDIUM",
      actionType:    "OPEN_WALLET",
      actionUrl:     "/wallet",
      meta:          { walletTransactionId: txn._id, amountInPaise: txn.amountInPaise },
    });

    return res.json({
      success: true,
      message: "Wallet credited successfully",
      walletBalance: updatedUser.walletBalance,
    });
  } catch (error) {
    logger.error("WALLET VERIFY TOPUP ERROR", { message: error.message, stack: error.stack });
    return res.status(500).json({ success: false, message: "Top-up verification failed" });
  } finally {
    session.endSession();
  }
};

//////////////////////////////////////////////////////////////
// 3. GET WALLET TRANSACTIONS — paginated history
// GET /api/v1/wallet/transactions?page=1&limit=20
//
// Only SUCCESS entries shown by default — PENDING (abandoned) and
// FAILED (declined/cancelled) are noise for a "here's your history"
// view. Business can revisit this later if a "show failed" filter
// is wanted.
//////////////////////////////////////////////////////////////

export const getWalletTransactions = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    const page  = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Number(req.query.limit) || 20, 100);
    const skip  = (page - 1) * limit;

    const filter = { userId, status: WALLET_TXN_STATUS.SUCCESS };
    const [entries, total] = await Promise.all([
      WalletTransaction.find(filter)
        .sort({ createdAt: -1, _id: -1 })
        .skip(skip)
        .limit(limit)
        .select("-razorpaySignature")
        .lean(),
      WalletTransaction.countDocuments(filter),
    ]);

    //////////////////////////////////////////////////////////////
    // ENRICH — TOPUP/BOOKING_PAYMENT/REFUND entries have a bookingId;
    // pull salon name + service names + booking date/time for those
    // in one bulk query (not N+1) so the list/detail screens never
    // need a second round-trip per transaction.
    //////////////////////////////////////////////////////////////
    const bookingIds = entries
      .filter((e) => e.bookingId)
      .map((e) => e.bookingId);
    let bookingMap = {};
    if (bookingIds.length > 0) {
      const bookings = await Booking.find({ _id: { $in: bookingIds } })
        .select("salonRef serviceRefs startTime cancellationPolicy")
        .populate({ path: "salonRef", select: "basicInfo.shopName" })
        .populate({ path: "serviceRefs", select: "name" })
        .lean();

      bookingMap = bookings.reduce((map, b) => {
        map[b._id.toString()] = {
          salonName: b.salonRef?.basicInfo?.shopName || null,
          serviceNames: (b.serviceRefs || []).map((s) => s.name).filter(Boolean),
          bookingStartTime: b.startTime || null,
          cancellationPolicy: b.cancellationPolicy || null,
        };
        return map;
      }, {});
    }

    const enrichedEntries = entries.map((e) => ({
      ...e,
      booking: e.bookingId ? (bookingMap[e.bookingId.toString()] || null) : null,
      friendlyTxnId: toFriendlyId(e._id, "WTX"),
      friendlyBookingId: e.bookingId ? toFriendlyId(e.bookingId, "BK") : null,
    }));

    return res.json({
      success: true,
      data: enrichedEntries,
      pagination: { total, page, limit },
    });
  } catch (error) {
    logger.error("WALLET GET TRANSACTIONS ERROR", { message: error.message, stack: error.stack });
    return res.status(500).json({ success: false, message: "Could not load transactions" });
  }
};

//////////////////////////////////////////////////////////////
// 4. GET WALLET BALANCE — lightweight, wallet-only read
// GET /api/v1/wallet/balance
//
// Avoids the wallet screen depending on the full /api/user/me
// payload just to read one field.
//////////////////////////////////////////////////////////////

export const getWalletBalance = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    const user = await User.findOne({ _id: userId, isDeleted: false })
      .select("walletBalance")
      .lean();

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true, walletBalance: user.walletBalance ?? 0 });
  } catch (error) {
    logger.error("WALLET GET BALANCE ERROR", { message: error.message, stack: error.stack });
    return res.status(500).json({ success: false, message: "Could not load wallet balance" });
  }
};




//////////////////////////////////////////////////////////////
// DEV-ONLY MOCK VERIFY — bypasses real Razorpay checkout
// POST /api/v1/wallet/add-money/mock-verify
// Body: { orderId }
//
// Needed because react-native-razorpay's native checkout can't open
// inside Expo Go — only in a real dev/production build. This lets
// wallet top-ups be tested end-to-end in Expo Go; once a dev/EAS
// build exists, the frontend switches to the real RazorpayCheckout
// flow automatically (see walletApi.js / WalletScreen.js).
//
// HARD-LOCKED to non-production — never reachable in prod even if
// someone tries to call it directly.
//////////////////////////////////////////////////////////////

export const mockVerifyTopup = async (req, res) => {
  if (process.env.NODE_ENV === "production") {
    return res.status(404).json({ success: false, message: "Not found" });
  }

  const session = await mongoose.startSession();
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    const { orderId } = req.body;
    if (!orderId) {
      return res.status(400).json({ success: false, message: "orderId is required" });
    }

    const txn = await WalletTransaction.findOne({ razorpayOrderId: orderId, userId });
    if (!txn) {
      return res.status(404).json({ success: false, message: "Top-up order not found" });
    }

    if (txn.status === WALLET_TXN_STATUS.SUCCESS) {
      return res.json({ success: true, message: "Already credited" });
    }

    const amountRupees = txn.amountInPaise / 100;
    let updatedUser;
    let balanceBeforeInPaise;

    await session.withTransaction(async () => {
      const currentUser = await User.findOne({ _id: userId, isDeleted: false })
        .select("walletBalance")
        .session(session);
      if (!currentUser) throw new Error("User not found");
      balanceBeforeInPaise = Math.round((currentUser.walletBalance || 0) * 100);

      updatedUser = await User.findOneAndUpdate(
        { _id: userId, isDeleted: false },
        { $inc: { walletBalance: amountRupees } },
        { new: true, session }
      ).select("walletBalance");

      const transitionResult = await WalletTransaction.updateOne(
        { _id: txn._id, status: WALLET_TXN_STATUS.PENDING },
        {
          status: WALLET_TXN_STATUS.SUCCESS,
          source: WALLET_TXN_SOURCE.SYSTEM,
          razorpayPaymentId: `mock_${Date.now()}`,
          balanceBeforeInPaise,
          balanceAfterInPaise: Math.round(updatedUser.walletBalance * 100),
        },
        { session }
      );

      if (transitionResult.matchedCount === 0) {
        throw new Error("Transaction already processed concurrently");
      }
    });

    await NotificationService.send({
      recipientId:   userId,
      recipientType: "USER",
      templateKey:   NOTIFICATION_EVENTS.WALLET_CREDIT,
      variables:     { amount: Math.round(amountRupees) },
      title:         "Wallet Credited",
      message:       `₹${Math.round(amountRupees)} has been added to your wallet.`,
      type:          "PAYMENT",
      priority:      "MEDIUM",
      actionType:    "OPEN_WALLET",
      actionUrl:     "/wallet",
      meta:          { walletTransactionId: txn._id, amountInPaise: txn.amountInPaise },
    });

    return res.json({
      success: true,
      message: "Wallet credited successfully (mock/dev mode)",
      walletBalance: updatedUser.walletBalance,
    });
  } catch (error) {
    logger.error("WALLET MOCK VERIFY ERROR", { message: error.message, stack: error.stack });
    return res.status(500).json({ success: false, message: "Mock verification failed" });
  } finally {
    session.endSession();
  }
};