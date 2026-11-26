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
import { isStagingEnv } from "../utils/stagingGuards.js";
import { creditTopupFromPayment, TOPUP_CREDIT_OUTCOME } from "../services/walletTopupCredit.service.js";

//////////////////////////////////////////////////////////////
// CONSTANTS
//////////////////////////////////////////////////////////////

const MIN_TOPUP_RUPEES = 10;
const MAX_TOPUP_RUPEES = 50000;

// Only a CAPTURED payment is money received. The capture/amount/order/currency
// rules live in services/walletTopupCredit.service.js, shared with the webhook.

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
// Sequence: duplicate paymentId check → signature verify → fetch the
// payment from Razorpay → creditTopupFromPayment (shared with the
// webhook): status exactly "captured", order/amount/currency match,
// then one atomic PENDING→SUCCESS + wallet credit. "authorized" is
// NOT money yet: the row stays PENDING and the captured webhook
// credits it later (202). A mismatch never credits (review flag).
//////////////////////////////////////////////////////////////

const TOPUP_REVIEW_MESSAGE =
  "We could not match this payment to your top-up. It has been flagged for review — please contact support if money was deducted.";

export const verifyTopup = async (req, res) => {
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

    // Idempotency — this same payment was already credited (client
    // retried, or the webhook got there first). Safe no-op.
    if (txn.status === WALLET_TXN_STATUS.SUCCESS && txn.razorpayPaymentId === paymentId) {
      const u = await User.findOne({ _id: userId, isDeleted: false }).select("walletBalance").lean();
      return res.json({ success: true, message: "Already credited", walletBalance: u?.walletBalance ?? null });
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
    if (payment?.id !== paymentId) {
      logger.error("WALLET VERIFY TOPUP: fetched payment id differs from the requested one", { walletTxnId: String(txn._id) });
      return res.status(409).json({ success: false, needsReview: true, message: TOPUP_REVIEW_MESSAGE });
    }
    const result = await creditTopupFromPayment({ txn, payment, signature, via: "verify" });

    switch (result.outcome) {
      case TOPUP_CREDIT_OUTCOME.CREDITED:
        return res.json({ success: true, message: "Wallet credited successfully", walletBalance: result.walletBalance });

      case TOPUP_CREDIT_OUTCOME.ALREADY_CREDITED:
        return res.json({ success: true, message: "Already credited", walletBalance: result.walletBalance });

      case TOPUP_CREDIT_OUTCOME.NOT_CAPTURED:
        // e.g. "authorized": not money yet. Row stays PENDING; the captured webhook credits it.
        return res.status(202).json({
          success: false,
          pending: true,
          message: "Your payment is being confirmed by the bank. Your wallet will be credited automatically once it completes.",
        });

      case TOPUP_CREDIT_OUTCOME.PAYMENT_FAILED:
        await WalletTransaction.updateOne(
          { _id: txn._id, status: WALLET_TXN_STATUS.PENDING },
          {
            status: WALLET_TXN_STATUS.FAILED,
            failureCode: WALLET_TXN_FAILURE_CODE.PAYMENT_FAILED,
            failureReason: 'Payment status was "failed", not captured',
          }
        );
        return res.status(400).json({ success: false, message: "Payment was not captured" });

      case TOPUP_CREDIT_OUTCOME.NOT_FOUND:
        return res.status(404).json({ success: false, message: "Top-up order not found" });

      default:
        // Every review outcome (order/amount/currency/user mismatch, refunded, credited by a
        // different payment, payment already used, row not PENDING): no credit, flagged.
        logger.error("WALLET VERIFY TOPUP NEEDS REVIEW", { walletTxnId: String(txn._id), outcome: result.outcome });
        return res.status(409).json({ success: false, needsReview: true, message: TOPUP_REVIEW_MESSAGE });
    }
  } catch (error) {
    logger.error("WALLET VERIFY TOPUP ERROR", { message: error.message, stack: error.stack });
    return res.status(500).json({ success: false, message: "Top-up verification failed" });
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
// someone tries to call it directly. Also locked on staging, where real
// Razorpay test-mode checkout is used and this would credit wallets for free.
// The 404 is returned before any database or wallet work.
//////////////////////////////////////////////////////////////

export const mockVerifyTopup = async (req, res) => {
  if (process.env.NODE_ENV === "production" || isStagingEnv()) {
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