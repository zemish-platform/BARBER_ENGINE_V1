/**
 * BARBER_ENGINE_V1
 * backend/services/walletTopupCredit.service.js
 *
 * The ONE place a Razorpay wallet top-up is credited. Used by both
 *   - POST /api/v1/wallet/add-money/verify   (controllers/wallet.controller.js)
 *   - the Razorpay payment webhook            (services/razorpayWebhook.service.js)
 * so both paths enforce identical rules.
 *
 * RULES (a payment is credited only if ALL hold):
 *   - payment.status is exactly "captured" (never "authorized", "failed", ...)
 *   - payment.order_id  === the PENDING WalletTransaction's razorpayOrderId
 *   - payment.amount    === the WalletTransaction's amountInPaise
 *   - payment.currency  === "INR" (and the WalletTransaction's currency is INR)
 *   - nothing of the payment has been refunded
 *   - if the payment carries notes.userId, it is the WalletTransaction's owner
 *
 * EXACTLY ONCE: the credit is one MongoDB transaction that flips the row
 * PENDING -> SUCCESS with a filter on status PENDING and increments
 * User.walletBalance. A concurrent verify / webhook / retry either loses the
 * filter (0 matched -> aborted, nothing applied) or hits a write conflict and is
 * retried by withTransaction, then loses the filter. The sparse unique index on
 * razorpayPaymentId additionally stops one payment crediting two rows.
 *
 * A mismatch never credits and never marks the row FAILED: the row stays PENDING
 * (hidden from the user's history) and a review flag is recorded in the existing
 * `metadata` field. Nothing here ever debits a wallet.
 *
 * Notification: sent only by the caller that actually credited, AFTER commit; a
 * notification failure is logged and never changes the result.
 */

import mongoose from "mongoose";
import User from "../models/User.js";
import WalletTransaction, {
  WALLET_TXN_SOURCE,
  WALLET_TXN_STATUS,
  WALLET_TXN_TYPE,
} from "../models/WalletTransaction.js";
import NotificationService from "./NotificationService.js";
import { NOTIFICATION_EVENTS } from "../modules/notifications/constants/notificationEvents.constants.js";
import logger from "../utils/logger.js";

export const TOPUP_CREDIT_OUTCOME = Object.freeze({
  CREDITED:          "CREDITED",           // this call credited the wallet
  ALREADY_CREDITED:  "ALREADY_CREDITED",   // this same payment was credited before
  NOT_CAPTURED:      "NOT_CAPTURED",       // authorized / created / pending — not money yet, retry later
  PAYMENT_FAILED:    "PAYMENT_FAILED",     // the payment itself failed
  ORDER_MISMATCH:    "ORDER_MISMATCH",
  AMOUNT_MISMATCH:   "AMOUNT_MISMATCH",
  CURRENCY_MISMATCH: "CURRENCY_MISMATCH",
  USER_MISMATCH:     "USER_MISMATCH",
  PAYMENT_REFUNDED:  "PAYMENT_REFUNDED",
  DIFFERENT_PAYMENT: "DIFFERENT_PAYMENT",   // the top-up was already credited by ANOTHER payment
  PAYMENT_USED_ELSEWHERE: "PAYMENT_USED_ELSEWHERE", // this payment already credited another row
  NOT_PENDING:       "NOT_PENDING",        // row is FAILED — never auto-credited
  NOT_FOUND:         "NOT_FOUND",
});

/** Outcomes that mean "money may have been taken but was not credited — a human must look". */
export const TOPUP_REVIEW_OUTCOMES = Object.freeze(new Set([
  TOPUP_CREDIT_OUTCOME.ORDER_MISMATCH,
  TOPUP_CREDIT_OUTCOME.AMOUNT_MISMATCH,
  TOPUP_CREDIT_OUTCOME.CURRENCY_MISMATCH,
  TOPUP_CREDIT_OUTCOME.USER_MISMATCH,
  TOPUP_CREDIT_OUTCOME.PAYMENT_REFUNDED,
  TOPUP_CREDIT_OUTCOME.DIFFERENT_PAYMENT,
  TOPUP_CREDIT_OUTCOME.PAYMENT_USED_ELSEWHERE,
  TOPUP_CREDIT_OUTCOME.NOT_PENDING,
]));

/**
 * evaluateTopupPayment({ txn, payment }) -> null | outcome
 * Pure. null = the payment may credit this row. Identity checks come first so a
 * payment for another order/amount is reported as such even when not captured.
 */
export const evaluateTopupPayment = ({ txn, payment }) => {
  if (!payment || typeof payment !== "object") return TOPUP_CREDIT_OUTCOME.ORDER_MISMATCH;
  if (payment.order_id !== txn.razorpayOrderId) return TOPUP_CREDIT_OUTCOME.ORDER_MISMATCH;
  if (payment.currency !== "INR" || (txn.currency || "INR") !== "INR") return TOPUP_CREDIT_OUTCOME.CURRENCY_MISMATCH;
  if (payment.amount !== txn.amountInPaise) return TOPUP_CREDIT_OUTCOME.AMOUNT_MISMATCH;
  const notedUser = payment.notes?.userId;
  if (notedUser !== undefined && notedUser !== null && String(notedUser) !== String(txn.userId)) {
    return TOPUP_CREDIT_OUTCOME.USER_MISMATCH;
  }
  if (payment.status === "failed") return TOPUP_CREDIT_OUTCOME.PAYMENT_FAILED;
  if (payment.status !== "captured") return TOPUP_CREDIT_OUTCOME.NOT_CAPTURED;
  if ((payment.amount_refunded || 0) > 0 || payment.refund_status) return TOPUP_CREDIT_OUTCOME.PAYMENT_REFUNDED;
  return null;
};

// Records a review flag in the existing Mixed `metadata` field. Never changes status,
// amount or balance. Best-effort: a failure here is logged, not thrown.
const recordReviewFlag = async ({ txnId, outcome, payment, via }) => {
  try {
    await WalletTransaction.updateOne(
      { _id: txnId },
      {
        $push: {
          "metadata.reviewFlags": {
            $each: [{
              code: outcome,
              via,
              paymentId: payment?.id || null,
              paymentStatus: payment?.status || null,
              paidAmountInPaise: Number.isFinite(payment?.amount) ? payment.amount : null,
              paidCurrency: payment?.currency || null,
              at: new Date(),
            }],
            $slice: -20,
          },
        },
      }
    );
  } catch (err) {
    logger.error("[WalletTopupCredit] could not record review flag", { txnId: String(txnId), outcome, message: err.message });
  }
};

class AlreadyTransitioned extends Error {}

const readBalance = async (userId) => {
  const u = await User.findOne({ _id: userId, isDeleted: false }).select("walletBalance").lean();
  return u ? (u.walletBalance ?? 0) : null;
};

/**
 * creditTopupFromPayment({ txn, payment, signature, via })
 *   txn       — the WalletTransaction (TOPUP) row this payment is for; the caller has already
 *               established ownership (verify: looked up by orderId AND the authenticated userId;
 *               webhook: looked up by the payment's own order id).
 *   payment   — the Razorpay payment entity as fetched from / sent by Razorpay.
 *   signature — the checkout signature (verify path only), stored as before.
 *   via       — "verify" | "webhook" (audit only).
 * @returns {Promise<{ outcome: string, credited: boolean, walletBalance: number|null, needsReview: boolean }>}
 * Throws only on infrastructure errors (DB unavailable, ...), so a webhook can be retried.
 */
export const creditTopupFromPayment = async ({ txn, payment, signature = null, via }) => {
  const result = (outcome, extra = {}) => ({
    outcome,
    credited: outcome === TOPUP_CREDIT_OUTCOME.CREDITED,
    needsReview: TOPUP_REVIEW_OUTCOMES.has(outcome),
    walletBalance: null,
    ...extra,
  });

  if (!txn || txn.type !== WALLET_TXN_TYPE.TOPUP) return result(TOPUP_CREDIT_OUTCOME.NOT_FOUND);

  // Already settled?
  if (txn.status === WALLET_TXN_STATUS.SUCCESS) {
    if (payment?.id && txn.razorpayPaymentId === payment.id) {
      return result(TOPUP_CREDIT_OUTCOME.ALREADY_CREDITED, { walletBalance: await readBalance(txn.userId) });
    }
    await recordReviewFlag({ txnId: txn._id, outcome: TOPUP_CREDIT_OUTCOME.DIFFERENT_PAYMENT, payment, via });
    return result(TOPUP_CREDIT_OUTCOME.DIFFERENT_PAYMENT);
  }

  const verdict = evaluateTopupPayment({ txn, payment });
  if (verdict) {
    if (TOPUP_REVIEW_OUTCOMES.has(verdict)) await recordReviewFlag({ txnId: txn._id, outcome: verdict, payment, via });
    return result(verdict);
  }

  if (txn.status !== WALLET_TXN_STATUS.PENDING) {
    // A FAILED row with a captured, matching payment: money taken, row closed earlier. Never auto-credit.
    await recordReviewFlag({ txnId: txn._id, outcome: TOPUP_CREDIT_OUTCOME.NOT_PENDING, payment, via });
    return result(TOPUP_CREDIT_OUTCOME.NOT_PENDING);
  }

  const amountRupees = txn.amountInPaise / 100; // User.walletBalance is in rupees (existing unit)
  let walletBalance = null;
  const session = await mongoose.startSession();
  try {
    await session.withTransaction(async () => {
      const set = {
        status: WALLET_TXN_STATUS.SUCCESS,
        source: WALLET_TXN_SOURCE.RAZORPAY,
        razorpayPaymentId: payment.id,
        "metadata.creditedVia": via,
      };
      if (signature) set.razorpaySignature = signature;

      // The PENDING filter is the exactly-once gate.
      const transition = await WalletTransaction.updateOne(
        { _id: txn._id, status: WALLET_TXN_STATUS.PENDING },
        { $set: set },
        { session }
      );
      if (transition.matchedCount === 0) throw new AlreadyTransitioned();

      const before = await User.findOne({ _id: txn.userId, isDeleted: false }).select("walletBalance").session(session);
      if (!before) throw new Error("User not found");
      const updatedUser = await User.findOneAndUpdate(
        { _id: txn.userId, isDeleted: false },
        { $inc: { walletBalance: amountRupees } },
        { new: true, session }
      ).select("walletBalance");

      await WalletTransaction.updateOne(
        { _id: txn._id },
        {
          $set: {
            balanceBeforeInPaise: Math.round((before.walletBalance || 0) * 100),
            balanceAfterInPaise: Math.round(updatedUser.walletBalance * 100),
          },
        },
        { session }
      );
      walletBalance = updatedUser.walletBalance;
    });
  } catch (err) {
    if (err instanceof AlreadyTransitioned) {
      // Someone else settled this row first — report what actually happened.
      session.endSession();
      const now = await WalletTransaction.findById(txn._id).lean();
      if (now?.status === WALLET_TXN_STATUS.SUCCESS && now.razorpayPaymentId === payment.id) {
        return result(TOPUP_CREDIT_OUTCOME.ALREADY_CREDITED, { walletBalance: await readBalance(txn.userId) });
      }
      if (now?.status === WALLET_TXN_STATUS.SUCCESS) {
        await recordReviewFlag({ txnId: txn._id, outcome: TOPUP_CREDIT_OUTCOME.DIFFERENT_PAYMENT, payment, via });
        return result(TOPUP_CREDIT_OUTCOME.DIFFERENT_PAYMENT);
      }
      await recordReviewFlag({ txnId: txn._id, outcome: TOPUP_CREDIT_OUTCOME.NOT_PENDING, payment, via });
      return result(TOPUP_CREDIT_OUTCOME.NOT_PENDING);
    }
    if (err?.code === 11000) {
      // razorpayPaymentId unique index: this payment already credited a DIFFERENT row.
      session.endSession();
      await recordReviewFlag({ txnId: txn._id, outcome: TOPUP_CREDIT_OUTCOME.PAYMENT_USED_ELSEWHERE, payment, via });
      return result(TOPUP_CREDIT_OUTCOME.PAYMENT_USED_ELSEWHERE);
    }
    session.endSession();
    throw err;
  }
  session.endSession();

  // Committed. Notify — a failure here never changes the (already durable) credit.
  try {
    await NotificationService.send({
      recipientId:   txn.userId,
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
  } catch (err) {
    logger.error("[WalletTopupCredit] wallet credited but the notification failed", { txnId: String(txn._id), via, message: err.message });
  }

  return result(TOPUP_CREDIT_OUTCOME.CREDITED, { walletBalance });
};

/** The TOPUP row for a Razorpay order (webhook path). */
export const findTopupForOrder = (orderId) =>
  WalletTransaction.findOne({ razorpayOrderId: orderId, type: WALLET_TXN_TYPE.TOPUP });
