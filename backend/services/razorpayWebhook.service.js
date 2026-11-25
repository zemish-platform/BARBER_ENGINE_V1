/**
 * BARBER ENGINE V1
 * backend/services/razorpayWebhook.service.js
 *
 * RAZORPAY P0-B — inbound Razorpay webhook handling.
 *
 *   payment.captured / order.paid
 *       booking HOLD still valid  -> confirm it through the SAME core as the
 *                                    client's /confirm (runBookingConfirmationCore:
 *                                    P0-A gateway check, Transaction, salon PENDING
 *                                    credit, CONFIRMED)
 *       hold expired / booking not payable / duplicate or orphan payment
 *                                 -> automatic Razorpay refund (once per payment)
 *       amount or currency mismatch -> NEEDS_REVIEW, no automatic action
 *   wallet top-up (captured / order.paid) -> credited via services/walletTopupCredit.service.js
 *                       (same rules as /add-money/verify); validation failure -> NEEDS_REVIEW
 *   payment.failed   -> recorded only (the customer can retry the same order)
 *   refund.processed -> P0-C: completes the Refund record, updates the Transaction and
 *                       (fully refunded) Booking.paymentStatus = REFUNDED; a refund of a payment that
 *                       DID confirm a booking is flagged NEEDS_REVIEW (no wallet or
 *                       ledger change is made here)
 *
 * Idempotency: every event is claimed in WebhookEvent by its Razorpay event id
 * (unique {provider,eventId}); duplicates are acknowledged and ignored. The refund
 * itself is additionally serialized per payment through an ACTION lock document, so
 * payment.captured + order.paid (two events for one payment) refund at most once,
 * and Razorpay is asked for the payment's existing refunds before a new one is made.
 *
 * Wallet / ledger code is not modified: confirmation reuses the existing core,
 * which credits through WalletBalanceService exactly as before.
 */

import mongoose from "mongoose";
import Booking, { BOOKING_STATUS } from "../models/Booking.js";
import Transaction from "../models/Transaction.js";
import WalletTransaction, { WALLET_TXN_TYPE } from "../models/WalletTransaction.js";
import WebhookEvent, {
  WEBHOOK_PROVIDER,
  WEBHOOK_EVENT_KIND,
  WEBHOOK_EVENT_STATUS,
} from "../models/WebhookEvent.js";
import {
  fetchRazorpayOrder,
  fetchRazorpayPayment,
  isRazorpayNotFound,
} from "./Razorpay.service.js";
import Refund from "../models/Refund.js";
import { completeRefund, issueRazorpayRefund, recordExternalRefund } from "./RazorpayRefundService.js";
import { runBookingConfirmationCore, runBookingConfirmedEffects } from "../controllers/booking.controller.js";
import { creditTopupFromPayment, findTopupForOrder, TOPUP_CREDIT_OUTCOME } from "./walletTopupCredit.service.js";
import logger from "../utils/logger.js";

const LEASE_MS = 2 * 60 * 1000;
const MAX_CONFIRM_ATTEMPTS = 3;
const TERMINAL = [WEBHOOK_EVENT_STATUS.PROCESSED, WEBHOOK_EVENT_STATUS.IGNORED, WEBHOOK_EVENT_STATUS.NEEDS_REVIEW];

const isTransientConflict = (err) =>
  typeof err?.hasErrorLabel === "function" && err.hasErrorLabel("TransientTransactionError");

// ─── IDEMPOTENCY ────────────────────────────────────────────────────
/** @returns {{claimed:true,doc}|{claimed:false,reason:"DUPLICATE"|"IN_FLIGHT",doc}} */
export const claimWebhookEvent = async ({ eventId, kind = WEBHOOK_EVENT_KIND.EVENT, meta = {} }) => {
  try {
    const doc = await WebhookEvent.create({
      provider: WEBHOOK_PROVIDER.RAZORPAY, kind, eventId, ...meta,
      status: WEBHOOK_EVENT_STATUS.PROCESSING, lockedAt: new Date(),
    });
    return { claimed: true, doc };
  } catch (err) {
    if (err?.code !== 11000) throw err;
  }
  const existing = await WebhookEvent.findOne({ provider: WEBHOOK_PROVIDER.RAZORPAY, eventId });
  if (TERMINAL.includes(existing.status)) return { claimed: false, reason: "DUPLICATE", doc: existing };

  // FAILED, or a PROCESSING claim whose worker vanished (lease expired): take it over.
  const reclaimed = await WebhookEvent.findOneAndUpdate(
    {
      _id: existing._id,
      $or: [
        { status: WEBHOOK_EVENT_STATUS.FAILED },
        { status: WEBHOOK_EVENT_STATUS.PROCESSING, lockedAt: { $lt: new Date(Date.now() - LEASE_MS) } },
      ],
    },
    { $set: { status: WEBHOOK_EVENT_STATUS.PROCESSING, lockedAt: new Date(), error: null }, $inc: { attempts: 1 } },
    { new: true }
  );
  if (reclaimed) return { claimed: true, doc: reclaimed };
  return { claimed: false, reason: "IN_FLIGHT", doc: existing };
};

const finish = (doc, status, outcome, extra = {}) =>
  WebhookEvent.updateOne(
    { _id: doc._id },
    { $set: { status, outcome, processedAt: new Date(), lockedAt: null, ...extra } }
  );

const fail = (doc, err) =>
  WebhookEvent.updateOne(
    { _id: doc._id },
    { $set: { status: WEBHOOK_EVENT_STATUS.FAILED, error: String(err?.message || err).slice(0, 500), lockedAt: null } }
  );

// ─── HELPERS ────────────────────────────────────────────────────────
const findBookingForOrder = async (orderId) => {
  const booking = await Booking.findOne({ razorpayOrderId: orderId });
  if (booking) return { booking, orphan: false };

  // A top-up order, not a booking order: not ours to act on here.
  if (await WalletTransaction.exists({ razorpayOrderId: orderId })) return { booking: null, walletTopup: true };

  // An order this server minted for a booking but that is not the booking's
  // CURRENT stored order (e.g. replaced, or an orphan from a create-order race).
  let order;
  try {
    order = await fetchRazorpayOrder(orderId);
  } catch (err) {
    if (isRazorpayNotFound(err)) return { booking: null };
    throw err;
  }
  const bookingId = order?.notes?.bookingId;
  if (!bookingId || !mongoose.Types.ObjectId.isValid(bookingId)) return { booking: null };
  const byNotes = await Booking.findById(bookingId);
  return byNotes ? { booking: byNotes, orphan: true } : { booking: null };
};

/** Confirm through the shared core, retrying transient write conflicts. */
const confirmBookingFromWebhook = async ({ booking, paymentId, orderId, app }) => {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_CONFIRM_ATTEMPTS; attempt++) {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
      const result = await runBookingConfirmationCore({
        session,
        bookingId: booking._id,
        actorUserId: booking.userRef,
        paymentMethod: "RAZORPAY",
        paymentId,
        orderId,
        gatewayCheckBypassed: false,
      });
      await session.commitTransaction();
      session.endSession();
      try {
        await runBookingConfirmedEffects({ req: { app }, booking: result.booking, amount: result.amount });
      } catch (effectErr) {
        logger.warn("[RazorpayWebhook] post-confirm effects failed (booking IS confirmed)", { message: effectErr.message });
      }
      return result;
    } catch (err) {
      if (session.inTransaction()) await session.abortTransaction();
      session.endSession();
      lastErr = err;
      if (isTransientConflict(err) && attempt < MAX_CONFIRM_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, 150 * attempt));
        continue;
      }
      throw err;
    }
  }
  throw lastErr;
};

/**
 * Refund a captured payment that cannot be used for its booking — through the
 * P0-C refund engine (persistent Refund record, idempotent by `auto:<paymentId>`,
 * once per payment). The ACTION lock is kept as an outer once-only guard so the
 * P0-B contract (captured + order.paid → one refund) is unchanged.
 */
const issueAutoRefund = async ({ payment, bookingId, reason }) => {
  const remaining = payment.amount - (payment.amount_refunded || 0);
  const lock = await claimWebhookEvent({
    eventId: `ACTION:refund:${payment.id}`,
    kind: WEBHOOK_EVENT_KIND.ACTION,
    meta: { eventType: "auto_refund", paymentId: payment.id, orderId: payment.order_id, bookingId, amountInPaise: remaining },
  });
  if (!lock.claimed) return { outcome: "REFUND_ALREADY_CLAIMED", refundId: lock.doc.refundId || null };

  try {
    // The payment may have been recorded against a booking while we were deciding.
    if (await Transaction.exists({ paymentId: payment.id })) {
      await finish(lock.doc, WEBHOOK_EVENT_STATUS.PROCESSED, "REFUND_SKIPPED_PAYMENT_RECORDED");
      return { outcome: "REFUND_SKIPPED_PAYMENT_RECORDED", refundId: null };
    }
    if (remaining <= 0) {
      await finish(lock.doc, WEBHOOK_EVENT_STATUS.PROCESSED, "REFUND_ALREADY_EXISTS");
      return { outcome: "REFUND_ALREADY_EXISTS", refundId: null };
    }
    const { refund, idempotent } = await issueRazorpayRefund({
      paymentId: payment.id,
      amountInPaise: null, // full — everything still refundable
      reason,
      bookingId,
      initiatedBy: { type: "SYSTEM" },
      idempotencyKey: `auto:${payment.id}`,
    });
    const outcome = idempotent ? "REFUND_ALREADY_EXISTS" : `REFUND_CREATED:${reason}`;
    await finish(lock.doc, WEBHOOK_EVENT_STATUS.PROCESSED, outcome, { refundId: refund.razorpayRefundId });
    return { outcome, refundId: refund.razorpayRefundId };
  } catch (err) {
    await fail(lock.doc, err); // lets the next delivery re-attempt
    throw err;
  }
};

// ─── WALLET TOP-UP ──────────────────────────────────────────────────
/**
 * A captured payment for a wallet top-up order: credited through the SAME service
 * as POST /add-money/verify (status exactly "captured", order/amount/currency
 * match, one atomic PENDING→SUCCESS + credit). Any validation failure is
 * NEEDS_REVIEW — never PROCESSED, never a credit, never a refund.
 */
const handleWalletTopupCaptured = async ({ payment, orderId }) => {
  const txn = await findTopupForOrder(orderId);
  if (!txn) return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "WALLET_TOPUP_NOT_FOUND" };
  const r = await creditTopupFromPayment({ txn, payment, via: "webhook" }); // throws on DB trouble → FAILED, Razorpay retries
  if (r.outcome === TOPUP_CREDIT_OUTCOME.CREDITED) {
    return { status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "WALLET_TOPUP_CREDITED" };
  }
  if (r.outcome === TOPUP_CREDIT_OUTCOME.ALREADY_CREDITED) {
    return { status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "WALLET_TOPUP_ALREADY_CREDITED" };
  }
  if (r.outcome === TOPUP_CREDIT_OUTCOME.NOT_CAPTURED || r.outcome === TOPUP_CREDIT_OUTCOME.PAYMENT_FAILED) {
    return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: `WALLET_TOPUP_${r.outcome}` };
  }
  logger.error("[RazorpayWebhook] captured wallet top-up failed validation — needs review", { walletTxnId: String(txn._id), outcome: r.outcome });
  return { status: WEBHOOK_EVENT_STATUS.NEEDS_REVIEW, outcome: `WALLET_TOPUP_${r.outcome}` };
};

// ─── EVENT HANDLERS ─────────────────────────────────────────────────
const handleCaptured = async ({ payment, order, app }) => {
  const paymentId = payment?.id;
  const orderId = payment?.order_id || order?.id;
  if (!paymentId || !orderId) return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "NO_ORDER" };
  if (payment.status !== "captured") return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "NOT_CAPTURED" };

  if (await Transaction.exists({ paymentId })) {
    return { status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "ALREADY_RECORDED" }; // the client's /confirm got there first
  }

  const found = await findBookingForOrder(orderId);
  if (found.walletTopup) return handleWalletTopupCaptured({ payment, orderId });
  if (!found.booking) return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "UNKNOWN_ORDER" };
  const { booking, orphan } = found;
  const base = { bookingId: booking._id };

  if (payment.currency !== "INR" || payment.amount !== booking.totalAmountInPaise) {
    logger.error("[RazorpayWebhook] captured payment does not match the booking amount — needs review", { paymentId, bookingId: String(booking._id), paid: payment.amount, expected: booking.totalAmountInPaise });
    return { ...base, status: WEBHOOK_EVENT_STATUS.NEEDS_REVIEW, outcome: "AMOUNT_MISMATCH" };
  }

  const holdValid = booking.status === BOOKING_STATUS.HOLD && booking.lockUntil && booking.lockUntil > new Date();
  if (holdValid && !orphan) {
    try {
      await confirmBookingFromWebhook({ booking, paymentId, orderId, app });
      return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "AUTO_CONFIRMED" };
    } catch (err) {
      // Re-read the truth after a failed attempt.
      if (await Transaction.exists({ paymentId })) return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "ALREADY_RECORDED" };
      const msg = String(err?.message || "");
      const unusable = [409, 400].includes(err?.status) &&
        (/hold has expired|already booked|already in state|Invalid booking state|Duplicate payment/i.test(msg));
      if (!unusable) throw err; // gateway unreachable, DB trouble…: FAILED, Razorpay retries
      const refund = await issueAutoRefund({ payment, bookingId: booking._id, reason: /already booked/i.test(msg) ? "SLOT_TAKEN" : "BOOKING_NOT_PAYABLE" });
      return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: `AUTO_REFUND(${refund.outcome})`, refundId: refund.refundId };
    }
  }

  const reason = orphan ? "ORDER_NOT_CURRENT"
    : booking.status === BOOKING_STATUS.HOLD ? "HOLD_EXPIRED"
    : booking.status === BOOKING_STATUS.EXPIRED ? "HOLD_EXPIRED"
    : "BOOKING_NOT_PAYABLE";
  const refund = await issueAutoRefund({ payment, bookingId: booking._id, reason });
  return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: `AUTO_REFUND(${refund.outcome})`, refundId: refund.refundId };
};

const handleFailed = async ({ payment }) => {
  // A failed attempt is not a failed booking: the customer can pay the same
  // order again. Recorded for audit only.
  const bookingId = payment?.order_id ? (await Booking.findOne({ razorpayOrderId: payment.order_id }).select("_id").lean())?._id : null;
  return { bookingId: bookingId || null, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "PAYMENT_FAILED_RECORDED" };
};

const findRefundDoc = (gatewayRefund) =>
  Refund.findOne({ razorpayRefundId: gatewayRefund.id }).then((d) => d || (gatewayRefund?.notes?.refundRef && mongoose.Types.ObjectId.isValid(gatewayRefund.notes.refundRef) ? Refund.findById(gatewayRefund.notes.refundRef) : null));

const handleRefundProcessed = async ({ refund, payment }) => {
  if (!refund?.id || refund.status !== "processed") return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "REFUND_NOT_PROCESSED" };
  const paymentId = refund.payment_id || payment?.id;

  // Ours (created by the engine) or made outside this system (e.g. dashboard).
  let doc = await findRefundDoc(refund);
  const external = !doc;
  if (external) {
    let pay = payment;
    if (!pay || pay.id !== paymentId) {
      try { pay = await fetchRazorpayPayment(paymentId); } catch (err) { if (!isRazorpayNotFound(err)) throw err; pay = payment; }
    }
    doc = await recordExternalRefund({ gatewayRefund: refund, payment: pay });
  }
  doc = await completeRefund({ refundDoc: doc, gatewayStatus: refund.status, gatewayRefundId: refund.id });

  const base = { bookingId: doc.bookingId || null, refundId: refund.id, amountInPaise: refund.amount };
  if (!doc.bookingId) {
    // A refund of a wallet top-up payment (the engine never refunds top-ups, so it came from
    // outside, e.g. the dashboard): the wallet was credited and is NOT debited automatically.
    const topupOrderId = doc.orderId || payment?.order_id || null;
    const isTopup = await WalletTransaction.exists({
      type: WALLET_TXN_TYPE.TOPUP,
      $or: [{ razorpayPaymentId: paymentId }, ...(topupOrderId ? [{ razorpayOrderId: topupOrderId }] : [])],
    });
    if (isTopup) {
      logger.error("[RazorpayWebhook] refund on a wallet top-up payment — wallet not debited, needs review", { refundId: refund.id });
      return { ...base, status: WEBHOOK_EVENT_STATUS.NEEDS_REVIEW, outcome: "REFUND_ON_WALLET_TOPUP" };
    }
    return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "REFUND_RECORDED" };
  }

  const paidByThisPayment = await Transaction.exists({ paymentId });
  if (paidByThisPayment) {
    // A refund of the payment that confirmed the booking. If WE issued it (cancellation refund to
    // source) it is complete. If it came from outside, the salon's pending earnings were not
    // reversed here (wallet/ledger untouched) — flag for review.
    return external
      ? { ...base, status: WEBHOOK_EVENT_STATUS.NEEDS_REVIEW, outcome: "REFUND_ON_CONFIRMED_BOOKING" }
      : { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "REFUND_COMPLETED" };
  }
  if (await Transaction.exists({ bookingId: doc.bookingId })) {
    return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "DUPLICATE_PAYMENT_REFUND_RECORDED" }; // booking paid by another payment
  }
  return { ...base, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "REFUND_RECORDED" };
};

const handleRefundFailed = async ({ refund }) => {
  if (!refund?.id) return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "NO_REFUND" };
  const doc = await findRefundDoc(refund);
  if (!doc) return { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "UNKNOWN_REFUND" };
  await completeRefund({ refundDoc: doc, gatewayStatus: "failed", gatewayRefundId: refund.id, failureReason: refund.status_description || "Refund failed at the gateway" });
  return { bookingId: doc.bookingId || null, refundId: refund.id, status: WEBHOOK_EVENT_STATUS.PROCESSED, outcome: "REFUND_FAILED_RECORDED" };
};

// ─── ENTRY POINT ────────────────────────────────────────────────────
/**
 * Processes an already signature-verified payload.
 * @returns {Promise<{httpStatus:number, body:object}>}
 */
export const processRazorpayWebhook = async ({ payload, eventId, app }) => {
  const eventType = payload?.event;
  const entities = payload?.payload || {};
  const payment = entities.payment?.entity;
  const order = entities.order?.entity;
  const refund = entities.refund?.entity;

  const claim = await claimWebhookEvent({
    eventId,
    meta: {
      eventType,
      paymentId: payment?.id || refund?.payment_id || null,
      orderId: payment?.order_id || order?.id || null,
      refundId: refund?.id || null,
      amountInPaise: payment?.amount ?? refund?.amount ?? null,
    },
  });
  if (!claim.claimed) {
    if (claim.reason === "IN_FLIGHT") return { httpStatus: 503, body: { success: false, message: "Event is being processed" } }; // Razorpay retries
    return { httpStatus: 200, body: { success: true, duplicate: true, outcome: claim.doc.outcome } };
  }

  try {
    let result;
    switch (eventType) {
      case "payment.captured":
      case "order.paid":
        result = await handleCaptured({ payment, order, app });
        break;
      case "payment.failed":
        result = await handleFailed({ payment });
        break;
      case "refund.processed":
        result = await handleRefundProcessed({ refund, payment });
        break;
      case "refund.failed":
        result = await handleRefundFailed({ refund });
        break;
      default:
        result = { status: WEBHOOK_EVENT_STATUS.IGNORED, outcome: "UNHANDLED_EVENT" };
    }
    const { status, outcome, ...extra } = result;
    await finish(claim.doc, status, outcome, extra);
    return { httpStatus: 200, body: { success: true, status, outcome } };
  } catch (err) {
    await fail(claim.doc, err);
    logger.error("[RazorpayWebhook] processing failed", { eventType, eventId, message: err.message });
    return { httpStatus: 500, body: { success: false, message: "Webhook processing failed" } };
  }
};
