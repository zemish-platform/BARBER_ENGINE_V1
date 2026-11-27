/**
 * BARBER_ENGINE_V1
 * backend/utils/adminActivationGate.js
 *
 * Admin secure activation — the single server-side rule for "this ADMIN
 * account may not hold a session". Used by adminLogin, protect and
 * rotateSession (dependency-free so session.service can import it).
 *
 * Blocked when:
 *   - mustChangePassword is true (assigned/seeded, owner never set a password), or
 *   - a STATE/DISTRICT account was never assigned to an employee by an
 *     authorized admin (adminAssignedAt unset). This also covers seeded
 *     placeholders whose mustChangePassword flag is false — knowing a
 *     seed/shared password is never enough.
 * The INDIA super admin has no superior to assign it; only the first rule applies.
 */
export const ADMIN_GATE_FIELDS = "mustChangePassword adminAssignedAt";

export const isAssignableLevel = (level) => level === "STATE" || level === "DISTRICT";

export const isAdminActivationBlocked = (user) =>
  !!user &&
  user.role === "ADMIN" &&
  (user.mustChangePassword === true || (isAssignableLevel(user.adminLevel) && !user.adminAssignedAt));
