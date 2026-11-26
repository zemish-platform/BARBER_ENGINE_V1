# Admin Secure Activation — rollout runbook

Code: `services/adminCredential.service.js`, `utils/adminActivationGate.js`,
`controllers/adminAccount.controller.js`, Admin Panel `/app/admin-accounts`,
`/activate-account`, `/reset-password`. Tests: `scripts/verifyAdminActivation.js`
(CI job `backend-db-suites`).

Nothing in this runbook has been executed. Every step that changes an
environment or a database needs the founder's explicit approval.

## What changes the moment the backend is deployed

An ADMIN account can no longer sign in, refresh, or use any protected route when:

- `mustChangePassword` is `true`, or
- it is a STATE/DISTRICT account that was never assigned by an authorized admin
  (`adminAssignedAt` unset). This holds even if `mustChangePassword` is false.

On Staging (read-only audit, 2026-11-26), that is **every** admin account:

| Accounts | Count | After deploy |
|---|---|---|
| INDIA | 1 | blocked until it activates by OTP (`mustChangePassword: true`) |
| STATE primary + backup | 36 + 36 | blocked until assigned + activated |
| DISTRICT primary | 780 | blocked until assigned + activated (4 of these had `mustChangePassword: false` and could previously sign in with the seed password) |

No data migration is needed: the gate reads existing fields, and no record is
created, renamed or deleted by the deploy.

## Prerequisite — India Admin OTP activation (Staging)

The INDIA admin has no superior, so it activates itself with an OTP sent to the
phone already stored on its account (seeded from `INDIA_ADMIN_PHONE`). Before
the backend reaches Staging, confirm (founder, in the Render dashboard — values
are never read by Claude):

1. **Which phone** the INDIA admin account holds — the founder must have that SIM.
2. **That Staging can deliver an OTP to it.** Staging sends real SMS only in one
   of these configurations (see `utils/stagingGuards.js`):
   - *Allowlist mode*: `STAGING_SMS_OTP_MODE=allowlist`, `SMS_PROVIDER=msg91`,
     MSG91 keys set, and the INDIA phone listed in `STAGING_SMS_ALLOWED_PHONES`.
   - *Standard mode*: `SMS_PROVIDER=msg91` with MSG91 keys, and
     `STAGING_SMS_OTP_MODE`, `STAGING_SMS_ALLOWED_PHONES`, `STAGING_TEST_LOGINS`
     all unset.
   - *Tester-login mode*: the INDIA phone listed in `STAGING_TEST_LOGINS` with
     its own secret 6-digit OTP (no SMS is sent; the listed OTP is used).
   If none applies to that phone, the OTP is never delivered and the request
   still answers "If this number is eligible, an OTP has been sent."
3. An environment change only takes effect after a deploy/restart.

Then, on the Staging Admin Panel: **Activate new account** → INDIA phone → code →
new password (10+ chars, upper, lower, number, symbol) → sign in with the
existing admin email, the new password and the admin key.

## Rolling out to employees

1. INDIA signs in → **Admin Accounts** → filter by state/level → **Assign** an
   employee (name, verified mobile, work email). The same account is reused.
2. The employee opens `/activate-account`, enters that mobile, the code, and a
   new password. Their phone must be reachable under the Staging SMS mode above.
3. A STATE admin can then assign the DISTRICT accounts of its own state.
4. Forgotten password: `/reset-password` (OTP to the assigned mobile). Every
   old session is signed out.

## Production

Same gate. The Production INDIA admin is seeded with `mustChangePassword: true`
(`scripts/02_seedIndiaSuperAdmin.js`), so it also activates by OTP to
`INDIA_ADMIN_PHONE`; Production uses the normal SMS provider. Production master
data seeding is a separate, not-yet-approved task. The seeds now reuse existing
admin accounts without renaming or re-enabling them.

## Staging data notes (read-only analysis, 2026-11-26)

Seed data defines 36 States / 779 Districts. Staging has 43 State records
(42 live) and 789 District records. The extras are test fixtures, not
duplicates: 7 `ZTEST_*` States (6 live, 1 soft-deleted) with 9 `ZTEST_*`
Districts, created by test suites on 2026-09-15 and 2026-10-06, plus one
`TEST ARCHIVE DISTRICT` (Maharashtra, created by the INDIA admin on 2026-07-07,
with one District admin). None has salons; the ZTEST records have no admins.
All 36 seed States and 779 seed Districts are present. Nothing was modified.
