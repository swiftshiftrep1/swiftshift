# SwiftShift MVP — upgraded beta build

This build upgrades the original prototype with:

- strict CSP-compatible frontend (no inline onclick handlers)
- valid, separate signup/login forms
- transactional SQLite database using Node 22's built-in `node:sqlite`
- proper user-ID based authorization
- complete job state machine and status history
- in-app job chat with polling
- notification records + unread toast notifications
- active-job location sharing/viewing with explicit browser permission
- requester + runner reviews and reputation statistics
- demand-aware transparent pricing
- expanded admin operations dashboard
- safety incidents and disputes
- audit logging
- PayFast checkout/ITN integration retained

## Runtime requirement

**Node.js 22.5+** is required because this version uses the built-in `node:sqlite` module. Node 22.16+ is recommended.

The sandbox used for this build could not reliably download npm packages, so the database layer uses Node's built-in SQLite instead of pretending PostgreSQL was installed. SQLite is appropriate for a single-server closed beta. For a multi-instance/public launch, migrate the same schema to PostgreSQL and use a managed database.

## Run

```bash
npm install
cp .env.example .env
npm start
```

Then open `http://localhost:3000`.

## Demo mode

```bash
DEMO_MODE=true \
BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
BOOTSTRAP_ADMIN_PASSWORD='ChangeThis123!' \
node server.js
```

Demo mode automatically approves new verification requests and marks created jobs as paid. **Do not use demo mode publicly.**

## Core flows

### Requester
1. Create account.
2. Verification is pending unless demo mode is enabled.
3. Post a job.
4. Price is calculated from base, distance indicator, complexity, urgency, demand and materials.
5. In normal mode, payment must be confirmed before the job can be accepted.
6. Track status, chat with the runner, open a dispute or report a safety issue.
7. Confirm delivery and review the runner.

### Runner
1. Verify account.
2. Turn availability on.
3. Browse paid open jobs.
4. Accept one job; only the assigned runner can progress it.
5. Share live location only during the active job and only after browser permission.
6. Chat with the requester.
7. Mark delivery.
8. Requester confirmation creates a payout record.

### Admin
The admin dashboard includes platform metrics, verification queue, disputes, safety incidents, recent users, recent jobs and audit records.

## Payment

PayFast checkout is supported through the custom payment flow and ITN confirmation. Configure merchant credentials and a public HTTPS `PUBLIC_BASE_URL` before enabling real payments.

PayFast Split Payments is **not implemented as escrow**. Runner payout execution still requires an approved payout provider and compliant bank-account workflow.

## Important production work still required

- migrate SQLite to managed PostgreSQL before horizontal scaling/public launch
- configure real student/identity verification with an authorized process
- secure object storage + retention/deletion controls for ID documents
- add CSRF protection or strict Origin checks for cookie-authenticated state-changing requests
- add payment-provider server validation/IP/domain checks as required by the provider
- implement actual runner payouts and refunds with provider webhooks
- complete POPIA/privacy/terms/safety/refund policies with qualified South African legal review
- add automated security/integration tests and monitoring
- deploy behind HTTPS and configure trusted proxy settings
