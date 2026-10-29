# Phase 7 Authentication System

This project is a standalone Express authentication service built for the Phase 7 auth/security task. It includes:

- User signup with bcrypt hashing
- Login returning an access token and refresh token
- Refresh-token rotation and server-side revocation
- Admin-only routes protected by RBAC checks
- Password reset request and completion flow with expiry and single-use protection
- CSRF protection for cookie-authenticated state-changing requests
- Verified security checklist and threat model

## Project structure

- `src/app.js` — Express app bootstrap
- `src/auth.routes.js` — auth endpoints
- `src/auth.service.js` — signup/login/refresh/reset logic
- `src/auth.middleware.js` — JWT/session auth and RBAC enforcement
- `src/admin.routes.js` — protected admin routes
- `src/db.js` — SQLite schema and startup seeding
- `test/security.test.js` — focused authentication security tests

## Setup

1. Install dependencies:
   npm install
2. Copy the env template:
   cp .env.example .env
3. Start the server:
   npm start

The app runs at `http://localhost:3000`.

## Default admin account

This app seeds an admin user for testing:

- email: `admin@local.test`
- password: `AdminPass123!`

## Key routes

### Auth

- `POST /auth/signup`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/request-reset`
- `POST /auth/complete-reset`
- `POST /auth/logout`
- `GET /auth/me`

### Admin

- `GET /admin/users` — admin-only route
- `GET /admin/dashboard` — admin-only route

## Security notes

- Passwords are stored only as bcrypt hashes.
- Login failures use a generic response.
- Access tokens are short-lived, and refresh tokens are rotated and revoked on reuse.
- Reset tokens are hashed before storage and are single-use and time-limited.
- RBAC checks are enforced on server-side protected routes.
- Admin routes return `403` for authenticated non-admin users.
- Cookie-authenticated state-changing requests require a CSRF token.
- Reset requests use an identical response whether or not an email exists.

## Security checklist

| Requirement | Status | Verification |
|---|---|---|
| Passwords are protected | VERIFIED | Signup and password reset use bcrypt; only password hashes are stored. |
| Login failures are generic | VERIFIED | Unknown emails and wrong passwords return the same `401` response. |
| Access tokens are short-lived | VERIFIED | Access tokens expire after 15 minutes. |
| Refresh tokens work securely | VERIFIED | Refresh tokens are hashed, rotated, and revoked after use; reuse is rejected. |
| Tokens are not leaked | VERIFIED | Tokens are not logged or returned in error messages; reset tokens are not returned by the request endpoint. |
| Secure cookies are used | VERIFIED | Session cookies use `HttpOnly`, `Secure` in production, and `SameSite=Strict`. |
| CSRF is protected | VERIFIED | Cookie-authenticated state-changing requests require a matching CSRF cookie and header. |
| RBAC is enforced server-side | VERIFIED | Admin routes require the `admin` role; regular users receive `403 Forbidden`. |
| Reset tokens expire | VERIFIED | Reset tokens expire after 15 minutes. |
| Reset tokens are single-use | VERIFIED | A completed or expired reset token cannot be used again. |
| Reset requests do not reveal accounts | VERIFIED | Existing and unknown emails receive the same response. |
| SQL injection is prevented | VERIFIED | Database operations use prepared statements and bound parameters. |
| XSS is not introduced by the API | VERIFIED | The service returns JSON and does not render user input as HTML. |

## Threat model summary

| Threat | Defense |
|---|---|
| Password database theft | bcrypt password hashing makes offline password cracking more difficult. |
| Account and email enumeration | Login and reset-request responses are intentionally generic. |
| Stolen access tokens | Fifteen-minute expiry limits the replay window. |
| Stolen refresh tokens | Random refresh tokens are hashed, rotated, and revoked after use. |
| Reset-token theft or replay | Reset tokens are hashed, time-limited, and marked single-use. |
| Privilege escalation | Every admin route applies server-side role enforcement. |
| SQL injection | All request values use prepared SQL statements. |
| CSRF attacks | Cookie-authenticated state changes require a matching CSRF token. |
| XSS attacks | The API returns JSON; clients must preserve framework output escaping. |

### Deployment requirements

- Replace the development `JWT_SECRET` with a high-entropy secret.
- Use HTTPS and keep `COOKIE_SECURE=true` in production.
- Add rate limiting, monitoring, email delivery, and key rotation for production use.

## Verification

Run the security tests and smoke check with:

```text
npm test
npm run smoke
```

Expected result: all security tests pass and the application smoke check prints
`smoke-ok function`.
