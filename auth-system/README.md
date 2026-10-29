# Phase 7 Authentication System

This project is a standalone Express authentication service built for the Phase 7 auth/security task. It includes:

- User signup with bcrypt hashing
- Login returning an access token and refresh token
- Refresh-token rotation and server-side revocation
- Admin-only routes protected by RBAC checks
- Password reset request and completion flow with expiry and single-use protection
- Security checklist documenting verification

## Project structure

- `src/app.js` — Express app bootstrap
- `src/auth.routes.js` — auth endpoints
- `src/auth.service.js` — signup/login/refresh/reset logic
- `src/auth.middleware.js` — JWT/session auth and RBAC enforcement
- `src/admin.routes.js` — protected admin routes
- `src/db.js` — SQLite schema and startup seeding
- `SECURITY_CHECKLIST.md` — verified checklist for this project

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
- Access tokens are short-lived.
- Refresh tokens are tracked and revoked on reuse.
- Reset tokens are hashed before storage and are single-use and time-limited.
- RBAC checks are enforced on server-side protected routes.

## Verification

Run a smoke check with:

npm run smoke

A full checklist is included in `SECURITY_CHECKLIST.md`.
