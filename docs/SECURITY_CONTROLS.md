# Security Controls

## Authentication

Passwords are hashed with Argon2id. Usernames and email addresses are normalized
before storage. Authentication failures use generic responses, and unknown
usernames still execute a dummy Argon2 verification to reduce obvious timing
differences.

Login is protected in two layers: an IP-oriented Flask-Limiter policy and a
short temporary per-account lock after repeated incorrect passwords. Locked
accounts still receive the same generic credential failure response.

## Session and JWT security

JWTs are not treated as the sole source of truth. Every token carries a
server-generated session identifier (`sid`). Protected requests verify that the
session still exists, belongs to the JWT subject, has not been revoked, has not
expired, and belongs to an active user.

Access tokens live for 10 minutes. Refresh sessions have a seven-day maximum
lifetime. Each successful refresh rotates the refresh token and replaces its
stored JTI. Reusing an older refresh token is treated as a possible theft signal
and revokes the whole session.

Logout revokes the current server-side session. `POST /logout-all` revokes every
session for the current user. A password change also revokes all sessions and
requires a fresh sign-in.

## Authorization

The API implements owner-or-admin authorization for user records. The `/users`
collection and destructive user deletion are admin-only. User-controlled update
requests cannot modify `role`, preventing mass-assignment privilege escalation.

JWT role claims are intentionally not used for authorization. The current role is
read from the database so a stale token cannot preserve old privileges.

## Input and response hardening

JSON bodies are validated before use. Email addresses use `email-validator`;
usernames follow a strict allow-list; passwords use a 12-128 character length
policy plus a small deny-list and user-identifier checks. Request bodies are
capped at 16 KiB.

Responses include request correlation IDs and defensive headers:
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, a restrictive
API-oriented Content Security Policy, and `Cache-Control: no-store`. HSTS is
emitted only in production mode where HTTPS is expected.

## Security observability

Security-relevant events are persisted in `audit_events` and emitted through
application logging. Event payloads are intentionally minimal and must never
contain passwords, raw access tokens, or refresh tokens.

Important event types include login failures, temporary lockouts, successful
login, token refresh, refresh-token reuse detection, session revocation,
password changes, and authorization denials.

## Deployment boundary

`memory://` rate-limit storage and SQLite are convenient local defaults.
Multi-worker or multi-instance deployment should configure a shared rate-limit
backend and a production database. Forwarding headers should only be trusted
after configuring a known reverse proxy; the application intentionally does not
blindly trust client-supplied forwarding headers.
