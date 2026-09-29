# Security Controls

## Password authentication

Passwords are hashed with Argon2id. Usernames and email addresses are normalized
before storage. Unknown usernames still execute a dummy Argon2 verification to
reduce an obvious timing difference. Authentication failures deliberately avoid
revealing whether an account exists, is inactive, or is temporarily locked.

Login uses both IP-oriented rate limiting and temporary per-account lockout.

## JWT and server-side session security

JWTs are not treated as the sole source of truth. Every normal access/refresh
token carries a server-generated session identifier (`sid`). Protected requests
verify that the session exists, belongs to the JWT subject, remains active, has
not expired, and belongs to an active user.

JWTs also carry explicit issuer and audience values for this API.

Access tokens live for 10 minutes. Refresh sessions have a seven-day maximum
lifetime. Each successful refresh rotates the refresh token and replaces the
stored JTI. Presenting an older refresh token is treated as a possible theft
signal and revokes the session.

A user may keep at most five active sessions. Creating a sixth session revokes
the oldest valid session.

## Fresh-token step-up authentication

Initial password/MFA authentication issues a fresh access token. A token issued
by the refresh endpoint is non-fresh.

Sensitive endpoints use `jwt_required(fresh=True)`. A valid non-fresh token can
be upgraded through `POST /reauth` only after the current password is verified
and, when MFA is enabled, a second factor is verified.

This separates ordinary session continuity from recent proof of identity.

## TOTP MFA

MFA enrollment generates a TOTP seed. The seed is encrypted before database
storage using a dedicated Fernet key that is separate from Flask and JWT secrets.

When MFA is enabled, password login creates a five-minute server-side MFA
challenge instead of an authenticated session. The challenge must be completed
with TOTP or an unused recovery code before a session is created.

Challenges:

- are stored server-side,
- have an attempt limit,
- are rate-limited,
- expire quickly, and
- are atomically consumed so successful challenge replay cannot create another
  authenticated session.

The last successfully accepted TOTP time step is stored to reject reuse of the
same or an older TOTP step.

## Recovery codes

Eight high-entropy recovery codes are generated when MFA is enabled. They are
returned to the user once and stored only as Argon2 hashes.

A successful recovery-code login marks that code used. Reusing the same code
fails.

Regenerating recovery codes replaces all previous recovery-code hashes.

## MFA lifecycle

Enabling MFA revokes sessions created before MFA was active, forcing subsequent
authentication through the second factor.

Disabling MFA requires:

1. a fresh access token,
2. the current password, and
3. TOTP or an unused recovery code.

Disabling MFA revokes all sessions and removes stored MFA material.

## Authorization

The API uses owner-or-admin authorization for user records. User-controlled
updates cannot change roles. Admin-only destructive actions and account
mutations require a fresh token.

Self-service email changes additionally require the user's current password.

JWT role claims are not used for authorization; current role state is read from
the database.

## Security observability

Security-relevant events are persisted in `audit_events` and emitted through
application logging. Raw passwords, JWTs, TOTP seeds, and recovery codes are not
stored in audit event payloads.

Authenticated users can inspect their own recent events through
`GET /security-events`.

## Input and response hardening

The API validates JSON input, normalized email addresses, allow-listed
usernames, password length, and password/user-identifier overlap. Request bodies
are capped at 16 KiB.

Responses include request correlation IDs, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, a restrictive API-oriented Content
Security Policy, and `Cache-Control: no-store`. HSTS is added in production
mode.

## Schema management

Database schema evolution uses Flask-Migrate/Alembic rather than relying on
`db.create_all()`. CI applies the committed migration chain to a fresh database
before running application tests.

## Deployment boundary

SQLite and `memory://` rate-limit storage are local-development defaults.
Distributed deployment should use a production database and shared rate-limit
backend. Proxy forwarding headers should only be trusted behind a configured,
known reverse proxy.

TOTP itself is not phishing-resistant. Stronger production assurance may require
WebAuthn/passkeys or hardware-backed authenticators.
