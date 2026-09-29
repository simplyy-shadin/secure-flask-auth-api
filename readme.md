# Secure Flask Authentication API

A security-engineering project focused on **authentication, MFA, JWT/session
security, authorization, abuse resistance, and attack-focused API testing**.

This repository intentionally goes deep on identity and API security. It is not a
second DevSecOps scanner project.

## What this project demonstrates

- Argon2id password hashing
- normalized usernames and email addresses
- generic authentication failures to reduce account enumeration
- dummy password verification for unknown users
- IP login throttling and temporary per-account lockout
- short-lived JWT access tokens
- rotating refresh tokens with replay detection
- server-side revocable authentication sessions
- five-active-session cap with oldest-session eviction
- fresh-token step-up authentication for sensitive actions
- TOTP multi-factor authentication
- encrypted MFA secrets using a dedicated Fernet key
- replay-safe, short-lived MFA login challenges
- TOTP replay prevention
- eight single-use Argon2-hashed recovery codes
- MFA setup, status, disable, and recovery-code regeneration
- RBAC plus owner-or-admin object authorization
- BOLA/IDOR protection
- mass-assignment privilege-escalation protection
- password confirmation for self-service email changes
- security-event history and request correlation IDs
- JWT issuer/audience validation
- versioned Alembic/Flask-Migrate database migrations
- controlled JSON/JWT errors and defensive response headers
- attack-oriented automated tests and coverage enforcement

## Authentication architecture

```text
                       PASSWORD LOGIN
                             |
                    +--------+--------+
                    |                 |
                 MFA off            MFA on
                    |                 |
                    v                 v
             create session     MFA challenge token
                    |                 |
                    |          TOTP / recovery code
                    |                 |
                    |            challenge claimed
                    |                 |
                    +--------+--------+
                             |
                             v
                     AuthSession record
                             |
                 +-----------+-----------+
                 |                       |
          fresh access JWT         refresh JWT
             10 minutes              7 days max
                 |                       |
                 |                 refresh rotation
                 |                       |
                 |               current JTI replaced
                 |                       |
                 +-----------+-----------+
                             |
                     server-side session
                        source of truth
```

A valid JWT signature alone is not enough. Protected requests also require a
valid server-side session belonging to an active user.

## Refresh-token theft detection

```text
Refresh A used legitimately
        |
        v
server stores Refresh B JTI

stolen Refresh A used later
        |
        v
presented JTI != current JTI
        |
        v
refresh replay detected
        |
        v
entire session revoked
```

## MFA design

MFA is implemented as a two-stage login. Password verification does **not**
create a fully authenticated session when MFA is enabled. Instead it returns a
short-lived MFA challenge token.

A successful challenge can use either:

- a six-digit TOTP code, or
- one single-use recovery code.

MFA challenges are server-tracked and atomically consumed, so replaying the same
challenge cannot create a second authenticated session.

TOTP secrets are encrypted at rest with a dedicated Fernet key. Recovery codes
are never stored in plaintext; they are Argon2-hashed and marked used after one
successful redemption.

TOTP improves resistance to password-only compromise, but it is **not
phishing-resistant**. A production identity platform with stronger requirements
would normally consider WebAuthn/passkeys or hardware-backed authenticators.

## Step-up authentication

Initial password/MFA login issues a **fresh** access token. Access tokens issued
through refresh are intentionally non-fresh.

Sensitive operations require a fresh token, including account mutation, session
revocation, password changes, MFA changes, and administrative deletion.

A user holding a valid non-fresh token can call:

```http
POST /reauth
```

with the current password and, when MFA is enabled, a TOTP or recovery code.
Successful reauthentication returns a fresh access token for the same session.

## API endpoints

### Authentication and session security

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/register` | Register a user |
| `POST` | `/login` | Password login or begin MFA challenge |
| `POST` | `/mfa/verify-login` | Complete MFA login |
| `POST` | `/refresh` | Rotate refresh token and issue non-fresh access token |
| `POST` | `/reauth` | Step up to a fresh access token |
| `POST` | `/logout` | Revoke current session |
| `POST` | `/logout-all` | Revoke all sessions; fresh auth required |
| `GET` | `/sessions` | View active sessions |
| `DELETE` | `/sessions/<id>` | Revoke an owned session; fresh auth required |
| `PUT` | `/password` | Change password and revoke all sessions |

### MFA

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/mfa/status` | View MFA state and unused recovery-code count |
| `POST` | `/mfa/setup` | Generate encrypted TOTP enrollment secret |
| `POST` | `/mfa/enable` | Verify TOTP and enable MFA |
| `POST` | `/mfa/recovery-codes` | Regenerate recovery codes |
| `POST` | `/mfa/disable` | Disable MFA with password + second factor |

### Users and security events

| Method | Endpoint | Authorization |
|---|---|---|
| `GET` | `/profile` | Current user |
| `GET` | `/security-events` | Current user's security history |
| `GET` | `/users` | Admin |
| `GET` | `/users/<id>` | Owner or admin |
| `PUT` | `/users/<id>` | Owner/admin + fresh auth |
| `DELETE` | `/users/<id>` | Admin + fresh auth |

The machine-readable API contract is in [openapi.yaml](openapi.yaml).

## Local setup

```bash
git clone https://github.com/simplyy-shadin/secure-flask-auth-api.git
cd secure-flask-auth-api

python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate         # Windows

pip install -r requirements-dev.txt
cp .env.example .env
```

Generate two independent application secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Generate the separate MFA encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the generated values in `.env`, then apply the committed database
migrations:

```bash
flask --app app.py db upgrade
```

If you have a database created by the earlier pre-migration version of this
repository, follow [migrations/README](migrations/README) before upgrading.

Run the API:

```bash
flask --app app.py run
```

Create an administrator without exposing a public role-change endpoint:

```bash
flask --app app.py create-admin
```

## Testing

```bash
ruff check .
pytest --cov=secure_api --cov-report=term-missing --cov-fail-under=85
```

GitHub Actions also validates that the Alembic migration chain can build a fresh
database before running the security test suite.

The tests cover authentication failures, account lockout, refresh replay,
session revocation, session caps, fresh-token enforcement, MFA enrollment,
challenge replay, recovery-code replay, BOLA/IDOR, RBAC, mass assignment,
token-type confusion, malformed input, security headers, and security-event
history.

## Configuration

| Variable | Purpose | Local default |
|---|---|---|
| `SECRET_KEY` | Flask secret | required |
| `JWT_SECRET_KEY` | JWT signing secret | required |
| `MFA_ENCRYPTION_KEY` | Fernet key for TOTP secrets | required |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///users.db` |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter backend | `memory://` |
| `APP_ENV` | Enables production-only behavior such as HSTS | `development` |

For multi-process or multi-instance deployment, use a production database and a
shared rate-limit backend. Forwarded client-IP headers should only be trusted
after configuring a known reverse proxy.

## Repository structure

```text
.
├── app.py
├── config.py
├── openapi.yaml
├── migrations/
│   ├── env.py
│   └── versions/
├── secure_api/
│   ├── __init__.py
│   ├── auth.py
│   ├── audit.py
│   ├── extensions.py
│   ├── mfa.py
│   ├── mfa_routes.py
│   ├── models.py
│   ├── security.py
│   ├── security_events.py
│   ├── session_service.py
│   └── users.py
├── tests/
│   ├── conftest.py
│   ├── test_api_security.py
│   ├── test_auth.py
│   ├── test_authorization.py
│   ├── test_identity_security.py
│   └── test_mfa.py
└── docs/
    ├── API_SECURITY_TESTS.md
    ├── SECURITY_CONTROLS.md
    └── THREAT_MODEL.md
```

## Project boundary

The deliberate scope is **authentication and API security engineering**.
Infrastructure-as-code scanning, container orchestration, broad SAST/SCA
orchestration, cloud provisioning, and full DevSecOps pipeline design are kept
outside this repository so it remains complementary to a separate DevSecOps
project rather than duplicating one.

## Author

**Shadin K V**

Cybersecurity student focused on Security Engineering, Application Security, and
offensive/defensive security.
