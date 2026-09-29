# Secure Flask Authentication API

A security-engineering project focused on **authentication, JWT/session lifecycle
security, authorization, abuse resistance, and API security testing**.

This repository is deliberately not a generic DevSecOps demo. Its purpose is to
show how authentication systems fail and how those failure modes can be designed,
implemented, and tested defensively.

## Security architecture

```text
Client
  |
  v
Authentication API
  |
  +-- Password security -------- Argon2id
  +-- Login abuse defense ------ IP throttling + temporary account lock
  +-- Access token ------------ short-lived JWT (10 min)
  +-- Refresh token ----------- rotating, session-bound JWT
  +-- Server-side session ----- revocable source of truth
  +-- Authorization ----------- owner-or-admin + RBAC
  +-- Audit trail ------------- security event records + request IDs

Refresh replay
  -> old refresh JTI detected
  -> session revoked
  -> access tokens from that session become unusable
```

## Security controls

- Argon2id password hashing
- 12-128 character password policy with weak-password checks
- Access + refresh JWT separation
- Server-side authentication sessions
- Refresh-token rotation
- Refresh-token replay detection
- Session revocation on logout
- Logout from all sessions
- Password-change session invalidation
- User-visible active session inventory and revocation
- Role-based access control
- Owner-or-admin object authorization against BOLA/IDOR
- Mass-assignment protection for privileged fields
- Generic login and duplicate-registration responses
- Dummy password verification for unknown users to reduce obvious timing differences
- IP login throttling and temporary per-account lockout
- Request-size limits
- Structured security audit events
- Request correlation IDs
- Defensive response headers
- Controlled JSON/JWT/error responses
- Attack-focused automated tests

See [Threat Model](docs/THREAT_MODEL.md),
[Security Controls](docs/SECURITY_CONTROLS.md), and
[API Security Tests](docs/API_SECURITY_TESTS.md).

## Authentication lifecycle

```text
LOGIN
  |
  +--> server-side session
          |
          +--> short-lived access token
          |
          +--> refresh token (JTI stored server-side)
                    |
                    v
                 REFRESH
                    |
          current JTI matches?
              /           \
            yes            no
             |              |
        rotate token    replay detected
             |              |
        replace JTI     revoke session
```

A valid JWT signature is therefore not enough by itself. The associated
server-side session must still be valid.

## API endpoints

### Authentication and sessions

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/register` | Register a user |
| `POST` | `/login` | Create a server-side session and token pair |
| `POST` | `/refresh` | Rotate refresh token and issue a new token pair |
| `POST` | `/logout` | Revoke current session |
| `POST` | `/logout-all` | Revoke every session for the user |
| `GET` | `/sessions` | View active sessions |
| `DELETE` | `/sessions/<id>` | Revoke one owned session |
| `PUT` | `/password` | Change password and revoke all sessions |

### Users

| Method | Endpoint | Authorization |
|---|---|---|
| `GET` | `/profile` | Current user |
| `GET` | `/users` | Admin |
| `GET` | `/users/<id>` | Owner or admin |
| `PUT` | `/users/<id>` | Owner or admin; email only |
| `DELETE` | `/users/<id>` | Admin |

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

Generate two different random secrets of at least 32 characters and put them in
`.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Initialize the database and run the API:

```bash
flask --app app.py init-db
flask --app app.py run
```

Create an administrator without exposing a role-change API:

```bash
flask --app app.py create-admin
```

The command prompts for the password without echoing it.

## Testing

```bash
pytest --cov=secure_api --cov-report=term-missing
ruff check .
```

The test suite covers refresh-token replay, logout revocation, password-change
session invalidation, account lockout, BOLA/IDOR, RBAC, privileged-field
injection, malformed JSON, authentication enforcement, session revocation, and
security response headers.

GitHub Actions runs the same focused test suite and lint checks on pull requests
and pushes to `main`. The CI is intentionally small because this repository's
engineering focus is the authentication system itself rather than security
scanner orchestration.

## Configuration

| Variable | Purpose | Local default |
|---|---|---|
| `SECRET_KEY` | Flask secret | required |
| `JWT_SECRET_KEY` | JWT signing secret | required |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///users.db` |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter backend | `memory://` |
| `APP_ENV` | Enables production-only behavior such as HSTS | `development` |

For multi-process or multi-instance deployments, use a production database and
shared rate-limit storage. Configure forwarding headers only behind a trusted
reverse proxy.

## Repository structure

```text
.
├── app.py
├── config.py
├── secure_api/
│   ├── __init__.py
│   ├── auth.py
│   ├── audit.py
│   ├── extensions.py
│   ├── models.py
│   ├── security.py
│   └── users.py
├── tests/
│   ├── conftest.py
│   ├── test_api_security.py
│   ├── test_auth.py
│   └── test_authorization.py
├── docs/
│   ├── API_SECURITY_TESTS.md
│   ├── SECURITY_CONTROLS.md
│   └── THREAT_MODEL.md
├── SECURITY.md
├── requirements.txt
├── requirements-dev.txt
└── .github/workflows/ci.yml
```

## Project scope

This project intentionally goes deep on **authentication and API security**.
Infrastructure-as-code scanning, container orchestration, broad SAST/SCA
pipelines, cloud deployment automation, and full DevSecOps platform concerns are
kept outside the core project so this repository retains a clear
security-engineering identity.

## Author

**Shadin K V**

Cybersecurity student focused on Security Engineering, Application Security,
and offensive/defensive security.
