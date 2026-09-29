# Threat Model

## Scope

Protected assets are user credentials, authentication sessions, JWTs, user
profile data, authorization boundaries, and security audit records. The primary
trust boundary is the HTTP API: all client input is untrusted.

## High-value abuse cases

| Threat | Attack path | Primary controls | Verification |
|---|---|---|---|
| Credential guessing | Repeated `/login` attempts | IP rate limiting + temporary account lock | `test_account_temporarily_locks_after_repeated_failures` |
| Username/email enumeration | Registration and login response differences | Generic authentication failure and duplicate-account response | `test_registration_does_not_reveal_duplicate_field` |
| Password database theft | Offline cracking of password hashes | Argon2id via `argon2-cffi` | Model implementation review |
| JWT replay after logout | Stolen access token used after logout | Server-side session lookup on every protected request | `test_logout_revokes_entire_session` |
| Stolen refresh token | Reuse of an already rotated refresh token | Refresh rotation + replay detection + session revocation | `test_refresh_rotation_rejects_replayed_refresh_token` |
| BOLA / IDOR | User changes object ID in `/users/<id>` | Owner-or-admin authorization | Authorization negative tests |
| Privilege escalation | User submits `role=admin` | Role is not user-editable | `test_user_cannot_submit_role_field_for_self_escalation` |
| Session persistence after password compromise | Existing sessions survive password change | Password change revokes all sessions | `test_password_change_revokes_all_sessions` |
| Sensitive-data leakage | Tokens/passwords exposed in logs or errors | Minimal event payloads and generic errors | Code review + API tests |

## STRIDE summary

- **Spoofing:** password guessing and token theft are addressed with Argon2id,
  throttling, short access-token lifetime, and server-side sessions.
- **Tampering:** JWT signature verification prevents unsigned claim changes;
  authorization decisions are made from current server-side state.
- **Repudiation:** login, refresh, logout, password, and authorization-denial
  events are recorded with request IDs.
- **Information disclosure:** authentication responses are deliberately generic,
  and API errors do not expose stack traces or token contents.
- **Denial of service:** authentication endpoints use request-size limits and
  rate limits. Distributed production deployments should use shared rate-limit
  storage.
- **Elevation of privilege:** roles are not user-editable and object access is
  checked with owner-or-admin authorization.

## Trust assumptions

TLS termination, reverse-proxy configuration, database backup/encryption,
infrastructure IAM, and centralized log shipping are deployment responsibilities.
They are intentionally outside this repository's main scope so the project stays
focused on authentication and API security rather than becoming another
DevSecOps platform project.
