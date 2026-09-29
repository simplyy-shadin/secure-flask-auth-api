# Threat Model

## Scope

Protected assets include credentials, TOTP secrets, recovery codes,
authentication sessions, JWTs, user profile data, authorization boundaries, and
security audit records. All HTTP client input is untrusted.

## High-value abuse cases

| Threat | Attack path | Primary controls | Verification |
|---|---|---|---|
| Credential guessing | Repeated password attempts | IP throttling + temporary account lock | Account-lock tests |
| Account enumeration | Login/registration response differences | Generic failures + dummy Argon2 verification | Enumeration tests |
| Password database theft | Offline hash cracking | Argon2id password hashing | Model review |
| JWT replay after logout | Stolen access token | Server-side session validation | Logout revocation test |
| Refresh-token theft | Reuse of a rotated token | JTI rotation + replay detection + session revocation | Refresh replay test |
| Access-token privilege on sensitive action | Long-lived authenticated session attempts account change | Fresh-token step-up authentication | Fresh-token tests |
| MFA challenge replay | Reuse MFA challenge after successful verification | Server-side challenge + atomic one-time consumption | Challenge replay test |
| TOTP replay | Reuse same valid TOTP time step | Last accepted TOTP step tracking | MFA tests |
| MFA-secret database theft | Read encrypted TOTP seed | Fernet encryption with separate environment key | Code/config review |
| Recovery-code database theft | Offline recovery-code recovery | High-entropy codes + Argon2 hashes | Model/helper review |
| Recovery-code replay | Reuse previously redeemed code | Used timestamp + single-use verification | Recovery replay test |
| MFA brute force | Guess six-digit code | Short challenge lifetime + attempt cap + endpoint rate limit | MFA attempt-limit test |
| Session sprawl | Many valid stolen/forgotten sessions | Maximum five active sessions + oldest eviction | Session-cap test |
| BOLA / IDOR | Modify `/users/<id>` | Owner-or-admin authorization | Authorization tests |
| Privilege escalation | Submit `role=admin` | Strict field allow-list | Mass-assignment test |
| Stolen bearer token changes email | Sensitive mutation with token only | Fresh auth + current-password confirmation | Email-change tests |
| Session persistence after password/MFA change | Old sessions remain valid | Global session revocation | Password/MFA tests |
| Token-type confusion | Access token used as refresh or vice versa | Flask-JWT token-type enforcement | Token substitution test |
| Sensitive-data leakage | Secrets/tokens logged or returned | Minimal audit payloads + controlled errors | Review + API tests |

## MFA limitation

TOTP provides a meaningful second factor against password-only compromise, but
it is not phishing-resistant. A real-time phishing proxy can potentially capture
and immediately relay a TOTP value. This project therefore does not claim that
TOTP provides the same assurance as WebAuthn/passkeys or hardware-backed,
origin-bound authenticators.

## STRIDE summary

- **Spoofing:** Argon2id, throttling, MFA, recovery-code controls, and
  server-side sessions reduce account takeover paths.
- **Tampering:** JWT signatures plus issuer/audience validation protect token
  integrity and intended-service boundaries; authorization is read from current
  server-side state.
- **Repudiation:** security-sensitive operations are persisted as audit events
  with request IDs and source IP metadata.
- **Information disclosure:** MFA seeds are encrypted, recovery codes are hashed,
  authentication errors are generic, and raw tokens/passwords are not logged.
- **Denial of service:** request-size limits and endpoint throttles constrain
  obvious abuse; shared rate-limit storage is required for distributed
  deployments.
- **Elevation of privilege:** roles are not user-editable, object authorization
  is explicit, and sensitive mutations require recent authentication.

## Trust assumptions

TLS termination, reverse-proxy trust, database backup/encryption, infrastructure
IAM, encryption-key lifecycle, centralized log shipping, and production secret
management remain deployment responsibilities.

The repository intentionally keeps those infrastructure concerns outside its
core scope so the project remains focused on authentication and API security.
