# API Security Test Matrix

The automated tests are attack-oriented. They exist to prove security properties,
not merely to increase line coverage.

| Test area | Security property |
|---|---|
| Registration normalization | Canonical identifiers |
| Duplicate registration | Reduced account enumeration |
| Unknown/inactive login | Generic authentication failures |
| Repeated login failure | Temporary account lock |
| Refresh rotation | Single-use current refresh token |
| Refresh replay | Theft signal revokes session |
| Token-type substitution | Access/refresh tokens cannot swap roles |
| Logout | Session invalidation |
| Logout-all | Global session invalidation |
| Password change | Existing sessions invalidated |
| Session cap | Sixth login revokes oldest session |
| Non-fresh sensitive action | Step-up authentication required |
| Reauthentication | Password proof restores fresh token |
| MFA enrollment | TOTP secret + recovery-code lifecycle |
| MFA challenge replay | Completed challenge cannot be reused |
| MFA attempt exhaustion | Challenge stops after configured failures |
| Recovery-code replay | Recovery code is single use |
| MFA disable | Password + second factor required |
| Cross-user GET/PUT | BOLA/IDOR denied |
| Role field injection | Mass-assignment escalation denied |
| Email self-change | Current password required |
| Admin deletion | RBAC + fresh authentication |
| Missing/invalid JWT | Controlled authentication errors |
| Malformed JSON | Controlled client error |
| Oversized request | 413 request-size enforcement |
| Security headers | Defensive response policy present |
| Session inventory | User can inspect/revoke owned sessions |
| Security-event history | User can inspect own authentication events |
| Database migration | Committed Alembic chain builds a fresh schema |

CI requires Ruff, the migration smoke test, and the security test suite to pass
with at least 85% measured coverage.

The pipeline intentionally remains focused. Broad scanner orchestration belongs
in the separate DevSecOps project rather than being duplicated here.
