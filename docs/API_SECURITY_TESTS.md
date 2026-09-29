# API Security Test Matrix

The automated tests are attack-oriented. They provide evidence for security
claims in the README rather than existing only to increase line coverage.

| Test area | Security property |
|---|---|
| Registration normalization | Canonical user identifiers |
| Duplicate registration | Reduced identifier enumeration |
| Login | Access/refresh token issuance |
| Refresh rotation | Single-use refresh-token behavior |
| Refresh replay | Theft signal revokes the session |
| Logout | Issued access and refresh tokens stop working |
| Password change | Existing sessions are invalidated |
| Repeated login failure | Temporary account lock activates |
| Cross-user GET/PUT | BOLA/IDOR denied |
| Role field injection | Mass-assignment privilege escalation denied |
| Missing JWT | Protected route rejects unauthenticated access |
| Malformed JSON | Controlled client error, not a server exception |
| Security headers | Defensive response policy present |
| Session inventory | User can identify and revoke owned sessions |

CI requires both the test suite and Ruff linting to pass. The pipeline is
intentionally lightweight: this repository demonstrates authentication/API
security engineering, while broad security-scanner orchestration belongs in the
separate DevSecOps project.
