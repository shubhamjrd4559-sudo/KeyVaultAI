# Security — Milestones 1 & 2

## Implemented security controls

| Control | Status | Implementation |
|---|---|---|
| Secrets in environment variables | ✅ | `.env` excluded by `.gitignore` |
| `DEBUG=False` in production | ✅ | Production settings guard |
| Real `DJANGO_SECRET_KEY` required in production | ✅ | `production.py` raises on fallback key |
| Health endpoint discloses no infrastructure details | ✅ | `health.py` swallows exceptions |
| CORS origins from environment | ✅ | `base.py` |
| HTTP security headers | ✅ | `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_REFERRER_POLICY`, `X_FRAME_OPTIONS` |
| **Argon2id password hashing** | ✅ | `argon2-cffi`, OWASP params (m=64MB, t=3, p=4) |
| **Plaintext password never stored** | ✅ | Service layer; tests verify |
| **JWT access + refresh tokens** | ✅ | HS256, type-embedded payloads |
| **Refresh token revocation (JTI)** | ✅ | MongoDB `refresh_tokens` collection |
| **Token rotation on refresh** | ✅ | Old JTI revoked before new pair issued |
| **Rate limiting abstraction** | ✅ | Redis-backed; NullRateLimiter when unavailable |
| **Anti-enumeration responses** | ✅ | Wrong email/password → identical 401 |
| **user_id from JWT only** | ✅ | LogoutView uses `request.user.user_id` |
| **Audit logging foundation** | ✅ | REGISTER, LOGIN, LOGIN_FAILED, LOGOUT events |
| **Safe audit records** | ✅ | No passwords, hashes, or tokens in audit |
| Constant-time password comparison | ✅ | Argon2 verify runs even on unknown email |

## NOT implemented (future milestones)

| Capability | Status |
|---|---|
| Email verification | NOT IMPLEMENTED (M4/M5) |
| Password reset emails | NOT IMPLEMENTED (M4/M5) |
| AES-256-GCM credential encryption | IMPLEMENTED (M3); `ENCRYPTION_KEY` must be a base64url-encoded 32-byte key and has no fallback |
| Vault access controls | IMPLEMENTED (M3); credential access is scoped to JWT user ID |
| Security engine / breach detection | NOT IMPLEMENTED (M5) |
| ML threat detection | NOT IMPLEMENTED (M6) |
| NVIDIA NIM | NOT IMPLEMENTED (M7) |
| Browser extension | NOT IMPLEMENTED (M8) |

## Argon2id parameters

```
time_cost  = 3       (iterations)
memory_cost = 65536  (64 MB)
parallelism = 4
hash_len   = 32 bytes
salt_len   = 16 bytes
```

These meet OWASP's Argon2id minimum recommendation.

## JWT token design

- **Algorithm:** HS256 with `JWT_SECRET_KEY` (must differ from `DJANGO_SECRET_KEY` in production)
- **Access token lifetime:** 300 seconds (5 min, configurable)
- **Refresh token lifetime:** 2592000 seconds (30 days, configurable)
- **Type claim:** `"access"` / `"refresh"` — prevents cross-use
- **JTI claim:** UUID4 in refresh tokens — enables per-token revocation
- **Revocation store:** MongoDB `refresh_tokens` collection with TTL index

## Rate limiting

- Login: 10 attempts per 5 minutes per IP
- Registration: 5 per hour per IP
- Token refresh: 30 per 5 minutes per IP
- Password reset: 3 per hour per IP

When Redis is unavailable, `NullRateLimiter` allows all requests and emits a WARNING log. Operators must start Redis to enable enforcement.

## MongoDB security

- `MONGODB_URI` contains credentials — stored in `.env` only, never in source code.
- Health probe uses a bounded 1s timeout and never returns connection strings.
- User email is normalized (lowercased, stripped) before storage and lookup.
- Duplicate email detection uses a unique index, not application-level SELECT.
