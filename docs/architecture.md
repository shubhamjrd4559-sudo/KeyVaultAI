# Architecture — Current repository implementation

```text
Client → Django REST API (/api/v1)
              ├→ apps.common   — health probe
              ├→ apps.users    — verified email authentication, password recovery, JWT + Argon2id
              ├→ apps.audit    — audit event logging
              ├→ apps.vault    — owner-scoped AES-256-GCM credentials
              ├→ apps.security — deterministic security analysis (M5)
              ├→ apps.ml_engine — ML risk prediction layer (M6)
              ├→ MongoDB Atlas (primary persistent store)
              │     ├─ users collection        (user accounts)
              │     ├─ refresh_tokens collection (JTI revocation)
              │     ├─ email_verification_tokens (hashed, expiring, single-use tokens)
              │     ├─ password_reset_tokens (hashed, expiring, single-use tokens)
              │     └─ audit_events collection   (security event log)
              └→ TLS Redis (atomic rate limiting, Celery broker/result backend)

Next.js frontend → Vercel (`frontend/` root directory)
Celery Worker + Beat → separate long-running container services
```

## Layer architecture

```
HTTP Request
    │
    ▼
View (apps/users/views.py)
  Validate request via Serializer
    │
    ▼
Service (apps/users/services/users.py)
  Business logic: hashing, token generation, validation
    │
    ├─→ Repository (apps/users/repositories/users.py)
    │     MongoDB CRUD — users + refresh_tokens collections
    │
    ├─→ TokenService (apps/users/services/authentication.py)
    │     JWT generation and validation
    │
    ├─→ RateLimiter (apps/users/services/rate_limiting.py)
    │     Atomic Redis-backed; rate-limited actions fail closed if unavailable
    │
    └─→ AuditService (apps/audit/services/audit.py)
          Safe metadata logging to logger + MongoDB
```

## Authentication flow

```
Register → Serializer → Normalize email → Check duplicate
         → Argon2id hash → pending account insert → hashed email token
         → SMTP verification message → Safe pending-account response

Verify   → Consume unexpired single-use token hash → mark account verified

Login    → Rate limit → find_by_email → Argon2id verify (always runs)
         → Generate JWT access + refresh → Store JTI → Update last_login
         → Audit LOGIN → Return tokens

Logout   → Validate Bearer token → Revoke JTI → Audit LOGOUT

Refresh  → Decode refresh JWT → Validate JTI in MongoDB
         → Revoke old JTI → Generate new pair → Store new JTI
         → Audit TOKEN_REFRESH
```

## Database

### MongoDB (primary store — NOT SQLite)

- **users** — email (unique index), user_id (unique index)
- **refresh_tokens** — jti (unique), user_id (index), TTL index on expires_at
- **audit_events** — append-only security event log
- Accessed via `apps.common.database.get_db()` (lazy connection, returns None if unconfigured)

### Redis (operational data only)

- Rate-limiting counters (atomic Lua increment/check with expiry)
- Celery broker and result backend
- Never used for persistent credential storage

### SQLite (Django ORM compatibility only)

- Present for Django framework internals
- Not used for application data

## Installed apps — Milestone 5

| App | Purpose |
|---|---|
| `apps.common` | Health probe, shared database factory |
| `apps.users` | Authentication: register, login, logout, token refresh |
| `apps.audit` | Security event logging |
| `apps.vault` | Encrypted, owner-scoped credential storage |
| `apps.security` | JWT-scoped score summary, safe alerts, and same-user reuse analysis |

## Deployment layout

- Vercel project root is set to `frontend/`; `NEXT_PUBLIC_API_BASE_URL` is a public build-time API URL, never a secret.
- A container host runs the Django web service, a separate Celery Worker, and a separate Celery Beat service from the backend image. The web process binds `0.0.0.0:$PORT`.
- Run one Beat scheduler instance. Mount persistent storage at `/var/run/celerybeat` for its schedule file; Compose defines this volume for local use, and the container host must attach an equivalent persistent volume to the Beat service.
- Railway does not run `docker-compose.yml` directly; create one Railway service for each required long-running process and set its start command and service variables in the dashboard.
- Use an Upstash TCP Redis connection URL with TLS (`rediss://`) for Python Redis and Celery. Do not use the Upstash REST URL/token as `REDIS_URL`.
- Atlas connections use TLS. Production checks require explicit hosts/origins, HTTPS frontend origin, SMTP TLS, and TLS Redis.
- MongoDB indexes are not created on application startup. Use the read-only preflight in `ensure_mongodb_indexes`; do not pass `--apply` without separate approval.

## Planned apps (future milestones)

`apps.vault` is implemented for Milestone 3 with owner-scoped MongoDB credential access and AES-256-GCM encryption. `apps.security` (M5) reads its safe metadata and transient encrypted-password projection to produce in-memory, same-user-only reuse analysis. `ai_engine`, `ml_engine`, and `browser_extension` remain planned.

## Current file tree

```
backend/
  config/settings/{base,development,production}.py
  config/{urls,asgi,wsgi,celery}.py
  apps/common/{database,services,views,urls}.py
  apps/users/{authentication,serializers,views,urls,apps}.py
  apps/users/models/__init__.py
  apps/users/repositories/users.py
  apps/users/services/{authentication,users,rate_limiting}.py
  apps/users/tests/{conftest,test_registration,test_login,test_tokens,test_security}.py
  apps/audit/services/audit.py
  apps/security/services/analyzer.py
  apps/security/{views,urls,apps}.py
  apps/ml_engine/{features,dataset,model,views,urls,apps}.py  ← M6
  apps/ml_engine/tests/test_ml_engine.py                       ← M6
  tests/test_health.py
```

## M6 ML Engine architecture

```
M5 deterministic security analysis
        ↓
safe derived features (length, char classes, diversity, score, reuse)
        ↓
M6 LogisticRegression pipeline (sklearn, in-memory, synthetic training data)
        ↓
risk_level (LOW/MEDIUM/HIGH) + confidence + explanation
        ↓
frontend SecurityPanel ML Risk badge
```

**M5 vs M6 responsibilities:**
- **M5 (SecurityAnalyzer):** Deterministic, rule-based. Produces `security_score` (0–100) and `security_level`. Detects reuse via SHA-256 hashes. Always runs.
- **M6 (ML Engine):** Probabilistic, learned. Consumes M5's safe derived features. Produces `risk_level` + `confidence`. Operates only on numerical features — never on raw passwords.
