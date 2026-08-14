# Architecture — Milestones 1 & 2

```text
Client → Django REST API (/api/v1)
              ├→ apps.common   — health probe
              ├→ apps.users    — authentication (JWT + Argon2id + MongoDB)
              ├→ apps.audit    — audit event logging
              ├→ MongoDB Atlas (primary persistent store)
              │     ├─ users collection        (user accounts)
              │     ├─ refresh_tokens collection (JTI revocation)
              │     └─ audit_events collection   (security event log)
              └→ Redis (rate limiting, Celery broker, future caching)
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
    │     Redis-backed (NullRateLimiter if Redis unavailable)
    │
    └─→ AuditService (apps/audit/services/audit.py)
          Safe metadata logging to logger + MongoDB
```

## Authentication flow

```
Register → Serializer → Normalize email → Check duplicate
         → Argon2id hash → MongoDB insert → Audit REGISTER
         → Safe user response (no password_hash)

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

- Rate-limiting counters (INCR + EXPIRE)
- Celery broker and result backend
- Never used for persistent credential storage

### SQLite (Django ORM compatibility only)

- Present for Django framework internals
- Not used for application data

## Installed apps — Milestone 2

| App | Purpose |
|---|---|
| `apps.common` | Health probe, shared database factory |
| `apps.users` | Authentication: register, login, logout, token refresh |
| `apps.audit` | Security event logging |

## Planned apps (future milestones)

`users`, `vault`, `security`, `ai_engine`, `ml_engine`, `browser_extension`
(separate from `apps.users` which covers authentication only)

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
  tests/test_health.py
```
