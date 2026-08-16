# API — Milestones 1 & 2

## `GET /api/v1/health/`

Reports service and dependency reachability.

Success (`200`):
```json
{"status":"ok","services":{"mongodb":"ok","redis":"ok"}}
```
Dependency unavailable (`503`):
```json
{"status":"degraded","services":{"mongodb":"unavailable","redis":"ok"}}
```
If `MONGODB_URI` is empty, MongoDB reports `"not_configured"`; overall status is `degraded`.

---

## Authentication — `POST /api/v1/auth/`

All authentication endpoints accept and return `application/json`.

### `POST /api/v1/auth/register/`  ✅ IMPLEMENTED

Register a new user account.

**Request:**
```json
{
  "email": "alice@example.com",
  "full_name": "Alice Smith",
  "password": "SecurePass1!"
}
```

**Success (`201`):**
```json
{
  "user": {
    "user_id": "...",
    "email": "alice@example.com",
    "full_name": "Alice Smith",
    "email_verified": false,
    "account_status": "active",
    "created_at": "2026-08-14T00:00:00+00:00"
  }
}
```

**Errors:**
- `400` — validation failure (invalid email, weak password, missing fields)
- `400` — duplicate email (vague message — does not reveal email is taken)
- `429` — rate limit exceeded
- `503` — MongoDB unavailable

**Password requirements:** ≥10 characters, uppercase, lowercase, digit, special character.

`password_hash` is **never** returned. Stored as Argon2id hash.

---

### `POST /api/v1/auth/login/`  ✅ IMPLEMENTED

Authenticate and obtain JWT tokens.

**Request:**
```json
{"email": "alice@example.com", "password": "SecurePass1!"}
```

**Success (`200`):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer"
}
```

**Errors:**
- `401` — invalid credentials (same message for wrong email and wrong password)
- `429` — rate limit exceeded
- `503` — MongoDB unavailable

The API does not distinguish between "email not found" and "wrong password" to prevent account enumeration.

---

### `POST /api/v1/auth/logout/`  ✅ IMPLEMENTED

Revoke the refresh token. Requires a valid access token.

**Authorization:** `Bearer <access_token>`

**Request:**
```json
{"refresh_token": "eyJ..."}
```

**Success (`200`):**
```json
{"detail": "Logged out successfully."}
```

**Errors:**
- `401` — missing or invalid access token

---

### `POST /api/v1/auth/token/refresh/`  ✅ IMPLEMENTED

Rotate refresh token and issue new access + refresh pair.

**Request:**
```json
{"refresh_token": "eyJ..."}
```

**Success (`200`):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer"
}
```

**Errors:**
- `401` — expired, revoked, or invalid refresh token
- `429` — rate limit exceeded

---

### `POST /api/v1/auth/verify-email/`  ⚠️ SCAFFOLDED

Returns `503` — email infrastructure not yet implemented.

### `POST /api/v1/auth/forgot-password/`  ⚠️ SCAFFOLDED

Returns `503` — email infrastructure not yet implemented.

### `POST /api/v1/auth/reset-password/`  ⚠️ SCAFFOLDED

Returns `503` — email infrastructure not yet implemented.

---

## Milestone 3 vault API — implemented

- `POST /api/v1/vault/credentials/`
- `GET  /api/v1/vault/credentials/`
- `GET  /api/v1/vault/credentials/{id}/`
- `PATCH /api/v1/vault/credentials/{id}/`
- `DELETE /api/v1/vault/credentials/{id}/`
- `POST /api/v1/vault/credentials/{id}/reveal/`
- `POST /api/v1/vault/credentials/{id}/copy/`

All vault routes require a JWT bearer token. Credential list and detail responses exclude plaintext passwords and encrypted ciphertext. Reveal and copy return a plaintext password only to the authenticated owner, are rate-limit-hooked, and generate audit events. MongoDB must be configured for live persistence.

## Milestone 5 security API — implemented

- `GET /api/v1/security/summary/` returns the authenticated user's credential totals by security level, reused-credential count, average score, overall score, and overall level.
- `GET /api/v1/security/credentials/` returns safe per-credential score, level, reuse flag, and alert labels.

Both routes require a JWT bearer token, scope all queries to its user ID, and never return plaintext passwords, ciphertext, or encryption keys. A temporarily unavailable vault dependency returns `503` with a generic message.

## Planned — not yet implemented

- `POST /api/v1/ai/query/`
