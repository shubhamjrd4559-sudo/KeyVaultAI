# Environment variables

Configure real values in the relevant local environment or hosting dashboard. Do not commit secrets or put backend credentials in `NEXT_PUBLIC_*` variables. Values shown as `<CONFIGURED_LOCALLY>` are placeholders, not credentials or domains.

| Variable | Purpose | Requirement / default |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | Django signing key. | Required in production; unsafe development fallback rejected. |
| `DJANGO_SETTINGS_MODULE` | Django settings profile. | Use `config.settings.production` in production; do not copy the development value from the example. |
| `JWT_SECRET_KEY` | Dedicated JWT signing key. | Required separately in production. |
| `DEBUG` | Django debug mode. | Must be false in production. |
| `ALLOWED_HOSTS` | Explicit backend hostnames. | Required in production; wildcard rejected. |
| `CORS_ALLOWED_ORIGINS` | Allowed browser origins. | Required in production; configure actual frontend origin. |
| `MONGODB_URI` | MongoDB connection URI. | Required in production; TLS required. Atlas SRV uses TLS by default. |
| `MONGODB_DATABASE` | Database name. | Defaults to `keyvaultai`. |
| `REDIS_URL` | Health, rate-limit, and Celery Redis. | Required in production; `rediss://` TLS required. Compose uses its local Redis only for development. |
| `ENCRYPTION_KEY` | Base64url-encoded 32-byte AES-256-GCM key. | Required in production. Configure securely; never print or commit. |
| `JWT_ACCESS_TOKEN_LIFETIME` | Access token lifetime in seconds. | Defaults to `300`. |
| `JWT_REFRESH_TOKEN_LIFETIME` | Refresh token lifetime in seconds. | Defaults to `2592000`. |
| `EMAIL_HOST`, `EMAIL_PORT` | SMTP server and port. | Set from the chosen email provider. |
| `EMAIL_USE_TLS`, `EMAIL_USE_SSL` | SMTP transport security. | Production requires exactly one enabled. |
| `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` | SMTP credentials. | Store in backend hosting secrets. |
| `DEFAULT_FROM_EMAIL` | Verified sender address. | Required in production. |
| `FRONTEND_BASE_URL` | Frontend origin used in email links. | Required in production and must use HTTPS. |
| `NEXT_PUBLIC_API_BASE_URL` | Frontend API base URL, including `/api/v1`. | Required in the Vercel frontend environment; set to the actual API URL. |
| `EMAIL_VERIFICATION_TOKEN_TTL_SECONDS` | Verification token lifetime. | Defaults to `86400` seconds. |
| `PASSWORD_RESET_TOKEN_TTL_SECONDS` | Reset token lifetime. | Defaults to `1800` seconds. |
| `NVIDIA_API_KEY`, `NVIDIA_BASE_URL`, `NVIDIA_MODEL` | Optional future NVIDIA integration. | Not required by the current local ML implementation. |

Use the backend and root `.env.example` files as development templates. Their development Redis URL is not suitable for production. `docker-compose.yml` runs separate backend, Celery Worker, Celery Beat, and local Redis services.

MongoDB indexes are not initialized automatically. The `ensure_mongodb_indexes` command performs a read-only duplicate preflight by default; `--apply` creates indexes only after explicit approval. Do not use `--apply` against production without a separate approval and verified database target.
