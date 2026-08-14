# Environment variables

Copy `.env.example` to a local `.env` file. Do not commit `.env`, and never place real values in documentation. Secret placeholders below are deliberately shown as `<CONFIGURED_LOCALLY>`.

| Variable | Purpose | Required | Status | Safe placeholder |
| --- | --- | --- | --- | --- |
| `DJANGO_SECRET_KEY` | Django cryptographic signing key. Production settings reject the built-in unsafe fallback. | Yes for production; recommended locally | Current | `<CONFIGURED_LOCALLY>` |
| `DEBUG` | Enables Django debug mode when `true`. | Optional | Current | `False` |
| `ALLOWED_HOSTS` | Comma-separated permitted Django hostnames. | Yes for deployed environments | Current | `localhost,127.0.0.1` |
| `MONGODB_URI` | PyMongo connection URI for the persistent application database. | Required to use/check MongoDB | Current configuration; database usage is future | `<CONFIGURED_LOCALLY>` |
| `MONGODB_DATABASE` | MongoDB database name. | Optional; defaults to `keyvaultai` | Current | `keyvaultai` |
| `REDIS_URL` | Redis URL for health probing and Celery transport. | Required to run Redis-dependent services | Current | `redis://localhost:6379/0` locally; `redis://redis:6379/0` in Compose |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed browser origins. | Optional until frontend integration | Current configuration | `http://localhost:3000` |
| `JWT_ACCESS_TOKEN_LIFETIME` | Proposed access-token lifetime in seconds. | Optional | Future — JWT is not implemented | `300` |
| `JWT_REFRESH_TOKEN_LIFETIME` | Proposed refresh-token lifetime in seconds. | Optional | Future — JWT is not implemented | `2592000` |
| `ENCRYPTION_KEY` | Reserved base64-encoded 32-byte AES-256 key. | Not currently required | Future — vault encryption is not implemented | `<CONFIGURED_LOCALLY>` |
| `NVIDIA_API_KEY` | Reserved credential for NVIDIA NIM. | Not currently required | Future — NVIDIA integration is not implemented | `<CONFIGURED_LOCALLY>` |
| `NVIDIA_BASE_URL` | Reserved NVIDIA API base URL. | Not currently required | Future — NVIDIA integration is not implemented | `https://integrate.api.nvidia.com/v1` |
| `NVIDIA_MODEL` | Reserved NVIDIA model identifier. | Not currently required | Future — NVIDIA integration is not implemented | `<CONFIGURED_LOCALLY>` |

`docker-compose.yml` overrides `REDIS_URL` for the backend and worker to use the Compose service hostname. MongoDB remains external and must be supplied securely through `MONGODB_URI` when it is needed.
