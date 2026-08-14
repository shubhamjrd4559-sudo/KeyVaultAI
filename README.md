# KeyVaultAI

Secure credential-management platform. The locked sticky-notes landing-page reference is preserved as `Gemini_Generated_Image_pi6ae1pi6ae1pi6a.png`; frontend implementation is intentionally deferred to Milestone 4.

## Milestone 1 status

The Django REST foundation provides configuration, MongoDB and Redis health probes, Celery wiring, Docker development services, and automated health endpoint tests. Authentication, vault, encryption, AI, ML, and browser-extension features are not implemented yet.

## Run locally

1. Copy `.env.example` to `.env` and set non-placeholder values.
2. `cd backend`
3. Create a Python 3.12+ virtual environment and install `pip install -r requirements.txt`.
4. Start Redis (`docker compose up redis`), then run `python manage.py runserver`.
5. Visit `http://localhost:8000/api/v1/health/`.

Run tests with `pytest` from `backend/`.

## Docker

`docker compose up --build` starts the backend, Redis, and a Celery worker. MongoDB remains external (MongoDB Atlas) and must be supplied via `MONGODB_URI`.

See [docs/architecture.md](docs/architecture.md), [docs/api.md](docs/api.md), and [docs/security.md](docs/security.md).
