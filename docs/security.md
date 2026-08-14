# Security baseline — Milestone 1

- Secrets live in environment variables; `.env` is ignored by Git.
- `DEBUG` defaults to `False`; production settings require a real `DJANGO_SECRET_KEY` and `ALLOWED_HOSTS`.
- CORS origins are explicit environment configuration.
- The health probe emits no infrastructure details or secrets.
- MongoDB is designated as the future durable store. Redis is limited to short-lived operational data and Celery transport.

Authentication, encryption, credential processing, and audit events are deliberately not present in this milestone and must not be inferred from the health endpoint.
