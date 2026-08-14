# Architecture — Milestone 1

```text
Client -> Django REST API (/api/v1)
                    |-> MongoDB Atlas (primary persistent store)
                    |-> Redis (cache, rate limits, temporary state, Celery broker)
                    `-> Celery worker wiring (future background jobs)
```

The backend uses a layered package layout. Views are limited to request/response handling; later milestones add serializers, services, and repository/data-access layers in their respective apps. MongoDB is accessed through the official `pymongo` driver rather than Django ORM models, so it remains the primary data store. Redis is never used as persistent credential storage.

`apps/common/services/health.py` is the first service-layer implementation. It performs bounded `ping` probes and returns only dependency status—never connection strings or secrets.

## Current tree

```text
backend/
  config/settings/{base,development,production}.py
  config/{urls,asgi,wsgi,celery}.py
  apps/common/{services,views,urls}.py
  tests/
```

Planned app packages (`users`, `vault`, `security`, `ai_engine`, `ml_engine`, `browser_extension`, `audit`) are intentionally absent until their respective milestones.
