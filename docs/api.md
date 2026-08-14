# API — Milestone 1

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

If `MONGODB_URI` has not been configured, MongoDB is reported as `"not_configured"`; the response remains `503`/`"degraded"`.

No credentials, hostnames, or internal error details are exposed.
