# Production deployment

## Prerequisites and supported topology

- A Docker-enabled host or a Python 3.12 runtime.
- A trusted secret manager or equivalent runtime environment injection.
- A persistent filesystem location writable by UID/GID `10001:10001`.
- Outbound access to the configured OpenAI service and the fixed GHL origin when those operations
  are used.
- A trusted TLS-terminating reverse proxy or platform load balancer.

The supported production topology is one application instance, one process, and one Uvicorn
worker. SQLite, operational metrics, and rate limits are process-local. Do not run multiple workers
or replicas against this SQLite database. Horizontal operation requires a separately designed
durable database, distributed coordination, rate limiting, and metrics system.

## Required configuration

Set `APP_ENVIRONMENT=production`, `APP_DEBUG=false`, and a non-`DEBUG` log level. Production
requires:

- `APP_APPROVAL_DATABASE_PATH`, explicitly set to a relative `.sqlite3` path whose trusted parent
  already exists.
- A non-development `APP_APPROVER_ID` fallback label.
- At least one complete `APP_AUTH_TOKEN_1`, `APP_AUTH_ACTOR_1`, `APP_AUTH_ROLE_1` credential slot.
  Slots 2 and 3 are optional but must be complete when used.
- `APP_GHL_API_KEY`; `APP_GHL_API_VERSION` remains `v3` and the timeout remains bounded.
- `APP_OPENAI_API_KEY`; `APP_OPENAI_MODEL` remains the allowlisted `gpt-5-mini` and AI input,
  output, and timeout settings remain bounded.
- A policy confidence threshold in the production-safe range.

Production rejects missing, weak, whitespace-bearing, duplicate, and obvious placeholder secrets,
debug settings, the development approver, unsafe/missing SQLite parents, unapproved model names,
and unsafe policy configuration. It does not include secret values in errors.

## Secret setup

Inject authentication, GHL, and OpenAI credentials at container/process start through the platform
secret manager. Do not write a production `.env`, include credentials in command history, build
arguments, Docker layers, image metadata, repository files, logs, or backups. `.env.example` is a
non-secret development reference and intentionally omits credential values.

Rotate a credential by updating its complete server slot and restarting the single process through
the deployment platform's controlled rollout. The application has no credential-management API.

## SQLite storage and permissions

The container creates `/app/data` owned by `10001:10001`; mount a persistent volume there and use,
for example, `APP_APPROVAL_DATABASE_PATH=data/approvals.sqlite3`. The path is evaluated relative to
the application working directory. The parent must already exist and be a directory. The
application does not create arbitrary parents and clients cannot select a path.

SQLite connections preserve foreign keys, WAL mode, a bounded busy timeout, explicit transactions,
conditional state changes, and operation-scoped cleanup. Production startup initializes and checks
local schema access before serving, without calling OpenAI, GHL, or an executor.

Back up the database and its WAL consistently with an operator-reviewed SQLite backup procedure.
Test restoration separately. Encryption at rest, retention, off-host copies, access controls, and
backup monitoring are deployment responsibilities. Never delete or replace a production database
as part of automated release verification.

## Docker deployment

Build in a Docker-enabled environment:

```text
docker build --tag ai-business-automation:0.1.0 .
```

Run one instance behind a trusted reverse proxy, publish only port 8000 as required, mount the data
volume at `/app/data`, and inject `APP_` settings through the platform rather than a checked-in
Compose file. The image uses `python:3.12.10-slim-bookworm`, exactly pinned runtime dependencies,
an exec-form Uvicorn command, one worker, and fixed non-root UID/GID `10001:10001`.

Before promotion, inspect the built configuration and process identity in that environment. Confirm
the configured image user is `10001:10001`, the application can write only its mounted data
location, the healthcheck succeeds, and no secret appears in image history or environment metadata.

Static Docker checks are verified by `scripts/verify_release.py`. A successful live image build,
runtime UID check, and healthcheck can only be reported when a Docker CLI and daemon are available;
static validation is not a substitute for runtime verification.

## Health, readiness, and shutdown

- `GET /health` is public constant liveness. It does not access SQLite or external providers.
- `GET /ready` performs only a bounded local SQLite schema/readiness check and returns HTTP 503
  with closed `not_ready` status when persistence is unavailable.
- `GET /api/v1/admin/status` is `ADMIN`-only and returns closed operational fields and process-local
  metrics, never settings, paths, or credentials.

The container healthcheck calls only `/health`. Configure the platform to stop routing traffic on
termination and allow Uvicorn to receive the termination signal. Connections are operation-scoped;
the application lifespan releases repository state on shutdown. There are no background workers,
external retries, or queues to drain.

## Network and HTTP expectations

Terminate TLS at a trusted proxy or platform load balancer. Configure request/connection limits
consistent with the application's bounded provider timeouts. CORS is disabled and must not be made
permissive. All responses include `X-Content-Type-Options: nosniff`; protected responses disable
caching. Uvicorn access and server-version headers are disabled in the container.

The GHL destination is fixed to `https://services.leadconnectorhq.com` and the only operation is
`POST /contacts/{contactId}/tags` with `Version: v3`. No environment or request field can override
the origin, path, method, headers, bearer token, version, query, or body shape.

OpenAI uses the server-owned allowlisted model, bounded input/output and timeout, strict structured
output, no tools, storage disabled, and zero retries. Neither health nor readiness calls a provider.

## Monitoring and operational safety

Collect the structured JSON logs with an external system and alert on health/readiness, safe failure
categories, authentication failures, execution `FAILED`/`UNKNOWN`, capacity, filesystem health,
and backup results. The application itself does not provide log shipping, dashboards, alerting,
distributed metrics, real-time external monitoring, or provider-health polling.

Metrics contain fixed counters and aggregate latency only. They reset when the process restarts and
do not aggregate across workers. Rate limits are also process-local and are not a substitute for
reverse-proxy or perimeter controls.

An `UNKNOWN` execution is terminal and is never automatically replayed. Investigate provider state
manually before any operator-approved follow-up; this release has no reconciliation endpoint.

## Release checks

Run from a clean checkout:

```text
python -m pytest --cov
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pip_audit .
python scripts/security_scan.py
python scripts/verify_release.py
```

The release verifier is static and local. It does not contact providers, mutate a database, modify
the repository, create a release, or replace live Docker verification.
