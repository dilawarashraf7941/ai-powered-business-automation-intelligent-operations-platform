# Production deployment

## Supported baseline

Phase 9 supports one Python 3.12 process and one application instance backed by one persistent
SQLite database. SQLite, metrics, and authentication/mutation rate limiting are process-local. Do
not deploy multiple replicas against the same database. Horizontal deployment requires a separately
designed durable persistence, coordination, rate-limiting, and metrics architecture.

## Required production environment

Set `APP_ENVIRONMENT=production`, keep `APP_DEBUG=false`, and inject configuration at runtime. Never
bake secrets into an image or commit an environment file. Required settings are:

- `APP_LOG_LEVEL=INFO`; production rejects `DEBUG`.
- `APP_APPROVAL_DATABASE_PATH=data/approvals.sqlite3` and a non-development
  `APP_APPROVER_ID`.
- At least one complete fixed credential slot: `APP_AUTH_TOKEN_1`, `APP_AUTH_ACTOR_1`, and
  `APP_AUTH_ROLE_1`. Optional slots 2 and 3 must also be complete.
- `APP_GHL_API_KEY`, `APP_GHL_API_VERSION=v3`, and a bounded timeout.
- `APP_OPENAI_API_KEY`, allowlisted `APP_OPENAI_MODEL=gpt-5-mini`, and bounded timeout, input, and
  output settings.
- A validated deterministic policy threshold.

Production rejects missing, short, whitespace-bearing, duplicate, or obvious placeholder
credentials without including their values in errors. Store credentials in the deployment
platform's secret manager. They must not be logged, returned, persisted, or placed in image layers.

The GHL origin is fixed as `https://services.leadconnectorhq.com`; configuration and requests cannot
override it. OpenAI uses the server-owned model, no tools, no retries, storage disabled, and strict
structured output. CORS remains disabled.

## SQLite persistence and lifecycle

Mount a persistent volume at `/app/data`. The configured relative path's parent must already exist
and be writable only by UID/GID `10001:10001`; the application does not create arbitrary parent
directories. Existing foreign-key, WAL, busy-timeout, and transactional locking behavior remains.
Production startup validates and initializes local persistence without contacting GHL or OpenAI.

Back up the database and WAL consistently with an operator-reviewed SQLite backup procedure, and
test restoration separately. Retention, encryption, and off-host storage are deployment concerns.
SQLite connections are operation-scoped and close deterministically. Graceful termination releases
repository lifecycle state; there are no background workers or shutdown retries.

## Container deployment

The production `Dockerfile` uses pinned `python:3.12.10-slim-bookworm`, installs only exactly pinned
runtime dependencies, and copies only application source. It starts one Uvicorn worker with an
exec-form command. The process runs as fixed non-root UID/GID `10001:10001`, with write access only
to the mounted `/app/data` location. Tests, Git metadata, environment files, databases, caches,
coverage data, and build artifacts are excluded from the context.

Publish port 8000 only behind a trusted reverse proxy, terminate TLS there, and inject configuration
through the platform's secret facility. The proxy should enforce network boundaries and connection
limits compatible with the application's bounded timeouts.

## Health, readiness, and operations

- `GET /health` is public lightweight liveness and does no provider or database work.
- `GET /ready` performs only bounded local SQLite readiness checks.
- `GET /api/v1/admin/status` remains authenticated and ADMIN-only.

Structured JSON logs exclude credentials, headers, payloads, customer text, prompts, provider
responses, database paths, and raw exceptions. External log collection, alerting, dashboards,
backups, and uptime monitoring are operator responsibilities. Metrics and rate limiting reset on
restart because they remain process-local.

Only `ADD_CONTACT_TAG` exists. There is no generic HTTP or arbitrary URL capability, AI-directed
execution, autonomous worker, scheduled action, or automatic replay of `UNKNOWN` executions.

## Release verification

Run the test, coverage, lint, formatting, type, dependency-audit, security-source-scan, and
`python scripts/verify_release.py` gates before a release. The verifier is static/local: it never
contacts providers, modifies the repository, or opens a database.
