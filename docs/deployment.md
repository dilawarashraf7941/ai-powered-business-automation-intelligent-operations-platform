# Production deployment

## Supported baseline

Phase 10 supports one Python 3.12 process and one application instance backed by one persistent
SQLite database. SQLite, the authentication/mutation rate limiter, and any process-local telemetry
make this a single-process, single-instance-oriented baseline. Do not deploy multiple replicas
against the same database. Multi-instance operation would require a separately designed durable
database, distributed coordination, distributed rate limiting, and externally aggregated metrics.

## Required production environment

Set `APP_ENVIRONMENT=production` and inject all configuration at runtime. Do not bake secrets into
an image or commit an environment file.

Required values include:

- `APP_LOG_LEVEL=INFO` (production rejects `DEBUG`)
- `APP_APPROVAL_DATABASE_PATH=data/approvals.sqlite3`
- non-development `APP_APPROVER_ID` and `APP_RECONCILER_ID` fallback labels
- at least one complete fixed credential slot: `APP_AUTH_TOKEN_1`, `APP_AUTH_ACTOR_1`, and
  `APP_AUTH_ROLE_1`; slots 2 and 3 are optional but must also be complete
- `APP_GHL_API_KEY`, with `APP_GHL_API_VERSION=v3` and a bounded timeout
- `APP_OPENAI_API_KEY`, allowlisted `APP_OPENAI_MODEL=gpt-5-mini`, bounded timeout/input/output
  settings, and the validated deterministic policy threshold

Production rejects missing, short, whitespace-bearing, duplicate, or obvious placeholder
credentials without including their values in errors. The GHL origin is fixed in code as
`https://services.leadconnectorhq.com`; no environment variable can override it. OpenAI remains the
only AI provider, uses no tools, performs no retries, and returns only strict structured analysis.

`APP_DEBUG` must remain false. Request-size, payload-depth, node, field, array, and string bounds
remain application-enforced. CORS is disabled; no wildcard policy is installed.

## SQLite persistence and startup

Mount a persistent volume at `/app/data` and set the relative database path inside that mount. The parent
directory must already exist and be writable by UID/GID `10001:10001`. The application does not
create arbitrary parent directories. It enables foreign keys, WAL, a bounded five-second busy
timeout, explicit transactions, and fail-closed schema version checks. Incompatible or unversioned
databases stop startup; no table drop, rebuild, destructive migration, or database deletion occurs.

Back up the database and its WAL consistently using an operator-reviewed SQLite backup procedure.
Test restoration separately. Backups, retention, encryption, and off-host storage are deployment
responsibilities.

## Container deployment

The production `Dockerfile` uses `python:3.12.10-slim-bookworm`, installs only exactly pinned runtime
dependencies from `requirements.lock`, copies only application source, and starts one Uvicorn
worker with an exec-form command. The process runs as fixed non-root UID/GID `10001:10001` and has
write access only to the mounted `/app/data` location. Tests, Git metadata, environment files, databases,
caches, coverage data, and build artifacts are excluded from the build context.

Example runtime configuration should be supplied by the platform's secret manager, not a checked-in
command or compose file. Mount `/app/data` persistently, publish port 8000 only behind a trusted reverse
proxy, and allow the container to receive termination signals. Uvicorn stops accepting new work;
SQLite connections are operation-scoped and close deterministically, and there are no background
workers to drain.

The image healthcheck calls only `GET /health`. Docker was not required for unit tests; when a daemon
is unavailable, `scripts/verify_release.py` performs deterministic static validation instead.

## Health, readiness, and administration

- `GET /health` is lightweight liveness. It performs no database or provider work.
- `GET /ready` performs only bounded local SQLite connectivity and schema checks in production.
- `GET /api/v1/admin/status` remains authenticated and ADMIN-only, returning no configuration,
  paths, environment variables, or credentials.

Neither health endpoint calls GHL, OpenAI, or any external API.

## Reverse proxy and operations

Terminate TLS at a trusted reverse proxy or platform load balancer. That layer is responsible for
trusted network boundaries, request filtering, secure secret injection, connection limits, and
timeouts compatible with the application's bounded AI/GHL timeouts. Do not enable permissive CORS.

Structured JSON application logs remain content-minimal and exclude credentials, headers, payloads,
prompts, provider responses, and customer text. External log collection, alerting, dashboards,
uptime checks, and monitoring are deployment responsibilities. Any metrics are process-local and
reset on restart. Rate limits are also process-local and reset on restart; they are not a substitute
for proxy or perimeter rate limiting.

## Release verification

Before release, run:

```text
python -m pytest --cov
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pip_audit .
python scripts/security_scan.py
python scripts/verify_release.py
```

The release verifier performs local/static configuration, Docker, ignore, artifact, secret-pattern,
fixed-origin, CORS, pinning, and CI-audit checks. It does not contact GHL, OpenAI, or other providers
and does not require real credentials.
