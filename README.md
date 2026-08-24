# AI-Powered Business Automation & Intelligent Operations Platform

This repository contains the secure Phase 9 production deployment boundary for a business
automation and intelligent operations platform. It normalizes bounded events, obtains strictly
validated advisory AI analysis, evaluates deterministic policy, and records approval-required
decisions before allowing one narrowly scoped external mutation.

> **AI IS ADVISORY ONLY.**
>
> **AI CANNOT SELECT OR EXECUTE ACTIONS, CALL PROVIDERS OR N8N, OR INVOKE TOOLS.**
>
> **ONLY ONE GHL MUTATION IS SUPPORTED: ADD_CONTACT_TAG.**
>
> **NO GENERIC HTTP CAPABILITY OR ARBITRARY GHL ENDPOINT EXISTS.**
>
> **NO EXTERNAL WORKFLOW EXECUTION IS IMPLEMENTED.**
>
> **AI recommends. Policy decides. Human approves. Executor performs only the approved allowlisted operation.**
>
> **The provider adapter performs one fixed external mutation.**

## Current Phase 9 scope

- Python 3.12 project using a `src` layout
- Strict environment configuration through `APP_` variables
- Lightweight public liveness and local-only readiness checks
- Server-configured bearer authentication with closed role-based authorization
- Closed event/source taxonomies and strict, bounded external-event validation
- UTC normalization, server event identity, and deterministic event classification
- Canonical sorted UTF-8 serialization with an 8 KiB internal ceiling
- Provider-neutral advisory analysis interface with one isolated OpenAI adapter
- Bounded, server-owned prompt policy and strict structured AI output
- Pure deterministic policy version `1.0` with a server-owned `0.85` confidence threshold
- Closed decisions, recommended actions, risk levels, and bounded explanatory evidence
- Transactional local SQLite approval records with a server-owned 30-minute default TTL
- Canonical SHA-256 provenance commitments and an application-enforced audit hash chain
- Single-use execution records with atomic SQLite claiming
- One dedicated GHL contact-tag executor; no action registry or generic dispatcher
- Fixed GHL origin `https://services.leadconnectorhq.com` and path `POST /contacts/{contactId}/tags`
- Server-owned bearer authentication, API version `v3`, and bounded timeout
- Approval provenance commits to canonical contact ID and tag parameters
- Stable provider failure categories with a 1–60 second timeout range and no retries
- 16 KiB request-body ceiling enforced before framework body parsing
- Bounded allowlisted JSON logs and fixed 32-hex server-generated correlation IDs
- Recursive bounded redaction, closed failure categories, and fixed process-local metrics
- Aggregate request latency without per-request history or dynamic metric labels
- Sanitized, stable API errors and defensive response headers
- Automated tests, security source scan, static analysis, dependency audit, and CI
- Fail-closed production validation for credentials, policy, model, debug, and SQLite settings
- Pinned non-root container deployment with static, non-mutating release verification

## Architecture

The API layer accepts HTTP input and maps it into strict Pydantic models. Side-effect-free services
normalize and classify events, isolate advisory AI access, and apply deterministic policy.
Configuration, logging, and security middleware are separated into focused packages. Outbound
networking is isolated to the OpenAI analysis adapter and the dedicated GHL adapter. Policy,
approvals, execution authorization, models, and API routes perform no networking.

See [Architecture](docs/architecture.md), [Security](docs/security.md), and
[Production deployment](docs/deployment.md) for the trust boundaries and operating requirements.

## API overview

### `GET /health`

Returns only:

```json
{"status": "ok"}
```

This public liveness route performs no database or provider call.

### `GET /ready`

Returns `{"status":"ready"}` only when the bounded local SQLite schema check succeeds, otherwise
HTTP 503 with `{"status":"not_ready"}`. It never calls OpenAI, GHL, or another external service.

### `GET /api/v1/admin/status`

Requires the `ADMIN` role and returns only application status, policy version, the single supported
action, authenticated role, readiness, fixed counters, and aggregate request latency. It never
returns configuration, paths, secrets, provider content, customer data, or raw logs.

### `POST /api/v1/events`

Accepts a bounded event such as:

```json
{
  "event_type": "CUSTOMER_REQUEST",
  "source": "WEB_FORM",
  "occurred_at": "2026-08-23T10:00:00Z",
  "payload": {"request_type": "demo"}
}
```

Successful validation returns HTTP 202 with:

```json
{
  "accepted": true,
  "event_id": "evt_server_generated_value",
  "event_type": "CUSTOMER_REQUEST",
  "category": "CUSTOMER",
  "received_at": "2026-08-23T10:00:01Z"
}
```

The payload is not stored, logged, forwarded, interpreted, or executed.

### `POST /api/v1/events/analyze`

Accepts the same strict external event, normalizes it internally, and returns only an advisory
result containing the authoritative event ID, category, closed priority/urgency/intent enums,
bounded confidence, summary and reasons, and a closed recommended-next-step enum. It does not
return the prompt, raw provider response, payload, internal metadata, model, or configuration.

The endpoint requires configured provider credentials. Without them it fails deterministically
with `AI_CONFIGURATION` and makes no network call.

### `POST /api/v1/events/decide`

Accepts the same strict external event, reuses the Phase 3 analysis boundary, and evaluates policy
version `1.0`. It returns only the authoritative decision, recommended action, risk, policy version,
confidence threshold, bounded evidence codes, event ID, and server-generated timestamp. Clients
cannot submit or override policy fields. AI failure produces a safe error and no policy decision.

`ALLOW` means only that policy permits the recommendation. It never executes the recommendation.

## Deterministic policy

Decision outcomes are `ALLOW`, `REQUIRE_HUMAN_APPROVAL`, and `DENY`. Recommended actions are
`NONE`, `REVIEW`, `CONTACT_HUMAN`, `REQUEST_INFORMATION`, `ESCALATE`,
`SCHEDULE_CONSULTATION`, and `NURTURE`. Risk is one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.

The confidence threshold defaults to `0.85` and is bounded from `0.0` to `1.0` through the
server-owned `APP_POLICY_CONFIDENCE_THRESHOLD` setting. The client cannot select the version,
threshold, rules, decision, action, risk, or evidence. The pure calculation does not read time,
environment, network state, randomness, or mutable state; `generated_at` is attached afterward.

Clean `NONE` and low-risk `REVIEW` recommendations may be allowed. Low confidence, elevated
priority, high urgency, unknown intent, and all other actionable recommendations require human
approval. Identity/category mismatches, invalid versions, missing AI reasons, and contradictory
`NONE` plus high-priority/high-urgency signals are denied. Evidence uses only closed codes and
bounded enum or confidence values; it never contains payloads, prompts, reasons, or secrets.

## Human approval records

`POST /api/v1/approvals` accepts the strict external event, runs the existing normalization and AI
boundaries, and recomputes policy internally. Only `REQUIRE_HUMAN_APPROVAL` creates a `PENDING`
record. `ALLOW` and `DENY` return `POLICY_VALIDATION_FAILED` and create nothing. Clients cannot
submit approval IDs, policy fields, timestamps, expiry, approver identity, or provenance hashes.

`GET /api/v1/approvals/{approval_id}` returns bounded metadata. A pending record read at or after
expiry is atomically persisted as `EXPIRED`. `POST .../approve` permits only `PENDING → APPROVED`;
`POST .../reject` permits only `PENDING → REJECTED` and requires a sanitized reason of at most 500
characters. No terminal state can transition again.

Approval IDs and audit IDs use cryptographically secure randomness. TTL defaults to 1,800 seconds
and is bounded to 60–86,400 seconds through `APP_APPROVAL_TTL_SECONDS`. The database location is a
validated server-owned relative `.sqlite3` path. `APP_APPROVER_ID` is a bounded development/server
identity only; it is not authentication and is never accepted from request bodies.

Full canonical events and intelligence are hashed but not stored. The trusted provenance record
stores SHA-256 digest commitments for those canonical representations plus event identity/type,
source, confidence, policy version, decision, action, risk, and closed evidence. Its deterministic
UTF-8 canonical JSON is hashed again as the lowercase 64-character `provenance_hash` and verified
before every transition.

SQLite uses foreign keys, WAL mode, a busy timeout, `BEGIN IMMEDIATE`, parameterized SQL, and
pending-only conditional updates. Each lifecycle change appends a SHA-256-linked audit event. The
approval row stores the expected audit count and head hash so deletion of the final event is also
detectable. Audit verification detects modification, deletion, reordering, broken links, and
duplicate identities.

## Controlled action execution

`POST /api/v1/actions/contact-tag` accepts exactly `approval_id`, `contact_id`, and `tag`. The server reloads the
approval, verifies the approval and audit hash chains, requires `APPROVED` status before TTL expiry,
and verifies that target and tag exactly match approval provenance. Clients cannot provide the
execution ID, action, URL, method, headers, body, credentials, command, module, callable, provider,
timeout, retry policy, or actor.

The only execution action is `ADD_CONTACT_TAG`. A dedicated server-owned executor exposes only that
operation. There is no runtime registration, dynamic import, plugin loading, generic HTTP client,
shell, subprocess, arbitrary provider call, or client-selected callable.

Execution follows `PENDING → CLAIMED → SUCCEEDED | FAILED | UNKNOWN`. Creation and claim occur in
one `BEGIN IMMEDIATE` transaction with a unique approval reference and conditional pending-only
update. Each approval is single-use: terminal results cannot replay, and `FAILED` or `UNKNOWN`
results are never retried automatically. `UNKNOWN` deliberately means completion cannot be
established and requires future reconciliation rather than replay.

The POST response returns only execution ID, closed status, and action. Execution records have
SHA-256 integrity commitments. Authorized, claimed, succeeded, failed, and unknown events extend
the existing per-approval audit hash chain without
storing event payloads, AI content, provider responses, or credentials.

## Event normalization and classification

Supported event types are `CUSTOMER_REQUEST`, `CUSTOMER_MESSAGE`, `CUSTOMER_CREATED`,
`CUSTOMER_UPDATED`, `ORDER_CREATED`, `ORDER_UPDATED`, `PAYMENT_RECEIVED`, `SUPPORT_REQUEST`,
`INTERNAL_TASK`, `SYSTEM_ALERT`, and `GHL_CONTACT_TAG_REQUEST`. The GHL request type requires the
`INTERNAL` source and the exact bounded `{contact_id, tag}` schema. Supported sources are
`WEB_FORM`, `API`, `WEBHOOK`, `IMPORT`, and `INTERNAL`. Clients cannot define event types, sources,
categories, server IDs, receipt times, or metadata.

Customer events map to `CUSTOMER`; order and payment events map to `COMMERCE`; support requests map
to `SUPPORT`; internal tasks map to `INTERNAL`; and system alerts map to `SYSTEM`.

`occurred_at` requires an ISO-8601 timestamp with an explicit offset. It is converted to UTC and
must be no more than 365 days old or five minutes in the future. The server generates the random
`event_id` and `received_at`, deep-copies the payload, creates fixed metadata, and verifies a
deterministic canonical representation.

An optional 1–128 character external event reference is available for future durable idempotency.
It is not authoritative, and no in-memory or durable deduplication store exists.

## AI architecture and configuration

`BusinessIntelligenceService` depends only on the `AIAnalysisProvider` protocol. The official
OpenAI SDK is imported solely by the OpenAI provider adapter. Production requires the secret
`APP_OPENAI_API_KEY`; the server-owned model defaults to `gpt-5-mini` and may be configured with
`APP_OPENAI_MODEL`. The key must come from a deployment secret manager and is never returned or
logged. Timeout, maximum AI input bytes, and maximum output tokens are bounded `APP_` settings.

The server instruction says that payload content is untrusted data, not commands. The event is
delimited, canonical, and bounded to 8 KiB including instructions. Provider output is limited to
800 tokens by default and 4 KiB before strict Pydantic validation. Unknown fields, arbitrary URLs,
credentials, code, shell commands, HTTP instructions, and non-enum recommendations are rejected.

The OpenAI request uses structured output, disables storage, performs no application or SDK retry,
and supplies no tool, function, web-search, code-interpreter, conversation, or arbitrary endpoint
configuration. Prompt injection remains an adversarial risk; isolation, bounded input, structured
output, and the complete absence of action/tool capabilities reduce its impact.

## Observability and operational safety

Every request receives a cryptographically random 32-character lowercase hexadecimal
`X-Request-ID`. Client correlation headers are always replaced. An async-safe internal request
context carries only that ID and, after authentication, the server-derived actor ID and role.

Application logs are compact JSON built from an allowlist. Event names, field count, nesting,
sequence length, individual values, and total serialized size are bounded. Recursive redaction
recognizes authorization, cookie, API-key, token, password, secret, and credential keys at every
supported nesting level. Request bodies, customer text, AI prompts/output, provider responses,
credentials, arbitrary URLs, exception traces, and filesystem/database paths are excluded.

Metrics use a fixed closed enum of saturating counters plus one latency aggregate containing count,
total, minimum, and maximum. They have no labels and never use customer, event, approval, actor, or
URL values. Metrics are process-local, reset on restart, and are not a durable monitoring system.
No Prometheus, OpenTelemetry, StatsD, Redis, or other monitoring dependency is present.

**OBSERVABILITY NEVER AUTHORIZES ACTIONS.**

**HEALTH/READINESS NEVER CALL EXTERNAL PROVIDERS.**

**METRICS NEVER CONTAIN CUSTOMER DATA.**

## Local setup

```bash
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m uvicorn ai_business_automation.main:app
```

Configuration is optional and uses safe defaults. Copy `.env.example` only as a reference; local
`.env` files are ignored. Supported environments are `development`, `test`, and `production`.

## Quality checks

```bash
python -m pytest --cov
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pip_audit .
python scripts/security_scan.py
python scripts/verify_release.py
```

Coverage is required to remain at or above 95%.

## Security principles

- Treat all event fields as untrusted data and give them no capabilities.
- Own limits and configuration on the server; never trust client identity headers.
- Log allowlisted metadata only—never bodies, credentials, headers, or full URLs.
- Return stable errors without exception details, paths, configuration, or stack traces.
- Keep CORS disabled until an explicit, reviewed origin allowlist is required.
- Exclude arbitrary networking, dynamic execution, shell access, and provider credentials.

## GHL provider boundary

`ADD_CONTACT_TAG` is selected only by deterministic policy for a validated internal
`GHL_CONTACT_TAG_REQUEST`, then bound—together with its canonical contact ID and tag—to trusted
approval provenance. The execution API requires those exact bound values; it cannot accept or alter
the provider, operation, origin, path, version, timeout, headers, or body.

`GHLClient` exposes only `add_contact_tag`. It constructs the fixed origin and endpoint internally,
adds the server-owned bearer credential and `Version: v3`, and validates the bounded response. It
does not expose a generic request method and sends no invented idempotency header. Provider response
bodies, authorization, contact IDs, tags, and credentials are excluded from API responses and logs.
The credential is a deployment secret supplied through `APP_GHL_API_KEY`; it is never persisted.

Definitive HTTP failures become `FAILED` with one of the closed GHL failure categories. Timeout or
an ambiguous transport interruption becomes `UNKNOWN`. Neither result is retried or replayed;
`UNKNOWN` requires future manual reconciliation. The audit chain binds the safe failure category,
while excluding request/response bodies and secrets.

## Current limitations

Phase 9 uses server-configured static bearer credentials rather than an external identity provider.
It has no queue, workflow engine, tool calling, AI memory, autonomous action selection, n8n
integration, or other CRM mutation. SQLite persists approval,
execution, audit, and action-parameter commitments; business
events and AI content are not stored. Execution is single-process and there is no distributed lock,
retry worker, reconciliation process, or external provider delivery guarantee.

Operational metrics are process-local, reset when the process restarts, and do not aggregate across
workers. Readiness verifies local SQLite schema access only; it is not an external-provider health
signal.

## Roadmap

Future phases may add authenticated tenancy, durable storage, auditable workflows, and narrowly
scoped integrations. Each capability must receive its own threat model, authorization policy,
data-handling rules, failure design, and security tests before it is enabled. AI analysis remains
separately governed from every future action boundary.
