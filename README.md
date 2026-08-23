# AI-Powered Business Automation & Intelligent Operations Platform

This repository contains the secure Phase 3 advisory intelligence boundary for a future business
automation and intelligent operations platform. It normalizes a closed taxonomy of events and can
send a bounded canonical representation through a provider-isolated AI adapter for strictly
validated, structured business analysis.

> **AI IS ADVISORY ONLY.**
>
> **AI CANNOT EXECUTE BUSINESS ACTIONS, CALL GHL OR N8N, OR INVOKE TOOLS.**
>
> **NO EXTERNAL BUSINESS INTEGRATIONS ARE IMPLEMENTED.**
>
> **NO AUTONOMOUS ACTIONS ARE IMPLEMENTED.**
>
> **NO WORKFLOW EXECUTION IS IMPLEMENTED.**

## Current Phase 3 scope

- Python 3.12 project using a `src` layout
- Strict environment configuration through `APP_` variables
- Lightweight unauthenticated health check
- Closed event/source taxonomies and strict, bounded external-event validation
- UTC normalization, server event identity, and deterministic event classification
- Canonical sorted UTF-8 serialization with an 8 KiB internal ceiling
- Provider-neutral advisory analysis interface with one isolated OpenAI adapter
- Bounded, server-owned prompt policy and strict structured AI output
- Stable provider failure categories with a 1–60 second timeout range and no retries
- 16 KiB request-body ceiling enforced before framework body parsing
- Safe JSON request-completion logs and server-generated correlation IDs
- Sanitized, stable API errors and defensive response headers
- Automated tests, security source scan, static analysis, dependency audit, and CI

## Architecture

The API layer accepts HTTP input and maps it into strict Pydantic models. The service layer is
currently a side-effect-free acknowledgement function. Configuration, logging, and security
middleware are separated into focused packages. There is no persistence or outbound adapter.

See [Architecture](docs/architecture.md) and [Security](docs/security.md) for the trust boundaries
and design rationale.

## API overview

### `GET /health`

Returns only:

```json
{"status": "ok"}
```

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

## Event normalization and classification

Supported event types are `CUSTOMER_REQUEST`, `CUSTOMER_MESSAGE`, `CUSTOMER_CREATED`,
`CUSTOMER_UPDATED`, `ORDER_CREATED`, `ORDER_UPDATED`, `PAYMENT_RECEIVED`, `SUPPORT_REQUEST`,
`INTERNAL_TASK`, and `SYSTEM_ALERT`. Supported sources are `WEB_FORM`, `API`, `WEBHOOK`, `IMPORT`,
and `INTERNAL`. Clients cannot define event types, sources, categories, server IDs, receipt times, or
metadata.

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
```

Coverage is required to remain at or above 95%.

## Security principles

- Treat all event fields as untrusted data and give them no capabilities.
- Own limits and configuration on the server; never trust client identity headers.
- Log allowlisted metadata only—never bodies, credentials, headers, or full URLs.
- Return stable errors without exception details, paths, configuration, or stack traces.
- Keep CORS disabled until an explicit, reviewed origin allowlist is required.
- Exclude arbitrary networking, dynamic execution, shell access, and provider credentials.

## Current limitations

Phase 3 intentionally has no authentication, database, queue, event persistence, business
integration, workflow engine, tool calling, AI memory, or autonomous action mechanism. The only
outbound boundary is the fixed OpenAI provider adapter. Analysis is advisory and does not promise
durable or idempotent processing. No action is executed.

## Roadmap

Future phases may add authenticated tenancy, durable storage, auditable workflows, and narrowly
scoped integrations. Each capability must receive its own threat model, authorization policy,
data-handling rules, failure design, and security tests before it is enabled. AI analysis remains
separately governed from every future action boundary.
