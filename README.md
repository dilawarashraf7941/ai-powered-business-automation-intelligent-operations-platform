# AI-Powered Business Automation & Intelligent Operations Platform

This repository contains the secure Phase 1 foundation for a future business automation and
intelligent operations platform. It establishes a small, production-oriented FastAPI service and
an explicit untrusted-data boundary before any higher-risk capabilities are introduced.

> **AI IS NOT IMPLEMENTED IN PHASE 1.**
>
> **NO EXTERNAL BUSINESS INTEGRATIONS ARE IMPLEMENTED.**
>
> **NO AUTONOMOUS ACTIONS ARE IMPLEMENTED.**
>
> **NO WORKFLOW EXECUTION IS IMPLEMENTED.**

## Phase 1 scope

- Python 3.12 project using a `src` layout
- Strict environment configuration through `APP_` variables
- Lightweight unauthenticated health check
- Strict, bounded business-event validation and safe acknowledgement
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
  "event_type": "customer_request",
  "source": "web_form",
  "payload": {"request_type": "demo"}
}
```

Successful validation returns HTTP 202 with:

```json
{"accepted": true, "event_type": "customer_request"}
```

The payload is not stored, logged, forwarded, interpreted, or executed.

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

Phase 1 intentionally has no authentication, database, queue, event persistence, outbound network
access, AI provider, external integration, workflow engine, or autonomous action mechanism. An
accepted response confirms validation only; it does not promise durable processing.

## Roadmap

Future phases may add authenticated tenancy, durable storage, auditable workflows, narrowly scoped
integrations, and a separately governed AI boundary. Each capability must receive its own threat
model, authorization policy, data-handling rules, failure design, and security tests before it is
enabled.
