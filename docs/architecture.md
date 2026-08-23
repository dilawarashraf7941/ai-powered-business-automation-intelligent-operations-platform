# Architecture

## Phase 1 shape

The project uses a compact `src` layout with responsibilities split by boundary:

| Layer | Responsibility |
| --- | --- |
| `main.py` | Application construction and explicit middleware/handler registration |
| `api/` | HTTP routes and stable public error contracts |
| `models/` | Strict event schemas and recursive validation limits |
| `services/` | Side-effect-free event acknowledgement |
| `config/` | Validated server-owned settings |
| `logging/` | Allowlisted JSON log serialization and reusable redaction |
| `security/` | Request-size enforcement, correlation IDs, and response headers |

## API boundary

HTTP is the only application boundary in Phase 1. Middleware first assigns a cryptographically
random request ID and then reads at most the configured request-body ceiling. FastAPI parses only a
body that has already passed this limit. Pydantic then validates the event envelope and recursively
checks its payload. Routes receive validated models rather than raw dictionaries.

The health route is deliberately isolated from external resources. It proves only that the process
can serve a response.

## Untrusted event boundary

An event is data, never an instruction. Its envelope rejects unknown fields, and its payload has
limits on serialized bytes, nesting depth, fields, fields per object, array items, total values,
field-name syntax, string length, and numeric range. Capability-bearing keys and URL-, credential-,
or command-like content are rejected.

After validation, the service derives only the event type for the acknowledgement. There are no
repositories, queues, outbound clients, dynamic dispatchers, or interpreters.

## Future AI boundary

No AI boundary exists in executable code. A future AI component must live behind a dedicated
adapter with an explicit data-minimization contract, prompt-injection defenses, output validation,
timeouts, budget controls, model allowlists, and audit policy. Untrusted event data must never gain
authority merely because a model processed it.

## Future workflow boundary

No workflow engine or action runner exists. A future workflow boundary must separate proposals from
authorized actions and use server-owned workflow identifiers, typed parameters, tenant-aware
authorization, idempotency, approval gates, and immutable audit records. Neither event fields nor AI
output may select arbitrary tools or destinations.
