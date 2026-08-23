# Architecture

Phase 2 normalizes and classifies events only. No action is executed.

## Phase 2 shape

The project uses a compact `src` layout with responsibilities split by boundary:

| Layer | Responsibility |
| --- | --- |
| `main.py` | Application construction and explicit middleware/handler registration |
| `api/` | HTTP routes and stable public error contracts |
| `models/` | Closed taxonomies, strict external input, and canonical internal events |
| `services/` | Side-effect-free normalization, canonicalization, and classification |
| `config/` | Validated server-owned settings |
| `logging/` | Allowlisted JSON log serialization and reusable redaction |
| `security/` | Request-size enforcement, correlation IDs, and response headers |

## API boundary

HTTP is the only application boundary in Phase 2. Middleware first assigns a cryptographically
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

## Normalization and classification

The API passes a validated `ExternalEvent` to `EventIngestionService`. `EventNormalizer` converts
the timestamp to UTC, enforces a 365-day past and five-minute future skew window, creates a random
authoritative event ID and server receipt time, deep-copies the payload, and builds fixed internal
metadata. The client may provide only a bounded external reference, never internal metadata.

The resulting `CanonicalBusinessEvent` has deterministic enum and UTC datetime representations.
Canonical JSON uses sorted keys, compact separators, UTF-8, and an 8 KiB ceiling. It is not signed
or hashed in Phase 2. `EventClassifier` then maps the closed event enum to the closed `CUSTOMER`,
`COMMERCE`, `SUPPORT`, `INTERNAL`, or `SYSTEM` category enum.

The response exposes only acknowledgement fields. There are no repositories, queues, outbound
clients, dynamic dispatchers, background workers, interpreters, or in-memory deduplication stores.
Durable event storage, idempotency, provenance, and processing remain future boundaries.

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
