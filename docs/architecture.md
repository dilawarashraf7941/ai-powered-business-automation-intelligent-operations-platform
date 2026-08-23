# Architecture

Phase 3 adds advisory structured analysis after normalization and classification. No action is
executed.

## Phase 3 shape

The project uses a compact `src` layout with responsibilities split by boundary:

| Layer | Responsibility |
| --- | --- |
| `main.py` | Application construction and explicit middleware/handler registration |
| `api/` | HTTP routes and stable public error contracts |
| `models/` | Closed taxonomies, strict external input, and canonical internal events |
| `services/` | Side-effect-free normalization, canonicalization, and classification |
| `providers/` | Provider protocol, stable failures, and isolated OpenAI adapter |
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

## Advisory AI boundary

`POST /api/v1/events/analyze` accepts the existing strict `ExternalEvent`; it does not pretend to
look up an event because persistence still does not exist. The existing ingestion service creates
the canonical event and category. `BusinessIntelligenceService` then constructs an allowlisted,
bounded representation and calls only the `AIAnalysisProvider` protocol.

The OpenAI adapter is the sole module importing the official SDK and the sole outbound provider
network boundary. It uses the Responses API with a server-owned model and system instruction,
strict JSON-schema output, storage disabled, an SDK timeout, zero retries, and no tools. The service
revalidates the returned mapping, attaches authoritative event identity/category, and returns only
the advisory result.

No prompt, headers, cookies, server settings, credentials, internal metadata, or filesystem details
cross the provider boundary. No raw provider response crosses the API boundary. Later action policy,
approval, workflow, integration, persistence, and automation layers remain explicitly absent.

## Future AI evolution

The Phase 3 AI boundary is analysis-only. Any future expansion requires separate budget controls,
model allowlists, audit policy, authorization, and threat modeling. Untrusted event data and model
output must never gain authority merely because a model processed or generated them.

## Future workflow boundary

No workflow engine or action runner exists. A future workflow boundary must separate proposals from
authorized actions and use server-owned workflow identifiers, typed parameters, tenant-aware
authorization, idempotency, approval gates, and immutable audit records. Neither event fields nor AI
output may select arbitrary tools or destinations.
