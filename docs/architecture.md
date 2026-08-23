# Architecture

Phase 4 adds deterministic policy evaluation after advisory structured analysis. No action is
executed.

## Phase 4 shape

The project uses a compact `src` layout with responsibilities split by boundary:

| Layer | Responsibility |
| --- | --- |
| `main.py` | Application construction and explicit middleware/handler registration |
| `api/` | HTTP routes and stable public error contracts |
| `models/` | Strict events, intelligence, policy results, and closed taxonomies |
| `services/` | Normalization, advisory analysis, and pure deterministic policy |
| `providers/` | Provider protocol, stable failures, and isolated OpenAI adapter |
| `config/` | Validated server-owned settings |
| `logging/` | Allowlisted JSON log serialization and reusable redaction |
| `security/` | Request-size enforcement, correlation IDs, and response headers |

## API boundary

HTTP is the only application boundary. Middleware first assigns a cryptographically
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
cross the provider boundary. No raw provider response crosses the API boundary.

## Deterministic policy boundary

`POST /api/v1/events/decide` normalizes the submitted event, reuses
`BusinessIntelligenceService`, and passes only the validated canonical event and validated
`BusinessIntelligenceResult` to `DeterministicPolicyEngine`. The engine is provider-independent,
has no I/O, and returns an immutable evaluation from policy version `1.0`. A separate wrapper adds
`generated_at` after calculation and emits allowlisted operational logs.

The pure calculation uses a `0.85` server-owned confidence threshold and closed event, AI, action,
decision, risk, and evidence enums. It never uses time, randomness, environment-dependent logic,
network state, headers, prompts, raw responses, or payload text. Identical inputs and version always
produce the same evaluation.

Rule precedence is fail-closed: invalid version, event identity mismatch, deterministic category
mismatch, or absent AI reasons returns `DENY`. A `NONE` recommendation conflicting with `HIGH` or
`CRITICAL` priority or `HIGH` urgency is also denied. Otherwise low confidence, high/critical
priority, high urgency, unknown intent, and `CONTACT_HUMAN`, `REQUEST_INFORMATION`, `ESCALATE`,
`SCHEDULE_CONSULTATION`, or `NURTURE` require human approval. Clean `NONE` and low-risk `REVIEW`
produce `ALLOW`. `ESCALATE` and high signals elevate risk deterministically.

`ALLOW` is a policy result, not an execution command. Human approval persistence, action execution,
workflow, integration, persistence, and automation layers remain absent.

## Future AI evolution

The AI boundary remains analysis-only. Any future expansion requires separate budget controls,
model allowlists, audit policy, authorization, and threat modeling. Untrusted event data and model
output must never gain authority merely because a model processed or generated them.

## Future workflow boundary

No workflow engine or action runner exists. A future workflow boundary must separate proposals from
authorized actions and use server-owned workflow identifiers, typed parameters, tenant-aware
authorization, idempotency, approval gates, and immutable audit records. Neither event fields nor AI
output may select arbitrary tools or destinations.
