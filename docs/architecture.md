# Architecture

Phase 7 extends the controlled execution boundary after trusted human approval with exactly one
external business mutation while preserving all Phase 6 local actions.

## Phase 7 shape

The project uses a compact `src` layout with responsibilities split by boundary:

| Layer | Responsibility |
| --- | --- |
| `main.py` | Application construction and explicit middleware/handler registration |
| `api/` | HTTP routes and stable public error contracts |
| `models/` | Strict events, intelligence, policy, approval, execution, and action schemas |
| `services/` | Advisory analysis, policy, approval, and fixed allowlisted action handlers |
| `providers/` | Isolated OpenAI analysis and single-operation GHL adapters |
| `repositories/` | Provider-neutral approval/execution contracts and transactional SQLite adapters |
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

The event response exposes only acknowledgement fields. There are no event repositories, queues,
generic outbound clients, dynamic dispatchers, background workers, interpreters, or in-memory
deduplication stores. Durable business-event storage, idempotency, and processing remain future
boundaries; the approval repository added in Phase 5 stores no event content.

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

`ALLOW` is a policy result, not an execution command. Execution requires a persisted human approval
where policy required one; workflow engines and non-allowlisted integrations remain absent.

## Human approval boundary

`POST /api/v1/approvals` accepts only `ExternalEvent`. It reuses ingestion and intelligence, then
`ApprovalService` calls the existing `PolicyDecisionService`; no client policy result is trusted.
Only `REQUIRE_HUMAN_APPROVAL` is persisted. The service owns random approval identity, creation and
expiry times, policy fields, provenance, TTL, and the configured development approver identity.

The lifecycle is closed: `PENDING` may become `APPROVED`, `REJECTED`, or `EXPIRED`; every terminal
state is final. Reads atomically persist expiration. Approval and rejection transitions perform
integrity validation inside `BEGIN IMMEDIATE`, then use `UPDATE ... WHERE approval_id = ? AND
status = 'PENDING'` and require one affected row. This serializes concurrent SQLite writers and
prevents double decisions and expiry races.

The provenance builder canonicalizes the full validated event and intelligence separately and
stores only their SHA-256 digest commitments. A second canonical safe object binds those digests to
event type/source, confidence, policy version, decision, action, risk, and evidence; its SHA-256 is
the stored provenance hash. Transitions recompute the safe hash and compare every stored policy
field. Payloads, AI summaries/reasons, prompts, headers, and credentials are never persisted.

Each creation, transition, expiry, and rejected transition appends an audit event. Event hashes are
`SHA-256(canonical event bytes + previous hash)`; the first event uses 64 zero characters. Sequence,
previous hash, event hash, unique audit ID, stored count, and stored head are verified together by
an internal service before authorization.

## Controlled execution boundary

The execution API accepts only an approval reference. `SQLiteExecutionRepository.claim` starts
`BEGIN IMMEDIATE`, verifies the full approval provenance and audit chain, requires `APPROVED` before
the server-owned expiry, rejects any prior execution for that approval, derives the internal action
from a closed mapping, writes `PENDING`, and conditionally changes it to `CLAIMED`. A unique
`approval_id` constraint and affected-row check make claiming single-use under concurrent requests.

`ActionRegistry` is immutable application code containing five local handlers plus exactly one
external handler:
`NO_OP`, `CREATE_INTERNAL_TASK`, `UPDATE_INTERNAL_STATUS`, `REQUEST_HUMAN_REVIEW`, and
`GENERATE_INTERNAL_NOTE`, and `GHL_ADD_CONTACT_TAG`. Each handler receives a server-reconstructed `ActionContext`, builds one
strict bounded input model, and returns one bounded local effect. No API value can select a handler,
callable, module, plugin, URL, provider, method, headers, body, command, timeout, or retry policy.

The lifecycle is `PENDING → CLAIMED → SUCCEEDED | FAILED | UNKNOWN`. Local effects and successful
completion commit together. `FAILED` is definitive non-completion; `UNKNOWN` means completion cannot
be established. Neither state retries automatically, and every terminal state is final. The current
handlers are deterministic and local, while `UNKNOWN` preserves safe future provider semantics.

Execution events reuse the approval audit chain and canonical SHA-256 event hashing. The existing
approval row count/head commitment covers `EXECUTION_CREATED`, `EXECUTION_CLAIMED`,
`EXECUTION_SUCCEEDED`, `EXECUTION_FAILED`, `EXECUTION_UNKNOWN`, and `EXECUTION_REJECTED`. Execution
rows and typed internal effects also carry deterministic SHA-256 integrity commitments.

## Controlled GHL provider boundary

The only external action is `GHL_ADD_CONTACT_TAG`. Deterministic policy derives it solely from a
validated internal `GHL_CONTACT_TAG_REQUEST`; AI has no GHL action in its recommendation taxonomy.
Approval provenance contains a canonical commitment to the action, contact ID, sorted tags, event
and intelligence digests, policy version, decision, risk, and evidence. Execution reconstructs the
typed parameters from that trusted record and accepts no execution-time substitution.

The dedicated adapter exposes only `add_contact_tag`, uses the fixed origin
`https://services.leadconnectorhq.com`, constructs `POST /contacts/{contactId}/tags`, supplies
server-owned bearer authentication and `Version: v3`, and creates exactly `{tags: [...]}`. `httpx`
is confined to this adapter. There is no configurable origin, arbitrary endpoint, generic request
method, arbitrary header/body capability, provider selector, or automatic retry.

Documented definitive HTTP failures produce `FAILED`; timeout and post-transmission ambiguity
produce `UNKNOWN`. Both are terminal locally. `UNKNOWN` requires manual reconciliation because no
unsupported idempotency mechanism is invented. Audit events reuse the execution lifecycle and bind
only the closed failure category—not credentials, targets, tags, or provider bodies.

**AI recommends. Policy decides. Human approves. Executor performs only the approved allowlisted operation.**

## Future AI evolution

The AI boundary remains analysis-only. Any future expansion requires separate budget controls,
model allowlists, audit policy, authorization, and threat modeling. Untrusted event data and model
output must never gain authority merely because a model processed or generated them.

## Future integration constraints

The sole GHL contact-tag adapter does not generalize into a workflow framework. Any future
integration would require a separately reviewed provider-owned schema, authorization policy,
reconciliation design, and delivery guarantees. Neither event fields nor AI output may select
arbitrary tools or destinations.
