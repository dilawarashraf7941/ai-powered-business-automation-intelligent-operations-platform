# Security model

## Security objectives

The platform is designed to keep untrusted event data and probabilistic AI output from becoming
authority. Configuration, identity, policy, approval state, execution targets, provider
credentials, network destination, and retry behavior remain server-owned. Failures return bounded
public errors and do not broaden capability.

## Authentication and RBAC

Protected endpoints require exactly one `Authorization: Bearer <token>` header. Parsing rejects
missing, duplicate, malformed, whitespace-bearing, and oversized credentials. The authenticator
compares the supplied value against every configured slot using `hmac.compare_digest`, then accepts
exactly one match. It does not short-circuit after an early match.

Each server setting slot binds a `SecretStr` token to one bounded actor ID and one closed role. A
slot must be complete, configured tokens must be unique, and production tokens must meet stronger
length and placeholder checks. Request bodies and alternate headers cannot inject actor IDs or
roles. Tokens and Authorization headers are never returned, persisted, audited, or logged.

| Role | Permissions |
| --- | --- |
| `READ_ONLY` | Protected reads, analysis, deterministic policy |
| `APPROVER` | `READ_ONLY` plus create/approve/reject approvals |
| `EXECUTOR` | `READ_ONLY` plus controlled execution |
| `ADMIN` | All permissions plus administrative status |

Authentication failures and mutation requests consume fixed process-local counters. The limiter
has two fixed buckets, bounded settings, and constant memory; it is not distributed and resets on
restart. `/health` is unaffected.

## Input and HTTP safety

The default HTTP body ceiling is 16,384 bytes and is enforced before framework parsing against
both declared and streamed size. Event models forbid extra fields and bound serialized payload
bytes, nesting depth, total nodes/fields, per-object fields, arrays, key/value length, numeric range,
and timestamp age/skew. Capability keys, credential-like keys, URL schemes, control characters, and
common command syntax are rejected.

Every response includes `X-Content-Type-Options: nosniff`. Protected responses also include
`Cache-Control: no-store` and `Pragma: no-cache`. CORS middleware is absent. Client request IDs are
ignored and replaced with random 128-bit server IDs.

## AI and prompt-injection safety

The fixed system instruction treats event content as untrusted data and forbids following embedded
instructions, revealing credentials, using tools, or inventing external actions. Only a bounded
allowlist of the canonical event reaches the provider. Headers, cookies, settings, internal
metadata, secrets, and filesystem data are excluded.

The OpenAI adapter uses a server-owned allowlisted model, bounded timeout/input/output, no SDK or
application retry, `store=False`, strict JSON-schema output, and no tools/functions/web search/code
interpreter. Returned content is size checked, decoded, and strictly revalidated. Prompt injection
cannot be eliminated; its impact is constrained because AI has no policy, approval, credential,
network-destination, or execution capability.

## Deterministic policy and approval

Policy accepts only validated canonical events and validated intelligence. Version, confidence
threshold, rule ordering, decisions, recommended actions, risk, and evidence taxonomy are closed
and server-owned. Invalid identity/category/version, contradictory signals, or missing required AI
evidence fail closed. An AI recommendation and a policy `ALLOW` never execute an action.

Approval creation recomputes intelligence and policy. Clients cannot supply policy output,
approval identity, timestamps, expiry, actor identity, audit data, or provenance. Only
`REQUIRE_HUMAN_APPROVAL` creates a record. Approve/reject requires the corresponding RBAC permission
and records the authenticated server-derived actor.

Provenance commits SHA-256 digests of canonical event and intelligence plus closed event, policy,
action, risk, confidence, and evidence fields. Transitions recompute and compare those commitments.
Event payloads, AI summaries/reasons, prompts, and credentials are not stored.

## Audit integrity

Approval/execution lifecycle events form a canonical hash chain beginning with a fixed genesis
hash. The approval record commits the expected event count and head hash, allowing verification of
modification, deletion, reordering, duplication, and broken links. Authentication and authorization
decisions use a separate persistent security-audit chain.

This is application-level tamper evidence based on unkeyed SHA-256, not an immutable ledger. A
database administrator who can rewrite every row and recompute every hash is outside the stated
guarantee. Database access controls and backups remain deployment responsibilities.

## Execution safety and replay resistance

The only supported execution action is `ADD_CONTACT_TAG`. The request contains only approval ID,
contact ID, and tag. Before any provider call, the repository validates approval existence,
`APPROVED` state, expiry, provenance, policy version, audit integrity, exact action, and exact target
parameters.

`BEGIN IMMEDIATE`, a unique execution-per-approval constraint, and a conditional state update make
the claim atomic and prevent duplicate/concurrent execution. Client input cannot select an action,
executor, provider, URL, origin, path, method, header, body shape, credential, timeout, retry,
callable, module, or plugin.

Execution states are `PENDING`, `CLAIMED`, `SUCCEEDED`, `FAILED`, and `UNKNOWN`. `UNKNOWN` is used
when an ambiguous transport outcome means completion cannot be established. It is terminal and is
never automatically retried or replayed. There is no reconciliation endpoint, background retry
worker, queue, or scheduler.

## GHL provider isolation

The GHL adapter is the only production module importing `httpx`. It exposes only
`add_contact_tag`, fixes the origin to `https://services.leadconnectorhq.com`, constructs only
`POST /contacts/{contactId}/tags`, fixes `Version: v3`, disables redirect following, bounds timeout
and response size, and builds the strict tag body internally. The API key is a server-owned
`SecretStr` unwrapped only inside the adapter.

Raw provider responses and transport exception details never cross the adapter. Definitive
provider errors become safe closed failure categories. Ambiguous timeouts/interrupted transmission
become `UNKNOWN`. There is no generic HTTP, arbitrary URL, configurable GHL origin, additional GHL
operation, arbitrary CRM mutation, n8n integration, or AI-directed provider call.

## Logging, errors, and metrics

Logs are structured JSON built from a closed field allowlist. Event names, keys, values,
containers, recursion, and final serialized size are bounded. Recursive redaction recognizes
authorization, cookies, API keys, access/refresh tokens, passwords, secrets, and credentials.
Logs exclude request/response bodies, customer text, prompts, provider output, contact/tag values,
database paths, arbitrary URLs, tokens, headers, and raw exceptions.

Errors expose stable codes, generic messages, and the server request ID. They exclude validation
internals, stack traces, SQL, paths, configuration, credentials, and provider details.

Metrics contain only a fixed set of saturating counters and aggregate request latency. They have no
labels, dynamic keys, customer/event/approval/actor identifiers, URLs, credentials, or per-request
history. Metrics are process-local and do not authorize actions.

## Production configuration and secrets

All settings use the `APP_` environment prefix and reject unknown configuration fields. Production
fails startup for missing/weak/placeholder authentication, GHL, or OpenAI credentials; incomplete
credential slots; duplicate tokens; debug mode; `DEBUG` logging; an unapproved model; unsafe policy
threshold; the development approver label; an implicit/unsafe SQLite path; or a missing database
parent.

Secret values use `SecretStr`, are injected at runtime, and are absent from `.env.example`, images,
API schemas, persistence, audit records, and logs. `.env`, private keys, databases, coverage, caches,
test data, and Git metadata are excluded from the Docker context. The repository security scan and
release verifier check for prohibited capabilities, obvious secrets, unsafe origins, changed action
sets, and missing deployment controls.

## SQLite and container security

The database path is server-owned, relative, bounded, and `.sqlite3`-suffixed. Parent traversal,
hidden non-test locations, inappropriate absolute paths, unavailable parents, and directory targets
are rejected. Clients cannot influence the path, and the application does not create arbitrary
parents. Connections enable foreign keys, WAL, busy timeout, explicit transactions, parameterized
SQL, and deterministic close behavior.

The production image uses pinned Python 3.12 slim and exactly pinned runtime packages. It copies
only source, uses exec-form startup, runs one worker as fixed non-root UID/GID `10001:10001`, and
exposes only port 8000. `/health` is the container healthcheck; server and access headers are
disabled. Live runtime validation still requires Docker.

## Threat model

| Threat | Implemented mitigations | Residual limitation |
| --- | --- | --- |
| Prompt injection | Untrusted-data instruction, bounded allowlist, strict output, no tools, policy/approval separation | Model output remains probabilistic and must stay advisory |
| Credential leakage | `SecretStr`, runtime injection, redaction, allowlisted logs, safe errors, no persistence/image secrets | Host/deployment secret management remains operator-owned |
| Unauthorized execution | Strict Bearer auth, server actor/role, closed RBAC, approval/provenance verification | Static credentials lack external identity lifecycle features |
| Replay or duplicate execution | Atomic transaction, unique approval constraint, conditional claim, terminal states | Ambiguous provider delivery cannot be externally proven |
| Arbitrary URL abuse | URLs rejected from inputs; GHL origin/path are fixed | Adding another provider would require a new reviewed adapter |
| Arbitrary HTTP abuse | `httpx` isolated to one adapter with one method; source scan enforces isolation | The fixed adapter still performs its documented network call |
| Log injection | Safe event-name syntax, JSON serialization, field/value bounds, allowlist | External log transport and retention are not implemented |
| Sensitive data leakage | Minimal responses, no bodies/prompts/provider data in logs/metrics/audit | Operators must secure SQLite files, backups, and host logs |
| Configuration tampering | Server-owned fields, `extra=forbid`, production validation, fixed origin/version/model allowlist | Environment integrity is a deployment-platform responsibility |

## Explicitly excluded capabilities

The application has no shell/subprocess execution, dynamic evaluation, generic HTTP API, arbitrary
URL, arbitrary GHL/CRM mutation, action registry, plugin loader, workflow engine, n8n execution,
autonomous agent, AI tool calling, automatic `UNKNOWN` replay, background worker, distributed queue,
horizontal SQLite coordination, or distributed metrics backend.
