# Architecture v2

## Status

Architecture v2 decisions in this document were explicitly confirmed on 2026-09-30. The document preserves README vision and architecture layers. Undecided details are marked **TBD**; no product or cloud vendor is selected here.

## Context and principles

The platform is cloud-first and does not require a local GPU or local production server. It follows security-first, least-privilege, evidence-based analysis, isolated malware execution, human approval for high-risk actions, full audit logging, and reproducible testing.

## Logical layers

The README identifies these logical layers; detailed boundaries and APIs are **TBD**:

1. AI / Agent Layer
2. RAG / Knowledge Layer
3. MCP Tool Layer
4. Security Control Plane
5. Sandbox Orchestration
6. Malware Analysis
7. Threat Intelligence
8. Detection Engine
9. Response Engine
10. API / SaaS Layer

## Confirmed architecture decisions

### Tenancy and persistence

- PostgreSQL Row-Level Security (RLS) is the tenant-isolation boundary for tenant data.
- Application identity/role model, schema, policies, connection pooling behavior, migration process, and treatment of privileged database roles: **TBD**.

### Asynchronous processing

- MVP uses Redis Streams.
- Production uses Kafka.
- Queue topology, event schema, delivery semantics, ordering, idempotency strategy, retry policy, and migration/cutover plan: **TBD**.
- A dead-letter queue (DLQ) is required. A message goes directly to the DLQ on a permanent failure: malformed or unparseable message, missing or invalid required fields or tenant context, unsupported message/schema version, authorization denial, or deterministic validation/business-rule rejection. A retryable transient failure (dependency unavailable, timeout, throttling, transient storage/worker error, or interrupted processing) is retried; after the configured retry limit is exhausted, the message goes to the DLQ. An unclassified processing error follows the same bounded retry policy and goes to the DLQ if retries are exhausted. Retry count, backoff, DLQ retention, and replay authorization: **TBD**.

### Malware detonation boundary

- Dynamic malware detonation runs in QEMU/KVM nested virtualization or on bare metal.
- Containers must not be used as the isolation boundary for dynamic malware detonation.
- Sandbox network policy, image lifecycle, host hardening, resource quotas, snapshot strategy, cleanup, and selection criteria between nested virtualization and bare metal: **TBD**.
- Advanced anti-VM evasion is outside MVP. Local production sandbox is outside MVP.

### Cryptographic protection and worker identity

- KMS envelope encryption is required for protected data. KMS provider, key hierarchy, key rotation, data-key caching, and coverage by data class: **TBD**.
- Workers use SPIFFE identities and mTLS. SPIFFE trust domain, workload attestation, certificate lifetimes, authorization mapping, and revocation behavior: **TBD**.

### MCP tool control path

- MCP tools come only from a static, signed, version-locked registry.
- Tool invocation follows PEP → PDP → Tool: the PEP mediates invocation, asks the PDP for authorization, and invokes the tool only after an allow decision.
- Registry signing format, signer authority, distribution/update process, PDP policy language, decision logging, and behavior on PDP unavailability: **TBD**.

### Retrieval-augmented generation

- RAG has two knowledge tiers: Global verified and Per-Tenant dynamic.
- Global verified content and Per-Tenant dynamic content must remain distinguishable. Their write/approval flows, retrieval precedence, indexing, source provenance, and cross-tier access rules: **TBD**.

### Agent and cost controls

- Agent execution is bounded by iteration, elapsed-time, and spend limits.
- Rate limiting is cost-aware.
- Limit values, accounting model, enforcement point, tenant/user budgets, and behavior when limits are reached: **TBD**.

### Cloud metadata and input integrity

- IMDS access is blocked for all platform workloads, including sandbox workloads. Blocking IMDS for sandbox workloads is mandatory, not optional. The enforcement mechanism is **TBD**; the block itself is not TBD.
- TOCTOU protection is required for relevant operations. Protected assets, identity/version binding, and required verification points: **TBD**.
- PII redaction is required. Detection scope, redaction locations, reversible/irreversible behavior, and audit treatment: **TBD**.

### Resilience

- Recovery Time Objective (RTO) is less than 4 hours.
- Recovery Point Objective (RPO) is less than 1 hour.
- Measurement scope, service tiers, test cadence, backup/replication design, and responsible roles: **TBD**.

## Deployment boundaries

- Cloud-first deployment is confirmed.
- Local inference, a local production sandbox, and full air-gapped deployment are outside MVP.
- Cloud provider, regions, network topology, environments, and deployment automation: **TBD**.

## Architecture diagram

Component-level deployment and data-flow diagram: **TBD**. The logical layers above are the extent of the current source-backed layer map.
