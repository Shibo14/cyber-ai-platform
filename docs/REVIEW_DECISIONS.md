# Architecture v2 Review Decisions

## Record status

This file records the Architecture v2 decision set supplied and confirmed by the product owner on 2026-09-30. It is not evidence of an independent security, architecture, or implementation review. Reviewer identities and formal review outcomes are **TBD**.

## Decisions recorded

The product owner confirmed the following decisions for Architecture v2:

- Cloud-first.
- PostgreSQL RLS for tenant isolation.
- Redis Streams for MVP and Kafka for production.
- QEMU/KVM nested virtualization or bare metal for dynamic malware detonation; containers are not used for that execution.
- KMS envelope encryption.
- SPIFFE/mTLS worker identity.
- Static, signed, version-locked MCP registry.
- PEP → PDP → Tool authorization flow.
- Two-tier RAG: Global verified and Per-Tenant dynamic.
- Agent iteration, time, and spend limits.
- Block IMDS for all platform workloads, including sandbox workloads.
- DLQ: permanent failures route directly; retryable transient failures route after retry exhaustion. See `ARCHITECTURE.md` for the defined failure classes; retry count and backoff remain TBD.
- Cost-aware rate limiting.
- PII redaction.
- TOCTOU protection.
- RTO < 4h and RPO < 1h.
- MVP excludes advanced anti-VM evasion, autonomous destructive response, local inference/local production sandbox, and full air-gapped deployment.

## Review findings

- These are approved Architecture v2 decisions based on the user's explicit instruction.
- Approval of the decision set does not fill in parameters marked TBD in the architecture and security documents.
- Product-level MVP workflow, detailed acceptance criteria, threat model, and independent review findings remain TBD.

## Review metadata

- Decision date: 2026-09-30.
- Decision source: product owner instruction in the project conversation.
- Named reviewers, review method, evidence, and follow-up date: TBD.
