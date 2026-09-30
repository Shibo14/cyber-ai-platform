# Security Architecture and Requirements

## Status and scope

This document records README principles and confirmed Architecture v2 security decisions as of 2026-09-30. Details not explicitly decided are **TBD** and must not be inferred as approved controls. This document is not a complete threat model.

## Security principles

- Security first and evidence-based analysis.
- Least-privilege access.
- Isolated malware execution.
- Human approval for high-risk actions.
- Full audit logging and reproducible testing.
- Cloud-first operation.

## Confirmed security controls

### Tenant isolation and authorization

- PostgreSQL RLS is the tenant data isolation mechanism.
- MCP invocation uses PEP → PDP → Tool authorization; a tool is invoked only after the PDP authorizes the request.
- MCP tool inventory is a static, signed, version-locked registry.
- Detailed identity lifecycle, user authorization, database roles/policies, policy definitions, deny behavior, and audit event schema: **TBD**.

### Workload and sandbox isolation

- Dynamic malware detonation uses QEMU/KVM nested virtualization or bare metal. Containers are not used to execute dynamically detonated malware.
- Workers have SPIFFE identities and communicate over mTLS.
- IMDS access is blocked for all platform workloads, including sandbox workloads; sandbox blocking is mandatory.
- Local production sandbox and advanced anti-VM evasion are outside MVP.
- Host hardening, sandbox egress policy, hypervisor configuration, bare-metal handling, attestation, and isolation verification: **TBD**.

### Data protection and privacy

- KMS envelope encryption is required.
- PII redaction is required.
- TOCTOU protection is required.
- Data classification, encryption coverage, key custody/rotation, redaction rules, retention/deletion, data residency, and TOCTOU-specific validation procedure: **TBD**.

### Agent and operational abuse controls

- Agent work has iteration, time, and spend limits.
- Rate limiting is cost-aware.
- Failed asynchronous work is routed to a DLQ under the permanent-failure and retry-exhaustion rules in `ARCHITECTURE.md`.
- Retry count/backoff, cost model, throttling policy, DLQ retention/access/replay controls, and alerting: **TBD**.

### Human approval and response

- Human approval is required for high-risk actions.
- Autonomous destructive response is outside MVP.
- High-risk action taxonomy, approver roles, approval evidence, expiration, and emergency procedure: **TBD**.

## Security objectives

- RTO < 4 hours and RPO < 1 hour.
- Full audit logging is a stated principle; exact events, tamper resistance, access controls, and retention are **TBD**.

## Threat model and security operations

Assets, trust boundaries, attacker profiles, abuse cases, incident response, vulnerability management, security testing, and disclosure process: **TBD**. These omissions are open work, not evidence that a control is unnecessary.
