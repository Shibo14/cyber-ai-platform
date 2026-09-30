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
- The CYB-12 database runtime role is non-login, non-superuser, and `NOBYPASSRLS`; tenant tables use `FORCE ROW LEVEL SECURITY`. The separate migration role is not used by application requests.
- The application sets `app.tenant_id` with transaction-local scope through the pgxpool transaction helper. Pool connections are reset before and after tenant transactions; cleanup failure discards the connection.
- `app.tenant_id` is trusted application context, not a signed database claim. A caller with arbitrary SQL access using the runtime credential could change it; the runtime credential therefore remains internal to trusted application code, and SQL injection protection is still required. RLS blocks unscoped and incorrectly tenant-filtered operations within the intended application boundary.
- The chi tenant middleware accepts identity only from trusted authentication middleware context and ignores client-supplied tenant headers. Authentication, identity-provider choice, and membership authorization are not implemented by this foundation and remain **TBD**.
- The database login principals that may assume `cyber_runtime` or `cyber_migrator` are provisioned separately. Superuser/BYPASSRLS credentials are not application credentials.
- The initial runtime grants are SELECT-only for `tenants` and `tenant_memberships`; membership mutation and tenant-provisioning workflows remain **TBD**.
- MCP invocation uses PEP → PDP → Tool authorization; a tool is invoked only after the PDP authorizes the request.
- MCP tool inventory is a static, signed, version-locked registry.
- Identity lifecycle, user-level authorization within a tenant, production membership/tenant write policy, policy definitions outside this RLS foundation, deny behavior beyond the middleware boundary, and audit event schema: **TBD**.

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
