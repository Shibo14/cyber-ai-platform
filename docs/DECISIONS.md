# Architecture Decision Record: Architecture v2

## Record status

**Accepted by the product owner as Architecture v2 on 2026-09-30.** This record captures only the decisions explicitly supplied for this version. It does not select unspecified products or operational parameters.

## Context

The platform is cloud-first. The README describes a cybersecurity platform vision and logical architecture but does not provide detailed technical decisions. The following Architecture v2 decisions supply those choices.

## Decisions

1. **Tenant isolation:** PostgreSQL Row-Level Security (RLS).
2. **Asynchronous work:** Redis Streams for MVP; Kafka for production.
3. **Dynamic malware sandbox:** QEMU/KVM nested virtualization or bare metal. Do not use containers for dynamic malware detonation.
4. **Encryption:** KMS envelope encryption.
5. **Worker identity and transport:** SPIFFE worker identity with mTLS.
6. **MCP tool supply chain:** static, signed, version-locked registry.
7. **MCP invocation authorization:** PEP → PDP → Tool.
8. **RAG knowledge partition:** Global verified plus Per-Tenant dynamic.
9. **Agent bounds:** iteration, time, and spend limits.
10. **Cloud metadata:** block IMDS access for all platform workloads, including sandbox workloads.
11. **Asynchronous failures:** use a DLQ. Permanent failures go directly to it; retryable failures go to it after the configured retries are exhausted. Failure classes are defined in `ARCHITECTURE.md`; retry count and backoff remain TBD.
12. **Abuse/cost control:** cost-aware rate limiting.
13. **Privacy handling:** PII redaction.
14. **Race protection:** TOCTOU protection.
15. **Recovery objectives:** RTO < 4h and RPO < 1h.
16. **MVP exclusions:** advanced anti-VM evasion; autonomous destructive response; local inference/local production sandbox; full air-gapped deployment.

## Consequences

- Cloud-first is the deployment direction; the excluded local and air-gapped modes are not MVP targets.
- Dynamic detonation requires a virtualization or bare-metal isolation design; container isolation is expressly disallowed for that purpose.
- MVP and production use different queue technologies, so a migration/cutover design is needed; its details are TBD.
- RLS, KMS, SPIFFE/mTLS, PEP/PDP, signed registry, and the remaining controls require detailed policies and verification plans; those are not specified in this decision record.

## Open decisions

See `ARCHITECTURE.md`, `SECURITY.md`, and `PRD.md` for TBD details. No additional provider, database beyond PostgreSQL, signing format, policy language, cloud, region, retention period, or numeric agent/rate limit is selected by this record.

## CYB-12 implementation decisions

The product owner confirmed the following implementation stack for CYB-12 on 2026-09-30. These choices implement the Architecture v2 PostgreSQL RLS decision and do not select a product workflow or identity provider:

- Application language and HTTP router: Go and chi.
- PostgreSQL driver and application pool: pgx/v5 and pgxpool.
- Migration framework: golang-migrate.
- Initial tenant schema: `cyber.tenants` and `cyber.tenant_memberships`. The membership `principal_id` is opaque text so the schema does not depend on a selected identity provider.
- Tenant context: `app.tenant_id` set with transaction-local scope by the application tenant transaction helper.
- Database roles: `cyber_runtime` and `cyber_migrator` are separate non-login roles without superuser or `BYPASSRLS`. Runtime access is initially SELECT-only; tenant/member provisioning is outside this issue.

The identity provider, authentication flow, membership lifecycle and authorization semantics, tenant creation workflow, cloud/database login principals, and production migration secret provisioning remain **TBD**. See `ARCHITECTURE.md` and `SECURITY.md` for the implementation boundary.
