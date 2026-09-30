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

## CYB-12 Gemini security review

This section records the Gemini findings and dispositions provided by the product owner on 2026-09-30. It does not represent an independent review by the repository author.

### ACCEPT AS-IS

- PostgreSQL RLS isolation.
- `FORCE ROW LEVEL SECURITY` on tenant tables.
- Separate `cyber_runtime` and `cyber_migrator` roles.
- Transaction-local tenant context.
- pgxpool connection reuse and context cleanup.
- Cross-tenant negative tests.
- `BYPASSRLS`/`SUPERUSER` protections.
- Separate migration role.

### REQUIRED BEFORE MERGE

The following checks were completed during the CYB-12 implementation review:

- **SQL injection and arbitrary SQL:** all SQL shipped by this foundation and its migrations is fixed text; dynamic values use pgx positional bind parameters. Role and migration-table identifiers are fixed, migration URL parameters are encoded, and no request path forwards client-provided SQL. `TenantTx` is a trusted Go API that accepts SQL text, so future callers must use fixed statements and bind untrusted values; the current repository has no product query handlers. Test-only role DDL also uses fixed SQL and a test-only credential.
- **Client control of tenant context:** `DB.WithTenantTx` no longer accepts a tenant ID argument. It requires a non-empty identity in the server-side context, validates its tenant UUID, and sets the RLS context itself. chi middleware returns unauthorized without that context and does not read `X-Tenant-ID` or another request field for tenant selection.
- **SQL and parameter binding audit:** all production query call sites, test queries, role setup statements, and migration SQL were inspected. Variable query values use positional bind parameters; schema, table, and role identifiers are fixed in code or migration files.

The repository has no identity-provider integration or product request handlers yet. The tenant context setter is a trusted in-process API; the future authentication integration must call it only after authenticating the principal. Authenticated principal-to-tenant binding remains deferred to CYB-13.

### DEFER TO CYB-13

- Identity provider.
- Tenant provisioning.
- Authenticated principal → tenant binding.
- User-level authorization.

### Separate signed database claim decision

Gemini's signed database claim recommendation is **not** adopted as an Architecture v2 requirement. Whether to add signed tenant claims to the database context is an open, separate architecture/security decision and requires its own review record. No signed-claim requirement was added to `ARCHITECTURE.md`.
