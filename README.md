# Cyber AI Platform

A cloud-first AI-powered cybersecurity platform.

## Vision

Build a production-grade cybersecurity platform capable of:

- Malware analysis
- APK analysis
- Threat intelligence
- IOC extraction
- MITRE ATT&CK mapping
- Threat hunting
- Anomaly detection
- Incident analysis
- Authorized sandbox testing
- MCP tool integration
- REST API
- Developer integrations
- Enterprise deployment

## Architecture

The platform is cloud-first.

Local GPU or local production server is not required.

Core layers:

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

## Development Principles

- Security first
- Evidence-based analysis
- Human approval for high-risk actions
- Isolated malware execution
- Least-privilege access
- Full audit logging
- Reproducible testing
- Cloud-first architecture

## Architecture v2

Architecture v2 decisions are documented in [`docs/DECISIONS.md`](docs/DECISIONS.md) and detailed in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SECURITY.md`](docs/SECURITY.md), and [`docs/PRD.md`](docs/PRD.md). The confirmed direction remains cloud-first. Key decisions include PostgreSQL RLS, Redis Streams for MVP and Kafka for production, QEMU/KVM nested virtualization or bare metal for dynamic malware detonation (never containers for detonation), KMS envelope encryption, SPIFFE/mTLS worker identity, a static signed/version-locked MCP registry, PEP → PDP → Tool authorization, two-tier RAG, bounded agents, blocked IMDS (including sandbox workloads), a DLQ for permanent failures and retry-exhausted transient failures, cost-aware rate limiting, PII redaction, TOCTOU protection, and RTO < 4h / RPO < 1h.

MVP exclusions: advanced anti-VM evasion, autonomous destructive response, local inference/local production sandbox, and full air-gapped deployment. Detailed parameters and product-level MVP workflow not yet decided are marked TBD in the documents. The full vision and original architecture-layer list above remain intact.

For CYB-12, the tenant-isolation foundation uses Go, chi, pgx/v5 with pgxpool, and golang-migrate over PostgreSQL RLS. This does not select an identity provider or first product workflow; both remain TBD.

### CYB-12 setup and verification

- As a database administrator, apply [`db/bootstrap_roles.sql`](db/bootstrap_roles.sql), then grant `cyber_runtime` to the application login and `cyber_migrator` to a separate migration login. Do not use a superuser or `BYPASSRLS` login for application requests.
- From the repository root, set `MIGRATIONS_DATABASE_URL` to a PostgreSQL URL for the migration login and run `go run ./cmd/db-migrate up`. The `down` migration drops both tenant tables and their data.
- Application code opens `DATABASE_URL` with `tenantdb.Open` and runs tenant-owned queries through `DB.WithTenantTx`. Trusted authentication middleware must set the verified identity context; this foundation does not implement an identity provider or tenant provisioning flow.
- Run `go test ./...` for unit tests. To run the PostgreSQL integration suite, set `CYB12_TEST_DATABASE_URL` to an isolated disposable database URL with role-creation privileges. The integration suite creates roles/schema and fixture rows, and temporarily grants then revokes write access to exercise RLS policies.

## Product and architecture documents

- [Product Requirements Document](docs/PRD.md)
- [Architecture v2](docs/ARCHITECTURE.md)
- [Security Architecture and Requirements](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)
- [Architecture Decisions](docs/DECISIONS.md)
- [Architecture v2 Review Decisions](docs/REVIEW_DECISIONS.md)
