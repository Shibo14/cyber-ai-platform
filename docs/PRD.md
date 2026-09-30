# Product Requirements Document

## Status and source of truth

This document records the Cyber AI Platform vision from `README.md` and the Architecture v2 decisions explicitly confirmed by the product owner on 2026-09-30. Statements marked **TBD** are unresolved and are not requirements. If a capability is listed in the vision, that alone does not make it an MVP commitment.

## Product vision

Build a cloud-first, AI-powered cybersecurity platform capable of malware and APK analysis, threat intelligence, IOC extraction, MITRE ATT&CK mapping, threat hunting, anomaly detection, incident analysis, authorized sandbox testing, MCP tool integration, REST API, developer integrations, and enterprise deployment.

## Product principles

- Security first and evidence-based analysis.
- Human approval for high-risk actions.
- Isolated malware execution.
- Least-privilege access and full audit logging.
- Reproducible testing.
- Cloud-first operation; a local GPU or local production server is not required.

## Confirmed Architecture v2 requirements

The following decisions are confirmed for Architecture v2. Where a decision names a design but not its operational parameters, those parameters remain TBD.

- Tenant data isolation uses PostgreSQL Row-Level Security (RLS).
- MVP asynchronous work uses Redis Streams; production uses Kafka.
- Dynamic malware detonation runs in QEMU/KVM nested virtualization or on bare metal. Containers are not used to execute dynamically detonated malware.
- Encryption uses KMS envelope encryption.
- Workers have SPIFFE identities and communicate using mutual TLS (mTLS).
- MCP tools are sourced from a static, signed, version-locked registry.
- Tool authorization follows PEP → PDP → Tool: the Policy Enforcement Point (PEP) requests a decision from the Policy Decision Point (PDP) before the tool is invoked.
- RAG has two tiers: Global verified knowledge and Per-Tenant dynamic knowledge.
- Agents have iteration, time, and spend limits.
- Access to cloud instance metadata service (IMDS) is blocked for all platform workloads, including sandbox workloads.
- Failed messages use a dead-letter queue (DLQ).
- Rate limiting is cost-aware.
- PII is redacted.
- Time-of-check/time-of-use (TOCTOU) risks are protected against.
- Availability objectives are RTO < 4 hours and RPO < 1 hour.

## MVP boundary

The confirmed architecture decisions above are requirements. They do not, by themselves, settle the complete user-facing MVP capability set or a complete end-to-end product workflow.

Explicitly outside MVP:

- Advanced anti-VM evasion.
- Autonomous destructive response.
- Local inference or a local production sandbox.
- Full air-gapped deployment.

MVP capability selection, supported users, sample types, and first workflow: **TBD**. The README vision list is not a release commitment.

## Functional requirements

The README establishes the capability areas below, but does not specify detailed behavior, inputs, outputs, or MVP priority. These details remain **TBD** until approved:

- Malware analysis and APK analysis.
- Threat intelligence and IOC extraction.
- MITRE ATT&CK mapping, threat hunting, anomaly detection, and incident analysis.
- Authorized sandbox testing.
- MCP tools, REST API, and developer integrations.
- Detection and response capabilities.

## Non-functional and security requirements

Architecture v2 decisions in the preceding section are normative. DLQ routing distinguishes permanent failures (direct to DLQ) from retryable transient failures (DLQ after the configured retry limit is exhausted); the precise cases are listed in `ARCHITECTURE.md`. Numerical or procedural details not stated there remain TBD, including retry count/backoff, throughput, retention, encryption key lifecycle, agent limit values, rate-limit policy, audit schema, availability measurement windows, and recovery procedures.

## Acceptance criteria

Product-level MVP acceptance criteria: **TBD**. They can be defined after selecting the MVP workflow and measurable behavior. Verification criteria and evidence format for Architecture v2 decisions: **TBD**.

## Open product decisions

- MVP users, tenant model details, and entry point (UI, REST, MCP, or another interface).
- Exact MVP features and first end-to-end workflow.
- Supported sample formats, size limits, retention, and deletion behavior.
- Threat-intelligence sources, ATT&CK versioning, and evidence/report formats.
- Which response actions exist and which require human approval.
- Agent iteration/time/spend limit values and cost-aware rate-limit policy.
- Availability measurement window, backup strategy, and recovery ownership for RTO/RPO.
- Acceptance criteria and release sequencing.
