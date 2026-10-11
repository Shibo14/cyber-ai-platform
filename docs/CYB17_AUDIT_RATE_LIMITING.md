# CYB-17 audit and cost-admission neutral core

This implements the approved neutral foundation, not a production audit service
or a pricing policy. Architecture v2 is unchanged. No storage, WORM, retention,
rate algorithm/values, production accounting backend or provider is selected.

## Audit contracts

`audit.Builder` constructs immutable, validated events with actor, subject,
tenant, action, resource, result, correlation and server timestamp attribution.
It requires an injected approved taxonomy and privacy projection. Every populated
attribution reference except the canonical tenant UUID is projected by that
privacy adapter before the existing sanitizer checks it. Missing/unknown policy
inputs fail closed. There is no raw metadata/payload/error field. Kind is an
approved taxonomy value; it is not client input. The trusted adapter must reject
or pseudonymize PII and secret-bearing references; pattern masking alone cannot
identify arbitrary secrets. Test-only allowlists/projections are not a PII policy.

`Recorder` sends only built events to a neutral Writer. Write errors are safe
`ErrDeliveryUnknown`: persistence may already have occurred. It never retries,
asserts rollback, or converts an attempted/pending action into success. A
committed event describes an observed committed effect, not a successful API
response. Timestamp is event construction time, not proof of durable storage.

`ReadService` requires trusted current ScopeResolver, AccessPolicy, Reader and
Integrity adapters. Cross-tenant queries/results, malformed events, excessive
result counts and failed integrity checks return no records. Identity/access are
rechecked after blocking reads/integrity and access-policy operations. Reader
implementations must also enforce tenant access in storage; PostgreSQL adapters
must use WithTenantTx/RLS. Integrity covers the whole returned batch and relevant
scope/order/completeness evidence under the future approved scheme. No concrete
tamper-resistant backend or cryptographic evidence format is implemented.

The existing Logger and CYB-13/14/15/16 event flows are preserved. They are not
automatically migrated to a final taxonomy or declared fully PII-classified.
CYB-16 pending events remain pending; no new blocking success event follows its
final validity guard. Full authentication result correlation and coverage for
audit read/export, approvals, privileged actions and replay require approved
event definitions and production wiring. Legacy Logger has no context parameter;
the new context recursion guard does not retrofit arbitrary legacy writer cycles.

## Cost admission and PEP binding

`authorization.BindAdmission` returns a copied PEP with mandatory Admission for
both preparation and final execution. Pass this PEP to existing CYB-14 service
and CYB-15 protected-processor constructors. Nil gate is rejected. Existing
unbound PEPs remain unmetered; deployment coverage/entrypoints are not selected.
There is no flag in a request or queue message to turn off a bound gate.

The gate runs after trusted principal/delegation and actor/subject authorization
and approval validation. Preparation admission precedes KMS work; execution
admission precedes one-shot consumption/tool execution. After blocking admission,
worker identity and actor AND subject PDP are rechecked, including a worker guard
after that PDP; approval/delegation periods are checked again. Limiter allowance
is not business authority, a transport identity or a reusable execution token.

Execution admission runs OUTSIDE the DB transaction and row locks. A short,
non-consuming preflight transaction authorizes and checks approval/state/delegation,
then fully returns (including pool cleanup) before the limiter is called. After
admission, a new final transaction reloads approval and object state, reloads and
compares authoritative worker delegation, and performs fresh actor/subject PDP
and validity checks. Only this final transaction atomically consumes approval and
executes the state-bound tool. Preflight observations never authorize execution.
Concurrent operations may change state or consume approval while admission is
blocked; final revalidation denies those stale operations. Admission denial,
timeout or cancellation cannot execute the tool. Remote debit cannot be rolled
back with either DB transaction; no automatic refund/settlement policy is added.

`ratelimit.Core` accepts only trusted context-matching actor, subject and tenant.
The injected Policy chooses bucket/epoch/version, positive abstract cost, limit
and admission-attempt identity for each stage. No cost unit or numeric default is
chosen. Canonical structured tenant keys have length-prefixed encoding to avoid
delimiter collisions. Checked subtraction prevents integer overflow. Zero cost
is rejected by this cost-bearing primitive; any policy exemption/zero-cost route
requires explicit future design, not an unlimited fallback.

Accounting.TryDebit must atomically check/debit across all processes, durably
bind tenant-scoped attempts to the exact request and reject conflicting reuse.
Duplicate admission never grants a second execution. Backend receipts are checked
against the complete request. The in-memory atomic ledger exists only in tests;
the neutral contract alone cannot make an arbitrary production adapter atomic.

No refund, settlement, automatic retry, cache, TTL/reset or new attempt ID is
invented. The approved injected policy must define intentional retries. A debit
can remain charged if audit, fresh authorization, KMS or execution subsequently
fails. That is an unresolved accounting outcome, not an automatic refund. KMS
preparation and final execution are distinct policy stages, not prescribed double
billing. ACK-only completed recovery does not repeat business execution admission;
fresh worker/delegation/PDP authorization remains required. Transport-operation
cost coverage is a separate production policy decision.

Cost audit records initial `cost_admission/pending`, rejection, and observed
`cost_debit/committed` after positive backend confirmation. The last event describes
only the debit, never authentication/tool success. A write failure after debit
denies execution without pretending the debit rolled back. Context-propagated
audit -> limiter -> audit and admission recursion are denied. Trusted adapters
must propagate the supplied context, not detach it to bypass guards.

## Existing effects and failure boundaries

- CYB-12 RLS and pool isolation remain authoritative.
- CYB-13 final audit remains AFTER transaction completion. Audit failure returns
  a safe error; committed writes and consumed approvals stay committed/consumed.
- CYB-14 audit failure returns no plaintext. Remote KMS/debit effects cannot be
  rolled back by PostgreSQL. No plaintext fallback is added.
- CYB-15 metadata-only payloads, bounded retry, fail-safe DLQ and fresh recovery
  authorization remain unchanged. Admission errors use the existing safe PEP
  dependency result; queue retries remain bounded. Specific HTTP/throttle response
  and richer failure taxonomy are not selected here.
- CYB-16 chain/SVID expiry and pending audit corrections remain in place.

## Verification and remaining production decisions

Tests cover cross-tenant audit/limiter denial, actor spoofing, privacy projections,
unconfirmed writes, integrity/access failures, concurrent budget admission,
overflow, duplicates/conflicting retries, recursion, committed DB -> audit error,
live mTLS expiry during limiter/audit/PDP, approval/delegation expiry, preparation
before KMS and ACK-only recovery. Existing real Redis/PostgreSQL and race suites
remain required validation.

The real PostgreSQL `ExecutionAdmissionOutsideTransactionAndLocks` regression
blocks the limiter, checks `pg_stat_activity` for zero open application transactions,
and acquires both approval and object row locks from a separate connection with
`FOR UPDATE NOWAIT`. It changes state/approval while admission is paused and verifies
final denial, timeout behavior, and atomic rollback. `ConcurrentAdmittedReplayConsumesOnce`
admits concurrent callers after every preflight has completed and verifies exactly
one approval consumption/business execution. These are test fixtures, not a
production accounting or exactly-once delivery policy.

Still TBD: final audit schema/taxonomy/PII rules; durable write/read backend,
integrity mechanism and evidence, retention/access/alerting, post-commit delivery
and reconciliation; production cost policy/units/limits/windows/bursts, backend,
distributed durability/fairness, retry/duplicate/refund/settlement accounting,
outage/limit responses, and application/worker wiring. Full CYB-17 production
acceptance is not claimed until those adapters/policies and evidence are approved.
