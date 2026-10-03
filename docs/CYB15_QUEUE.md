# CYB-15 queue core and Redis Streams adapter

Scope: [CYB-15](https://linear.app/cyber-ai-platform/issue/CYB-15/build-mvp-redis-streams-processing-and-dlq)
and its approved implementation plan. Architecture v2 is unchanged: Redis
Streams is the MVP transport; Kafka remains the production-stage choice.

## Implemented foundation

`internal/queue` supplies metadata/schema validation, trusted producer/consumer
contracts, safe failure classification, explicitly configured bounded processing
attempts, DLQ transitions and protected CYB-12/13/14 integration.
`internal/queue/redis` executes Redis Streams commands through an injected
`Commander`: explicit group creation, publish, group reads, own pending history,
pending inspection, claim, ACK and DLQ publication. No production Redis client,
deployment, credentials, topology or transport/security configuration is selected.

The in-memory message contains schema/version and one opaque immutable-delegation
reference. Field names, supported schema/version and reference validation must be
injected; there is no default production message format. Extra fields, including
tenant/worker/subject/approval claims, retry counters, payloads, secrets or PII,
are rejected. The trusted producer creates the reference through `PEP.Delegate`;
references are locators and are never bearer credentials or access grants.
The reference validator must accept only approved non-secret opaque IDs, not
URLs, emails, payloads or tokens. It is trusted configuration, not client input.

Only sanitized source-entry ID, fixed failure class/reason and server-controlled
attempt count enter a DLQ record. Raw poison-message contents and unvalidated
references are discarded. DLQ field names are also injected configuration. This
source reference requires approved source/DLQ access and retention before replay
can be designed; this implementation has no replay endpoint or automatic replay.

## Authorization and tenant boundary

1. The consumer verifies the existing trusted worker marker before read, claim,
   processing or ACK-only handling. This does not implement SPIFFE/mTLS itself.
2. `PEP.ResolveWorker` loads authoritative delegation operation/correlation and
   reuses existing immutable actor, tenant/subject, operation and validity checks.
   Fresh actor AND subject PDP checks run with the internally reconstructed
   trusted tenant context. Expiry is checked again after a slow PDP call.
3. The queue processor uses `ExecuteWorker` or `DecryptWorker`; these re-resolve
   delegation and preserve final PDP, state/CAS and one-shot approval checks.
   Tenant-owned reads/writes use the supplied `WithTenantTx` transaction.
4. Consumer names and Redis claims change transport ownership only. An assigned
   worker actor mismatch remains denied. No delegation reassignment is provided.
5. Successful completion recovery performs fresh authorization before ACK and
   never calls business processing again. Per-operation authorization denial is
   a permanent failure and may create a sanitized DLQ record; that grants no
   payload access. An unverified caller cannot even perform that transition.

Trusted resolver callbacks construct/select adapters only. They do not read
tenant-owned storage, call KMS, release plaintext, publish or execute effects
before the PEP boundary. Decrypt wiring must use the same PEP/repositories and
the existing CYB-14 storage contracts. Its owned plaintext is cleared/discarded;
there is no separate post-decrypt action callback that could bypass approval.
Tool and decrypt modes are exclusive. The approval composition for a future
decrypt-plus-business workflow remains TBD.

Explicit authorization denials are permanent. Existing CYB-13 classification
is preserved: an RLS-hidden/missing row reported by a repository as a dependency
error stays a safe dependency failure, receives bounded retry and cannot execute
or disclose the foreign row. The queue does not guess existence from raw errors.

## Processing, retry and DLQ flow

`Handle` performs at most one processing attempt and never sleeps or loops.
`Consume` and `Recover` process one explicit bounded batch. Count, idle threshold,
maximum attempts and backoff come from trusted server configuration, not messages.

An injected `Store` must provide durable, exclusive, fenced per-delivery leases
and monotonic progress across consumers/restarts. State is bound to the validated
metadata; swapping a reference cannot reuse another completed delivery record.
An attempt is saved before processing. No production backend/schema or in-memory
fallback is supplied. The mutex stores in tests are test doubles only.

`MaxAttempts` counts attempt slots including the initial attempt and preflight or
audit failures. Failed fresh authorization during completed-job recovery uses
the remaining budget and persists backoff, then reaches DLQ when exhausted.
Neither this counter nor the backoff is controlled by Redis delivery counts or
message fields. Successful ACK-only recovery never repeats the protected action.

- Permanent: malformed/unparseable metadata, missing/invalid fields or trusted
  tenant context, unsupported schema/version, authorization denial, deterministic
  validation/business rejection. Direct DLQ.
- Transient: dependency unavailable, timeout, interruption and safe dependency
  failures. Configured bounded retry, then DLQ.
- Unknown: fixed unclassified result, same bounded retry, then DLQ.

DLQ progress is saved before publication. Only confirmed DLQ publication and
saved `DLQWritten` progress allow source ACK. Unavailable/denied/wrong-type DLQ
writes leave the source pending. A confirmed DLQ followed by failed ACK recovers
without rewriting that DLQ record when progress remains available. No Redis
`MULTI` rollback or atomic PostgreSQL/Redis transaction is assumed.

ACK, DLQ publication, store and audit confirmation failures return safe errors
and leave recoverable work pending. They never restart business processing in a
terminal state. Dependency failure in terminal DLQ authorization prevents ACK;
operation denial remains a valid sanitized terminal failure. Transport outages
cannot safely be converted into deletion: recovery cadence, operational budgets
and manual reconciliation are deployment decisions still TBD. The core contains
no unlimited automatic transport retry loop.

## Pending recovery and reliability limits

Pending inspection maintains a mutex-protected numeric-ID cursor and wraps at
the end of the PEL. A recent first entry therefore cannot repeatedly hide later
eligible entries. The adapter uses inclusive `XPENDING` ranges with a numeric
successor, including overflow handling, instead of relying on a newly selected
Redis-version-specific option. Claim still checks the supplied minimum idle
threshold, and every delivered claim enters the normal security boundary.

There is no exactly-once claim. PostgreSQL business commit and transport state
save/ACK are separate. In the commit-before-completion-save uncertainty window,
the consumed approval remains consumed: retry cannot reset it or repeat the
protected effect. Such a delivery may be denied/DLQed even though its original
operation committed. Business result reconciliation, receipts and idempotency
schema remain open decisions, not an implemented production protocol.

Similarly, publish or DLQ timeout can follow Redis acceptance; if confirmation
or progress is lost, duplicate transport records remain possible. An outbox or
DLQ deduplication format is not silently selected. Completion records only
prevent re-processing of that recorded transport delivery, not all logical-job
duplicates across new stream IDs. New delivery IDs still meet one-shot approval.

The adapter does not trim/delete source data. Own pending reads expose missing
bodies as malformed entries. Redis may remove a deleted-body PEL entry during
claim without returning a body; this implementation cannot recover already-lost
payload metadata. Retention/pending protection and missing-entry reconciliation
must be approved before production use. No safe retention duration is invented.

## Audit and secret handling

Queue enqueue/transition events reuse the existing `audit.Logger` sanitizer.
Only fixed event/outcome/class/reason and numeric attempts are emitted. No raw
Redis/SDK/storage error, original message, payload, token, credential, key,
plaintext DEK or untrusted metadata reference is emitted. The sanitizer is not
assumed to be a universal PII detector: sensitive values are excluded first.
Audit failure fails closed for output/ACK; audit is not atomic with DB commit.
Final taxonomy, storage, retention, integrity and delivery policy remain CYB-17
open decisions. No WORM or cost/rate-limit values are added.

## Tests and local verification

Tests cover metadata/schema rejection, permanent DLQ, bounded transient/unknown
retry, completed PDP failure/backoff/exhaustion, server-only budgets, duplicate
and concurrent delivery, reference manipulation, claim recovery/authorization,
unverified/wrong workers, fresh PDP, consumed approvals, commit/ACK uncertainty,
DLQ/ACK failures, secret-free audit/Streams/DLQ and KMS fail-closed behavior.
Real Redis tests include actual wrong-type and ACL-denied DLQ publication, pending
pagination starvation, recovery and source PEL checks. Real PostgreSQL tests use
`WithTenantTx`, FORCE RLS, a non-superuser/NOBYPASSRLS runtime login, approval
atomicity and rollback; no production migration/grant/schema is introduced.

Run:

```text
go test ./...
go vet ./...
go mod verify
git diff --check
```

Set `CYB15_TEST_REDIS_ADDRESS` to a disposable Redis `host:port` and
`CYB12_TEST_DATABASE_URL` to a disposable, CYB-12-bootstrapped PostgreSQL URL.
The suites explicitly skip integrations when those variables are absent.
The RESP client, Redis names/schema values, retry numbers, SQL tables/logins,
AES-GCM/JSON crypto and authenticated KMS doubles in `_test.go` are fixtures only.
Ordinary `git diff --check` does not inspect untracked files; check them separately.

## Remaining TBD and trusted assumptions

Production Redis client/version/deployment/TLS/ACL/at-rest protection/durability;
shared versus per-tenant topology; final message/DLQ schema and reference policy;
retry/backoff/claim/retention values; durable state backend/lease fencing and
lifecycle; logical-job idempotency/completion reconciliation; publish consistency
and outbox; replay permissions/workflow; worker reassignment; composite approval
workflow; Kafka migration; CYB-17 audit/rate policies; production payload storage
and CYB-14 KMS/cipher/serialization remain open. Object/version cryptographic
binding stays DEFER/TBD.

Reviewed server wiring, independently verified identity/SPIFFE context, current
PDP, immutable approval/delegation repositories, SQL-safe RLS adapters, a durable
state/lease implementation and conforming Redis/KMS/cipher adapters are required
before production readiness can be claimed. `Processor`, `Store`, `Commander`
and resolver interfaces are trusted adapter contracts, not client extensions or
evidence that arbitrary injected implementations are secure.
