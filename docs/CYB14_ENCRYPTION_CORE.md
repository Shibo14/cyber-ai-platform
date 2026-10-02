# CYB-14 neutral envelope-encryption core

Scope source: [CYB-14](https://linear.app/cyber-ai-platform/issue/CYB-14/integrate-kms-envelope-encryption-with-tenant-binding)
and [CYB-6](https://linear.app/cyber-ai-platform/issue/CYB-6/define-multi-tenant-cloud-and-security-control-foundation),
with queue/audit boundaries from CYB-15/CYB-17. The product owner authorized the
reviewed plan for implementation. Architecture v2 decisions are unchanged.

## Implemented boundary

`internal/encryption` provides typed KMS/context, authenticated-cipher, key-policy
and tenant-storage contracts plus a protected envelope service. There is no
production provider, cipher implementation, default suite/profile, SDK, wire
codec, storage schema, route, worker or queue implementation. The symbolic
profile/suite IDs and in-memory types do not choose a production format.

The application injects reviewed adapters/configuration; missing dependencies
fail closed. All public encrypt/decrypt entry points go through CYB-13 PEP:

1. Authenticate the existing trusted identity, or reconstruct worker authority
   through the existing verified-worker/immutable-delegation path.
2. In a CYB-12 tenant transaction, obtain a fresh actor AND subject PDP allow,
   load approval/state and recompute the exact operation's input binding using
   the trusted storage/tool adapter. Validate approval/delegation and state.
   This preparation transaction does not consume the approval.
3. Outside the transaction, prepare crypto data in memory. Tenant binding comes
   exclusively from the verified context. No application data is persisted or
   published in this stage, and no plaintext is released to an external caller.
4. Re-enter the existing CYB-13 final execution path: fresh PDP, immutable
   approval/delegation checks, validity, state precondition and atomic one-shot
   consumption. Store only the envelope using this same tenant transaction;
   decrypt uses the adapter's final transactional state check.
5. Return a cloned envelope/plaintext only if final execution AND PEP audit
   succeed. Clear owned preparation buffers on success and failure.

`internal/authorization/prepared.go` adds a neutral preparation contract and
human/worker entry points; it preserves existing `Execute`/`ExecuteWorker`
behavior. Production adapters must implement the inherited lock/CAS/state and
immutable approval/delegation contracts. No production action taxonomy or
workflow is selected. These entry points cover protected operations using the
existing mandatory one-shot approval path; they do not classify all future
encryption usage as high risk or define ordinary-read authorization policy.

## Cryptographic contracts

- KMS wrapping and unwrapping authenticate the exact typed tenant/profile/suite
  binding and key reference. Provider field names/encoding are adapter work.
  KEKs never leave KMS. A shared KEK is not prohibited; key-per-tenant is not
  required or implemented as a policy choice.
- The configured suite authenticates every `Header` field: tenant, profile,
  suite, key reference and wrapped DEK. It authenticates ciphertext, nonce and
  tag, uses secure generation/nonce handling, rejects malformed key/payload
  shapes and returns no unauthenticated plaintext. A future adapter's AAD
  encoding must be unambiguous and cover the entire header; adapters cannot
  silently ignore context/AAD. The core cannot prove a malicious adapter's
  cryptographic implementation correct; these trusted contracts require review
  and conformance/integration tests when concrete adapters are chosen.
- The core checks metadata against trusted configuration and identity, and
  checks decrypt key references through injected trusted policy. Stored or
  request tenant values never establish authority. There is no plaintext or
  unsupported-suite fallback.
- Encrypt verifies the wrapped-DEK response with a KMS unwrap round trip and
  constant-time equality before returning a persistable envelope. Empty,
  plaintext-equivalent, unusable wrapping responses and incorrect unwrapped
  keys fail closed. This core needs wrap AND unwrap access for encrypt; exact
  least-privilege application/worker roles and key scopes are still TBD.
- Adapters return caller-owned buffers and do not retain/log/persist keys or
  plaintext. Owned DEKs and failed partial plaintext are cleared. Go runtime,
  cipher key schedules and dependency-internal copies cannot be guaranteed
  erased by clearing these buffers; no universal memory-erasure claim is made.

No object/version fields are added to KMS context/AAD. Cryptographic object
binding, same-tenant whole-envelope substitution and valid old-envelope replay
protection remain **DEFER / TBD**. Existing CYB-13 approval/resource state
preconditions are preserved; they are not a new ciphertext-version protocol.

Authenticating wrapped DEK/key reference in data AAD affects future rewrapping:
changes require data authentication to be updated. Rotation, rewrap versus
re-encryption and compatibility policies must be decided before production
encoding/adapters are selected; this in-memory contract is not a stable wire
format commitment.

## Failures and audit

KMS unavailable, denied, timeout, cancellation, corrupt response and unknown
dependency errors become fixed classifications. Raw SDK/storage/cipher/sink
errors are never returned in security diagnostics or audit. Decrypt failure
returns nil plaintext; preparation failure does not persist an envelope or
consume approval. No data key is written to storage, Streams or DLQ by this core.

KMS attempts/results emit minimal `kms_access` metadata via the existing
`audit.Logger`: fixed action/outcome/failure class plus trusted tenant, actor,
subject and correlation. No key reference, envelope, plaintext, DEK, credentials,
SDK request/response or raw error is emitted. `audit` also masks DEK/KEK/data-key
field names and copied values as defense in depth. Final audit schema, retention,
PII taxonomy, storage/integrity and delivery policy remain TBD.

KMS-call audit failure prevents output; a failure before an attempted-call event
prevents that KMS call. A successful KMS event describes the dependency access,
not final application persistence. KMS calls/audit cannot be rolled back with
the DB and concurrent preparations can perform redundant KMS work before one
final approval wins. There is no new retry/caching/idempotency policy.

As in CYB-13, final PEP audit occurs after DB completion. If that audit fails,
the service returns no output but a committed encrypted write/approval remains
committed/consumed. No audit outbox or DB/KMS distributed transaction is invented;
production retry and uncertain-result handling remain open decisions.

## Verification

All concrete AES-GCM, JSON AAD/persistence, key sizes/IDs, permission/action names,
clock values, schemas and roles in `_test.go` files are fixtures only. The KMS
double cryptographically authenticates context using a test-only shared KEK;
it does not merely compare tenant strings or keep a plaintext-DEK repository.

Tests cover same-tenant round trip; different/relabeled tenant; metadata,
ciphertext/tag/nonce/wrapped-DEK modification; AAD/KMS-context mismatch; wrapped
DEK swapping; KMS failure/corrupt responses; no fallback; key/partial-plaintext
cleanup; sanitized audit; audit failure; verified worker reconstruction;
authorization/approval/input mismatch/replay; validity/state/PDP changes during
preparation; final CAS and rollback; and real PostgreSQL RLS/approval atomicity.

Run `go test ./...`, `go vet ./...`, `go mod verify` and `git diff --check`.
Set `CYB12_TEST_DATABASE_URL` to a bootstrapped disposable PostgreSQL instance
to run CYB-12, CYB-13 and CYB-14 integration suites; otherwise they explicitly
skip. CYB-14 creates/removes test-only RLS tables and a non-superuser/NOBYPASSRLS
login. There is no production migration or grant change.

Verified locally on 2026-10-02 with Go 1.27.1 and disposable PostgreSQL 18.3:
the four required checks passed. An uncached full-suite run passed 194 test/
subtest events with zero failures and zero skips, including all three real
PostgreSQL suites. New untracked files also passed a separate whitespace check;
ordinary `git diff --check` does not inspect untracked files. No real-provider
KMS test was run because no production provider has been selected.

## Remaining decisions and assumptions

Provider/SDK/cloud; approved protected data classes/storage boundary; production
algorithm/key generation/AAD and envelope encoding; hierarchy/key mappings;
DEK caching; rotation/revoke/delete/recovery; least-privilege KMS roles; production
storage and workflow wiring; resource/action/fingerprint/state contracts; queue
retry/backoff/idempotency; audit delivery/lifecycle; and object/version binding
remain **TBD / Open Decision** (object/version binding is explicitly deferred).

Trusted middleware/SPIFFE verification, current actor/subject policy, immutable
approval/delegation stores and SQL-safe/RLS-scoped adapters are prerequisites,
not supplied production integrations. Concrete KMS/cipher/storage adapters must
meet these contracts and run real-provider tests before production readiness
can be claimed. No cloud permissions, API, queue or product workflow is deployed.
