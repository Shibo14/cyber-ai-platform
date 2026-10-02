# CYB-13 required security corrections

Scope: only approval execution binding, worker delegation, and application-side
audit secret redaction. The earlier CYB-13 implementation plan was inspected in
the project chat titled "Review and update CYB-5". This checkout contains the
completed CYB-12 foundation and architecture documents, but no existing API,
worker, Redis client, PDP, tool implementation, or approval/audit storage adapter.

## Components

- `internal/authorization/context.go`: separate actor and subject types, trusted
  context setters, exact operation bindings, approval and delegation records.
- `internal/authorization/pep.go`: protected PEP execution, scoped job creation,
  worker execution, and neutral PDP/repository/tool interfaces.
- `internal/audit/audit.go`: field allowlisting and secret masking before JSON
  serialization and delivery to an `io.Writer` sink.
- `cmd/db-migrate/main.go`: migration diagnostics use the same sanitizer instead
  of printing raw URL/dependency errors which may contain database credentials.
- The corresponding unit tests and `internal/authorization/postgres_test.go`:
  negative security tests plus real PostgreSQL transaction/RLS/CAS/replay tests.

CYB-12 tenant identity/database code, production schema/grants, dependency versions and
Architecture v2 decisions are unchanged. The PostgreSQL approval/object schema
and action names in tests are fixtures, not production architecture decisions.

## Approval execution binding and TOCTOU

Protected execution always requires an approval. There is no request flag that
disables approval. A trusted approval record binds its unique ID, tenant, human
subject, exact action/resource/argument fingerprint, approved resource state,
issuance time and exclusive expiry boundary. This minimal boundary supports
one-shot approvals only; it offers no reusable approval capability.

Within `tenantdb.DB.WithTenantTx`, the PEP evaluates the PDP, reads the approval
and current object state, checks the complete binding and validity, atomically
consumes the approval, rechecks validity after consumption, and calls the tool
with the approved state precondition. Consumption and database changes commit
or roll back together. Missing, expired, mismatched or consumed approvals and
security dependency failures prevent tool execution. There is no fallback.

Repository adapters must use the supplied transaction and an atomic
unconsumed-to-consumed transition. Approval IDs/bindings are immutable and never
recycled, including after consumption. Tool adapters must lock the target state
within that transaction or enforce an atomic compare-and-set at mutation; the
provided test tool does both. An old approval cannot proceed if the precondition
fails. Failed database operations leave no committed consumption or mutation.

The resource-state representation remains tool-specific: an authoritative
version or deterministic fingerprint covering approval-relevant state. The
argument fingerprint must be calculated by the trusted tool adapter over all
execution-affecting arguments; a client assertion of that fingerprint is not
proof. `Action` identifies the exact server-selected tool operation; resource
identifiers include their object kind. Tool selection stays subject to the
existing static signed/version-locked registry requirement. No registry or
resource workflow is invented here.

## Worker delegation and confused deputy protection

Trusted middleware supplies the human identity and tenant through CYB-12 context.
The API/server actor comes from trusted server configuration/verification;
workers enter through `WithVerifiedWorker` after SPIFFE/mTLS verification.
These setters are trusted in-process APIs, not authentication implementations.
A worker-marked context is rejected by the direct human-request execution path.

`Delegate` authorizes the API actor and subject, then the assigned worker and
same subject. The trusted dispatcher chooses the exact operation, worker,
correlation, approval reference and expiry. An immutable stored record binds
these values to a generated internal job ID. This ID is a record reference,
not a new external identity/delegation token protocol.

A Redis Streams job can reference this record. `WorkerRequest` contains a
delegation ID, intended operation and correlation only, with no authority claims.
The worker loads authoritative immutable state, matches its independently
verified actor and the requested scope/correlation, and reconstructs tenant and
subject exclusively from that record. Any conflicting existing trusted identity
is rejected. Client payload/header fields cannot populate effective identities,
tenant or permissions. Forged/unknown references or altered scope fail closed.

Every execution obtains a fresh PDP decision with separate `ActorAllowed` and
`SubjectAllowed` results; both must allow. Authorization at enqueue time does
not bypass execution-time evaluation. Exact delegation scope and validity are
checked again at the final transaction boundary. Broader worker infrastructure
privileges do not confer subject permission. The Redis topology, transport and
delivery/retry policy remain unchanged/TBD; no queue adapter is added.

## Audit secret redaction

All PEP execution results pass through the central audit logger. Events contain minimal
identity/action/resource/correlation/outcome metadata; they never include raw
dependency/tool errors, request bodies, claims, arguments or approval objects.
The logger takes a trusted top-level field allowlist and sanitizes before
serialization and before calling the normal sink.

Known secret field names are matched without case/separator dependence and
masked as `[REDACTED]`: passwords, access/refresh/bearer tokens, authorization,
API keys, client/session secrets, cookies, private keys and credentials. Supported
nested maps/lists receive the same protection. Known secret strings copied into
other fields or keys are masked too, including when their source field is not
allowlisted. Bearer/Basic values and private-key PEM strings are masked.

Arbitrary structs, error/Stringer/JSON-marshaler objects, raw JSON/byte blobs and
over-deep/cyclic structures are masked rather than dumped. No reflection or
user-supplied serialization hook runs. Supported nesting is bounded to 16 levels.
Sink errors are reduced to a fixed error and cannot leak credential-bearing
error messages. Normal non-secret structured metadata remains available.
Migration CLI errors retain a diagnostic stage but mask the raw error object;
a regression test covers credentials inside invalid database URLs and errors.

Audit field allowlists must remain minimal and server-defined. Untagged opaque
secrets in arbitrary free text cannot be reliably identified; integrations must
never copy credentials into ordinary ID/metadata fields or dump free-form auth,
request, environment/config or token structures. This is minimum secret masking,
not a complete PII taxonomy or final audit schema.

## Verification

Run `go test ./...`, `go vet ./...`, `go mod verify`, and `git diff --check`.
Unit tests cover all requested approval/delegation/redaction cases plus changed
arguments, principal/workload mismatches, validity expiring during dependencies,
conditional mutation failure, worker downgrade prevention and copied secrets.

For database integration, first bootstrap a disposable CYB-12 database as
described in the README, then set `CYB12_TEST_DATABASE_URL` to its administrative
URL. Both CYB-12 and CYB-13 integration suites run with `go test ./...`. Without
that variable, database integration tests explicitly skip. CYB-13 creates and
removes test-only RLS tables and a non-superuser/NOBYPASSRLS test login. Its tests
verify atomic consumption, stale state, final CAS, rollback, cross-tenant denial
and eight concurrent callers consuming a one-shot approval exactly once.

Verified on 2026-10-02 with Go 1.27.1 and a local disposable PostgreSQL 18.3
instance: `go test ./...`, `go vet ./...`, `go mod verify`, and
`git diff --check` passed. Both CYB-12 and CYB-13 database integration suites ran
with the database variable set; all new unit tests, including the migration
diagnostic regression, passed. New untracked files were checked for whitespace
separately because ordinary `git diff --check` does not include them.

The implementation diff was reviewed for tenant boundary bypass, approval
replay, TOCTOU, confused deputy/worker escalation, and log secret leakage. The
only tool call follows a fresh actor-and-subject allow decision, complete
approval/delegation validation and atomic consumption, then uses the approved
state precondition. Tenant queries use the existing RLS transaction. The normal
structured log sink receives sanitized data only; migration diagnostics no
longer print raw credential-bearing errors. These conclusions rely on the
adapter contracts and assumptions below; they do not certify unimplemented
production integrations or replace an independent security review.

## Assumptions and unresolved integration choices

- Trusted middleware and workload verification have already authenticated their
  contexts; these APIs must never be called with unchecked client claims.
- The eventual PDP must evaluate the current subject authority and worker
  permission independently, including current membership where applicable.
  This package does not choose those membership/policy rules.
- Production approval/delegation storage is not selected. Adapters must satisfy
  the immutable, tenant-scoped and atomic contracts above. No protected route or
  worker should be wired with test repositories or bypass this PEP.
- Production tool adapters and their authoritative state/argument fingerprints
  depend on the still-undecided protected tool/resource inventory. This database
  transaction boundary must not perform nontransactional external side effects;
  those need an equivalent atomic approval/precondition/execution boundary.
- Audit delivery happens after transaction completion. A sink failure returns
  a fixed dependency error; a committed one-shot approval stays consumed. This
  does not supply an audit outbox or make an audit failure undo a committed tool.

Identity provider/protocol, JWT versus opaque tokens, sessions/refresh lifecycle,
MFA, RBAC versus ABAC, final permission vocabulary, tenant selection/membership
lifecycle, approver eligibility/issuance/revocation workflow, signed DB claims,
full audit schema/retention/tamper resistance, and complete PII classification
remain TBD. No Kafka change or autonomous response is introduced.
