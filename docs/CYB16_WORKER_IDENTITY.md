# CYB-16 SPIFFE/mTLS worker identity foundation

## Scope and trust boundary

The neutral `internal/workeridentity` core authenticates inbound worker
connections. It selects no issuer/provider, SPIRE/Vault deployment, trust domain,
organization-specific SPIFFE namespace, tenant mapping or production entrypoint.
SPIFFE syntax/X.509 constraints are protocol rules, not a selected workload naming
scheme. Configuration must supply approved domains, maximum SVID lifetime,
minimum TLS version, handshake timeout, source, verifier, mapper and audit sink.

`Source.Current` supplies an immutable current local SVID/key and domain-indexed
trust bundles. Its adapter must report refresh failure instead of silently
returning stale material. The bridge calls the source again after handshake and
on each worker validity check; there is no fallback cache. Source concurrency,
key custody and actual refresh/rotation scheduling belong to the future adapter.

`X509Verifier` checks chain signatures, explicit domain trust roots, validity,
bounded leaf lifetime, one SPIFFE URI SAN, leaf/key-usage constraints and EKU.
It never falls back to operating-system roots or another domain's bundle.
Parsed certificates alone prove neither key possession nor worker authentication.

`Bridge.Accept` owns a raw connection, obtains the local SVID, validates its
certificate/key match, and performs the server side of a mutual TLS handshake.
Client certificates are mandatory; the custom verification callback performs
SPIFFE chain/domain verification and approved actor mapping. A Session is created
only after successful handshake and a fresh source/peer verification. The remote
client must authenticate the server as well using its approved transport adapter.
The bridge cannot enforce a remote client's server-verification policy.

This foundation supports full handshakes only (session tickets disabled); it is
not a production resumption or session-invalidation policy. An authenticated
transport is exposed through a wrapper that suppresses raw TLS/network errors.
Callers close the Session on disconnect; observed I/O failures invalidate it.
Active detection/termination of all idle, resumed or in-flight sessions remains
a deployment/lifecycle decision, not a guarantee made by this core.

## CYB-13/15 integration

`Session.WorkerContext` alone bridges authenticated transport to
`WithVerifiedWorkerCheck`. Its guard refreshes trust/source, verifies peer
validity and stable identity-to-actor mapping, and consults optional status policy.
PEP invokes it at worker entry, before PDP/tenant transaction, after potentially
slow preflight, before preparation and before protected side effects. A failed
guard cannot downgrade to the legacy marker. Existing trusted in-process
`WithVerifiedWorker` remains for existing adapters/tests; it is NOT a network
authentication API. Application code and injected adapters are trusted wiring.

Actor identity grants no tenant or business authority. `ResolveWorker` reloads
immutable delegation and checks actor/subject PDP. `ExecuteWorker` and the
prepared/decrypt path preserve approval, one-shot consumption, state binding,
CYB-12 `WithTenantTx` and CYB-14 KMS failure behavior. Tenant is never extracted
from a SPIFFE path. Unknown workers, conflicting tenant/subject context and
worker/delegation mismatch are denied.

CYB-15 already invokes `VerifyWorker` for processing, claim/recovery and terminal
handling. The guarded context therefore reaches the existing boundary without
adding authority fields to messages. Tests cover wrong-worker claim, unknown
message fields, ACK recovery, fresh subject authorization and renewed certificates
that cannot restore a consumed approval. Queue topology and retry policy do not
change. Redis consumer names, claim ownership and opaque references are not
identities; a Redis SERVER certificate is not evidence of the worker's identity.
Direct-poll process identity wiring and worker deployment entrypoint remain TBD.

## Lifecycle, errors and audit

Source refresh failure, missing bundles, invalid/expired SVIDs, mapping changes
and optional withdrawal-policy denial fail closed. `Status.Active` is a neutral
hook; nil explicitly means withdrawal checking is not implemented. It must not
be presented as production revocation/quarantine support. No CRL is required.

Only fixed event/outcome/error-class values go through the existing audit
sanitizer. Certificates, private keys, identity objects and raw dependency errors
are not emitted. Unknown errors are reduced to safe dependency errors without
wrapping causes. Audit failure denies new context creation/validity checks.
The pre-final `worker_identity` audit event uses `outcome=pending`, which records
only that verification reached the final guard, never authentication success.
After that blocking write, local/peer SVID and verified-chain validity are
rechecked. A denial may emit `outcome=denied`; if that write fails, any persisted
earlier event is still pending, not a false success. Successful authentication is
the returned Session/context or nil guard error; no blocking success audit is
added after the final validity check.
Final audit taxonomy/storage/retention is coordinated with CYB-17.

## Verification and production-readiness decisions

Tests use disposable loopback TLS, test CAs/SVIDs, source/mapper/status doubles and
in-memory transactional queue fixtures. They do not select a production issuer,
algorithm, namespace, retention or numeric lifetime/rotation policy. Existing
real Redis/PostgreSQL and encryption regressions remain required alongside the
new transport tests. No runtime quarantine, automatic issuer rotation or sandbox
IMDS enforcement is implemented or claimed by these tests.

Remaining decisions: attestation/bootstrap; issuer/provider/library integration;
trust domains and registration/mapping; entrypoint/termination/direct-poll wiring;
SVID lifetime and real rotation interval; trust updates and source availability;
withdrawal/revocation and quarantine mechanism; session/resumption/in-flight
invalidation; sandbox IMDS/runtime configuration; operational compromise response.
Full CYB-16 production readiness requires those decisions and deployment evidence.
Architecture v2, Redis MVP/Kafka production, QEMU/KVM or bare-metal detonation,
CYB-14 object/version binding deferral and CYB-15 topology/outbox/replay TBD remain.
