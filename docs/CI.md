# GitHub Actions CI

`Go CI` runs for pull requests targeting `main` and pushes to `main`.
The `Go (normal)` and `Go (race)` jobs use separate disposable PostgreSQL 16
and Redis 7.2 service containers on Ubuntu 24.04. These versions and the fixed
test-only PostgreSQL password are CI fixtures, not production decisions.

Go is selected from `go.mod`; CGO is enabled for race detection. Each job first
runs the CYB-12 tenantdb tests to bootstrap database roles and migrations before
the full suite. The existing tests connect through `CYB12_TEST_DATABASE_URL`
and `CYB15_TEST_REDIS_ADDRESS`. They create restricted runtime roles for RLS
checks even though the disposable database bootstrap uses its test administrator.

Both jobs run uncached tests (`-count=1`), with `-race` in the race job, plus
`go vet ./...`, `go mod verify`, and `git diff --check`. JSON test output remains
in the Actions logs. The evidence guard rejects any FAIL or SKIP, empty/truncated
results, or missing critical real PostgreSQL/Redis integration PASS events.
It does not freeze the suite at a fixed test count. Bash pipefail propagates
Go failures through `tee`; failures are never marked continue-on-error.

The token has only `contents: read`; checkout does not persist credentials.
Actions are pinned to commit SHAs. No production secrets, environments, external
databases, deployment credentials or production providers are used. Service ports
bind to loopback on the disposable runner. Jobs have a 20-minute timeout and
superseded runs are canceled. Dependency caching is disabled.

The workflow also checks submitted changes for whitespace errors, because a
plain `git diff --check` on a clean checkout would not inspect the PR changes.
Guard tests run with `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`.

Branch protection is unchanged. Until required checks are separately configured,
GitHub does not enforce these jobs as a merge gate. CI does not resolve CYB-17
production audit storage, retention, cost policy, accounting/refund/settlement,
production wiring or other Architecture v2 TBD decisions.
