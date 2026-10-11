"""Fail CI on skipped tests, incomplete output or missing integration evidence."""

import argparse
import json
from pathlib import Path


MODULE = "cyber-ai-platform/internal/"
BOOTSTRAP = (MODULE + "tenantdb", "TestTenantIsolationAndTransactionLifecycle")
REQUIRED = {
    BOOTSTRAP,
    (MODULE + "authorization", "TestPostgresProtectedExecution"),
    (MODULE + "authorization", "TestPostgresProtectedExecution/ExecutionAdmissionOutsideTransactionAndLocks"),
    (MODULE + "authorization", "TestPostgresProtectedExecution/ConcurrentAdmittedReplayConsumesOnce"),
    (MODULE + "encryption", "TestPostgresEnvelopeBoundary"),
    (MODULE + "queue", "TestPostgresQueueProtectedWorkerBoundary"),
    (MODULE + "queue/redis", "TestRealRedisProduceConsumeCompletionACKAndDuplicate"),
    (MODULE + "queue/redis", "TestRealRedisPendingClaimRecovery"),
    (MODULE + "queue/redis", "TestRealRedisCompletedRecoveryPDPFailuresBounded"),
}


def validate(lines, bootstrap=False):
    started = set()
    completed = set()
    passed = set()
    running = set()
    for line in lines:
        event = json.loads(line)
        action, package, test = event.get("Action"), event.get("Package"), event.get("Test")
        if action in {"fail", "skip"}:
            raise ValueError(f"{action}: {package} {test or ''}")
        if action == "start" and not test:
            started.add(package)
        if action == "run" and test:
            running.add((package, test))
        if action == "pass":
            if test:
                passed.add((package, test))
            else:
                completed.add(package)
    if not started or started != completed or running != passed:
        raise ValueError("Missing/incomplete package or test results")
    missing = ({BOOTSTRAP} if bootstrap else REQUIRED) - passed
    if missing:
        raise ValueError(f"Missing integration PASS evidence: {sorted(missing)}")
    return len(passed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        with args.log.open(encoding="utf-8-sig") as stream:
            count = validate(stream, args.bootstrap)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise SystemExit(f"CI test evidence rejected: {error}") from error
    print(f"{count} tests/subtests PASS; zero FAIL/SKIP; required integration evidence present")
