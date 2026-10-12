import json
import unittest

from check_go_tests import BOOTSTRAP, REQUIRED, validate


def evidence(tests):
    events = []
    for package in sorted({package for package, _ in tests}):
        events.append(dict(Action="start", Package=package))
        for pkg, test in sorted(tests):
            if pkg == package:
                events.extend([dict(Action="run", Package=package, Test=test),
                               dict(Action="pass", Package=package, Test=test)])
        events.append(dict(Action="pass", Package=package))
    return [json.dumps(event) for event in events]


class EvidenceTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(validate(evidence(REQUIRED)), len(REQUIRED))

    def test_bootstrap(self):
        self.assertEqual(validate(evidence({BOOTSTRAP}), bootstrap=True), 1)

    def test_skip_or_failure_cannot_be_hidden_by_package_pass(self):
        for action in ("skip", "fail"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                validate(evidence(REQUIRED) + [json.dumps(dict(Action=action, Package="pkg", Test="test"))])

    def test_missing_integration(self):
        with self.assertRaises(ValueError):
            validate(evidence(REQUIRED - {BOOTSTRAP}))

    def test_truncated_package(self):
        with self.assertRaises(ValueError):
            validate(evidence(REQUIRED)[:-1])

    def test_unfinished_test(self):
        with self.assertRaises(ValueError):
            validate(evidence(REQUIRED) + [json.dumps(dict(Action="run", Package="pkg", Test="unfinished"))])

    def test_empty_or_malformed(self):
        for lines in ([], ["not json"], ["null"]):
            with self.subTest(lines=lines), self.assertRaises((ValueError, AttributeError)):
                validate(lines)
