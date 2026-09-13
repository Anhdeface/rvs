#!/usr/bin/env python3
"""
tests/test_e2e_dynamic.py - Comprehensive Opaque-Box E2E Test Suite for rvs Dynamic RE Upgrade.

Architecture:
- Strictly adheres to the 4-tier testing hierarchy defined in TEST_INFRA.md:
  - Tier 1: Feature Coverage (90 tests: >= 5 tests per feature for F1-F18)
  - Tier 2: Boundary & Corner Cases (90 tests: >= 5 boundary tests per feature for F1-F18)
  - Tier 3: Cross-Feature Combinations (20 pairwise interaction tests)
  - Tier 4: Real-World Scenarios (5 realistic end-to-end crackme workflows)
- Total: 205 tests.

Test Fixtures:
- tests/fixtures/crash_target.c (predictable SIGSEGV crash triage)
- tests/fixtures/decryptor_target.c (XOR loop decryption & memory dump)
- tests/fixtures/antidebug_target.c (ptrace / TracerPid anti-debug detection & bypass)
- tests/fixtures/auth_gate.c & tests/fixtures/crackme_case (decision gate bypass)

Execution:
  python3 tests/test_e2e_dynamic.py
  python3 -m unittest tests/test_e2e_dynamic.py
  pytest tests/test_e2e_dynamic.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

# Import all tier test cases from submodules
from tests.test_dynamic_tier1 import TestTier1FeatureCoverage
from tests.test_dynamic_tier2 import TestTier2BoundaryAndCornerCases
from tests.test_dynamic_tier3_4 import (
    TestTier3CrossFeatureCombinations,
    TestTier4RealWorldScenarios,
)

__all__ = [
    "TestTier1FeatureCoverage",
    "TestTier2BoundaryAndCornerCases",
    "TestTier3CrossFeatureCombinations",
    "TestTier4RealWorldScenarios",
]


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for test_class in [
        TestTier1FeatureCoverage,
        TestTier2BoundaryAndCornerCases,
        TestTier3CrossFeatureCombinations,
        TestTier4RealWorldScenarios,
    ]:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(load_tests(unittest.defaultTestLoader, None, None))
    sys.exit(0 if result.wasSuccessful() else 1)
