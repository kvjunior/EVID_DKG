"""Independent oracle: enumerate actual subsets, not a second tail formula."""

from fractions import Fraction
from itertools import combinations
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from accountable_dkg.committee import (committee_report, honest_majority_failure,
                                      meets_failure_target, minimum_committee_size)


def subset_oracle(n, t, k):
    outcomes = list(combinations(range(n), k))
    failures = sum(2 * sum(identity < t for identity in sample) >= k
                   for sample in outcomes)
    return Fraction(failures, len(outcomes))


class CommitteeTests(unittest.TestCase):
    def test_every_small_population_matches_subset_oracle(self):
        for n in range(1, 10):
            for t in range(n + 1):
                for k in range(1, n + 1):
                    with self.subTest(n=n, t=t, k=k):
                        self.assertEqual(honest_majority_failure(n, t, k),
                                         subset_oracle(n, t, k))

    def test_minimum_matches_independent_subset_search(self):
        for n in range(1, 9):
            for t in range(n + 1):
                for bits in (1, 2, 4, 8):
                    possible = [k for k in range(1, n + 1)
                                if subset_oracle(n, t, k) <= Fraction(1, 2 ** bits)]
                    self.assertEqual(minimum_committee_size(n, t, bits),
                                     min(possible) if possible else None)

    def test_ties_fail_and_successive_sizes_are_not_monotone(self):
        self.assertEqual(honest_majority_failure(4, 1, 1), Fraction(1, 4))
        self.assertEqual(honest_majority_failure(4, 1, 2), Fraction(1, 2))

    def test_one_honest_member_is_different_from_honest_majority(self):
        self.assertEqual(honest_majority_failure(9, 3, 3), Fraction(19, 84))
        self.assertNotEqual(honest_majority_failure(9, 3, 3), Fraction(1, 84))

    def test_zero_failure_from_population_constraint(self):
        self.assertEqual(honest_majority_failure(127, 42, 85), 0)
        self.assertGreater(honest_majority_failure(127, 42, 84), 0)

    def test_exact_boundary_is_inclusive(self):
        self.assertTrue(meets_failure_target(Fraction(1, 4), 2))
        self.assertFalse(meets_failure_target(Fraction(1, 4), 3))

    def test_none_if_no_size_meets_target(self):
        self.assertIsNone(minimum_committee_size(9, 9, 128))
        self.assertFalse(committee_report(9, 9, 128)["meets_target"])

    def test_exact_report_roundtrips(self):
        report = json.loads(json.dumps(committee_report(9, 3, 4, k=3)))
        exact = report["failure_probability_exact"]
        self.assertEqual(Fraction(int(exact["numerator_hex"], 16),
                                  int(exact["denominator_hex"], 16)), Fraction(19, 84))
        self.assertFalse(report["cryptographic_security_claim"])
        self.assertFalse(report["composition_security_proved"])

    def test_invalid_parameters_rejected(self):
        for parameters in ((0, 0, 1), (5, -1, 1), (5, 6, 1), (5, 1, 0),
                           (5, 1, 6), (True, 0, 1), (5, 1.0, 1)):
            with self.subTest(parameters=parameters), self.assertRaises(ValueError):
                honest_majority_failure(*parameters)
        for bits in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                minimum_committee_size(5, 1, bits)
        for probability in (0.5, Fraction(-1), Fraction(2)):
            with self.assertRaises(ValueError):
                meets_failure_target(probability, 3)

    def test_cli_json_and_error_status(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        command = [sys.executable, "-m", "accountable_dkg.committee"]
        run = subprocess.run(command + ["--n", "4", "--t", "1", "--failure-bits", "2"],
                             env=env, text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["committee_size"], 1)
        bad = subprocess.run(command + ["--n", "4", "--t", "5"], env=env,
                             text=True, capture_output=True)
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
