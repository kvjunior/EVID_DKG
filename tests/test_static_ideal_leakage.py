import unittest
from collections import Counter
from itertools import product

from accountable_dkg.execution.random_tapes import RandomTape
from accountable_dkg.simulation.ideal import StaticIdealDkg
from accountable_dkg.simulation.leakage import Exposure, ExposureKind, StaticLeakagePolicy


class StaticIdealLeakageTests(unittest.TestCase):
    def setUp(self):
        self.policy = StaticLeakagePolicy(4, 1, 2, frozenset({1}), frozenset({2}))

    def test_ideal_sampler_enumerates_every_polynomial_once(self):
        functionality = StaticIdealDkg(self.policy, 7)
        coefficients = Counter()
        leaked = Counter()
        for tape_words in product(range(7), repeat=3):
            output = functionality.sample(RandomTape(tuple(tape_words)))
            coefficients[output.coefficients] += 1
            leaked[tuple(value for _, value in output.leaked_shares)] += 1
        self.assertEqual(len(coefficients), 7 ** 3)
        self.assertEqual(set(coefficients.values()), {1})
        self.assertEqual(len(leaked), 7 ** 2)
        self.assertEqual(set(leaked.values()), {7})

    def test_c1_c2_policy_distinguishes_final_share_from_internal_state(self):
        exposures = (
            Exposure(ExposureKind.PUBLIC_TRANSCRIPT, None, b"ledger", "public"),
            Exposure(ExposureKind.INTERNAL_STATE, 1, b"corrupt-state", "c1-state"),
            Exposure(ExposureKind.FINAL_SHARE, 2, b"share", "c2-share"),
            Exposure(ExposureKind.INTERNAL_STATE, 2, b"honest-state", "c2-state"),
        )
        audit = self.policy.audit(exposures)
        self.assertEqual(len(audit.forbidden), 1)
        self.assertEqual(audit.forbidden[0].exposure.label, "c2-state")

    def test_honest_recovery_disclosure_is_conditional_not_silently_allowed(self):
        exposure = Exposure(ExposureKind.RECOVERY_KEY, 3, b"key", "honest-key")
        without = self.policy.audit((exposure,))
        self.assertEqual(len(without.conditional), 1)
        with_oracle = self.policy.audit((exposure,), frozenset({"dev1_recovery_joint"}))
        self.assertEqual(len(with_oracle.conditional), 0)
        self.assertTrue(with_oracle.accepted)

    def test_policy_rejects_adaptive_or_oversized_leakage_sets(self):
        with self.assertRaises(ValueError):
            StaticLeakagePolicy(4, 1, 2, frozenset({1, 2}), frozenset())
        with self.assertRaises(ValueError):
            StaticLeakagePolicy(4, 1, 2, frozenset({1}), frozenset({2, 3}))
        with self.assertRaises(ValueError):
            StaticLeakagePolicy(4, 1, 2, frozenset({1}), frozenset({1}))


if __name__ == "__main__":
    unittest.main()
