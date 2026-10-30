import unittest

from accountable_dkg.polynomial import evaluate
from accountable_dkg.simulation.hybrid import (
    finite_degree_one_hybrid_check, reprogram_degree_t_sharing,
)


class SimulatorHybridTests(unittest.TestCase):
    def test_reprogramming_preserves_commitments_and_corrupt_value_shares(self):
        q, alpha = 7, 3
        old_values = (2, 4, 1)
        old_masks = (5, 3, 6)
        result = reprogram_degree_t_sharing(
            old_values, old_masks, 6, (1, 2), q, alpha
        )
        self.assertEqual(result.value_coefficients[0], 6)
        for index in (1, 2):
            self.assertEqual(
                evaluate(result.value_coefficients, index, q),
                evaluate(old_values, index, q),
            )
        for coefficient in range(3):
            self.assertEqual(
                (result.value_coefficients[coefficient] + alpha * result.mask_coefficients[coefficient]) % q,
                result.commitments[coefficient],
            )

    def test_underconstrained_reprogramming_requires_exact_fresh_randomness(self):
        with self.assertRaisesRegex(ValueError, "wrong amount"):
            reprogram_degree_t_sharing((1, 2, 3), (3, 4, 5), 4, (1,), 7, 2)
        result = reprogram_degree_t_sharing(
            (1, 2, 3), (3, 4, 5), 4, (1,), 7, 2, free_randomness=(6,)
        )
        self.assertEqual(result.value_coefficients[0], 4)

    def test_exact_degree_one_real_and_simulated_view_distributions_match(self):
        report = finite_degree_one_hybrid_check()
        self.assertTrue(report.distributions_equal)
        self.assertEqual(report.real_views, 5 ** 4)
        self.assertEqual(report.simulated_views, 5 ** 4)

    def test_trapdoor_is_required(self):
        with self.assertRaisesRegex(ValueError, "nonzero"):
            reprogram_degree_t_sharing((1, 2), (3, 4), 5, (1,), 7, 0)


if __name__ == "__main__":
    unittest.main()
