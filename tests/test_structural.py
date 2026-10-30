"""Exact-enumeration checks of dealing interfaces (finite models only)."""

from fractions import Fraction
import unittest

from accountable_dkg.field import ToyField
from accountable_dkg.structural import (committee_direct_sum, completion_conditioning,
                                        interface_bias)


class StructuralTests(unittest.TestCase):
    def test_o1_honest_committee_member_does_not_prevent_programming(self):
        # O1 correction: rushing direct-sum committee stage
        for q, honest in ((5, 1), (7, 1), (5, 2)):
            r = committee_direct_sum(ToyField(q), honest_committee=honest)
            self.assertEqual(r["forced_share_probability"], "1")
            self.assertEqual(Fraction(r["share_total_variation"]), 1 - Fraction(1, q))
            self.assertEqual(r["secret_total_variation"], "0")

    def test_vulnerable_interface_is_biased_for_some_strategy(self):
        for q in (5, 7):
            r = interface_bias(ToyField(q), "DIRECT_SUM_RUSHING")
            self.assertEqual(r["strategies_enumerated"], 2 ** q)
            self.assertGreater(Fraction(r["max_share_total_variation"]), 0)

    def test_hide_until_fixed_interface_is_unbiased_for_every_strategy(self):
        # every strategy in the (finite) class leaves (z(0), z(j)) uniform
        for q in (5, 7, 11):
            r = interface_bias(ToyField(q), "HIDE_UNTIL_FIXED")
            self.assertEqual(r["max_share_total_variation"], "0")
            self.assertEqual(r["max_joint_total_variation"], "0")

    def test_latent_uniformity_differs_from_completion_conditioned(self):
        r = completion_conditioning(ToyField(7))
        self.assertEqual(r["latent_total_variation"], "0")
        self.assertEqual(r["favored_probability_output"], "33/49")
        self.assertGreater(Fraction(r["output_total_variation"]), 0)

    def test_unknown_interface_rejected(self):
        with self.assertRaises(ValueError):
            interface_bias(ToyField(5), "SOMETHING_ELSE")


if __name__ == "__main__":
    unittest.main()
