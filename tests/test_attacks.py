from fractions import Fraction
import unittest

from accountable_dkg.attacks import late_commit, selective_exclusion
from accountable_dkg.field import ToyField


class AttackTests(unittest.TestCase):
    def test_rushing_fixes_share_while_secret_remains_uniform(self):
        for q in (5, 7, 11):
            result = late_commit(ToyField(q))
            self.assertEqual(result["forced_share_probability"], "1")
            self.assertEqual(Fraction(result["share_total_variation"]), 1 - Fraction(1, q))
            self.assertEqual(result["secret_total_variation"], "0")

    def test_precommitted_contribution_can_still_be_selectively_included(self):
        for q in (5, 7, 11):
            result = selective_exclusion(ToyField(q))
            self.assertEqual(result["attacked_favored_probability"], result["expected_probability"])
            self.assertGreater(Fraction(result["total_variation"]), 0)
