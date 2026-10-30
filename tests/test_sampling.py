from itertools import product
import unittest

from accountable_dkg.field import ToyField
from accountable_dkg.functionality import Target, sample_ideal
from accountable_dkg.parameters import ModelParameters
from accountable_dkg.polynomial import evaluate, interpolate, sample_conditioned


class Tape:
    def __init__(self, values): self.values = iter(values)
    def randrange(self, stop):
        value = next(self.values)
        assert 0 <= value < stop
        return value


class SamplingTests(unittest.TestCase):
    def test_conditional_sampler_is_bijective(self):
        field = ToyField(7)
        polynomials = {sample_conditioned(field, 2, {4: 1}, Tape(values))
                       for values in product(range(7), repeat=2)}
        self.assertEqual(len(polynomials), 49)
        self.assertTrue(all(evaluate(p, 4, 7) == 1 for p in polynomials))
        counts = {x: sum(p[0] == x for p in polynomials) for x in range(7)}
        self.assertEqual(set(counts.values()), {7})

    def test_two_constraints_leave_secret_uniform(self):
        polynomials = [sample_conditioned(ToyField(7), 2, {4: 1, 2: 3}, Tape([x]))
                       for x in range(7)]
        self.assertEqual({p[0] for p in polynomials}, set(range(7)))

    def test_three_constraints_determine_polynomial(self):
        constraints = {1: 2, 2: 4, 3: 1}
        p = sample_conditioned(ToyField(7), 2, constraints, Tape([]))
        self.assertTrue(all(evaluate(p, x, 7) == y for x, y in constraints.items()))

    def test_strong_target_rejects_programmed_corrupt_shares(self):
        with self.assertRaises(ValueError):
            sample_ideal(ModelParameters(), Target.UNIFORM_POLYNOMIAL,
                         Tape([]), {4: 1})

    def test_duplicate_field_indices_rejected(self):
        with self.assertRaises(ValueError):
            interpolate({1: 2, 8: 3}, ToyField(7))

    def test_composite_modulus_rejected(self):
        with self.assertRaises(ValueError): ToyField(9)
