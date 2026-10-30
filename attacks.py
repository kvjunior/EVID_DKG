"""Known algebraic counterexamples, not new cryptanalytic results."""

from collections import Counter
from fractions import Fraction
from itertools import product

from .field import ToyField
from .polynomial import evaluate


def total_variation(counts: Counter, q: int) -> Fraction:
    total = sum(counts.values())
    if not total:
        raise ValueError("Empty distribution")
    return sum((abs(Fraction(counts[x], total) - Fraction(1, q))
                for x in range(q)), Fraction()) / 2


def late_commit(field: ToyField, degree: int = 2,
                corrupt_index: int = 4, target: int = 1) -> dict:
    """One uniform aggregate honest polynomial plus a late corrupt dealer.

    The corrupt dealer chooses a constant contribution after learning the
    honest aggregate at its own index. This models only the direct-sum stage;
    it is not an implementation or attack on AP, Das, Katz, or Chainlink DKG.
    """
    q = field.q
    if degree < 1 or corrupt_index % q == 0:
        raise ValueError("Require positive degree and a nonzero party index")
    final_shares, secrets = Counter(), Counter()
    for honest in product(range(q), repeat=degree + 1):
        correction = (target - evaluate(honest, corrupt_index, q)) % q
        final_shares[(evaluate(honest, corrupt_index, q) + correction) % q] += 1
        secrets[(honest[0] + correction) % q] += 1
    return {
        "worlds": q ** (degree + 1),
        "target": target % q,
        "forced_share_probability": str(Fraction(final_shares[target % q], sum(final_shares.values()))),
        "uniform_ideal_target_probability": str(Fraction(1, q)),
        "share_total_variation": str(total_variation(final_shares, q)),
        "secret_total_variation": str(total_variation(secrets, q)),
        "scope": "rushing direct-sum dealing; committee use requires the same vulnerable interface",
    }


def selective_exclusion(field: ToyField) -> dict:
    """Commit a uniform contribution c, then include it iff h+c is in L."""
    q = field.q
    favored = set(range(q // 2))
    outputs = Counter()
    for honest, committed in product(range(q), repeat=2):
        with_dealer = (honest + committed) % q
        outputs[with_dealer if with_dealer in favored else honest] += 1
    p = Fraction(len(favored), q)
    observed = Fraction(sum(outputs[x] for x in favored), q * q)
    return {
        "worlds": q * q,
        "uniform_ideal_favored_probability": str(p),
        "attacked_favored_probability": str(observed),
        "expected_probability": str(2 * p - p * p),
        "total_variation": str(total_variation(outputs, q)),
        "scope": "selective inclusion after observing the corrupt recipient's honest aggregate",
    }
