"""Exact sampling calculations; no DKG or coin-generation protocol.

Assume a uniform k-subset drawn without replacement from n fixed identities,
of which t are statically corrupt. A strict honest majority fails precisely
when 2*X >= k. Ties fail. This does not prove that any protocol generates
such a sample, hides its randomness, or composes securely with a DKG stage.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import json
from math import comb


def _integer(name: str, value: int, lower: int, upper: int | None = None) -> None:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if value < lower or (upper is not None and value > upper):
        raise ValueError(f"{name} is outside its permitted range")


def _population(n: int, t: int) -> None:
    _integer("n", n, 1)
    _integer("t", t, 0, n)


def honest_majority_failure(n: int, t: int, k: int) -> Fraction:
    """Exact rational hypergeometric tail Pr[2*X >= k].

    Start at mass C(t,a)*C(n-t,k-a), then use the ratio of consecutive
    binomial masses. All arithmetic is integral until the final Fraction.
    No floating point or independent-draw approximation is used.
    """
    _population(n, t)
    _integer("k", k, 1, n)
    lower = max((k + 1) // 2, k - (n - t))
    upper = min(t, k)
    if lower > upper:
        return Fraction(0)
    mass = comb(t, lower) * comb(n - t, k - lower)
    numerator = mass
    for x in range(lower, upper):
        mass = mass * (t - x) * (k - x) // ((x + 1) * (n - t - k + x + 1))
        numerator += mass
    return Fraction(numerator, comb(n, k))


def meets_failure_target(probability: Fraction, failure_bits: int) -> bool:
    """Exact comparison with 2**(-failure_bits), including equality."""
    _integer("failure_bits", failure_bits, 1)
    if not isinstance(probability, Fraction) or not 0 <= probability <= 1:
        raise ValueError("probability must be a Fraction in [0,1]")
    return (probability.numerator << failure_bits) <= probability.denominator


def minimum_committee_size(n: int, t: int, failure_bits: int) -> int | None:
    """Smallest feasible k, or None if no size meets the target.

    Scan all sizes: the tail is not monotone over successive k because ties
    fail. For n=4,t=1 it is 1/4 at k=1 but 1/2 at k=2. This exhaustive
    search is intended for parameter analysis, not huge population sizes.
    """
    _population(n, t)
    _integer("failure_bits", failure_bits, 1)
    for k in range(1, n + 1):
        if meets_failure_target(honest_majority_failure(n, t, k), failure_bits):
            return k
    return None


def committee_report(n: int, t: int, failure_bits: int, k: int | None = None) -> dict:
    """JSON-safe report. Hexadecimal exact integers avoid decimal size limits."""
    _population(n, t)
    _integer("failure_bits", failure_bits, 1)
    search = k is None
    if search:
        k = minimum_committee_size(n, t, failure_bits)
    result = {
        "n": n, "t": t, "failure_bits": failure_bits, "committee_size": k,
        "minimum_searched": search,
        "sampling_model": "uniform subset without replacement; fixed corrupt set",
        "failure_event": "2 * corrupt_committee_members >= committee_size",
        "cryptographic_security_claim": False,
        "composition_security_proved": False,
        "candidate_protocol_implemented": False,
    }
    if k is None:
        result["meets_target"] = False
        return result
    probability = honest_majority_failure(n, t, k)
    with localcontext() as context:
        context.prec = 20
        decimal_probability = Decimal(probability.numerator) / Decimal(probability.denominator)
    result.update({
        "meets_target": meets_failure_target(probability, failure_bits),
        "failure_probability_decimal": "0" if not probability else format(decimal_probability, ".12E"),
        "failure_probability_exact": {
            "numerator_hex": hex(probability.numerator),
            "denominator_hex": hex(probability.denominator),
        },
    })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--t", type=int, required=True)
    parser.add_argument("--failure-bits", type=int, default=128)
    parser.add_argument("--k", type=int, help="evaluate this size instead of searching")
    args = parser.parse_args()
    try:
        report = committee_report(args.n, args.t, args.failure_bits, args.k)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
