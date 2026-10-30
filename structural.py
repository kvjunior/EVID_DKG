"""Exact finite models of dealing *interfaces* (added 25 Oct 2026).

These are enumerations over tiny prime fields. They check stated algebraic
facts about abstract interfaces. They are not implementations of AP, Das'23,
Katz or Chainlink DKG, and they prove nothing about computational adversaries.

Interfaces modelled (all with one corrupt recipient j and degree-2 sharing):

* DIRECT_SUM_RUSHING: honest dealers' aggregate H is revealed to the corrupt
  party at index j *before* the adversary fixes its own contribution or the
  inclusion of its dealers. This is the interface of an ordinary rushing
  direct-sum stage, with or without a committee.
* HIDE_UNTIL_FIXED: every adversarial choice (its contribution and whether its
  dealers are included) is fixed before the adversary sees anything that
  depends on H. This abstracts the "secret bulletin board" structure
  (Boneh-Shoup 22.4.2, Chainlink DKG v2 Sec. 5) and the "shares of shares"
  structure (Katz Sec. 5.3): there, what the adversary sees before the
  qualified set is fixed is independent of H. Whether a concrete protocol has
  this interface is a property of that protocol, proved in its own paper.
"""

from collections import Counter
from fractions import Fraction
from itertools import product

from .attacks import total_variation
from .field import ToyField
from .polynomial import evaluate


def _tv_joint(counts: Counter, support_size: int) -> Fraction:
    total = sum(counts.values())
    seen = sum(abs(Fraction(c, total) - Fraction(1, support_size)) for c in counts.values())
    unseen = (support_size - len(counts)) * Fraction(1, support_size)
    return (seen + unseen) / 2


def committee_direct_sum(field: ToyField, honest_committee: int = 1,
                         corrupt_index: int = 4, target: int = 1) -> dict:
    """O1 trace: a committee containing `honest_committee` honest dealers and
    one rushing corrupt committee dealer, all dealing degree-2 polynomials to
    every party. The corrupt dealer sees the honest aggregate at its own
    index (it is a recipient) before choosing its polynomial, and forces its
    own final share to `target`. The secret z(0) stays uniform. Exhaustive
    over all honest polynomials."""
    q = field.q
    share, secret = Counter(), Counter()
    for honest in product(range(q), repeat=3 * honest_committee):
        polys = [honest[3 * i:3 * i + 3] for i in range(honest_committee)]
        agg_at_j = sum(evaluate(p, corrupt_index, q) for p in polys) % q
        agg_at_0 = sum(p[0] for p in polys) % q
        corr = (target - agg_at_j) % q          # constant corrupt polynomial
        share[(agg_at_j + corr) % q] += 1
        secret[(agg_at_0 + corr) % q] += 1
    return {
        "honest_committee_dealers": honest_committee,
        "worlds": q ** (3 * honest_committee),
        "forced_share_probability": str(Fraction(share[target % q], sum(share.values()))),
        "share_total_variation": str(total_variation(share, q)),
        "secret_total_variation": str(total_variation(secret, q)),
        "scope": "rushing direct-sum committee stage; an honest committee member "
                 "does not prevent corrupt-share programming",
    }


def interface_bias(field: ToyField, interface: str, corrupt_index: int = 4,
                   committed=(0, 1, 0)) -> dict:
    """Maximum bias over ALL deterministic adversary strategies in a finite
    class, for one honest aggregate H (uniform degree-2) and one committed
    corrupt contribution c that the adversary may include (b=1) or exclude.

    DIRECT_SUM_RUSHING: the strategy is a map b = s(H(j)) (2^q strategies).
    HIDE_UNTIL_FIXED:   the strategy is a constant b, since nothing that
                        depends on H is visible before the choice is fixed.

    Returns the maximum total-variation distance, over the strategy class, of
    (i) the corrupt party's final share and (ii) the joint pair
    (z(0), z(j)) from uniform."""
    q = field.q
    if interface == "DIRECT_SUM_RUSHING":
        strategies = [dict(zip(range(q), bits)) for bits in product((0, 1), repeat=q)]
    elif interface == "HIDE_UNTIL_FIXED":
        strategies = [{"const": 0}, {"const": 1}]
    else:
        raise ValueError("Unknown interface")
    worst_share, worst_joint = Fraction(0), Fraction(0)
    for s in strategies:
        share, joint = Counter(), Counter()
        for honest in product(range(q), repeat=3):
            hj = evaluate(honest, corrupt_index, q)
            b = s["const"] if "const" in s else s[hj]
            zj = (hj + b * evaluate(committed, corrupt_index, q)) % q
            z0 = (honest[0] + b * committed[0]) % q
            share[zj] += 1
            joint[(z0, zj)] += 1
        worst_share = max(worst_share, total_variation(share, q))
        worst_joint = max(worst_joint, _tv_joint(joint, q * q))
    return {
        "interface": interface,
        "strategies_enumerated": len(strategies),
        "max_share_total_variation": str(worst_share),
        "max_joint_total_variation": str(worst_joint),
    }


def completion_conditioning(field: ToyField, favored=None) -> dict:
    """Latent versus completion-conditioned uniformity.

    A first attempt samples a uniform key exponent x. An adversary that may
    force ONE restart after seeing g^x (modelled by x itself) restarts iff
    x is not favored. The first-attempt (latent) distribution is uniform;
    the distribution of the key actually output is biased. This is the bias
    that a secure-with-abort functionality (Katz Fig. 7, F^bot) permits and
    that a robust or abort-fair functionality excludes."""
    q = field.q
    favored = set(range(q // 2)) if favored is None else set(favored)
    latent, output = Counter(), Counter()
    for x1, x2 in product(range(q), repeat=2):
        latent[x1] += 1
        output[x1 if x1 in favored else x2] += 1
    p = Fraction(len(favored), q)
    observed = Fraction(sum(output[x] for x in favored), q * q)
    return {
        "latent_total_variation": str(total_variation(latent, q)),
        "output_total_variation": str(total_variation(output, q)),
        "favored_probability_ideal": str(p),
        "favored_probability_output": str(observed),
    }
