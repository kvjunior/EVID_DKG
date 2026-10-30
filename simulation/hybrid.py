"""Finite algebraic checks for the static Das'23 reprogramming hybrid."""

from collections import Counter
from dataclasses import dataclass
from itertools import product

from accountable_dkg.field import ToyField
from accountable_dkg.polynomial import evaluate, sample_conditioned


class _SequenceRng:
    def __init__(self, values: tuple[int, ...]) -> None:
        self.values = values
        self.offset = 0

    def randrange(self, stop: int) -> int:
        if self.offset >= len(self.values):
            raise RuntimeError("reprogramming randomness exhausted")
        value = self.values[self.offset]
        self.offset += 1
        if not 0 <= value < stop:
            raise ValueError("reprogramming randomness is outside the field")
        return value


@dataclass(frozen=True)
class ReprogrammedSharing:
    value_coefficients: tuple[int, ...]
    mask_coefficients: tuple[int, ...]
    commitments: tuple[int, ...]


def reprogram_degree_t_sharing(
    old_values: tuple[int, ...],
    old_masks: tuple[int, ...],
    target_constant: int,
    corrupt_indices: tuple[int, ...],
    modulus: int,
    alpha: int,
    free_randomness: tuple[int, ...] = (),
) -> ReprogrammedSharing:
    """Preserve Pedersen exponents while replacing the shared constant.

    This is the scalar algebra behind Figure 3, steps 5--7. It requires the
    simulation trapdoor alpha = log_g(h); the concrete backend does not expose
    that trapdoor.
    """
    degree = len(old_values) - 1
    if degree < 0 or len(old_masks) != degree + 1 or len(corrupt_indices) > degree:
        raise ValueError("invalid degree-t sharing")
    ToyField(modulus)
    if alpha % modulus == 0:
        raise ValueError("simulation trapdoor must be nonzero")
    constraints = {0: target_constant % modulus}
    for index in corrupt_indices:
        if index == 0 or index in constraints:
            raise ValueError("corrupt indices must be distinct and nonzero")
        constraints[index] = evaluate(old_values, index, modulus)
    free = degree + 1 - len(constraints)
    if len(free_randomness) != free:
        raise ValueError("wrong amount of reprogramming randomness")
    new_values = sample_conditioned(
        ToyField(modulus), degree, constraints, _SequenceRng(free_randomness)
    )
    alpha_inverse = pow(alpha, -1, modulus)
    new_masks = tuple(
        (old_masks[i] + (old_values[i] - new_values[i]) * alpha_inverse) % modulus
        for i in range(degree + 1)
    )
    commitments = tuple(
        (old_values[i] + alpha * old_masks[i]) % modulus
        for i in range(degree + 1)
    )
    assert commitments == tuple(
        (new_values[i] + alpha * new_masks[i]) % modulus
        for i in range(degree + 1)
    )
    return ReprogrammedSharing(new_values, new_masks, commitments)


@dataclass(frozen=True)
class FiniteHybridReport:
    modulus: int
    participants: int
    real_views: int
    simulated_views: int
    distributions_equal: bool


def finite_degree_one_hybrid_check(
    modulus: int = 5,
    participants: int = 3,
    corrupt_index: int = 1,
    alpha: int = 2,
) -> FiniteHybridReport:
    """Exhaustively compare real and ideal-parameterized degree-one views."""
    ToyField(modulus)
    if not 1 <= corrupt_index <= participants or alpha % modulus == 0:
        raise ValueError("invalid finite hybrid parameters")
    real: Counter[tuple[int, ...]] = Counter()
    simulated: Counter[tuple[int, ...]] = Counter()
    field = ToyField(modulus)

    for a0, a1, r0, r1 in product(range(modulus), repeat=4):
        values, masks = (a0, a1), (r0, r1)
        view = (
            a0,
            evaluate(values, corrupt_index, modulus),
            evaluate(masks, corrupt_index, modulus),
            *( (evaluate(values, j, modulus) + alpha * evaluate(masks, j, modulus)) % modulus
               for j in range(1, participants + 1) ),
        )
        real[view] += 1

    for target, corrupt_share, r0, r1 in product(range(modulus), repeat=4):
        values = sample_conditioned(
            field, 1, {0: target, corrupt_index: corrupt_share}, _SequenceRng(())
        )
        masks = (r0, r1)
        view = (
            target,
            corrupt_share,
            evaluate(masks, corrupt_index, modulus),
            *( (evaluate(values, j, modulus) + alpha * evaluate(masks, j, modulus)) % modulus
               for j in range(1, participants + 1) ),
        )
        simulated[view] += 1

    return FiniteHybridReport(
        modulus, participants, sum(real.values()), sum(simulated.values()), real == simulated
    )
