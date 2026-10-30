"""Executable static F_ADKG-shaped sampler for finite-model validation."""

from dataclasses import dataclass

from accountable_dkg.field import ToyField
from accountable_dkg.polynomial import evaluate

from .leakage import StaticLeakagePolicy


@dataclass(frozen=True)
class IdealDkgOutput:
    modulus: int
    coefficients: tuple[int, ...]
    shares: tuple[tuple[int, int], ...]
    leaked_shares: tuple[tuple[int, int], ...]

    @property
    def secret(self) -> int:
        return self.coefficients[0]

    @classmethod
    def from_shares(
        cls,
        modulus: int,
        degree: int,
        shares: tuple[tuple[int, int], ...],
        leaked_participants: frozenset[int],
    ) -> "IdealDkgOutput":
        if len(shares) < degree + 1:
            raise ValueError("insufficient shares to recover ideal polynomial")
        selected = tuple(sorted(shares)[:degree + 1])
        matrix = [
            [pow(x, column, modulus) for column in range(degree + 1)] + [y % modulus]
            for x, y in selected
        ]
        for column in range(degree + 1):
            pivot = next(
                (row for row in range(column, degree + 1) if matrix[row][column] % modulus),
                None,
            )
            if pivot is None:
                raise ValueError("share indices are not independent")
            matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
            inverse = pow(matrix[column][column], -1, modulus)
            matrix[column] = [(value * inverse) % modulus for value in matrix[column]]
            for row in range(degree + 1):
                if row == column:
                    continue
                factor = matrix[row][column]
                matrix[row] = [
                    (value - factor * base) % modulus
                    for value, base in zip(matrix[row], matrix[column], strict=True)
                ]
        coefficients = tuple(matrix[row][-1] for row in range(degree + 1))
        ordered = tuple(sorted(shares))
        if any(evaluate(coefficients, x, modulus) != y % modulus for x, y in ordered):
            raise ValueError("shares do not lie on one degree-bounded polynomial")
        by_participant = dict(ordered)
        if not leaked_participants <= set(by_participant):
            raise ValueError("unknown leaked participant")
        leaked = tuple((index, by_participant[index]) for index in sorted(leaked_participants))
        return cls(modulus, coefficients, ordered, leaked)


class StaticIdealDkg:
    def __init__(self, policy: StaticLeakagePolicy, modulus: int) -> None:
        if modulus <= policy.participants:
            raise ValueError("field must contain all participant indices")
        ToyField(modulus)
        self.policy = policy
        self.modulus = modulus

    def sample(self, tape) -> IdealDkgOutput:
        coefficients = tuple(
            tape.draw_below(self.modulus) for _ in range(self.policy.degree + 1)
        )
        shares = tuple(
            (participant, evaluate(coefficients, participant, self.modulus))
            for participant in range(1, self.policy.participants + 1)
        )
        by_participant = dict(shares)
        leaked = tuple(
            (participant, by_participant[participant])
            for participant in sorted(self.policy.revealed_final_shares)
        )
        return IdealDkgOutput(self.modulus, coefficients, shares, leaked)
