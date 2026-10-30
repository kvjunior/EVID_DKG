"""Cauchy hyperinvertible extraction at the Das'23 linear interface."""

from dataclasses import dataclass

from accountable_dkg.crypto.pedersen import Q


@dataclass(frozen=True)
class ExtractionMatrix:
    rows: tuple[tuple[int, ...], ...]
    modulus: int = Q

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def column_count(self) -> int:
        return len(self.rows[0]) if self.rows else 0

    def apply(self, vector: tuple[int, ...]) -> tuple[int, ...]:
        if len(vector) != self.column_count:
            raise ValueError("extractor vector has the wrong length")
        return tuple(sum(weight * value for weight, value in zip(row, vector, strict=True)) % self.modulus for row in self.rows)


def cauchy_extraction_matrix(outputs: int, inputs: int, modulus: int = Q) -> ExtractionMatrix:
    if outputs < 1 or inputs < outputs or outputs + inputs >= modulus:
        raise ValueError("invalid Cauchy matrix dimensions")
    xs = tuple(range(1, outputs + 1))
    ys = tuple(range(outputs + 1, outputs + inputs + 1))
    rows = tuple(tuple(pow((x - y) % modulus, -1, modulus) for y in ys) for x in xs)
    return ExtractionMatrix(rows, modulus)


def extract_coefficients(
    matrix: ExtractionMatrix,
    first: tuple[int, ...],
    second: tuple[int, ...],
    faults: int,
    degree: int,
) -> tuple[int, ...]:
    if matrix.row_count < degree + 1:
        raise ValueError("extractor has too few output rows")
    first_output = matrix.apply(first)[:faults + 1]
    second_count = degree - faults
    second_output = matrix.apply(second)[faults + 1:faults + 1 + second_count]
    if len(second_output) != second_count:
        raise ValueError("extractor cannot supply requested degree")
    return first_output + second_output
