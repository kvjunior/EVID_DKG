"""Finite online Reed-Solomon error correction for Batch 07 traces."""

from itertools import combinations

from accountable_dkg.crypto.pedersen import Q, evaluate


def _coefficients(points: tuple[tuple[int, int], ...], degree: int) -> tuple[int, ...]:
    matrix = [[pow(x, column, Q) for column in range(degree + 1)] + [y % Q] for x, y in points]
    for column in range(degree + 1):
        pivot = next((row for row in range(column, degree + 1) if matrix[row][column]), None)
        if pivot is None:
            raise ValueError("dependent Reed-Solomon points")
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inverse = pow(matrix[column][column], -1, Q)
        matrix[column] = [value * inverse % Q for value in matrix[column]]
        for row in range(degree + 1):
            if row == column:
                continue
            factor = matrix[row][column]
            matrix[row] = [
                (value - factor * base) % Q
                for value, base in zip(matrix[row], matrix[column], strict=True)
            ]
    return tuple(row[-1] for row in matrix)


def online_error_correct_pair(
    points: dict[int, tuple[int, int]], faults: int
) -> tuple[int, int] | None:
    """Return both constant terms after at least 2t+1 pairwise matches."""
    if len(points) < 2 * faults + 1:
        return None
    items = tuple(sorted(points.items()))
    for selected in combinations(items, faults + 1):
        xs = tuple((index, pair[0]) for index, pair in selected)
        ys = tuple((index, pair[1]) for index, pair in selected)
        try:
            first = _coefficients(xs, faults)
            second = _coefficients(ys, faults)
        except ValueError:
            continue
        matches = sum(
            evaluate(first, index) == pair[0] and evaluate(second, index) == pair[1]
            for index, pair in items
        )
        if matches >= 2 * faults + 1:
            return first[0], second[0]
    return None
