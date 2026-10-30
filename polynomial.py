"""Exact polynomials and uniform sampling under evaluation constraints."""

from collections.abc import Mapping, Sequence
from typing import Protocol

from .field import ToyField


class RandomSource(Protocol):
    def randrange(self, stop: int) -> int: ...


def evaluate(coefficients: Sequence[int], x: int, q: int) -> int:
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * x + coefficient) % q
    return value


def add(a: Sequence[int], b: Sequence[int], q: int) -> tuple[int, ...]:
    return tuple(((a[i] if i < len(a) else 0) +
                  (b[i] if i < len(b) else 0)) % q
                 for i in range(max(len(a), len(b))))


def multiply(a: Sequence[int], b: Sequence[int], q: int) -> tuple[int, ...]:
    result = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            result[i + j] = (result[i + j] + ai * bj) % q
    return tuple(result)


def interpolate(points: Mapping[int, int], field: ToyField) -> tuple[int, ...]:
    q = field.q
    normalized = [(x % q, y % q) for x, y in points.items()]
    if len({x for x, _ in normalized}) != len(normalized):
        raise ValueError("Evaluation indices must be distinct modulo q")
    result = (0,)
    for x, y in normalized:
        basis, denominator = (1,), 1
        for xx, _ in normalized:
            if xx != x:
                basis = multiply(basis, (-xx % q, 1), q)
                denominator = denominator * (x - xx) % q
        scalar = y * field.inverse(denominator) % q
        result = add(result, tuple(scalar * c % q for c in basis), q)
    return result


def sample_conditioned(field: ToyField, degree: int,
                       constraints: Mapping[int, int],
                       rng: RandomSource) -> tuple[int, ...]:
    """Sample f uniformly among degree-at-most-degree polynomials fitting points.

    Write f = p + Z*h, where p interpolates the constraints and Z vanishes
    on their indices. Uniform coefficients of h parameterize every solution
    exactly once. This is an ideal-distribution sampler, not a DKG protocol.
    """
    if degree < 0 or len(constraints) > degree + 1:
        raise ValueError("Invalid degree or too many constraints")
    q = field.q
    p = interpolate(constraints, field)
    z = (1,)
    for x in constraints:
        z = multiply(z, (-x % q, 1), q)
    free = degree + 1 - len(constraints)
    if free:
        h = tuple(rng.randrange(q) for _ in range(free))
        p = add(p, multiply(z, h, q), q)
    return p + (0,) * (degree + 1 - len(p))
