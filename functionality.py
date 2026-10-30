"""Keep strong joint uniformity separate from adversary-chosen corrupt shares."""

from collections.abc import Mapping
from enum import Enum

from .field import ToyField
from .parameters import ModelParameters
from .polynomial import RandomSource, sample_conditioned


class Target(str, Enum):
    UNIFORM_POLYNOMIAL = "uniform_polynomial"
    ADVERSARY_FIXED_CORRUPT_SHARES = "adversary_fixed_corrupt_shares"


def sample_ideal(parameters: ModelParameters, target: Target,
                 rng: RandomSource,
                 corrupt_values: Mapping[int, int] | None = None) -> tuple[int, ...]:
    values = dict(corrupt_values or {})
    if target is Target.UNIFORM_POLYNOMIAL and values:
        raise ValueError("The strong functionality samples corrupt shares too")
    if len(values) > parameters.t or any(not 1 <= j <= parameters.n for j in values):
        raise ValueError("Invalid corrupt-party constraints")
    if not isinstance(target, Target):
        raise TypeError("Specify an explicit Target")
    return sample_conditioned(ToyField(parameters.q), parameters.degree, values, rng)
