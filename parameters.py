from dataclasses import dataclass

from .field import ToyField


@dataclass(frozen=True)
class ModelParameters:
    n: int = 4
    t: int = 1
    degree: int = 2
    q: int = 7

    def __post_init__(self):
        ToyField(self.q)
        if self.t < 0 or self.n < 3 * self.t + 1:
            raise ValueError("Initial model requires n >= 3t+1")
        if not self.t <= self.degree <= self.n - self.t - 1:
            raise ValueError("Require t <= degree <= n-t-1")
        if self.q <= self.n:
            raise ValueError("Party indices and zero must be distinct field points")
