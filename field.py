"""Small-prime arithmetic for exact model enumeration, not cryptography."""

from dataclasses import dataclass
from math import isqrt


@dataclass(frozen=True)
class ToyField:
    q: int

    def __post_init__(self):
        if not 2 <= self.q <= 65521:
            raise ValueError("This model supports small primes up to 65521 only")
        if any(self.q % d == 0 for d in range(2, isqrt(self.q) + 1)):
            raise ValueError("q must be prime")

    def inverse(self, x: int) -> int:
        return pow(x % self.q, -1, self.q)
