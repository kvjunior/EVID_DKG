"""Explicit finite random tapes for repeatable adversarial schedules."""

from dataclasses import dataclass
from random import Random


@dataclass
class RandomTape:
    words: tuple[int, ...]
    cursor: int = 0

    def __post_init__(self) -> None:
        if any(not isinstance(word, int) or word < 0 or word >= 1 << 64 for word in self.words):
            raise ValueError("tape words must be unsigned 64-bit integers")

    @classmethod
    def from_seed(cls, seed: int, words: int) -> "RandomTape":
        if words < 0:
            raise ValueError("word count must be nonnegative")
        rng = Random(seed)
        return cls(tuple(rng.getrandbits(64) for _ in range(words)))

    def draw_below(self, modulus: int) -> int:
        if modulus <= 0:
            raise ValueError("modulus must be positive")
        if self.cursor >= len(self.words):
            raise RuntimeError("random tape exhausted")
        word = self.words[self.cursor]
        self.cursor += 1
        return word % modulus

    def remaining(self) -> int:
        return len(self.words) - self.cursor
