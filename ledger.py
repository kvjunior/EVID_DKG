"""Authenticated, bounded-capacity toy ledger; no consensus implementation.

Heights and window boundaries are integer block indices. All included writes,
including rejected calls, consume their declared model size. An author string
is trusted ledger authentication, not a simulated signature scheme.
"""

from dataclasses import dataclass

from .transcript import Record, Transcript


@dataclass(frozen=True)
class Window:
    name: str
    start: int
    end: int

    def __post_init__(self):
        if not 0 <= self.start < self.end:
            raise ValueError("Invalid window")

    def contains(self, height: int) -> bool:
        return self.start <= height < self.end


class ToyLedger:
    def __init__(self, roster: dict[int, str], capacity_bits: int):
        if (capacity_bits <= 0 or len(set(roster.values())) != len(roster)
                or any(not isinstance(a, str) or not a for a in roster.values())):
            raise ValueError("Invalid capacity or roster")
        self.roster = dict(roster)
        self.capacity_bits = capacity_bits
        self.transcript = Transcript()
        self.used: dict[int, int] = {}

    def submit(self, actor: str, kind: str, payload: dict[str, object],
               bits: int, height: int) -> int:
        if not isinstance(actor, str) or not actor:
            raise ValueError("The ledger must supply a nonempty authenticated actor")
        if not 0 < bits <= self.capacity_bits or height < 0:
            raise ValueError("Transaction must fit one block; splitting is not modeled")
        self.transcript.records.append(Record(actor, kind, dict(payload), bits, height))
        return len(self.transcript.records) - 1

    def include(self, tx: int, height: int, window: Window,
                declared_party: int) -> str:
        r = self.transcript.records[tx]
        if r.included_height is not None or height < r.submitted_height:
            raise ValueError("Invalid inclusion")
        if self.used.get(height, 0) + r.bits > self.capacity_bits:
            return "capacity_deferred"
        self.used[height] = self.used.get(height, 0) + r.bits
        r.included_height = height
        if declared_party not in self.roster or self.roster[declared_party] != r.actor:
            r.verdict = "rejected_unauthorized"
        elif not window.contains(height):
            r.verdict = "rejected_outside_window"
        else:
            r.verdict = "accepted"
        return r.verdict
