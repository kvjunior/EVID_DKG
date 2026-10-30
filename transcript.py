"""Public payloads are retained even when validation later rejects a write."""

from dataclasses import dataclass, field


@dataclass
class Record:
    actor: str
    kind: str
    payload: dict[str, object]
    bits: int
    submitted_height: int
    included_height: int | None = None
    verdict: str = "pending"


@dataclass
class Transcript:
    # Conservative model: submitted payloads are visible to the adversary.
    records: list[Record] = field(default_factory=list)
    read_bits: dict[str, int] = field(default_factory=dict)

    def public_payloads(self) -> list[dict[str, object]]:
        return [dict(r.payload) for r in self.records]

    def charge_read(self, party: str, bits: int) -> None:
        if bits < 0:
            raise ValueError("Read cost cannot be negative")
        self.read_bits[party] = self.read_bits.get(party, 0) + bits

    def costs(self) -> dict[str, int]:
        return {
            "submitted_bits": sum(r.bits for r in self.records),
            "included_bits": sum(r.bits for r in self.records if r.included_height is not None),
            "accepted_bits": sum(r.bits for r in self.records if r.verdict == "accepted"),
            "total_read_bits": sum(self.read_bits.values()),
        }
