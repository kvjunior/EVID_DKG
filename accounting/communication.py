"""Separate counters for submitted, included, rejected, read and private data."""

from dataclasses import asdict, dataclass


@dataclass
class CommunicationAccount:
    submitted_bytes: int = 0
    included_bytes: int = 0
    rejected_included_bytes: int = 0
    read_bytes: int = 0
    private_bytes: int = 0

    def _charge(self, field: str, amount: int) -> None:
        if not isinstance(amount, int) or amount < 0:
            raise ValueError("communication charge must be a nonnegative integer")
        setattr(self, field, getattr(self, field) + amount)

    def charge_submitted(self, amount: int) -> None:
        self._charge("submitted_bytes", amount)

    def charge_included(self, amount: int, *, rejected: bool = False) -> None:
        self._charge("included_bytes", amount)
        if rejected:
            self._charge("rejected_included_bytes", amount)

    def charge_read(self, amount: int) -> None:
        self._charge("read_bytes", amount)

    def charge_private(self, amount: int) -> None:
        self._charge("private_bytes", amount)

    def snapshot(self) -> dict[str, int]:
        return asdict(self)
