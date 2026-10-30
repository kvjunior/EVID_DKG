"""Typed immutable events for deterministic joint replay."""

from dataclasses import dataclass
from enum import Enum
class EventSource(str, Enum):
    NETWORK = "network"
    LOCAL = "local"
    LEDGER = "ledger"
    TIMER = "timer"


class EventKind(str, Enum):
    PACKET_DELIVERY = "packet_delivery"
    ANCHOR_ACCEPTED = "anchor_accepted"
    WINDOW_OPEN = "window_open"
    WINDOW_CLOSE = "window_close"
    SUBMISSION = "submission"
    INCLUSION = "inclusion"
    RECEIPT = "receipt"
    VERDICT = "verdict"
    TICK = "tick"
    ACSS_DELIVERY = "acss_delivery"
    RECOVERY_RELEASE = "recovery_release"


@dataclass(frozen=True)
class LogicalEvent:
    time: int
    sequence: int
    source: EventSource
    kind: EventKind
    payload: object = None

    def __post_init__(self) -> None:
        if self.time < 0 or self.sequence < 0:
            raise ValueError("event time and sequence must be nonnegative")
        if not isinstance(self.source, EventSource) or not isinstance(self.kind, EventKind):
            raise TypeError("event source and kind must be typed enums")

    @property
    def order_key(self) -> tuple[int, int]:
        return self.time, self.sequence
