"""Capability-gated retained delivery access for proof/simulator adapters."""

from dataclasses import dataclass
from hashlib import sha256


class RetainedAccessError(PermissionError):
    pass


@dataclass(frozen=True)
class RetainedEvent:
    sequence: int
    slot: bytes
    payload: bytes


@dataclass(frozen=True)
class PublicRetainedRecord:
    sequence: int
    slot_digest: bytes
    payload_digest: bytes


class _RetainedCapability:
    pass


class RetainedEventStore:
    """The live reporting controller receives only public digests, never this capability."""

    def __init__(self) -> None:
        self._events: dict[int, RetainedEvent] = {}
        self._capability = _RetainedCapability()
        self._sealed = False

    def proof_capability(self) -> object:
        return self._capability

    def retain(self, event: RetainedEvent) -> None:
        if self._sealed or event.sequence in self._events:
            raise ValueError("retained event store is sealed or sequence is duplicated")
        if event.sequence < 0 or not isinstance(event.slot, bytes) or not isinstance(event.payload, bytes):
            raise ValueError("invalid retained event")
        self._events[event.sequence] = event

    def public_records(self) -> tuple[PublicRetainedRecord, ...]:
        return tuple(
            PublicRetainedRecord(event.sequence, sha256(event.slot).digest(), sha256(event.payload).digest())
            for event in sorted(self._events.values(), key=lambda item: item.sequence)
        )

    def read(self, capability: object) -> tuple[RetainedEvent, ...]:
        if capability is not self._capability:
            raise RetainedAccessError("retained payload access requires the proof capability")
        return tuple(sorted(self._events.values(), key=lambda item: item.sequence))

    def erase(self, capability: object) -> None:
        if capability is not self._capability:
            raise RetainedAccessError("retained erasure requires the proof capability")
        self._events.clear()
        self._sealed = True
