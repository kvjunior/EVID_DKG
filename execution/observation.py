"""Observation views keep private, simulator and public data separate."""

from dataclasses import dataclass
from enum import Enum


class Visibility(str, Enum):
    LOCAL_PRIVATE = "local_private"
    SIMULATOR_METADATA = "simulator_metadata"
    PUBLIC_LEDGER = "public_ledger"


@dataclass(frozen=True)
class Observation:
    time: int
    kind: str
    visibility: Visibility
    actor: int | None
    payload: bytes

    def __post_init__(self) -> None:
        if self.time < 0 or not self.kind:
            raise ValueError("invalid observation")
        if not isinstance(self.payload, bytes):
            raise TypeError("observation payload must be immutable bytes")


class ObservationLog:
    def __init__(self) -> None:
        self._items: list[Observation] = []

    def append(self, observation: Observation) -> None:
        self._items.append(observation)

    @property
    def items(self) -> tuple[Observation, ...]:
        return tuple(self._items)

    def view(self, *, actor: int | None = None, simulator: bool = False) -> tuple[Observation, ...]:
        return tuple(
            item for item in self._items
            if item.visibility is Visibility.PUBLIC_LEDGER
            or (actor is not None and item.visibility is Visibility.LOCAL_PRIVATE and item.actor == actor)
            or (simulator and item.visibility is Visibility.SIMULATOR_METADATA)
        )
