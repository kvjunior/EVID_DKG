"""Stable event scheduler; it supplies ordering, not a network guarantee."""

from heapq import heappop, heappush

from .events import EventKind, EventSource, LogicalEvent


class EventScheduler:
    def __init__(self) -> None:
        self._next_sequence = 0
        self._queue: list[tuple[int, int, LogicalEvent]] = []

    def schedule(self, time: int, source: EventSource, kind: EventKind, payload=None) -> LogicalEvent:
        event = LogicalEvent(time, self._next_sequence, source, kind, payload)
        self._next_sequence += 1
        heappush(self._queue, (event.time, event.sequence, event))
        return event

    def drain(self) -> tuple[LogicalEvent, ...]:
        result: list[LogicalEvent] = []
        while self._queue:
            result.append(heappop(self._queue)[2])
        return tuple(result)

    def replay(self, handler) -> tuple[object, ...]:
        outputs: list[object] = []
        for event in self.drain():
            value = handler(event)
            if value is not None:
                if isinstance(value, tuple):
                    outputs.extend(value)
                else:
                    outputs.append(value)
        return tuple(outputs)
