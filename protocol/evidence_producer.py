"""Reviewed Dev2--Dev4 reporting controller on typed Batch 03 packets.

The controller consumes authenticated packets and public-relation results.  It
does not receive a corruption set.  Relation checkers and authentication remain
separate dependencies.
"""

from dataclasses import dataclass
from hashlib import sha256

from accountable_dkg.crypto.transcript_domains import Domain, frame
from accountable_dkg.execution.events import EventKind, LogicalEvent
from accountable_dkg.protocol.encoding import EncodingError, Reader, blob, sequence, text, u16
from accountable_dkg.protocol.messages import (
    AuthenticatedPacket, MessageKind, Packet, RandexBody, RecipientRole,
)


@dataclass(frozen=True)
class CheckedDelivery:
    authenticated: AuthenticatedPacket
    relation_valid: bool


@dataclass(frozen=True)
class ReceiptNotice:
    incident_id: bytes
    terminal: bool

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, bytes) or len(self.incident_id) != 32:
            raise ValueError("incident id must contain 32 bytes")


@dataclass(frozen=True)
class Incident:
    kind: str
    slot: tuple[bytes, bytes, MessageKind, int, object, int | None]
    source_packets: tuple[AuthenticatedPacket, ...]

    def encode(self) -> bytes:
        session_id, anchor_id, message_kind, sender, recipient_role, recipient = self.slot
        header = (
            text(self.kind, maximum=16)
            + blob(session_id, maximum=32)
            + blob(anchor_id, maximum=32)
            + u16(int(message_kind))
            + u16(sender)
            + u16(int(recipient_role))
            + u16(recipient or 0)
        )
        return header + sequence(tuple(source.raw_bytes for source in self.source_packets))

    @classmethod
    def decode(cls, raw: bytes) -> "Incident":
        reader = Reader(raw)
        kind = reader.text(maximum=16)
        session_id = reader.blob(maximum=32)
        anchor_id = reader.blob(maximum=32)
        try:
            message_kind = MessageKind(reader.u16())
            sender = reader.u16()
            recipient_role = RecipientRole(reader.u16())
        except ValueError as exc:
            raise EncodingError("invalid incident slot enum") from exc
        recipient_raw = reader.u16()
        source_packets = []
        for _ in range(reader.u16()):
            packet_raw = reader.blob()
            source_packets.append(AuthenticatedPacket(Packet.decode(packet_raw), packet_raw))
        reader.finish()
        if not source_packets:
            raise EncodingError("incident requires source packets")
        recipient = recipient_raw or None
        slot = (session_id, anchor_id, message_kind, sender, recipient_role, recipient)
        if source_packets[-1].packet.slot() != slot:
            raise EncodingError("incident header and source slot disagree")
        value = cls(kind, slot, tuple(source_packets))
        if value.encode() != raw:
            raise EncodingError("non-canonical incident")
        return value

    @property
    def incident_id(self) -> bytes:
        return sha256(frame(Domain.EVIDENCE_SIGNATURE, self.encode())).digest()


@dataclass(frozen=True)
class SubmissionIntent:
    time: int
    reporter: int
    window: int
    incident: Incident

    @property
    def payload(self) -> bytes:
        return self.incident.encode()


class ReportingController:
    def __init__(self, reporter: int, session_id: bytes) -> None:
        if reporter <= 0 or not isinstance(session_id, bytes) or len(session_id) != 32:
            raise ValueError("invalid controller context")
        self.reporter = reporter
        self.session_id = session_id
        self.anchor_id: bytes | None = None
        self.pending: list[CheckedDelivery] = []
        self.first: dict[tuple, AuthenticatedPacket] = {}
        self.candidates: dict[bytes, Incident] = {}
        self.terminal: set[bytes] = set()
        self.attempted: set[tuple[bytes, int]] = set()
        self.active_window: int | None = None
        self.last_window = -1
        self.outputs: list[SubmissionIntent] = []

    def _remember(self, kind: str, sources: tuple[AuthenticatedPacket, ...]) -> None:
        incident = Incident(kind, sources[-1].packet.slot(), sources)
        if incident.incident_id not in self.terminal:
            self.candidates.setdefault(incident.incident_id, incident)

    def _observe(self, delivery: CheckedDelivery) -> None:
        authenticated = delivery.authenticated
        packet = authenticated.packet
        if packet.anchor_id != self.anchor_id:
            return
        slot = packet.slot()
        first = self.first.get(slot)
        if first is None:
            self.first[slot] = authenticated
        elif first.packet.semantic_bytes() != packet.semantic_bytes():
            self._remember("Dev2", (first, authenticated))
        if packet.kind is MessageKind.RANDEX and isinstance(packet.body, RandexBody):
            if packet.body.recipient == self.reporter and not delivery.relation_valid:
                self._remember("Dev3", (authenticated,))
        elif packet.kind is MessageKind.KEY and not delivery.relation_valid:
            self._remember("Dev4", (authenticated,))

    def _flush(self, time: int) -> tuple[SubmissionIntent, ...]:
        if self.active_window is None:
            return ()
        new: list[SubmissionIntent] = []
        for incident_id in sorted(self.candidates):
            attempt = incident_id, self.active_window
            if incident_id not in self.terminal and attempt not in self.attempted:
                self.attempted.add(attempt)
                intent = SubmissionIntent(time, self.reporter, self.active_window, self.candidates[incident_id])
                self.outputs.append(intent)
                new.append(intent)
        return tuple(new)

    def step(self, event: LogicalEvent) -> tuple[SubmissionIntent, ...]:
        if event.kind is EventKind.PACKET_DELIVERY:
            if not isinstance(event.payload, CheckedDelivery):
                raise TypeError("packet event requires CheckedDelivery")
            packet = event.payload.authenticated.packet
            if packet.session_id != self.session_id:
                return self._flush(event.time)
            if self.anchor_id is None:
                self.pending.append(event.payload)
            else:
                self._observe(event.payload)
        elif event.kind is EventKind.ANCHOR_ACCEPTED:
            if not isinstance(event.payload, bytes) or len(event.payload) != 32:
                raise TypeError("anchor event requires a 32-byte id")
            if self.anchor_id is not None and self.anchor_id != event.payload:
                raise ValueError("accepted anchor is immutable")
            self.anchor_id = event.payload
            pending, self.pending = self.pending, []
            for delivery in pending:
                self._observe(delivery)
        elif event.kind is EventKind.WINDOW_OPEN:
            window = int(event.payload)
            if window > self.last_window:
                self.last_window = window
                self.active_window = window
        elif event.kind is EventKind.WINDOW_CLOSE:
            if int(event.payload) == self.active_window:
                self.active_window = None
        elif event.kind is EventKind.RECEIPT:
            if not isinstance(event.payload, ReceiptNotice):
                raise TypeError("receipt event requires ReceiptNotice")
            if event.payload.terminal:
                self.terminal.add(event.payload.incident_id)
        elif event.kind not in {EventKind.TICK, EventKind.SUBMISSION, EventKind.INCLUSION, EventKind.VERDICT}:
            raise ValueError("unsupported controller event")
        return self._flush(event.time)


def run_controller(events: tuple[LogicalEvent, ...], reporter: int, session_id: bytes) -> tuple[SubmissionIntent, ...]:
    controller = ReportingController(reporter, session_id)
    for event in sorted(events, key=lambda item: item.order_key):
        controller.step(event)
    return tuple(controller.outputs)


def erase_honest_deliveries(events: tuple[LogicalEvent, ...], honest_senders: frozenset[int]) -> tuple[LogicalEvent, ...]:
    """Proof projection only; the live controller never receives this set."""
    return tuple(
        event for event in events
        if not (
            event.kind is EventKind.PACKET_DELIVERY
            and isinstance(event.payload, CheckedDelivery)
            and event.payload.authenticated.packet.sender in honest_senders
        )
    )
