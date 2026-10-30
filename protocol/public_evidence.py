"""Self-describing public evidence envelopes for finalized-ledger judging."""

from dataclasses import dataclass
from enum import IntEnum

from .encoding import EncodingError, Reader, blob, u8
from .evidence_producer import Incident
from .recovery import Dev1Incident


EVIDENCE_VERSION = 1


class PublicEvidenceKind(IntEnum):
    DEV1 = 1
    PACKET = 2


@dataclass(frozen=True)
class PublicEvidence:
    kind: PublicEvidenceKind
    incident_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PublicEvidenceKind):
            raise EncodingError("unknown public evidence kind")
        if not isinstance(self.incident_bytes, bytes) or not self.incident_bytes:
            raise EncodingError("public evidence incident must be nonempty bytes")

    def encode(self) -> bytes:
        return u8(EVIDENCE_VERSION) + u8(int(self.kind)) + blob(self.incident_bytes)

    @classmethod
    def decode(cls, raw: bytes) -> "PublicEvidence":
        reader = Reader(raw)
        if reader.u8() != EVIDENCE_VERSION:
            raise EncodingError("unsupported public evidence version")
        try:
            kind = PublicEvidenceKind(reader.u8())
        except ValueError as exc:
            raise EncodingError("unknown public evidence kind") from exc
        value = cls(kind, reader.blob())
        reader.finish()
        if value.encode() != raw:
            raise EncodingError("non-canonical public evidence")
        return value

    @classmethod
    def dev1(cls, incident: Dev1Incident) -> "PublicEvidence":
        return cls(PublicEvidenceKind.DEV1, incident.encode())

    @classmethod
    def packet(cls, incident: Incident) -> "PublicEvidence":
        return cls(PublicEvidenceKind.PACKET, incident.encode())
