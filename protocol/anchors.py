"""Anchor references and the explicit acceptance boundary."""

from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha256

from accountable_dkg.crypto.interfaces import AnchorVerifier, CheckCode, CheckResult
from accountable_dkg.crypto.transcript_domains import Domain, frame

from .encoding import EncodingError, Reader, blob, u8, u64


class AnchorKind(IntEnum):
    ROSTER = 1
    DEALING = 2
    AGREEMENT = 3
    FINALIZATION = 4


@dataclass(frozen=True)
class AnchorMetadata:
    session_id: bytes
    kind: AnchorKind
    sequence: int
    payload_digest: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, bytes) or len(self.session_id) != 32:
            raise EncodingError("session id must contain 32 bytes")
        if not isinstance(self.kind, AnchorKind):
            raise EncodingError("unknown anchor kind")
        if not 0 <= self.sequence < 1 << 64:
            raise EncodingError("anchor sequence does not fit u64")
        if not isinstance(self.payload_digest, bytes) or len(self.payload_digest) != 32:
            raise EncodingError("payload digest must contain 32 bytes")

    def encode(self) -> bytes:
        return blob(self.session_id, maximum=32) + u8(int(self.kind)) + u64(self.sequence) + blob(self.payload_digest, maximum=32)

    @property
    def reference_id(self) -> bytes:
        return sha256(frame(Domain.ANCHOR_REFERENCE, self.encode())).digest()

    @classmethod
    def decode(cls, raw: bytes) -> "AnchorMetadata":
        reader = Reader(raw)
        session_id = reader.blob(maximum=32)
        try:
            kind = AnchorKind(reader.u8())
        except ValueError as exc:
            raise EncodingError("unknown anchor kind") from exc
        sequence = reader.u64()
        payload_digest = reader.blob(maximum=32)
        reader.finish()
        return cls(session_id, kind, sequence, payload_digest)


@dataclass(frozen=True)
class AcceptedAnchor:
    """Opaque acceptance token produced only after verifier success."""

    metadata: AnchorMetadata
    verification_record: bytes


@dataclass(frozen=True)
class AnchorAcceptance:
    result: CheckResult
    anchor: AcceptedAnchor | None = None


def accept_anchor(
    metadata: AnchorMetadata,
    supporting_bytes: bytes,
    verifier: AnchorVerifier,
) -> AnchorAcceptance:
    result = verifier.verify_anchor(metadata.encode(), supporting_bytes)
    if not result.accepted:
        return AnchorAcceptance(result)
    record = sha256(frame(Domain.HASH_REFERENCE, metadata.encode(), supporting_bytes)).digest()
    return AnchorAcceptance(CheckResult(CheckCode.ACCEPTED), AcceptedAnchor(metadata, record))


class AnchorSet:
    def __init__(self, anchors: tuple[AcceptedAnchor, ...] = ()) -> None:
        table: dict[bytes, AcceptedAnchor] = {}
        for anchor in anchors:
            ref = anchor.metadata.reference_id
            if ref in table:
                raise EncodingError("duplicate accepted anchor")
            table[ref] = anchor
        self._table = table

    def get(self, reference_id: bytes) -> AcceptedAnchor | None:
        return self._table.get(reference_id)

    def add(self, anchor: AcceptedAnchor) -> None:
        reference = anchor.metadata.reference_id
        if reference in self._table:
            raise EncodingError("duplicate accepted anchor")
        self._table[reference] = anchor
