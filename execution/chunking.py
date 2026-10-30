"""Deterministic evidence chunks and whole-upload completion checks."""

from dataclasses import dataclass
from hashlib import sha256

from accountable_dkg.crypto.transcript_domains import Domain, frame
from accountable_dkg.protocol.encoding import EncodingError, Reader, blob, u16


@dataclass(frozen=True)
class EvidenceChunk:
    upload_id: bytes
    index: int
    count: int
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.upload_id, bytes) or len(self.upload_id) != 32:
            raise ValueError("upload id must contain 32 bytes")
        if not 1 <= self.count <= 0xFFFF or not 0 <= self.index < self.count:
            raise ValueError("invalid chunk index/count")
        if not isinstance(self.payload, bytes) or not self.payload:
            raise ValueError("chunk payload must be nonempty immutable bytes")

    def encode(self) -> bytes:
        return blob(self.upload_id, maximum=32) + u16(self.index) + u16(self.count) + blob(self.payload)

    @classmethod
    def decode(cls, raw: bytes) -> "EvidenceChunk":
        reader = Reader(raw)
        value = cls(reader.blob(maximum=32), reader.u16(), reader.u16(), reader.blob())
        reader.finish()
        return value


def chunk_evidence(payload: bytes, maximum_payload: int) -> tuple[EvidenceChunk, ...]:
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("evidence must be nonempty immutable bytes")
    if maximum_payload <= 0:
        raise ValueError("maximum payload must be positive")
    count = (len(payload) + maximum_payload - 1) // maximum_payload
    if count > 0xFFFF:
        raise ValueError("evidence requires too many chunks")
    upload_id = sha256(frame(Domain.HASH_REFERENCE, payload)).digest()
    return tuple(
        EvidenceChunk(upload_id, index, count, payload[index * maximum_payload:(index + 1) * maximum_payload])
        for index in range(count)
    )


class ChunkAssembler:
    def __init__(self, upload_id: bytes, count: int) -> None:
        if len(upload_id) != 32 or not 1 <= count <= 0xFFFF:
            raise ValueError("invalid upload metadata")
        self.upload_id = upload_id
        self.count = count
        self._chunks: dict[int, bytes] = {}

    def add(self, chunk: EvidenceChunk) -> bool:
        if chunk.upload_id != self.upload_id or chunk.count != self.count:
            raise ValueError("chunk belongs to another upload")
        existing = self._chunks.get(chunk.index)
        if existing is not None and existing != chunk.payload:
            raise ValueError("conflicting duplicate chunk")
        is_new = existing is None
        self._chunks[chunk.index] = chunk.payload
        return is_new

    @property
    def complete(self) -> bool:
        return len(self._chunks) == self.count

    def assemble(self) -> bytes:
        if not self.complete:
            raise RuntimeError("upload is incomplete")
        payload = b"".join(self._chunks[index] for index in range(self.count))
        if sha256(frame(Domain.HASH_REFERENCE, payload)).digest() != self.upload_id:
            raise RuntimeError("assembled upload hash mismatch")
        return payload


def whole_upload_by_deadline(chunks: tuple[EvidenceChunk, ...], included: dict[int, int], deadline: int) -> bool:
    """True only when every chunk is included strictly before the deadline."""
    return bool(chunks) and all(index in included and included[index] < deadline for index in range(len(chunks)))
