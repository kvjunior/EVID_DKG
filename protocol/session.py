"""Authorized roster and canonical EVID-DKG session context."""

from dataclasses import dataclass
from hashlib import sha256

from .encoding import EncodingError, Reader, blob, sequence, text, u16, u32, u64


SESSION_TAG = b"EVID-DKG/session/v1\x00"


@dataclass(frozen=True, order=True)
class Participant:
    index: int
    verification_key: bytes

    def __post_init__(self) -> None:
        if not 1 <= self.index <= 0xFFFF:
            raise EncodingError("participant index must be in [1, 65535]")
        if not isinstance(self.verification_key, bytes) or not self.verification_key:
            raise EncodingError("verification key must be non-empty immutable bytes")
        if len(self.verification_key) > 4096:
            raise EncodingError("verification key is too large")

    def encode(self) -> bytes:
        return u16(self.index) + blob(self.verification_key, maximum=4096)


@dataclass(frozen=True)
class Roster:
    participants: tuple[Participant, ...]

    def __post_init__(self) -> None:
        if not 2 <= len(self.participants) <= 0xFFFF:
            raise EncodingError("roster size must be in [2, 65535]")
        indices = tuple(p.index for p in self.participants)
        if indices != tuple(sorted(indices)) or len(set(indices)) != len(indices):
            raise EncodingError("participants must have unique increasing indices")
        keys = tuple(p.verification_key for p in self.participants)
        if len(set(keys)) != len(keys):
            raise EncodingError("verification keys must be unique")

    def encode(self) -> bytes:
        return sequence(tuple(p.encode() for p in self.participants))

    @property
    def roster_id(self) -> bytes:
        return sha256(b"EVID-DKG/roster/v1\x00" + self.encode()).digest()

    def participant(self, index: int) -> Participant | None:
        return next((p for p in self.participants if p.index == index), None)


@dataclass(frozen=True)
class SessionContext:
    protocol: str
    version: int
    epoch: int
    threshold: int
    field_modulus: int
    nonce: bytes
    roster: Roster

    def __post_init__(self) -> None:
        text(self.protocol, maximum=32)
        if not 1 <= self.version <= 0xFFFF:
            raise EncodingError("version must be in [1, 65535]")
        if not 0 <= self.epoch < 1 << 64:
            raise EncodingError("epoch does not fit u64")
        if not 1 <= self.threshold < len(self.roster.participants):
            raise EncodingError("threshold must be positive and smaller than roster size")
        if not 3 <= self.field_modulus < 1 << 256:
            raise EncodingError("field modulus is outside the supported scalar range")
        if not isinstance(self.nonce, bytes) or not 16 <= len(self.nonce) <= 64:
            raise EncodingError("session nonce must contain 16..64 immutable bytes")

    def encode(self) -> bytes:
        modulus = self.field_modulus.to_bytes(32, "big")
        return (
            text(self.protocol, maximum=32)
            + u16(self.version)
            + u64(self.epoch)
            + u16(self.threshold)
            + blob(modulus, maximum=32)
            + blob(self.nonce, maximum=64)
            + blob(self.roster.encode())
        )

    @property
    def session_id(self) -> bytes:
        return sha256(SESSION_TAG + self.encode()).digest()

    @classmethod
    def decode(cls, raw: bytes) -> "SessionContext":
        reader = Reader(raw)
        protocol = reader.text(maximum=32)
        version = reader.u16()
        epoch = reader.u64()
        threshold = reader.u16()
        modulus_raw = reader.blob(maximum=32)
        if len(modulus_raw) != 32:
            raise EncodingError("field modulus must use the fixed 32-byte representation")
        nonce = reader.blob(maximum=64)
        roster_reader = Reader(reader.blob())
        count = roster_reader.u16()
        participants: list[Participant] = []
        for _ in range(count):
            item = Reader(roster_reader.blob())
            participants.append(Participant(item.u16(), item.blob(maximum=4096)))
            item.finish()
        roster_reader.finish()
        reader.finish()
        return cls(protocol, version, epoch, threshold, int.from_bytes(modulus_raw, "big"), nonce, Roster(tuple(participants)))
