"""Canonical RANDEX/KEY packets and authentication-before-attribution."""

from dataclasses import dataclass
from enum import IntEnum

from accountable_dkg.crypto.interfaces import CheckCode, CheckResult, SignatureProvider
from accountable_dkg.crypto.transcript_domains import Domain, frame

from .anchors import AnchorSet
from .encoding import EncodingError, Reader, blob, u8, u16
from .session import SessionContext


WIRE_VERSION = 1
MAX_CRYPTO_OBJECT = 1 << 16
MAX_SIGNATURE = 1 << 14


class MessageKind(IntEnum):
    RANDEX = 1
    KEY = 2


class RecipientRole(IntEnum):
    PRIVATE = 1
    BROADCAST = 2


@dataclass(frozen=True)
class RandexBody:
    recipient: int
    fragment: bytes
    commitment_column: bytes
    proof: bytes

    def __post_init__(self) -> None:
        if not 1 <= self.recipient <= 0xFFFF:
            raise EncodingError("RANDEX recipient is invalid")
        for name, value in (("fragment", self.fragment), ("commitment", self.commitment_column), ("proof", self.proof)):
            if not isinstance(value, bytes) or not value or len(value) > MAX_CRYPTO_OBJECT:
                raise EncodingError(f"RANDEX {name} is outside its byte limit")

    def encode(self) -> bytes:
        return u16(self.recipient) + blob(self.fragment, maximum=MAX_CRYPTO_OBJECT) + blob(self.commitment_column, maximum=MAX_CRYPTO_OBJECT) + blob(self.proof, maximum=MAX_CRYPTO_OBJECT)

    @classmethod
    def decode(cls, reader: Reader) -> "RandexBody":
        return cls(reader.u16(), reader.blob(maximum=MAX_CRYPTO_OBJECT), reader.blob(maximum=MAX_CRYPTO_OBJECT), reader.blob(maximum=MAX_CRYPTO_OBJECT))

    def semantic_bytes(self) -> bytes:
        return self.encode()


@dataclass(frozen=True)
class KeyBody:
    public_x: bytes
    public_y: bytes
    proof: bytes

    def __post_init__(self) -> None:
        for name, value in (("public_x", self.public_x), ("public_y", self.public_y), ("proof", self.proof)):
            if not isinstance(value, bytes) or not value or len(value) > MAX_CRYPTO_OBJECT:
                raise EncodingError(f"KEY {name} is outside its byte limit")

    def encode(self) -> bytes:
        return blob(self.public_x, maximum=MAX_CRYPTO_OBJECT) + blob(self.public_y, maximum=MAX_CRYPTO_OBJECT) + blob(self.proof, maximum=MAX_CRYPTO_OBJECT)

    @classmethod
    def decode(cls, reader: Reader) -> "KeyBody":
        return cls(reader.blob(maximum=MAX_CRYPTO_OBJECT), reader.blob(maximum=MAX_CRYPTO_OBJECT), reader.blob(maximum=MAX_CRYPTO_OBJECT))

    def semantic_bytes(self) -> bytes:
        # Randomized encodings proving the same pair are not equivocation.
        return blob(self.public_x, maximum=MAX_CRYPTO_OBJECT) + blob(self.public_y, maximum=MAX_CRYPTO_OBJECT)


Body = RandexBody | KeyBody


@dataclass(frozen=True)
class Packet:
    session_id: bytes
    anchor_id: bytes
    kind: MessageKind
    sender: int
    body: Body
    signature: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, bytes) or len(self.session_id) != 32:
            raise EncodingError("session id must contain 32 bytes")
        if not isinstance(self.anchor_id, bytes) or len(self.anchor_id) != 32:
            raise EncodingError("anchor id must contain 32 bytes")
        if not isinstance(self.kind, MessageKind):
            raise EncodingError("unknown packet kind")
        if not 1 <= self.sender <= 0xFFFF:
            raise EncodingError("sender is invalid")
        if self.kind is MessageKind.RANDEX and not isinstance(self.body, RandexBody):
            raise EncodingError("RANDEX packet has the wrong body type")
        if self.kind is MessageKind.KEY and not isinstance(self.body, KeyBody):
            raise EncodingError("KEY packet has the wrong body type")
        if not isinstance(self.signature, bytes) or len(self.signature) > MAX_SIGNATURE:
            raise EncodingError("signature is outside its byte limit")

    @property
    def recipient_role(self) -> RecipientRole:
        return RecipientRole.PRIVATE if self.kind is MessageKind.RANDEX else RecipientRole.BROADCAST

    @property
    def recipient(self) -> int | None:
        return self.body.recipient if isinstance(self.body, RandexBody) else None

    def unsigned_encoding(self) -> bytes:
        return (
            u8(WIRE_VERSION)
            + blob(self.session_id, maximum=32)
            + blob(self.anchor_id, maximum=32)
            + u8(int(self.kind))
            + u16(self.sender)
            + u8(int(self.recipient_role))
            + u16(self.recipient or 0)
            + blob(self.body.encode(), maximum=MAX_CRYPTO_OBJECT * 3 + 16)
        )

    def signed_statement(self) -> bytes:
        domain = Domain.RANDEX_SIGNATURE if self.kind is MessageKind.RANDEX else Domain.KEY_SIGNATURE
        return frame(domain, self.unsigned_encoding())

    def encode(self) -> bytes:
        return self.unsigned_encoding() + blob(self.signature, maximum=MAX_SIGNATURE)

    def with_signature(self, signature: bytes) -> "Packet":
        return Packet(self.session_id, self.anchor_id, self.kind, self.sender, self.body, signature)

    def sign(self, provider: SignatureProvider, signing_key: bytes) -> "Packet":
        return self.with_signature(provider.sign(signing_key, self.signed_statement()))

    def slot(self) -> tuple[bytes, bytes, MessageKind, int, RecipientRole, int | None]:
        return (self.session_id, self.anchor_id, self.kind, self.sender, self.recipient_role, self.recipient)

    def semantic_bytes(self) -> bytes:
        return self.body.semantic_bytes()

    def semantically_conflicts(self, other: "Packet") -> bool:
        return self.slot() == other.slot() and self.semantic_bytes() != other.semantic_bytes()

    @classmethod
    def decode(cls, raw: bytes) -> "Packet":
        reader = Reader(raw)
        if reader.u8() != WIRE_VERSION:
            raise EncodingError("unsupported wire version")
        session_id = reader.blob(maximum=32)
        anchor_id = reader.blob(maximum=32)
        try:
            kind = MessageKind(reader.u8())
        except ValueError as exc:
            raise EncodingError("unknown packet kind") from exc
        sender = reader.u16()
        try:
            role = RecipientRole(reader.u8())
        except ValueError as exc:
            raise EncodingError("unknown recipient role") from exc
        recipient = reader.u16()
        body_reader = Reader(reader.blob(maximum=MAX_CRYPTO_OBJECT * 3 + 16))
        if kind is MessageKind.RANDEX:
            if role is not RecipientRole.PRIVATE or recipient == 0:
                raise EncodingError("RANDEX must bind a private recipient")
            body = RandexBody.decode(body_reader)
            if body.recipient != recipient:
                raise EncodingError("RANDEX header and body recipients disagree")
        else:
            if role is not RecipientRole.BROADCAST or recipient != 0:
                raise EncodingError("KEY must use the broadcast role")
            body = KeyBody.decode(body_reader)
        body_reader.finish()
        signature = reader.blob(maximum=MAX_SIGNATURE)
        reader.finish()
        return cls(session_id, anchor_id, kind, sender, body, signature)


@dataclass(frozen=True)
class AuthenticatedPacket:
    packet: Packet
    raw_bytes: bytes


@dataclass(frozen=True)
class AuthenticationResult:
    result: CheckResult
    authenticated: AuthenticatedPacket | None = None


def authenticate_packet(
    raw_bytes: bytes,
    session: SessionContext,
    anchors: AnchorSet,
    provider: SignatureProvider,
) -> AuthenticationResult:
    try:
        packet = Packet.decode(raw_bytes)
    except EncodingError as exc:
        return AuthenticationResult(CheckResult(CheckCode.MALFORMED, str(exc)))
    if packet.session_id != session.session_id:
        return AuthenticationResult(CheckResult(CheckCode.MALFORMED, "wrong session"))
    participant = session.roster.participant(packet.sender)
    if participant is None:
        return AuthenticationResult(CheckResult(CheckCode.MALFORMED, "unknown sender"))
    anchor = anchors.get(packet.anchor_id)
    if anchor is None or anchor.metadata.session_id != session.session_id:
        return AuthenticationResult(CheckResult(CheckCode.INVALID_ANCHOR, "unaccepted anchor"))
    result = provider.verify(participant.verification_key, packet.signed_statement(), packet.signature)
    if not result.accepted:
        return AuthenticationResult(result)
    return AuthenticationResult(CheckResult.accept(), AuthenticatedPacket(packet, raw_bytes))


@dataclass(frozen=True)
class PublishedPayload:
    """Immutable ledger-facing payload; callers cannot mutate parsed fields."""

    raw_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw_bytes, bytes):
            raise EncodingError("published payload must be immutable bytes")
