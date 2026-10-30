"""Batch 06 ACSS dealing core with per-instance encrypted shares.

RBC totality and the CCS'21 fallback network are external assumptions.  This
module implements the canonical dealing, Pedersen relation and recipient-local
validation used by those protocols.
"""

from dataclasses import dataclass
from hashlib import sha256
from secrets import randbelow, token_bytes

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.interfaces import CheckResult, SignatureProvider
from accountable_dkg.crypto.pedersen import (
    Q, SCALAR_BYTES, PedersenPolynomialCommitment, decode_scalar, encode_scalar, evaluate,
)
from accountable_dkg.crypto.transcript_domains import Domain, frame

from .encoding import EncodingError, Reader, blob, sequence, u16


def _share_plaintext(share: int, blinding: int) -> bytes:
    return encode_scalar(share) + encode_scalar(blinding)


def _decode_share(raw: bytes) -> tuple[int, int]:
    if len(raw) != 2 * SCALAR_BYTES:
        raise EncodingError("ACSS share plaintext must contain two fixed scalars")
    try:
        return decode_scalar(raw[:SCALAR_BYTES]), decode_scalar(raw[SCALAR_BYTES:])
    except ValueError as exc:
        raise EncodingError(str(exc)) from exc


@dataclass(frozen=True)
class RecoveryPublicKey:
    recipient: int
    key: bytes

    def encode(self) -> bytes:
        if not 1 <= self.recipient <= 0xFFFF or len(self.key) != 32:
            raise EncodingError("invalid scoped recovery public key")
        return u16(self.recipient) + self.key


@dataclass(frozen=True)
class EncryptedShare:
    recipient: int
    ciphertext: bytes

    def encode(self) -> bytes:
        return u16(self.recipient) + blob(self.ciphertext)


@dataclass(frozen=True)
class AcssDealing:
    session_id: bytes
    dealer: int
    threshold: int
    nonce: bytes
    commitment: PedersenPolynomialCommitment
    recovery_keys: tuple[RecoveryPublicKey, ...]
    encrypted_shares: tuple[EncryptedShare, ...]

    def __post_init__(self) -> None:
        if len(self.session_id) != 32 or not 1 <= self.dealer <= 0xFFFF:
            raise EncodingError("invalid ACSS session or dealer")
        if self.threshold < 1 or self.commitment.degree != self.threshold:
            raise EncodingError("ACSS threshold and commitment degree disagree")
        if not 16 <= len(self.nonce) <= 32:
            raise EncodingError("ACSS nonce must contain 16..32 bytes")
        key_recipients = tuple(item.recipient for item in self.recovery_keys)
        share_recipients = tuple(item.recipient for item in self.encrypted_shares)
        if key_recipients != tuple(sorted(set(key_recipients))) or key_recipients != share_recipients:
            raise EncodingError("ACSS keys and ciphertexts require the same ordered recipients")
        if len(key_recipients) < self.threshold + 1:
            raise EncodingError("ACSS dealing has too few recipients")
        for item in self.recovery_keys:
            item.encode()
        if any(not item.ciphertext for item in self.encrypted_shares):
            raise EncodingError("ACSS ciphertext cannot be empty")

    @property
    def instance_id(self) -> bytes:
        header = (
            self.session_id + u16(self.dealer) + u16(self.threshold) + blob(self.nonce, maximum=32)
            + sequence(self.commitment.elements)
            + sequence(tuple(item.encode() for item in self.recovery_keys))
        )
        return sha256(frame(Domain.ACSS_INSTANCE, header)).digest()

    def context(self, recipient: int) -> bytes:
        return frame(Domain.ACSS_ENCRYPTION, self.session_id, self.instance_id, u16(self.dealer), u16(recipient))

    @property
    def dealing_id(self) -> bytes:
        return sha256(frame(Domain.ACSS_DEALING, self.encode())).digest()

    def encode(self) -> bytes:
        return (
            self.session_id + u16(self.dealer) + u16(self.threshold) + blob(self.nonce, maximum=32)
            + sequence(self.commitment.elements)
            + sequence(tuple(item.encode() for item in self.recovery_keys))
            + sequence(tuple(item.encode() for item in self.encrypted_shares))
        )

    @classmethod
    def decode(cls, raw: bytes) -> "AcssDealing":
        reader = Reader(raw)
        session_id = reader.fixed(32)
        dealer = reader.u16()
        threshold = reader.u16()
        nonce = reader.blob(maximum=32)
        commitment = PedersenPolynomialCommitment(
            tuple(reader.blob() for _ in range(reader.u16()))
        )
        recovery_keys = []
        for _ in range(reader.u16()):
            item = Reader(reader.blob())
            recovery_keys.append(RecoveryPublicKey(item.u16(), item.fixed(32)))
            item.finish()
        encrypted_shares = []
        for _ in range(reader.u16()):
            item = Reader(reader.blob())
            encrypted_shares.append(EncryptedShare(item.u16(), item.blob()))
            item.finish()
        reader.finish()
        value = cls(
            session_id, dealer, threshold, nonce, commitment,
            tuple(recovery_keys), tuple(encrypted_shares),
        )
        if value.encode() != raw:
            raise EncodingError("non-canonical ACSS dealing")
        return value

    def public_key(self, recipient: int) -> bytes | None:
        return next((item.key for item in self.recovery_keys if item.recipient == recipient), None)

    def ciphertext(self, recipient: int) -> bytes | None:
        return next((item.ciphertext for item in self.encrypted_shares if item.recipient == recipient), None)


@dataclass(frozen=True)
class SignedAcssDealing:
    dealing: AcssDealing
    signature: bytes

    def signed_statement(self) -> bytes:
        return frame(Domain.ACSS_DEALING, self.dealing.encode())

    def encode(self) -> bytes:
        return blob(self.dealing.encode()) + blob(self.signature, maximum=1 << 14)

    @classmethod
    def decode(cls, raw: bytes) -> "SignedAcssDealing":
        reader = Reader(raw)
        dealing = AcssDealing.decode(reader.blob())
        signature = reader.blob(maximum=1 << 14)
        reader.finish()
        value = cls(dealing, signature)
        if value.encode() != raw:
            raise EncodingError("non-canonical signed ACSS dealing")
        return value

    @classmethod
    def sign(cls, dealing: AcssDealing, provider: SignatureProvider, signing_key: bytes) -> "SignedAcssDealing":
        unsigned = cls(dealing, b"")
        return cls(dealing, provider.sign(signing_key, unsigned.signed_statement()))


@dataclass(frozen=True)
class AuthenticatedAcssDealing:
    signed: SignedAcssDealing
    raw_bytes: bytes


@dataclass(frozen=True)
class DealingAuthentication:
    result: CheckResult
    authenticated: AuthenticatedAcssDealing | None = None


def authenticate_dealing(
    signed: SignedAcssDealing, provider: SignatureProvider, verification_key: bytes
) -> DealingAuthentication:
    result = provider.verify(verification_key, signed.signed_statement(), signed.signature)
    if not result.accepted:
        return DealingAuthentication(result)
    return DealingAuthentication(result, AuthenticatedAcssDealing(signed, signed.encode()))


@dataclass(frozen=True)
class ShareCheck:
    recipient: int
    share: int | None
    blinding_share: int | None
    valid: bool
    reason: str


class RecoveryKeyUseRegistry:
    """Prevents a revealed recovery key from opening any second dealing."""

    def __init__(self) -> None:
        self._uses: dict[bytes, bytes] = {}
        self._scopes: set[bytes] = set()

    def claim(self, scope: bytes, keys: dict[int, bytes]) -> None:
        if scope in self._scopes:
            raise ValueError("ACSS recovery-key scope is already claimed")
        values = tuple(keys.values())
        if any(not isinstance(key, bytes) or len(key) != 32 for key in values):
            raise ValueError("recovery public keys must contain 32 bytes")
        if len(set(values)) != len(values):
            raise ValueError("one recovery public key cannot serve two recipients")
        reused = [key for key in values if key in self._uses and self._uses[key] != scope]
        if reused:
            raise ValueError("recovery public key is already bound to another dealing")
        for key in values:
            self._uses[key] = scope
        self._scopes.add(scope)


def create_dealing(
    session_id: bytes,
    dealer: int,
    threshold: int,
    secret: int,
    recovery_public_keys: dict[int, bytes],
    key_registry: RecoveryKeyUseRegistry,
    *,
    nonce: bytes | None = None,
    coefficients: tuple[int, ...] | None = None,
    blindings: tuple[int, ...] | None = None,
) -> AcssDealing:
    if len(session_id) != 32 or not 1 <= dealer <= 0xFFFF or threshold < 1:
        raise ValueError("invalid ACSS context")
    recipients = tuple(sorted(recovery_public_keys))
    if len(recipients) < threshold + 1 or recipients != tuple(range(1, len(recipients) + 1)):
        raise ValueError("recipients must be consecutive and exceed the threshold")
    values = coefficients or (secret % Q,) + tuple(randbelow(Q) for _ in range(threshold))
    masks = blindings or tuple(randbelow(Q) for _ in range(threshold + 1))
    if len(values) != threshold + 1 or len(masks) != threshold + 1 or values[0] != secret % Q:
        raise ValueError("polynomial inputs do not match threshold or secret")
    dealing_nonce = nonce or token_bytes(16)
    if not 16 <= len(dealing_nonce) <= 32:
        raise ValueError("ACSS nonce must contain 16..32 bytes")
    scope = frame(Domain.ACSS_INSTANCE, session_id, u16(dealer), dealing_nonce)
    key_registry.claim(scope, recovery_public_keys)
    commitment = PedersenPolynomialCommitment.commit(values, masks)
    keys = tuple(RecoveryPublicKey(i, recovery_public_keys[i]) for i in recipients)
    placeholders = tuple(EncryptedShare(i, b"\x00") for i in recipients)
    shell = AcssDealing(session_id, dealer, threshold, dealing_nonce, commitment, keys, placeholders)
    encryption = HybridEncryptionProvider()
    encrypted = tuple(
        EncryptedShare(i, encryption.encrypt(
            recovery_public_keys[i], _share_plaintext(evaluate(values, i), evaluate(masks, i)), shell.context(i)
        )) for i in recipients
    )
    return AcssDealing(session_id, dealer, threshold, shell.nonce, commitment, keys, encrypted)


def inspect_share(dealing: AcssDealing, recipient: int, recovery_private_key: bytes) -> ShareCheck:
    ciphertext = dealing.ciphertext(recipient)
    if ciphertext is None:
        return ShareCheck(recipient, None, None, False, "missing ciphertext")
    try:
        plaintext = HybridEncryptionProvider().decrypt(recovery_private_key, ciphertext, dealing.context(recipient))
        share, blinding = _decode_share(plaintext)
    except (ValueError, EncodingError) as exc:
        return ShareCheck(recipient, None, None, False, f"decryption failed: {exc}")
    valid = dealing.commitment.verify(recipient, share, blinding)
    return ShareCheck(recipient, share, blinding, valid, "valid" if valid else "Pedersen relation failed")
