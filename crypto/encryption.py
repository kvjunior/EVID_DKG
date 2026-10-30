"""Context-bound X25519/HKDF-SHA256/ChaCha20-Poly1305 envelope."""

from dataclasses import dataclass
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from accountable_dkg.protocol.encoding import EncodingError, Reader, blob, u8

from .backends import require_pinned_backend
from .groups import validate_x25519_public_key
from .transcript_domains import Domain, frame


ENVELOPE_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12


@dataclass(frozen=True)
class CiphertextEnvelope:
    ephemeral_public_key: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if len(self.ephemeral_public_key) != 32:
            raise EncodingError("ephemeral X25519 public key must contain 32 bytes")
        if len(self.salt) != SALT_BYTES:
            raise EncodingError("envelope salt must contain 16 bytes")
        if len(self.nonce) != NONCE_BYTES:
            raise EncodingError("ChaCha20-Poly1305 nonce must contain 12 bytes")
        if len(self.ciphertext) < 16:
            raise EncodingError("ciphertext must include a Poly1305 tag")

    def encode(self) -> bytes:
        return u8(ENVELOPE_VERSION) + self.ephemeral_public_key + self.salt + self.nonce + blob(self.ciphertext)

    @classmethod
    def decode(cls, raw: bytes) -> "CiphertextEnvelope":
        reader = Reader(raw)
        if reader.u8() != ENVELOPE_VERSION:
            raise EncodingError("unsupported encryption envelope version")
        ephemeral = reader._take(32)
        salt = reader._take(SALT_BYTES)
        nonce = reader._take(NONCE_BYTES)
        ciphertext = reader.blob()
        reader.finish()
        return cls(ephemeral, salt, nonce, ciphertext)


class HybridEncryptionProvider:
    """Single-recipient hybrid encryption; callers must supply unique context."""

    def __init__(self) -> None:
        require_pinned_backend()

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        private = X25519PrivateKey.generate()
        return private.private_bytes_raw(), private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @staticmethod
    def _key(shared_secret: bytes, salt: bytes, context: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=frame(Domain.ENCRYPTION_KDF, context),
        ).derive(shared_secret)

    def encrypt(
        self,
        recipient_public_key: bytes,
        plaintext: bytes,
        context: bytes,
        *,
        ephemeral_private_key: bytes | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        if not isinstance(plaintext, bytes) or not isinstance(context, bytes) or not context:
            raise ValueError("plaintext must be bytes and context must be non-empty bytes")
        check = validate_x25519_public_key(recipient_public_key)
        if not check.accepted:
            raise ValueError(check.detail)
        private = X25519PrivateKey.generate() if ephemeral_private_key is None else X25519PrivateKey.from_private_bytes(ephemeral_private_key)
        salt = urandom(SALT_BYTES) if salt is None else salt
        nonce = urandom(NONCE_BYTES) if nonce is None else nonce
        if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
            raise ValueError("salt or nonce has the wrong length")
        ephemeral = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = private.exchange(X25519PublicKey.from_public_bytes(recipient_public_key))
        aad = frame(Domain.ENCRYPTION_AAD, context, ephemeral, recipient_public_key, salt)
        ciphertext = ChaCha20Poly1305(self._key(shared, salt, context)).encrypt(nonce, plaintext, aad)
        return CiphertextEnvelope(ephemeral, salt, nonce, ciphertext).encode()

    def decrypt(self, recipient_private_key: bytes, encoded: bytes, context: bytes) -> bytes:
        if not isinstance(recipient_private_key, bytes) or len(recipient_private_key) != 32:
            raise ValueError("recipient X25519 private key must contain 32 bytes")
        if not isinstance(context, bytes) or not context:
            raise ValueError("context must be non-empty bytes")
        envelope = CiphertextEnvelope.decode(encoded)
        check = validate_x25519_public_key(envelope.ephemeral_public_key)
        if not check.accepted:
            raise ValueError(check.detail)
        private = X25519PrivateKey.from_private_bytes(recipient_private_key)
        recipient_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = private.exchange(X25519PublicKey.from_public_bytes(envelope.ephemeral_public_key))
        aad = frame(Domain.ENCRYPTION_AAD, context, envelope.ephemeral_public_key, recipient_public, envelope.salt)
        try:
            return ChaCha20Poly1305(self._key(shared, envelope.salt, context)).decrypt(
                envelope.nonce, envelope.ciphertext, aad
            )
        except InvalidTag as exc:
            raise ValueError("ciphertext authentication failed") from exc
