"""Ed25519 signature adapter using the pinned ``cryptography`` backend."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .backends import require_pinned_backend
from .interfaces import CheckCode, CheckResult


ED25519_PRIVATE_BYTES = 32
ED25519_PUBLIC_BYTES = 32
ED25519_SIGNATURE_BYTES = 64


class Ed25519SignatureProvider:
    """Raw 32-byte seed/public-key adapter; statements are signed unchanged."""

    def __init__(self) -> None:
        require_pinned_backend()

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        private = Ed25519PrivateKey.generate()
        return (
            private.private_bytes_raw(),
            private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        )

    def sign(self, signing_key: bytes, statement: bytes) -> bytes:
        if not isinstance(signing_key, bytes) or len(signing_key) != ED25519_PRIVATE_BYTES:
            raise ValueError("Ed25519 signing key must contain exactly 32 bytes")
        if not isinstance(statement, bytes):
            raise TypeError("statement must be bytes")
        return Ed25519PrivateKey.from_private_bytes(signing_key).sign(statement)

    def verify(self, verification_key: bytes, statement: bytes, signature: bytes) -> CheckResult:
        if not all(isinstance(value, bytes) for value in (verification_key, statement, signature)):
            return CheckResult(CheckCode.MALFORMED, "Ed25519 inputs must be bytes")
        if len(verification_key) != ED25519_PUBLIC_BYTES:
            return CheckResult(CheckCode.MALFORMED, "Ed25519 public key must contain 32 bytes")
        if len(signature) != ED25519_SIGNATURE_BYTES:
            return CheckResult(CheckCode.INVALID_SIGNATURE, "Ed25519 signature must contain 64 bytes")
        try:
            Ed25519PublicKey.from_public_bytes(verification_key).verify(signature, statement)
        except (InvalidSignature, ValueError):
            return CheckResult(CheckCode.INVALID_SIGNATURE, "Ed25519 verification failed")
        return CheckResult.accept()
