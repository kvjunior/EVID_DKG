"""Purpose-specific validation policy for concrete Batch 05 encodings."""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from accountable_dkg.protocol.encoding import EncodingError

from .encryption import CiphertextEnvelope
from .groups import validate_p256_point, validate_x25519_public_key
from .interfaces import CheckCode, CheckResult


@dataclass(frozen=True)
class CryptoPolicy:
    backend: str = "cryptography==50.0.2"
    signature: str = "Ed25519 (RFC 8032)"
    key_agreement: str = "X25519 (RFC 7748)"
    kdf: str = "HKDF-SHA256 (RFC 5869)"
    aead: str = "ChaCha20-Poly1305 (RFC 8439)"
    encoded_group: str = "compressed SEC1 P-256"
    byte_commitment: str = "domain-separated SHA-256"


class ConcretePublicValueValidator:
    def validate(self, purpose: str, value: bytes) -> CheckResult:
        if not isinstance(value, bytes):
            return CheckResult(CheckCode.MALFORMED, "public value must be bytes")
        if purpose == "ed25519_verification_key":
            if len(value) != 32:
                return CheckResult(CheckCode.MALFORMED, "Ed25519 public key must contain 32 bytes")
            try:
                Ed25519PublicKey.from_public_bytes(value)
            except ValueError:
                return CheckResult(CheckCode.INVALID_PUBLIC_VALUE, "invalid Ed25519 public key")
            return CheckResult.accept()
        if purpose == "x25519_public_key":
            return validate_x25519_public_key(value)
        if purpose == "p256_point":
            return validate_p256_point(value)
        if purpose == "sha256_commitment":
            return CheckResult.accept() if len(value) == 32 else CheckResult(
                CheckCode.MALFORMED, "SHA-256 commitment must contain 32 bytes"
            )
        if purpose == "hybrid_ciphertext":
            try:
                envelope = CiphertextEnvelope.decode(value)
            except (EncodingError, ValueError) as exc:
                return CheckResult(CheckCode.MALFORMED, str(exc))
            return validate_x25519_public_key(envelope.ephemeral_public_key)
        return CheckResult(CheckCode.MALFORMED, f"unsupported validation purpose: {purpose}")
