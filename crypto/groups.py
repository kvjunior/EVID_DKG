"""Strict public-key and encoded-point validation at the crypto boundary."""

from cryptography.hazmat.primitives.asymmetric import ec, x25519

from .backends import require_pinned_backend
from .interfaces import CheckCode, CheckResult


_VALIDATION_PRIVATE = bytes.fromhex("a0" * 32)


def validate_x25519_public_key(value: bytes) -> CheckResult:
    """Reject wrong lengths and low-order inputs yielding the all-zero secret."""
    require_pinned_backend()
    if not isinstance(value, bytes) or len(value) != 32:
        return CheckResult(CheckCode.MALFORMED, "X25519 public key must contain 32 bytes")
    try:
        public = x25519.X25519PublicKey.from_public_bytes(value)
        x25519.X25519PrivateKey.from_private_bytes(_VALIDATION_PRIVATE).exchange(public)
    except ValueError:
        return CheckResult(CheckCode.INVALID_PUBLIC_VALUE, "invalid or low-order X25519 public key")
    return CheckResult.accept()


def validate_p256_point(value: bytes) -> CheckResult:
    """Validate a compressed SEC1 P-256 point; infinity is not encodable here."""
    require_pinned_backend()
    if not isinstance(value, bytes) or len(value) != 33 or value[0] not in (2, 3):
        return CheckResult(CheckCode.MALFORMED, "P-256 point must use 33-byte compressed SEC1 encoding")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), value)
    except ValueError:
        return CheckResult(CheckCode.INVALID_PUBLIC_VALUE, "point is not on P-256")
    return CheckResult.accept()


class P256PointValidator:
    def validate(self, purpose: str, value: bytes) -> CheckResult:
        if purpose != "p256_point":
            return CheckResult(CheckCode.MALFORMED, "unsupported point purpose")
        return validate_p256_point(value)
