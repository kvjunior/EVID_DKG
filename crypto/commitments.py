"""Domain-separated SHA-256 commitments for byte strings.

This is a conventional hash commitment adapter, not a Feldman/Pedersen
polynomial commitment and not a substitute for VESS.
"""

from hashlib import sha256
from hmac import compare_digest
from secrets import token_bytes

from .transcript_domains import Domain, frame


OPENING_BYTES = 32
COMMITMENT_BYTES = 32


class Sha256CommitmentProvider:
    @staticmethod
    def commit(message: bytes, opening: bytes | None = None) -> tuple[bytes, bytes]:
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        opening = token_bytes(OPENING_BYTES) if opening is None else opening
        if not isinstance(opening, bytes) or len(opening) != OPENING_BYTES:
            raise ValueError("commitment opening must contain exactly 32 bytes")
        digest = sha256(frame(Domain.COMMITMENT, opening, message)).digest()
        return digest, opening

    @staticmethod
    def verify(commitment: bytes, message: bytes, opening: bytes) -> bool:
        if not isinstance(commitment, bytes) or len(commitment) != COMMITMENT_BYTES:
            return False
        try:
            expected, _ = Sha256CommitmentProvider.commit(message, opening)
        except (TypeError, ValueError):
            return False
        return compare_digest(commitment, expected)
