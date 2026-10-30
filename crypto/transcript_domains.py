"""Distinct transcript domains for signatures, hashes, and challenges."""

from enum import IntEnum


PREFIX = b"EVID-DKG/transcript/v1\x00"


def _u8(value: int) -> bytes:
    if not 0 <= value < 256:
        raise ValueError("domain does not fit one byte")
    return value.to_bytes(1, "big")


def _blob(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) >= 1 << 32:
        raise ValueError("transcript part is invalid")
    return len(value).to_bytes(4, "big") + value


class Domain(IntEnum):
    SESSION = 1
    ROSTER = 2
    ANCHOR_REFERENCE = 3
    RANDEX_SIGNATURE = 4
    KEY_SIGNATURE = 5
    EVIDENCE_SIGNATURE = 6
    FINALIZATION_SIGNATURE = 7
    HASH_REFERENCE = 8
    PROOF_CHALLENGE = 9
    COMMITMENT = 10
    ENCRYPTION_KDF = 11
    ENCRYPTION_AAD = 12
    DECRYPTION_ATTESTATION = 13
    ACSS_INSTANCE = 14
    ACSS_ENCRYPTION = 15
    ACSS_DEALING = 16
    ACSS_RECOVERY = 17


def frame(domain: Domain, *parts: bytes) -> bytes:
    if not isinstance(domain, Domain):
        raise TypeError("domain must be a Domain member")
    return PREFIX + _u8(int(domain)) + b"".join(_blob(part) for part in parts)
