"""Typed provider boundaries for authentication and public validation."""

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class CheckCode(str, Enum):
    ACCEPTED = "accepted"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_PUBLIC_VALUE = "invalid_public_value"
    INVALID_ANCHOR = "invalid_anchor"
    MALFORMED = "malformed"
    PROVIDER_ERROR = "provider_error"


@dataclass(frozen=True)
class CheckResult:
    code: CheckCode
    detail: str = ""

    @property
    def accepted(self) -> bool:
        return self.code is CheckCode.ACCEPTED

    @classmethod
    def accept(cls) -> "CheckResult":
        return cls(CheckCode.ACCEPTED)


class SignatureProvider(Protocol):
    """Provider for a chosen, externally specified signature scheme."""

    def sign(self, signing_key: bytes, statement: bytes) -> bytes: ...
    def verify(self, verification_key: bytes, statement: bytes, signature: bytes) -> CheckResult: ...


class PublicValueValidator(Protocol):
    """Validates typed public bytes without changing their wire representation."""

    def validate(self, purpose: str, value: bytes) -> CheckResult: ...


class AnchorVerifier(Protocol):
    """Checks that metadata is a correctly derived anchor at the trust boundary."""

    def verify_anchor(self, metadata_bytes: bytes, supporting_bytes: bytes) -> CheckResult: ...
