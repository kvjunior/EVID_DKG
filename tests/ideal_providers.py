"""Idealized test providers.  They are not production cryptography."""

from hashlib import sha256
from hmac import compare_digest, new

from accountable_dkg.crypto.interfaces import CheckCode, CheckResult


class IdealHMACProvider:
    def sign(self, signing_key: bytes, statement: bytes) -> bytes:
        return new(signing_key, statement, sha256).digest()

    def verify(self, verification_key: bytes, statement: bytes, signature: bytes) -> CheckResult:
        expected = self.sign(verification_key, statement)
        if compare_digest(expected, signature):
            return CheckResult.accept()
        return CheckResult(CheckCode.INVALID_SIGNATURE)


class IdealAnchorVerifier:
    def verify_anchor(self, metadata_bytes: bytes, supporting_bytes: bytes) -> CheckResult:
        if supporting_bytes == b"accepted:" + sha256(metadata_bytes).digest():
            return CheckResult.accept()
        return CheckResult(CheckCode.INVALID_ANCHOR)
