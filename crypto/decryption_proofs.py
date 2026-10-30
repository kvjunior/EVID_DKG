"""Signed decryption attestations.

These attestations are concrete and context-bound, but they are deliberately
not called zero-knowledge proofs: a signer can attest to a false plaintext.
The future VESS backend must supply its own reviewed proof system.
"""

from dataclasses import dataclass
from hashlib import sha256

from accountable_dkg.protocol.encoding import EncodingError, Reader, blob, u8

from .interfaces import CheckCode, CheckResult
from .signatures import Ed25519SignatureProvider
from .transcript_domains import Domain, frame


ATTESTATION_VERSION = 1


@dataclass(frozen=True)
class DecryptionAttestation:
    ciphertext_digest: bytes
    plaintext_digest: bytes
    signature: bytes

    def encode(self) -> bytes:
        return u8(ATTESTATION_VERSION) + self.ciphertext_digest + self.plaintext_digest + blob(self.signature)

    @classmethod
    def decode(cls, raw: bytes) -> "DecryptionAttestation":
        reader = Reader(raw)
        if reader.u8() != ATTESTATION_VERSION:
            raise EncodingError("unsupported attestation version")
        value = cls(reader._take(32), reader._take(32), reader.blob(maximum=64))
        reader.finish()
        if len(value.signature) != 64:
            raise EncodingError("attestation signature must contain 64 bytes")
        return value


class DecryptionAttestationProvider:
    def __init__(self, signatures: Ed25519SignatureProvider | None = None) -> None:
        self.signatures = signatures or Ed25519SignatureProvider()

    @staticmethod
    def _statement(ciphertext_digest: bytes, plaintext_digest: bytes, context: bytes) -> bytes:
        return frame(Domain.DECRYPTION_ATTESTATION, context, ciphertext_digest, plaintext_digest)

    def attest(self, signing_key: bytes, ciphertext: bytes, plaintext: bytes, context: bytes) -> bytes:
        cipher_digest = sha256(ciphertext).digest()
        plain_digest = sha256(plaintext).digest()
        signature = self.signatures.sign(signing_key, self._statement(cipher_digest, plain_digest, context))
        return DecryptionAttestation(cipher_digest, plain_digest, signature).encode()

    def verify(
        self,
        verification_key: bytes,
        ciphertext: bytes,
        plaintext: bytes,
        context: bytes,
        encoded: bytes,
    ) -> CheckResult:
        try:
            attestation = DecryptionAttestation.decode(encoded)
        except EncodingError as exc:
            return CheckResult(CheckCode.MALFORMED, str(exc))
        cipher_digest = sha256(ciphertext).digest()
        plain_digest = sha256(plaintext).digest()
        if attestation.ciphertext_digest != cipher_digest or attestation.plaintext_digest != plain_digest:
            return CheckResult(CheckCode.INVALID_PUBLIC_VALUE, "attested digest does not match supplied material")
        return self.signatures.verify(
            verification_key,
            self._statement(cipher_digest, plain_digest, context),
            attestation.signature,
        )
