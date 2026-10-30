"""Reference Schnorr proofs for Batch 07 key messages.

This Fiat-Shamir adapter is executable research code over the Batch 06 MODP
reference group.  It is not a deployment-audited NIZK library.
"""

from dataclasses import dataclass
from hashlib import sha256
from secrets import randbelow

from accountable_dkg.protocol.encoding import EncodingError, Reader

from .pedersen import ELEMENT_BYTES, SCALAR_BYTES, P, Q, decode_element, decode_scalar, encode_element, encode_scalar
from .transcript_domains import Domain, frame


@dataclass(frozen=True)
class SchnorrProof:
    announcement: bytes
    response: bytes

    def encode(self) -> bytes:
        return self.announcement + self.response

    @classmethod
    def decode(cls, raw: bytes) -> "SchnorrProof":
        if len(raw) != ELEMENT_BYTES + SCALAR_BYTES:
            raise EncodingError("Schnorr proof must contain one element and one scalar")
        try:
            decode_element(raw[:ELEMENT_BYTES])
            decode_scalar(raw[ELEMENT_BYTES:])
        except ValueError as exc:
            raise EncodingError(str(exc)) from exc
        return cls(raw[:ELEMENT_BYTES], raw[ELEMENT_BYTES:])


def _challenge(base: int, public: int, announcement: int, context: bytes) -> int:
    digest = sha256(frame(
        Domain.PROOF_CHALLENGE, context, encode_element(base), encode_element(public), encode_element(announcement)
    )).digest()
    return int.from_bytes(digest, "big") % Q


def prove_knowledge(base: int, secret: int, context: bytes, *, nonce: int | None = None) -> tuple[bytes, SchnorrProof]:
    if not context or not 0 <= secret < Q:
        raise ValueError("invalid Schnorr witness or context")
    public = pow(base, secret, P)
    randomizer = randbelow(Q - 1) + 1 if nonce is None else nonce % Q
    if randomizer == 0:
        raise ValueError("Schnorr nonce cannot be zero")
    announcement = pow(base, randomizer, P)
    response = (randomizer + _challenge(base, public, announcement, context) * secret) % Q
    return encode_element(public), SchnorrProof(encode_element(announcement), encode_scalar(response))


def verify_knowledge(base: int, public_raw: bytes, proof_raw: bytes, context: bytes) -> bool:
    try:
        public = decode_element(public_raw)
        proof = SchnorrProof.decode(proof_raw)
        announcement = decode_element(proof.announcement)
        response = decode_scalar(proof.response)
        encode_element(base)
    except (ValueError, EncodingError):
        return False
    challenge = _challenge(base, public, announcement, context)
    return pow(base, response, P) == (announcement * pow(public, challenge, P)) % P
