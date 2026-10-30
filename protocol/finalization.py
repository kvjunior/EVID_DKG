"""Signed common-output votes and quorum finalization certificates."""

from dataclasses import dataclass
from hashlib import sha256

from accountable_dkg.crypto.interfaces import SignatureProvider
from accountable_dkg.crypto.pedersen import ELEMENT_BYTES, decode_element
from accountable_dkg.crypto.transcript_domains import Domain, frame

from .encoding import EncodingError, Reader, blob, sequence, u16
from .session import SessionContext
from .state_machine import LocalDkgOutput


@dataclass(frozen=True)
class FinalizationValue:
    session_id: bytes
    anchor_id: bytes
    public_key: bytes
    threshold_public_keys: tuple[tuple[int, bytes], ...]

    def __post_init__(self) -> None:
        if len(self.session_id) != 32 or len(self.anchor_id) != 32:
            raise EncodingError("invalid finalization context")
        decode_element(self.public_key)
        indices = tuple(index for index, _ in self.threshold_public_keys)
        if not indices or indices != tuple(sorted(set(indices))):
            raise EncodingError("threshold public keys require unique increasing indices")
        for index, key in self.threshold_public_keys:
            if not 1 <= index <= 0xFFFF:
                raise EncodingError("invalid threshold-key index")
            decode_element(key)

    def encode(self) -> bytes:
        entries = tuple(u16(index) + key for index, key in self.threshold_public_keys)
        return self.session_id + self.anchor_id + blob(self.public_key, maximum=ELEMENT_BYTES) + sequence(entries)

    @classmethod
    def decode(cls, raw: bytes) -> "FinalizationValue":
        reader = Reader(raw)
        session_id = reader.fixed(32)
        anchor_id = reader.fixed(32)
        public_key = reader.blob(maximum=ELEMENT_BYTES)
        threshold_keys = []
        for _ in range(reader.u16()):
            item = Reader(reader.blob())
            threshold_keys.append((item.u16(), item.fixed(ELEMENT_BYTES)))
            item.finish()
        reader.finish()
        value = cls(session_id, anchor_id, public_key, tuple(threshold_keys))
        if value.encode() != raw:
            raise EncodingError("non-canonical finalization value")
        return value

    @classmethod
    def from_local_output(cls, session_id: bytes, output: LocalDkgOutput) -> "FinalizationValue":
        return cls(session_id, output.qualification_anchor, output.public_key, output.threshold_public_keys)

    @property
    def value_id(self) -> bytes:
        return sha256(frame(Domain.HASH_REFERENCE, self.encode())).digest()


@dataclass(frozen=True)
class FinalizationVote:
    signer: int
    value: FinalizationValue
    signature: bytes

    def __post_init__(self) -> None:
        if not 1 <= self.signer <= 0xFFFF or not isinstance(self.signature, bytes):
            raise EncodingError("invalid finalization vote")

    def signed_statement(self) -> bytes:
        return frame(Domain.FINALIZATION_SIGNATURE, u16(self.signer), self.value.encode())

    def encode(self) -> bytes:
        return u16(self.signer) + blob(self.value.encode()) + blob(self.signature, maximum=1 << 14)

    @classmethod
    def decode(cls, raw: bytes) -> "FinalizationVote":
        reader = Reader(raw)
        signer = reader.u16()
        value = FinalizationValue.decode(reader.blob())
        signature = reader.blob(maximum=1 << 14)
        reader.finish()
        vote = cls(signer, value, signature)
        if vote.encode() != raw:
            raise EncodingError("non-canonical finalization vote")
        return vote

    @classmethod
    def sign(
        cls,
        signer: int,
        value: FinalizationValue,
        provider: SignatureProvider,
        signing_key: bytes,
    ) -> "FinalizationVote":
        unsigned = cls(signer, value, b"")
        return cls(signer, value, provider.sign(signing_key, unsigned.signed_statement()))


class FinalizationVoteRegistry:
    """Local sign-once guard for one session/anchor finalization value."""

    def __init__(self) -> None:
        self._signed: dict[tuple[int, bytes, bytes], bytes] = {}

    def sign(
        self,
        signer: int,
        value: FinalizationValue,
        provider: SignatureProvider,
        signing_key: bytes,
    ) -> FinalizationVote:
        scope = signer, value.session_id, value.anchor_id
        previous = self._signed.get(scope)
        if previous is not None and previous != value.value_id:
            raise ValueError("participant already signed a conflicting finalization value")
        self._signed[scope] = value.value_id
        return FinalizationVote.sign(signer, value, provider, signing_key)


@dataclass(frozen=True)
class FinalizationCertificate:
    value: FinalizationValue
    votes: tuple[FinalizationVote, ...]

    def __post_init__(self) -> None:
        signers = tuple(vote.signer for vote in self.votes)
        if not self.votes or signers != tuple(sorted(set(signers))):
            raise EncodingError("certificate votes require unique increasing signers")
        if any(vote.value != self.value for vote in self.votes):
            raise EncodingError("certificate contains conflicting values")

    def encode(self) -> bytes:
        compact_votes = tuple(
            u16(vote.signer) + blob(vote.signature, maximum=1 << 14)
            for vote in self.votes
        )
        return blob(self.value.encode()) + sequence(compact_votes)

    @classmethod
    def decode(cls, raw: bytes) -> "FinalizationCertificate":
        reader = Reader(raw)
        value = FinalizationValue.decode(reader.blob())
        votes = []
        for _ in range(reader.u16()):
            item = Reader(reader.blob())
            signer = item.u16()
            signature = item.blob(maximum=1 << 14)
            item.finish()
            votes.append(FinalizationVote(signer, value, signature))
        reader.finish()
        certificate = cls(value, tuple(votes))
        if certificate.encode() != raw:
            raise EncodingError("non-canonical finalization certificate")
        return certificate

    @property
    def certificate_id(self) -> bytes:
        return sha256(frame(Domain.HASH_REFERENCE, self.encode())).digest()

    def verify(
        self,
        session: SessionContext,
        faults: int,
        provider: SignatureProvider,
    ) -> bool:
        participants = len(session.roster.participants)
        quorum = participants - faults
        expected_indices = tuple(item.index for item in session.roster.participants)
        if (
            faults < 0
            or participants < 3 * faults + 1
            or self.value.session_id != session.session_id
            or tuple(index for index, _ in self.value.threshold_public_keys) != expected_indices
            or len(self.votes) < quorum
        ):
            return False
        for vote in self.votes:
            member = session.roster.participant(vote.signer)
            if member is None or not provider.verify(
                member.verification_key, vote.signed_statement(), vote.signature
            ).accepted:
                return False
        return True

    @classmethod
    def build(
        cls,
        votes: tuple[FinalizationVote, ...],
        session: SessionContext,
        faults: int,
        provider: SignatureProvider,
    ) -> "FinalizationCertificate":
        if not votes:
            raise ValueError("cannot build an empty certificate")
        ordered = tuple(sorted(votes, key=lambda vote: vote.signer))
        certificate = cls(ordered[0].value, ordered)
        if not certificate.verify(session, faults, provider):
            raise ValueError("finalization votes do not form a valid quorum certificate")
        return certificate
