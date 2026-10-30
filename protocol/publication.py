"""Quorum-certificate publication, explicit finality, and window failover."""

from dataclasses import dataclass

from accountable_dkg.crypto.interfaces import SignatureProvider
from accountable_dkg.execution.ledger_adapter import (
    FinalizedLedgerInput, ReceiptCode, TerminalVerdict,
)

from .encoding import EncodingError, Reader, blob, u8
from .finalization import FinalizationCertificate
from .session import SessionContext


PUBLICATION_VERSION = 1


@dataclass(frozen=True)
class CertificatePublication:
    certificate: FinalizationCertificate

    def encode(self) -> bytes:
        return u8(PUBLICATION_VERSION) + blob(self.certificate.encode())

    @classmethod
    def decode(cls, raw: bytes) -> "CertificatePublication":
        reader = Reader(raw)
        if reader.u8() != PUBLICATION_VERSION:
            raise EncodingError("unsupported publication version")
        value = cls(FinalizationCertificate.decode(reader.blob()))
        reader.finish()
        if value.encode() != raw:
            raise EncodingError("non-canonical certificate publication")
        return value


@dataclass(frozen=True)
class PublicationSchedule:
    participants: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.participants or self.participants != tuple(sorted(set(self.participants))):
            raise ValueError("publication schedule requires unique increasing participants")

    def publisher(self, window: int) -> int:
        if window < 0:
            raise ValueError("window must be nonnegative")
        return self.participants[window % len(self.participants)]


@dataclass(frozen=True)
class PublicationIntent:
    window: int
    publisher: int
    payload: bytes


class PublicationCoordinator:
    """Emits at most one local intent in the windows assigned to this party."""

    def __init__(
        self,
        participant: int,
        schedule: PublicationSchedule,
        certificate: FinalizationCertificate,
    ) -> None:
        if participant not in schedule.participants:
            raise ValueError("publisher is outside the schedule")
        self.participant = participant
        self.schedule = schedule
        self.certificate = certificate
        self._attempted: set[int] = set()
        self._finalized = False

    def intent(self, window: int) -> PublicationIntent | None:
        if self._finalized or window in self._attempted or self.schedule.publisher(window) != self.participant:
            return None
        self._attempted.add(window)
        payload = CertificatePublication(self.certificate).encode()
        return PublicationIntent(window, self.participant, payload)

    def observe_finalized(self, publication: "FinalizedPublication") -> None:
        if publication.certificate.certificate_id == self.certificate.certificate_id:
            self._finalized = True


@dataclass(frozen=True)
class FinalizedPublication:
    tx_id: int
    publisher: int
    finalized_time: int
    certificate: FinalizationCertificate


def verify_finalized_publication(
    finalized: FinalizedLedgerInput,
    verdict: TerminalVerdict,
    session: SessionContext,
    faults: int,
    provider: SignatureProvider,
) -> FinalizedPublication:
    if finalized.receipt.code is not ReceiptCode.ACCEPTED_FOR_ADJUDICATION:
        raise ValueError("publication receipt was rejected")
    if verdict.tx_id != finalized.tx_id or not verdict.accepted or verdict.verdict_time < finalized.finalized_time:
        raise ValueError("publication lacks a matching accepted terminal verdict")
    publication = CertificatePublication.decode(finalized.payload)
    if not publication.certificate.verify(session, faults, provider):
        raise ValueError("publication certificate is invalid")
    return FinalizedPublication(
        finalized.tx_id, finalized.actor, finalized.finalized_time, publication.certificate
    )
