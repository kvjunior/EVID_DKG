"""Bias-safe qualification and immutable commitment anchor."""

from dataclasses import dataclass
from hashlib import sha256

from accountable_dkg.crypto.transcript_domains import Domain, frame

from .acss import AuthenticatedAcssDealing
from .agreement import AgreementDecision
from .encoding import blob, sequence, u16


@dataclass(frozen=True)
class QualifiedDealer:
    dealer: int
    first: AuthenticatedAcssDealing
    second: AuthenticatedAcssDealing

    def __post_init__(self) -> None:
        if self.first.signed.dealing.dealer != self.dealer or self.second.signed.dealing.dealer != self.dealer:
            raise ValueError("qualified contribution dealer mismatch")
        if self.first.signed.dealing.session_id != self.second.signed.dealing.session_id:
            raise ValueError("qualified contribution crosses sessions")

    def encode(self) -> bytes:
        return u16(self.dealer) + blob(self.first.raw_bytes) + blob(self.second.raw_bytes)


@dataclass(frozen=True)
class QualificationAnchor:
    session_id: bytes
    contributions: tuple[QualifiedDealer, ...]

    def __post_init__(self) -> None:
        dealers = tuple(item.dealer for item in self.contributions)
        if len(self.session_id) != 32 or dealers != tuple(sorted(set(dealers))):
            raise ValueError("invalid qualification anchor")
        if any(item.first.signed.dealing.session_id != self.session_id for item in self.contributions):
            raise ValueError("qualification contribution has the wrong session")

    def encode(self) -> bytes:
        return self.session_id + sequence(tuple(item.encode() for item in self.contributions))

    @property
    def reference_id(self) -> bytes:
        return sha256(frame(Domain.ANCHOR_REFERENCE, self.encode())).digest()


def qualify(
    session_id: bytes,
    decision: AgreementDecision,
    available: dict[int, tuple[AuthenticatedAcssDealing, AuthenticatedAcssDealing]],
) -> QualificationAnchor:
    missing = set(decision.dealers) - set(available)
    if missing:
        raise ValueError(f"qualified dealers are unavailable: {sorted(missing)}")
    return QualificationAnchor(
        session_id,
        tuple(QualifiedDealer(dealer, *available[dealer]) for dealer in decision.dealers),
    )
