"""Explicit leakage inventory for the static C1/C2 Batch 09 model."""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256


class ExposureKind(str, Enum):
    PUBLIC_TRANSCRIPT = "public_transcript"
    FINAL_SHARE = "final_share"
    INTERNAL_STATE = "internal_state"
    PRIVATE_DELIVERY = "private_delivery"
    RECOVERY_KEY = "recovery_key"
    RECOVERED_PLAINTEXT = "recovered_plaintext"
    SCHEDULER_CHOICE = "scheduler_choice"


@dataclass(frozen=True)
class Exposure:
    kind: ExposureKind
    owner: int | None
    payload: bytes
    label: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ExposureKind) or not isinstance(self.payload, bytes) or not self.label:
            raise ValueError("invalid leakage exposure")
        if self.owner is not None and self.owner <= 0:
            raise ValueError("exposure owner must be a positive participant")

    @property
    def digest(self) -> bytes:
        return sha256(self.payload).digest()


@dataclass(frozen=True)
class LeakageFinding:
    exposure: Exposure
    disposition: str
    reason: str
    required_oracle: str | None = None


@dataclass(frozen=True)
class LeakageAudit:
    findings: tuple[LeakageFinding, ...]

    @property
    def forbidden(self) -> tuple[LeakageFinding, ...]:
        return tuple(item for item in self.findings if item.disposition == "forbidden")

    @property
    def conditional(self) -> tuple[LeakageFinding, ...]:
        return tuple(item for item in self.findings if item.disposition == "conditional")

    @property
    def accepted(self) -> bool:
        return not self.forbidden


@dataclass(frozen=True)
class StaticLeakagePolicy:
    participants: int
    faults: int
    degree: int
    corrupt: frozenset[int]
    final_share_leaks: frozenset[int]

    def __post_init__(self) -> None:
        roster = frozenset(range(1, self.participants + 1))
        if self.participants < 3 * self.faults + 1 or not self.faults <= self.degree < self.participants - self.faults:
            raise ValueError("invalid static leakage parameters")
        if not self.corrupt <= roster or not self.final_share_leaks <= roster:
            raise ValueError("leakage set is outside the roster")
        if self.corrupt & self.final_share_leaks:
            raise ValueError("C2 contains only additional, noncorrupt share owners")
        if len(self.corrupt) > self.faults or len(self.corrupt | self.final_share_leaks) > self.degree:
            raise ValueError("C1/C2 exceeds the ideal functionality bound")

    @property
    def revealed_final_shares(self) -> frozenset[int]:
        return self.corrupt | self.final_share_leaks

    def audit(
        self,
        exposures: tuple[Exposure, ...],
        supplied_oracles: frozenset[str] = frozenset(),
    ) -> LeakageAudit:
        findings = []
        for exposure in exposures:
            disposition, reason, oracle = self._classify(exposure)
            if disposition == "conditional" and oracle in supplied_oracles:
                disposition = "allowed"
                reason = f"permitted only by supplied {oracle} assumption"
            findings.append(LeakageFinding(exposure, disposition, reason, oracle))
        return LeakageAudit(tuple(findings))

    def _classify(self, exposure: Exposure) -> tuple[str, str, str | None]:
        if exposure.kind in {ExposureKind.PUBLIC_TRANSCRIPT, ExposureKind.SCHEDULER_CHOICE}:
            return "allowed", "public transcript or adversarial scheduling data", None
        if exposure.owner is None:
            return "forbidden", "private exposure has no accountable owner", None
        if exposure.kind is ExposureKind.FINAL_SHARE:
            if exposure.owner in self.revealed_final_shares:
                return "allowed", "final share is in C1 union C2", None
            return "forbidden", "honest final share is outside C1 union C2", None
        if exposure.kind in {ExposureKind.INTERNAL_STATE, ExposureKind.PRIVATE_DELIVERY}:
            if exposure.owner in self.corrupt:
                return "allowed", "corrupt-party internal view is in C1", None
            return "forbidden", "C2 permits a final share, not honest internal state", None
        if exposure.kind in {ExposureKind.RECOVERY_KEY, ExposureKind.RECOVERED_PLAINTEXT}:
            if exposure.owner in self.corrupt:
                return "allowed", "corrupt-party recovery state is already internal leakage", None
            return "conditional", "honest recovery disclosure is outside F_ADKG", "dev1_recovery_joint"
        return "forbidden", "unrecognized leakage class", None
