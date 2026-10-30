"""Fail-closed static end-to-end simulator adapter and result record."""

from dataclasses import dataclass
from hashlib import sha256

from .composition import CompositionAssessment
from .ideal import IdealDkgOutput
from .leakage import Exposure, ExposureKind, LeakageAudit, StaticLeakagePolicy


@dataclass(frozen=True)
class SimulationCapabilities:
    das23_static_simulator: bool = False
    concrete_crs_trapdoor: bool = False
    key_proof_simulator: bool = False
    dev1_recovery_joint: bool = False
    ledger_joint: bool = False
    async_subprotocols: bool = False

    def missing(self) -> tuple[str, ...]:
        values = {
            "das23_static_simulator": self.das23_static_simulator,
            "concrete_crs_trapdoor": self.concrete_crs_trapdoor,
            "key_proof_simulator": self.key_proof_simulator,
            "dev1_recovery_joint": self.dev1_recovery_joint,
            "ledger_joint": self.ledger_joint,
            "async_subprotocols": self.async_subprotocols,
        }
        return tuple(name for name, present in values.items() if not present)


@dataclass(frozen=True)
class SimulationResult:
    audit: LeakageAudit
    missing_capabilities: tuple[str, ...]
    simulated_view_digest: bytes | None
    conditional_execution_complete: bool
    unconditional_security_proved: bool = False


class EndToEndSimulator:
    """Coordinates ideal leakage and imported simulators without overclaiming.

    A successful result is conditional on every supplied capability. This class
    never promotes executable tests or assumed adapters to a cryptographic
    security theorem.
    """

    def __init__(
        self,
        policy: StaticLeakagePolicy,
        capabilities: SimulationCapabilities = SimulationCapabilities(),
    ) -> None:
        self.policy = policy
        self.capabilities = capabilities
        self.assessment = CompositionAssessment.batch09()

    def simulate(
        self,
        ideal: IdealDkgOutput,
        public_transcript: tuple[bytes, ...],
        extra_exposures: tuple[Exposure, ...] = (),
    ) -> SimulationResult:
        expected_leaks = set(ideal.leaked_shares)
        if {participant for participant, _ in expected_leaks} != set(self.policy.revealed_final_shares):
            raise ValueError("ideal output leakage does not match the static policy")
        scalar_bytes = max(1, (ideal.modulus.bit_length() + 7) // 8)
        exposures = tuple(
            Exposure(
                ExposureKind.FINAL_SHARE, participant,
                value.to_bytes(scalar_bytes, "big"), f"ideal-final-share-{participant}",
            )
            for participant, value in ideal.leaked_shares
        ) + tuple(
            Exposure(ExposureKind.PUBLIC_TRANSCRIPT, None, payload, f"public-{index}")
            for index, payload in enumerate(public_transcript)
        ) + extra_exposures
        supplied = frozenset(
            {"dev1_recovery_joint"} if self.capabilities.dev1_recovery_joint else set()
        )
        audit = self.policy.audit(exposures, supplied)
        missing = self.capabilities.missing()
        complete = audit.accepted and not audit.conditional and not missing
        digest = None
        if audit.accepted:
            material = b"".join(
                item.exposure.kind.value.encode("ascii") + item.exposure.digest
                for item in audit.findings
                if item.disposition in {"allowed", "conditional"}
            )
            digest = sha256(material).digest()
        return SimulationResult(audit, missing, digest, complete, False)
