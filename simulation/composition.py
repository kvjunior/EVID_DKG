"""Machine-readable dependency graph for the Batch 09 composition claim."""

from dataclasses import dataclass
from enum import Enum


class ObligationStatus(str, Enum):
    PROVED_MODEL = "proved_model"
    PROVED_CONDITIONAL = "proved_conditional"
    IMPORTED = "imported"
    UNRESOLVED = "unresolved"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class CompositionObligation:
    identifier: str
    status: ObligationStatus
    statement: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompositionAssessment:
    obligations: tuple[CompositionObligation, ...]

    @classmethod
    def batch09(cls) -> "CompositionAssessment":
        return cls((
            CompositionObligation(
                "STATIC-IDEAL", ObligationStatus.PROVED_MODEL,
                "C1/C2 bounds and finite ideal polynomial sampling are executable",
            ),
            CompositionObligation(
                "REPROGRAM-ALG", ObligationStatus.PROVED_MODEL,
                "trapdoor reprogramming preserves Pedersen exponents and corrupt value shares",
                ("STATIC-IDEAL",),
            ),
            CompositionObligation(
                "DAS23-STATIC-SIM", ObligationStatus.IMPORTED,
                "static ADKG simulator theorem under the paper's ACSS/MVBA/CRS/NIZK assumptions",
            ),
            CompositionObligation(
                "REPORTER-PROJ", ObligationStatus.PROVED_CONDITIONAL,
                "honest admissible deliveries erase pathwise in the logical-event model",
            ),
            CompositionObligation(
                "PUBLIC-EXTENSION", ObligationStatus.PROVED_CONDITIONAL,
                "judge and certificate outputs are deterministic functions of validated public inputs",
                ("REPORTER-PROJ",),
            ),
            CompositionObligation(
                "CONCRETE-TRAPDOOR", ObligationStatus.UNRESOLVED,
                "the concrete Pedersen setup exposes a simulator trapdoor without weakening real security",
                ("REPROGRAM-ALG",),
            ),
            CompositionObligation(
                "NIZK-SIM", ObligationStatus.UNRESOLVED,
                "the concrete KEY proof interface supplies the required proof simulator",
                ("DAS23-STATIC-SIM",),
            ),
            CompositionObligation(
                "DEV1-RECOVERY-JOINT", ObligationStatus.UNRESOLVED,
                "validity bits, keys, plaintexts, timing, and dispositions are jointly simulatable",
            ),
            CompositionObligation(
                "LEDGER-JOINT", ObligationStatus.UNRESOLVED,
                "ledger events and DKG transcript remain jointly simulatable under evidence-adaptive scheduling",
                ("REPORTER-PROJ", "PUBLIC-EXTENSION"),
            ),
            CompositionObligation(
                "ASYNC-SUBPROTOCOLS", ObligationStatus.IMPORTED,
                "ACSS, RBC, MVBA, and OEC security/liveness satisfy the Das'23 interfaces",
            ),
            CompositionObligation(
                "ADAPTIVE-CORRUPTION", ObligationStatus.OUT_OF_SCOPE,
                "adaptive corruptions and erasure-free security are not in the frozen model",
            ),
        ))

    @property
    def blocking(self) -> tuple[CompositionObligation, ...]:
        return tuple(
            item for item in self.obligations
            if item.status in {ObligationStatus.UNRESOLVED, ObligationStatus.OUT_OF_SCOPE}
        )

    @property
    def complete_security_theorem(self) -> bool:
        return not self.blocking and all(
            item.status is not ObligationStatus.PROVED_CONDITIONAL for item in self.obligations
        )

    def require_complete(self) -> None:
        if not self.complete_security_theorem:
            names = ", ".join(item.identifier for item in self.blocking)
            raise RuntimeError(f"complete composition theorem is not established: {names}")
