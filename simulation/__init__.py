"""Static ideal-world models, leakage auditing, and fail-closed composition."""

from .composition import CompositionAssessment, ObligationStatus
from .end_to_end import EndToEndSimulator, SimulationCapabilities, SimulationResult
from .ideal import IdealDkgOutput, StaticIdealDkg
from .leakage import Exposure, ExposureKind, LeakageAudit, StaticLeakagePolicy

__all__ = [
    "CompositionAssessment", "EndToEndSimulator", "Exposure", "ExposureKind",
    "IdealDkgOutput", "LeakageAudit", "ObligationStatus", "SimulationCapabilities",
    "SimulationResult", "StaticIdealDkg", "StaticLeakagePolicy",
]
