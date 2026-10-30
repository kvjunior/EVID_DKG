"""External-MVBA validation adapter and typed agreement decision."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgreementParameters:
    participants: int
    faults: int
    reconstruction_threshold: int

    def __post_init__(self) -> None:
        if self.participants < 3 * self.faults + 1 or self.faults < 1:
            raise ValueError("agreement requires n >= 3t+1 and t >= 1")
        if not self.faults <= self.reconstruction_threshold < self.participants - self.faults:
            raise ValueError("reconstruction threshold must be in [t, n-t)")


@dataclass(frozen=True)
class AgreementDecision:
    dealers: tuple[int, ...]


def validate_external_decision(
    parameters: AgreementParameters,
    proposed: tuple[int, ...],
    locally_completed: frozenset[int],
) -> AgreementDecision:
    """Validate MVBA external validity; agreement/termination remain imported."""
    if proposed != tuple(sorted(set(proposed))):
        raise ValueError("agreement dealers must be unique and increasing")
    if len(proposed) < parameters.participants - parameters.faults:
        raise ValueError("agreement set is smaller than n-t")
    if any(not 1 <= dealer <= parameters.participants for dealer in proposed):
        raise ValueError("agreement contains an unknown dealer")
    if not set(proposed).issubset(locally_completed):
        raise ValueError("external validity waits until every selected ACSS completes locally")
    return AgreementDecision(proposed)
