"""Interfaces for later protocol research; no candidate is implemented here."""

from typing import Protocol

from .functionality import Target
from .parameters import ModelParameters


class DKGProtocol(Protocol):
    name: str
    target: Target

    def specification(self) -> dict[str, object]: ...
    def run(self, parameters: ModelParameters, adversary: object) -> object: ...


class AccountabilityTransformation(Protocol):
    def required_properties(self) -> tuple[str, ...]: ...
    def wrap(self, protocol: DKGProtocol) -> DKGProtocol: ...
    def proof_obligations(self) -> tuple[str, ...]: ...


CANDIDATE_PROTOCOL_IMPLEMENTED = False
