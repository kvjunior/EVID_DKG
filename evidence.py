"""Evidence lifecycle model: a submission is not an adjudication."""

from dataclasses import dataclass, field
from enum import Enum


class State(str, Enum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    ADJUDICATED = "adjudicated"


@dataclass
class Evidence:
    dealer: int
    kind: str
    state: State = State.PENDING
    attempted_phases: set[str] = field(default_factory=set)

    def attempt(self, believed_phase: str) -> bool:
        if (self.state is State.ADJUDICATED
                or believed_phase not in {"complaint", "dispute"}
                or believed_phase in self.attempted_phases):
            return False
        self.attempted_phases.add(believed_phase)
        self.state = State.SUBMITTED
        return True

    def observe_rejection(self) -> None:
        if self.state is not State.ADJUDICATED:
            self.state = State.PENDING

    def observe_adjudication(self) -> None:
        self.state = State.ADJUDICATED
