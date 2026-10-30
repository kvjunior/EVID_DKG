"""Ledger lifecycle model; no consensus, liveness, or bounded-delay theorem."""

from dataclasses import dataclass
from enum import Enum

from accountable_dkg.accounting.communication import CommunicationAccount

from .observation import Observation, ObservationLog, Visibility


@dataclass(frozen=True)
class LedgerWindow:
    number: int
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.number < 0 or not 0 <= self.start < self.end:
            raise ValueError("invalid ledger window")

    def contains(self, time: int) -> bool:
        return self.start <= time < self.end


@dataclass(frozen=True)
class LedgerAssumptions:
    capacity_bytes_per_time: int

    def __post_init__(self) -> None:
        if self.capacity_bytes_per_time <= 0:
            raise ValueError("capacity must be positive")


@dataclass(frozen=True)
class Submission:
    tx_id: int
    actor: int
    payload: bytes
    submitted_time: int


@dataclass(frozen=True)
class Inclusion:
    tx_id: int
    included_time: int


@dataclass(frozen=True)
class FinalizedTransaction:
    tx_id: int
    included_time: int
    finalized_time: int


class ReceiptCode(str, Enum):
    ACCEPTED_FOR_ADJUDICATION = "accepted_for_adjudication"
    REJECTED_OUTSIDE_WINDOW = "rejected_outside_window"
    REJECTED_UNAUTHORIZED = "rejected_unauthorized"


@dataclass(frozen=True)
class LedgerReceipt:
    tx_id: int
    included_time: int
    code: ReceiptCode


@dataclass(frozen=True)
class FinalizedLedgerInput:
    tx_id: int
    actor: int
    payload: bytes
    included_time: int
    finalized_time: int
    receipt: LedgerReceipt


@dataclass(frozen=True)
class TerminalVerdict:
    tx_id: int
    accepted: bool
    verdict_time: int


class LedgerAdapter:
    def __init__(self, roster: frozenset[int], assumptions: LedgerAssumptions) -> None:
        if not roster or any(index <= 0 for index in roster):
            raise ValueError("ledger roster must contain positive indices")
        self.roster = roster
        self.assumptions = assumptions
        self.account = CommunicationAccount()
        self.observations = ObservationLog()
        self._submissions: list[Submission] = []
        self._included: dict[int, Inclusion] = {}
        self._finalized: dict[int, FinalizedTransaction] = {}
        self._used: dict[int, int] = {}
        self._receipts: dict[int, LedgerReceipt] = {}
        self._verdicts: dict[int, TerminalVerdict] = {}

    def submit(self, actor: int, payload: bytes, time: int) -> Submission:
        if actor <= 0 or time < 0 or not isinstance(payload, bytes) or not payload:
            raise ValueError("invalid ledger submission")
        if len(payload) > self.assumptions.capacity_bytes_per_time:
            raise ValueError("payload cannot fit; chunk it before submission")
        submission = Submission(len(self._submissions), actor, payload, time)
        self._submissions.append(submission)
        self.account.charge_submitted(len(payload))
        self.observations.append(Observation(time, "submitted", Visibility.SIMULATOR_METADATA, actor, payload))
        return submission

    def include(self, tx_id: int, time: int) -> Inclusion | None:
        submission = self._submission(tx_id)
        if tx_id in self._included or time < submission.submitted_time:
            raise ValueError("invalid inclusion attempt")
        used = self._used.get(time, 0)
        if used + len(submission.payload) > self.assumptions.capacity_bytes_per_time:
            return None
        self._used[time] = used + len(submission.payload)
        inclusion = Inclusion(tx_id, time)
        self._included[tx_id] = inclusion
        self.account.charge_included(len(submission.payload))
        self.observations.append(Observation(time, "included", Visibility.PUBLIC_LEDGER, submission.actor, submission.payload))
        return inclusion

    def issue_receipt(self, inclusion: Inclusion, window: LedgerWindow, declared_actor: int) -> LedgerReceipt:
        if self._included.get(inclusion.tx_id) != inclusion or inclusion.tx_id in self._receipts:
            raise ValueError("receipt requires one included transaction")
        submission = self._submission(inclusion.tx_id)
        if declared_actor not in self.roster or declared_actor != submission.actor:
            code = ReceiptCode.REJECTED_UNAUTHORIZED
        elif not window.contains(inclusion.included_time):
            code = ReceiptCode.REJECTED_OUTSIDE_WINDOW
        else:
            code = ReceiptCode.ACCEPTED_FOR_ADJUDICATION
        receipt = LedgerReceipt(inclusion.tx_id, inclusion.included_time, code)
        self._receipts[inclusion.tx_id] = receipt
        if code is not ReceiptCode.ACCEPTED_FOR_ADJUDICATION:
            self.account.rejected_included_bytes += len(submission.payload)
        self.observations.append(Observation(inclusion.included_time, f"receipt:{code.value}", Visibility.PUBLIC_LEDGER, submission.actor, submission.payload))
        return receipt

    def finalize(self, inclusion: Inclusion, time: int) -> FinalizedTransaction:
        """Record explicit ledger finality; this does not imply any delay bound."""
        if self._included.get(inclusion.tx_id) != inclusion:
            raise ValueError("finality requires the recorded inclusion")
        if inclusion.tx_id in self._finalized or time < inclusion.included_time:
            raise ValueError("invalid finality transition")
        finalized = FinalizedTransaction(inclusion.tx_id, inclusion.included_time, time)
        self._finalized[inclusion.tx_id] = finalized
        submission = self._submission(inclusion.tx_id)
        self.observations.append(Observation(
            time, "finalized", Visibility.PUBLIC_LEDGER, submission.actor, submission.payload
        ))
        return finalized

    def finalized_input(
        self, finalized: FinalizedTransaction, receipt: LedgerReceipt
    ) -> FinalizedLedgerInput:
        if self._finalized.get(finalized.tx_id) != finalized:
            raise ValueError("unknown finalized transaction")
        if self._receipts.get(finalized.tx_id) != receipt:
            raise ValueError("receipt does not belong to finalized transaction")
        submission = self._submission(finalized.tx_id)
        return FinalizedLedgerInput(
            finalized.tx_id, submission.actor, submission.payload,
            finalized.included_time, finalized.finalized_time, receipt,
        )

    def adjudicate(self, receipt: LedgerReceipt, accepted: bool, time: int) -> TerminalVerdict:
        if receipt.code is not ReceiptCode.ACCEPTED_FOR_ADJUDICATION:
            raise ValueError("rejected receipt cannot be adjudicated")
        if receipt.tx_id in self._verdicts or time < receipt.included_time:
            raise ValueError("invalid terminal verdict")
        verdict = TerminalVerdict(receipt.tx_id, bool(accepted), time)
        self._verdicts[receipt.tx_id] = verdict
        payload = b"accepted" if accepted else b"rejected"
        self.observations.append(Observation(time, "terminal_verdict", Visibility.PUBLIC_LEDGER, None, payload))
        return verdict

    def _submission(self, tx_id: int) -> Submission:
        if not 0 <= tx_id < len(self._submissions):
            raise ValueError("unknown transaction")
        return self._submissions[tx_id]
