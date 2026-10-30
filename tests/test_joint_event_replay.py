import unittest

from accountable_dkg.execution.events import EventKind, EventSource
from accountable_dkg.execution.ledger_adapter import (
    LedgerAdapter,
    LedgerAssumptions,
    LedgerWindow,
    ReceiptCode,
)
from accountable_dkg.execution.random_tapes import RandomTape
from accountable_dkg.execution.scheduler import EventScheduler
from accountable_dkg.execution.observation import Visibility


class JointEventReplayTests(unittest.TestCase):
    def test_scheduler_is_stable_at_equal_times(self):
        scheduler = EventScheduler()
        scheduler.schedule(4, EventSource.TIMER, EventKind.TICK, b"first")
        scheduler.schedule(2, EventSource.NETWORK, EventKind.TICK, b"early")
        scheduler.schedule(4, EventSource.LEDGER, EventKind.TICK, b"second")
        self.assertEqual([event.payload for event in scheduler.drain()], [b"early", b"first", b"second"])

    def test_submission_inclusion_receipt_and_verdict_are_separate(self):
        ledger = LedgerAdapter(frozenset({1, 2}), LedgerAssumptions(10))
        submission = ledger.submit(1, b"evidence", 3)
        self.assertEqual(ledger.observations.items[-1].visibility, Visibility.SIMULATOR_METADATA)
        inclusion = ledger.include(submission.tx_id, 4)
        self.assertIsNotNone(inclusion)
        self.assertNotIn("receipt", ledger.observations.items[-1].kind)
        receipt = ledger.issue_receipt(inclusion, LedgerWindow(0, 2, 6), 1)
        self.assertEqual(receipt.code, ReceiptCode.ACCEPTED_FOR_ADJUDICATION)
        verdict = ledger.adjudicate(receipt, True, 7)
        self.assertTrue(verdict.accepted)
        self.assertEqual([item.kind for item in ledger.observations.items], [
            "submitted", "included", "receipt:accepted_for_adjudication", "terminal_verdict"
        ])

    def test_capacity_deferral_is_not_inclusion_or_receipt(self):
        ledger = LedgerAdapter(frozenset({1}), LedgerAssumptions(5))
        first = ledger.submit(1, b"12345", 0)
        second = ledger.submit(1, b"abcde", 0)
        self.assertIsNotNone(ledger.include(first.tx_id, 1))
        self.assertIsNone(ledger.include(second.tx_id, 1))
        self.assertEqual([item.kind for item in ledger.observations.items].count("included"), 1)
        self.assertIsNotNone(ledger.include(second.tx_id, 2))

    def test_oversize_payload_requires_chunking(self):
        ledger = LedgerAdapter(frozenset({1}), LedgerAssumptions(4))
        with self.assertRaisesRegex(ValueError, "chunk"):
            ledger.submit(1, b"12345", 0)

    def test_late_and_unauthorized_receipts_remain_public(self):
        ledger = LedgerAdapter(frozenset({1, 2}), LedgerAssumptions(20))
        late = ledger.submit(1, b"late", 1)
        late_inclusion = ledger.include(late.tx_id, 9)
        self.assertEqual(
            ledger.issue_receipt(late_inclusion, LedgerWindow(0, 2, 9), 1).code,
            ReceiptCode.REJECTED_OUTSIDE_WINDOW,
        )
        framed = ledger.submit(2, b"named-one", 1)
        framed_inclusion = ledger.include(framed.tx_id, 3)
        self.assertEqual(
            ledger.issue_receipt(framed_inclusion, LedgerWindow(0, 2, 9), 1).code,
            ReceiptCode.REJECTED_UNAUTHORIZED,
        )
        self.assertEqual(len(ledger.observations.view(actor=99)), 4)

    def test_random_tape_replay_and_exhaustion(self):
        first = RandomTape.from_seed(17, 3)
        second = RandomTape.from_seed(17, 3)
        self.assertEqual([first.draw_below(11) for _ in range(3)], [second.draw_below(11) for _ in range(3)])
        with self.assertRaises(RuntimeError):
            first.draw_below(11)


if __name__ == "__main__":
    unittest.main()
