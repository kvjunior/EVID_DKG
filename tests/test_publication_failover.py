import unittest

from accountable_dkg.execution.ledger_adapter import (
    LedgerAdapter, LedgerAssumptions, LedgerWindow, ReceiptCode,
)
from accountable_dkg.protocol.finalization import (
    FinalizationCertificate, FinalizationValue, FinalizationVote,
)
from accountable_dkg.protocol.publication import (
    PublicationCoordinator, PublicationSchedule, verify_finalized_publication,
)

from batch07_helpers import complete_fixture


class PublicationFailoverTests(unittest.TestCase):
    def setUp(self):
        self.session, self.provider, self.pairs, _, self.machines = complete_fixture()
        output = self.machines[1].output
        assert output is not None
        value = FinalizationValue.from_local_output(self.session.session_id, output)
        votes = tuple(
            FinalizationVote.sign(i, value, self.provider, self.pairs[i - 1][0])
            for i in (1, 2, 3)
        )
        self.certificate = FinalizationCertificate.build(votes, self.session, 1, self.provider)
        self.schedule = PublicationSchedule((1, 2, 3, 4))

    def test_rejected_primary_then_backup_finalizes_same_certificate(self):
        coordinators = {
            i: PublicationCoordinator(i, self.schedule, self.certificate)
            for i in (1, 2, 3, 4)
        }
        ledger = LedgerAdapter(frozenset({1, 2, 3, 4}), LedgerAssumptions(1 << 20))

        primary = coordinators[1].intent(0)
        self.assertIsNotNone(primary)
        first = ledger.submit(primary.publisher, primary.payload, 0)
        first_inclusion = ledger.include(first.tx_id, 2)
        first_receipt = ledger.issue_receipt(first_inclusion, LedgerWindow(0, 0, 2), 1)
        self.assertEqual(first_receipt.code, ReceiptCode.REJECTED_OUTSIDE_WINDOW)
        ledger.finalize(first_inclusion, 3)

        backup = coordinators[2].intent(1)
        self.assertIsNotNone(backup)
        second = ledger.submit(backup.publisher, backup.payload, 2)
        second_inclusion = ledger.include(second.tx_id, 3)
        second_receipt = ledger.issue_receipt(second_inclusion, LedgerWindow(1, 2, 5), 2)
        self.assertEqual(second_receipt.code, ReceiptCode.ACCEPTED_FOR_ADJUDICATION)
        second_finality = ledger.finalize(second_inclusion, 4)
        finalized_input = ledger.finalized_input(second_finality, second_receipt)
        terminal = ledger.adjudicate(second_receipt, True, 5)
        publication = verify_finalized_publication(
            finalized_input, terminal, self.session, 1, self.provider
        )
        self.assertEqual(publication.certificate.certificate_id, self.certificate.certificate_id)
        for coordinator in coordinators.values():
            coordinator.observe_finalized(publication)
        self.assertIsNone(coordinators[3].intent(2))

    def test_schedule_is_deterministic_and_one_intent_per_window(self):
        self.assertEqual([self.schedule.publisher(i) for i in range(6)], [1, 2, 3, 4, 1, 2])
        coordinator = PublicationCoordinator(1, self.schedule, self.certificate)
        self.assertIsNotNone(coordinator.intent(0))
        self.assertIsNone(coordinator.intent(0))
        self.assertIsNone(coordinator.intent(1))


if __name__ == "__main__":
    unittest.main()
