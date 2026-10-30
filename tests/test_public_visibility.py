import unittest

from accountable_dkg.accounting.communication import CommunicationAccount
from accountable_dkg.execution.observation import Observation, ObservationLog, Visibility


class PublicVisibilityTests(unittest.TestCase):
    def test_local_anchor_readiness_is_not_public(self):
        log = ObservationLog()
        log.append(Observation(1, "anchor_ready", Visibility.LOCAL_PRIVATE, 1, b"anchor"))
        log.append(Observation(2, "delivery_notice", Visibility.SIMULATOR_METADATA, 1, b"metadata"))
        log.append(Observation(3, "included", Visibility.PUBLIC_LEDGER, 1, b"public"))
        self.assertEqual([item.payload for item in log.view(actor=2)], [b"public"])
        self.assertEqual([item.payload for item in log.view(actor=1)], [b"anchor", b"public"])
        self.assertEqual([item.payload for item in log.view(simulator=True)], [b"metadata", b"public"])

    def test_accounting_categories_do_not_collapse(self):
        account = CommunicationAccount()
        account.charge_submitted(100)
        account.charge_included(60, rejected=True)
        account.charge_read(300)
        account.charge_private(900)
        self.assertEqual(account.snapshot(), {
            "submitted_bytes": 100,
            "included_bytes": 60,
            "rejected_included_bytes": 60,
            "read_bytes": 300,
            "private_bytes": 900,
        })

    def test_observation_payloads_are_immutable_bytes(self):
        with self.assertRaises(TypeError):
            Observation(0, "bad", Visibility.PUBLIC_LEDGER, None, {"mutable": True})


if __name__ == "__main__":
    unittest.main()
