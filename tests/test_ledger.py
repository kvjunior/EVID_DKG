import unittest

from accountable_dkg.ledger import ToyLedger, Window


class LedgerTests(unittest.TestCase):
    def test_late_inclusion_is_rejected_and_public(self):
        ledger = ToyLedger({1: "alice"}, 100)
        tx = ledger.submit("alice", "dispute", {"revealed_key": "model-K"}, 20, 9)
        self.assertEqual(ledger.include(tx, 10, Window("dispute", 5, 10), 1),
                         "rejected_outside_window")
        self.assertEqual(ledger.transcript.public_payloads()[0]["revealed_key"], "model-K")
        self.assertEqual(ledger.transcript.costs()["included_bits"], 20)
        self.assertEqual(ledger.transcript.costs()["accepted_bits"], 0)

    def test_unauthorized_write_cannot_name_an_honest_party(self):
        ledger = ToyLedger({1: "alice", 2: "mallory"}, 100)
        tx = ledger.submit("mallory", "vote", {"key": "wrong"}, 20, 5)
        self.assertEqual(ledger.include(tx, 5, Window("key", 5, 10), 1),
                         "rejected_unauthorized")

    def test_capacity_defers_instead_of_inventing_bounded_inclusion(self):
        ledger = ToyLedger({1: "alice"}, 100)
        a = ledger.submit("alice", "x", {}, 70, 0)
        b = ledger.submit("alice", "x", {}, 70, 0)
        w = Window("x", 0, 3)
        self.assertEqual(ledger.include(a, 0, w, 1), "accepted")
        self.assertEqual(ledger.include(b, 0, w, 1), "capacity_deferred")
        self.assertEqual(ledger.include(b, 1, w, 1), "accepted")

    def test_download_cost_is_separate(self):
        ledger = ToyLedger({1: "alice"}, 100)
        ledger.transcript.charge_read("alice", 400)
        self.assertEqual(ledger.transcript.costs()["total_read_bits"], 400)
        self.assertEqual(ledger.transcript.costs()["included_bits"], 0)

    def test_missing_authenticated_actor_is_rejected(self):
        ledger = ToyLedger({1: "alice"}, 100)
        with self.assertRaises(ValueError):
            ledger.submit(None, "vote", {}, 20, 0)

    def test_unknown_party_is_rejected(self):
        ledger = ToyLedger({1: "alice"}, 100)
        tx = ledger.submit("alice", "vote", {}, 20, 0)
        self.assertEqual(ledger.include(tx, 0, Window("key", 0, 2), 9),
                         "rejected_unauthorized")
