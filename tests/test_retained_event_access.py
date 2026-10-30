import unittest

from accountable_dkg.protocol.retained_events import (
    RetainedAccessError, RetainedEvent, RetainedEventStore,
)


class RetainedEventAccessTests(unittest.TestCase):
    def test_public_view_has_only_digests_and_proof_view_preserves_order(self):
        store = RetainedEventStore()
        capability = store.proof_capability()
        store.retain(RetainedEvent(2, b"slot-2", b"private-share-2"))
        store.retain(RetainedEvent(1, b"slot-1", b"private-share-1"))
        public = store.public_records()
        self.assertEqual(tuple(item.sequence for item in public), (1, 2))
        self.assertNotIn(b"private-share-1", repr(public).encode())
        self.assertEqual(tuple(item.sequence for item in store.read(capability)), (1, 2))
        with self.assertRaises(RetainedAccessError):
            store.read(object())

    def test_capability_gated_erasure_is_terminal(self):
        store = RetainedEventStore()
        capability = store.proof_capability()
        store.retain(RetainedEvent(1, b"slot", b"payload"))
        with self.assertRaises(RetainedAccessError):
            store.erase(object())
        store.erase(capability)
        self.assertEqual(store.read(capability), ())
        with self.assertRaisesRegex(ValueError, "sealed"):
            store.retain(RetainedEvent(2, b"slot", b"payload"))


if __name__ == "__main__":
    unittest.main()
