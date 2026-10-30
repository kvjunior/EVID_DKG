import unittest

from accountable_dkg.protocol.messages import KeyBody, MessageKind, Packet, PublishedPayload, RandexBody

from batch03_helpers import accepted_anchor, session


class SemanticSlotTests(unittest.TestCase):
    def packet(self, body, kind=MessageKind.KEY):
        ctx = session()
        anchor = accepted_anchor(ctx)
        return Packet(ctx.session_id, anchor.metadata.reference_id, kind, 1, body)

    def test_randex_recipients_are_distinct_slots(self):
        first = self.packet(RandexBody(2, b"f", b"c", b"p"), MessageKind.RANDEX)
        second = self.packet(RandexBody(3, b"f", b"c", b"p"), MessageKind.RANDEX)
        self.assertNotEqual(first.slot(), second.slot())
        self.assertFalse(first.semantically_conflicts(second))

    def test_randomized_key_proofs_do_not_create_dev2(self):
        first = self.packet(KeyBody(b"x", b"y", b"proof-one"))
        second = self.packet(KeyBody(b"x", b"y", b"proof-two"))
        self.assertEqual(first.slot(), second.slot())
        self.assertEqual(first.semantic_bytes(), second.semantic_bytes())
        self.assertFalse(first.semantically_conflicts(second))

    def test_different_key_value_in_one_slot_conflicts(self):
        first = self.packet(KeyBody(b"x", b"y", b"proof"))
        second = self.packet(KeyBody(b"different", b"y", b"proof"))
        self.assertTrue(first.semantically_conflicts(second))

    def test_published_payload_requires_immutable_bytes(self):
        payload = PublishedPayload(b"fixed")
        self.assertEqual(payload.raw_bytes, b"fixed")
        with self.assertRaises(Exception):
            payload.raw_bytes = b"changed"
        with self.assertRaises(Exception):
            PublishedPayload({"mutable": True})


if __name__ == "__main__":
    unittest.main()
