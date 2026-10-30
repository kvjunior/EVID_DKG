import unittest
from hashlib import sha256

from accountable_dkg.crypto.interfaces import CheckCode
from accountable_dkg.protocol.anchors import AnchorKind, AnchorMetadata, AnchorSet, accept_anchor
from accountable_dkg.protocol.messages import KeyBody, MessageKind, Packet, authenticate_packet

from batch03_helpers import KEYS, PROVIDER, accepted_anchor, anchor_set, session
from ideal_providers import IdealAnchorVerifier


class AuthenticationContextTests(unittest.TestCase):
    def signed_key(self, ctx=None, sender=1):
        ctx = ctx or session()
        anchor = accepted_anchor(ctx)
        packet = Packet(ctx.session_id, anchor.metadata.reference_id, MessageKind.KEY, sender, KeyBody(b"x", b"y", b"proof"))
        return ctx, anchor, packet.sign(PROVIDER, KEYS[sender - 1])

    def test_authentic_packet_is_attributable_only_after_anchor_acceptance(self):
        ctx, anchor, packet = self.signed_key()
        refused = authenticate_packet(packet.encode(), ctx, AnchorSet(), PROVIDER)
        self.assertEqual(refused.result.code, CheckCode.INVALID_ANCHOR)
        self.assertIsNone(refused.authenticated)
        accepted = authenticate_packet(packet.encode(), ctx, AnchorSet((anchor,)), PROVIDER)
        self.assertTrue(accepted.result.accepted)
        self.assertEqual(accepted.authenticated.raw_bytes, packet.encode())

    def test_rebinding_each_authenticated_context_fails(self):
        ctx, anchor, packet = self.signed_key()
        anchors = AnchorSet((anchor,))
        mutations = (
            Packet(b"s" * 32, packet.anchor_id, packet.kind, packet.sender, packet.body, packet.signature),
            Packet(packet.session_id, b"a" * 32, packet.kind, packet.sender, packet.body, packet.signature),
            Packet(packet.session_id, packet.anchor_id, packet.kind, 2, packet.body, packet.signature),
            Packet(packet.session_id, packet.anchor_id, packet.kind, packet.sender, KeyBody(b"changed", b"y", b"proof"), packet.signature),
        )
        for mutation in mutations:
            self.assertFalse(authenticate_packet(mutation.encode(), ctx, anchors, PROVIDER).result.accepted)
        different_version = session(version=2)
        self.assertFalse(authenticate_packet(packet.encode(), different_version, anchors, PROVIDER).result.accepted)

    def test_unknown_sender_never_becomes_attributable(self):
        ctx, anchor, packet = self.signed_key()
        unknown = Packet(packet.session_id, packet.anchor_id, packet.kind, 99, packet.body).sign(PROVIDER, b"unknown")
        result = authenticate_packet(unknown.encode(), ctx, AnchorSet((anchor,)), PROVIDER)
        self.assertEqual(result.result.code, CheckCode.MALFORMED)
        self.assertIsNone(result.authenticated)

    def test_digest_does_not_accept_an_anchor(self):
        ctx = session()
        metadata = AnchorMetadata(ctx.session_id, AnchorKind.DEALING, 1, sha256(b"payload").digest())
        bad = accept_anchor(metadata, b"payload", IdealAnchorVerifier())
        self.assertEqual(bad.result.code, CheckCode.INVALID_ANCHOR)
        self.assertIsNone(bad.anchor)


if __name__ == "__main__":
    unittest.main()
