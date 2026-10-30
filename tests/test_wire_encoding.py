import unittest

from accountable_dkg.protocol.encoding import EncodingError, Reader, blob, text, u16
from accountable_dkg.protocol.messages import KeyBody, MessageKind, Packet, RandexBody

from batch03_helpers import KEYS, PROVIDER, accepted_anchor, session


class WireEncodingTests(unittest.TestCase):
    def packets(self):
        ctx = session()
        anchor = accepted_anchor(ctx)
        return (
            Packet(ctx.session_id, anchor.metadata.reference_id, MessageKind.RANDEX, 1, RandexBody(2, b"f", b"column", b"proof")).sign(PROVIDER, KEYS[0]),
            Packet(ctx.session_id, anchor.metadata.reference_id, MessageKind.KEY, 2, KeyBody(b"x", b"y", b"proof")).sign(PROVIDER, KEYS[1]),
        )

    def test_roundtrip_is_stable_and_unique(self):
        for packet in self.packets():
            raw = packet.encode()
            decoded = Packet.decode(raw)
            self.assertEqual(decoded, packet)
            self.assertEqual(decoded.encode(), raw)

    def test_truncated_and_trailing_encodings_are_rejected(self):
        raw = self.packets()[0].encode()
        for end in range(len(raw)):
            with self.assertRaises(EncodingError):
                Packet.decode(raw[:end])
        with self.assertRaisesRegex(EncodingError, "trailing"):
            Packet.decode(raw + b"x")

    def test_oversized_and_noncanonical_fields_are_rejected(self):
        with self.assertRaises(EncodingError):
            blob(b"abc", maximum=2)
        with self.assertRaises(EncodingError):
            text("\u03bb")
        with self.assertRaises(EncodingError):
            u16(1 << 16)
        reader = Reader((1 << 20 | 1).to_bytes(4, "big"))
        with self.assertRaisesRegex(EncodingError, "exceeds"):
            reader.blob(maximum=1 << 20)

    def test_group_like_bytes_are_not_validated_by_parser(self):
        ctx = session()
        anchor = accepted_anchor(ctx)
        packet = Packet(ctx.session_id, anchor.metadata.reference_id, MessageKind.KEY, 1, KeyBody(b"not-a-point", b"still-bytes", b"not-a-proof"))
        self.assertEqual(Packet.decode(packet.encode()).body.public_x, b"not-a-point")


if __name__ == "__main__":
    unittest.main()
