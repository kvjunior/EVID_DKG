import unittest

from accountable_dkg.protocol.encoding import EncodingError
from accountable_dkg.protocol.session import Participant, Roster, SessionContext

from batch03_helpers import session


class SessionContextTests(unittest.TestCase):
    def test_session_roundtrip_and_identity(self):
        ctx = session()
        self.assertEqual(SessionContext.decode(ctx.encode()), ctx)
        self.assertEqual(SessionContext.decode(ctx.encode()).session_id, ctx.session_id)

    def test_every_bound_session_field_changes_identity(self):
        base = session()
        variants = (
            session(version=2),
            SessionContext(base.protocol, base.version, base.epoch + 1, base.threshold, base.field_modulus, base.nonce, base.roster),
            SessionContext(base.protocol, base.version, base.epoch, 2, base.field_modulus, base.nonce, base.roster),
            SessionContext(base.protocol, base.version, base.epoch, base.threshold, base.field_modulus - 2, base.nonce, base.roster),
            session(nonce=b"fedcba9876543210"),
        )
        for variant in variants:
            self.assertNotEqual(variant.session_id, base.session_id)

    def test_roster_is_fixed_ordered_and_unique(self):
        with self.assertRaises(EncodingError):
            Roster((Participant(2, b"b"), Participant(1, b"a")))
        with self.assertRaises(EncodingError):
            Roster((Participant(1, b"same"), Participant(2, b"same")))
        with self.assertRaises(EncodingError):
            Roster((Participant(1, b"one"),))

    def test_decoder_rejects_trailing_bytes(self):
        with self.assertRaisesRegex(EncodingError, "trailing"):
            SessionContext.decode(session().encode() + b"extra")


if __name__ == "__main__":
    unittest.main()
