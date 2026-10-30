import unittest

from accountable_dkg.crypto.commitments import Sha256CommitmentProvider


class CommitmentRelationTests(unittest.TestCase):
    def test_opening_relation_and_domain_changes(self):
        provider = Sha256CommitmentProvider()
        opening = bytes(range(32))
        commitment, returned = provider.commit(b"message", opening)
        self.assertEqual(returned, opening)
        self.assertTrue(provider.verify(commitment, b"message", opening))
        self.assertFalse(provider.verify(commitment, b"different", opening))
        self.assertFalse(provider.verify(commitment, b"message", bytes(reversed(opening))))

    def test_malformed_openings_and_commitments(self):
        provider = Sha256CommitmentProvider()
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            provider.commit(b"message", b"short")
        self.assertFalse(provider.verify(b"short", b"message", b"x" * 32))


if __name__ == "__main__":
    unittest.main()
