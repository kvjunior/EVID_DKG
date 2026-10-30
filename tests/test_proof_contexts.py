import unittest

from accountable_dkg.crypto.decryption_proofs import DecryptionAttestationProvider
from accountable_dkg.crypto.interfaces import CheckCode
from accountable_dkg.crypto.signatures import Ed25519SignatureProvider


class ProofContextTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public = Ed25519SignatureProvider.generate_keypair()
        self.provider = DecryptionAttestationProvider()
        self.ciphertext = b"ciphertext"
        self.plaintext = b"plaintext"
        self.context = b"session/round/dealer/recipient"
        self.attestation = self.provider.attest(
            self.private, self.ciphertext, self.plaintext, self.context
        )

    def test_attestation_accepts_exact_context(self):
        self.assertTrue(self.provider.verify(
            self.public, self.ciphertext, self.plaintext, self.context, self.attestation
        ).accepted)

    def test_wrong_context_key_ciphertext_or_plaintext_rejected(self):
        wrong_private, wrong_public = Ed25519SignatureProvider.generate_keypair()
        del wrong_private
        cases = (
            (wrong_public, self.ciphertext, self.plaintext, self.context),
            (self.public, b"other-ciphertext", self.plaintext, self.context),
            (self.public, self.ciphertext, b"other-plaintext", self.context),
            (self.public, self.ciphertext, self.plaintext, b"other-context"),
        )
        for args in cases:
            with self.subTest(args=args):
                self.assertFalse(self.provider.verify(*args, self.attestation).accepted)

    def test_malformed_attestation_is_typed(self):
        result = self.provider.verify(self.public, self.ciphertext, self.plaintext, self.context, b"bad")
        self.assertEqual(result.code, CheckCode.MALFORMED)


if __name__ == "__main__":
    unittest.main()
