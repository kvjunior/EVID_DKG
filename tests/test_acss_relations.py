import unittest

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.pedersen import PedersenPolynomialCommitment, Q, evaluate
from accountable_dkg.protocol.acss import RecoveryKeyUseRegistry, create_dealing, inspect_share


def key_material(count):
    pairs = [HybridEncryptionProvider.generate_keypair() for _ in range(count)]
    return ({i + 1: pair[0] for i, pair in enumerate(pairs)},
            {i + 1: pair[1] for i, pair in enumerate(pairs)})


class AcssRelationTests(unittest.TestCase):
    def test_pedersen_polynomial_relation(self):
        values = (17, 5, 9)
        masks = (23, 11, 4)
        commitment = PedersenPolynomialCommitment.commit(values, masks)
        for index in range(1, 8):
            self.assertTrue(commitment.verify(index, evaluate(values, index), evaluate(masks, index)))
            self.assertFalse(commitment.verify(index, (evaluate(values, index) + 1) % Q, evaluate(masks, index)))

    def test_honest_encrypted_dealing_validates_for_every_recipient(self):
        private, public = key_material(7)
        dealing = create_dealing(
            b"s" * 32, 1, 2, 17, public, RecoveryKeyUseRegistry(),
            nonce=b"batch06-dealing!", coefficients=(17, 5, 9), blindings=(23, 11, 4),
        )
        self.assertEqual(dealing.commitment.degree, 2)
        for recipient in range(1, 8):
            check = inspect_share(dealing, recipient, private[recipient])
            self.assertTrue(check.valid)
            self.assertEqual(check.share, evaluate((17, 5, 9), recipient))

    def test_wrong_recipient_key_and_context_fail_closed(self):
        private, public = key_material(7)
        dealing = create_dealing(
            b"s" * 32, 1, 2, 7, public, RecoveryKeyUseRegistry(), nonce=b"batch06-context!"
        )
        check = inspect_share(dealing, 1, private[2])
        self.assertFalse(check.valid)
        self.assertIn("decryption failed", check.reason)


if __name__ == "__main__":
    unittest.main()
