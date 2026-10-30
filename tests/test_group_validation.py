import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.groups import validate_p256_point, validate_x25519_public_key
from accountable_dkg.crypto.interfaces import CheckCode
from accountable_dkg.crypto.validation import ConcretePublicValueValidator


class GroupValidationTests(unittest.TestCase):
    def test_p256_compressed_point_and_wrong_encodings(self):
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        self.assertTrue(validate_p256_point(public).accepted)
        self.assertEqual(validate_p256_point(b"\x04" + b"\x00" * 32).code, CheckCode.MALFORMED)
        self.assertEqual(validate_p256_point(b"\x02" + b"\xff" * 32).code, CheckCode.INVALID_PUBLIC_VALUE)
        self.assertEqual(validate_p256_point(b"\x00").code, CheckCode.MALFORMED)

    def test_x25519_low_order_and_length_rejected(self):
        self.assertEqual(validate_x25519_public_key(b"\x00" * 32).code, CheckCode.INVALID_PUBLIC_VALUE)
        self.assertEqual(validate_x25519_public_key(b"\x01" * 31).code, CheckCode.MALFORMED)
        _, public = HybridEncryptionProvider.generate_keypair()
        self.assertTrue(validate_x25519_public_key(public).accepted)

    def test_purpose_separation(self):
        validator = ConcretePublicValueValidator()
        self.assertEqual(validator.validate("sha256_commitment", b"x" * 31).code, CheckCode.MALFORMED)
        self.assertEqual(validator.validate("unknown", b"x").code, CheckCode.MALFORMED)


if __name__ == "__main__":
    unittest.main()
