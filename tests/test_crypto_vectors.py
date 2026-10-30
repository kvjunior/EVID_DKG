import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from accountable_dkg.crypto.backends import PINNED_CRYPTOGRAPHY_VERSION, backend_info
from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.interfaces import CheckCode
from accountable_dkg.crypto.signatures import Ed25519SignatureProvider
from accountable_dkg.protocol.anchors import AnchorKind, AnchorMetadata, AnchorSet, accept_anchor
from accountable_dkg.protocol.messages import KeyBody, MessageKind, Packet, authenticate_packet
from accountable_dkg.protocol.session import Participant, Roster, SessionContext
from ideal_providers import IdealAnchorVerifier


class CryptoVectorTests(unittest.TestCase):
    def test_backend_pin(self):
        info = backend_info()
        self.assertEqual(info.version, PINNED_CRYPTOGRAPHY_VERSION)

    def test_rfc8032_ed25519_test_1(self):
        private = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        expected = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        provider = Ed25519SignatureProvider()
        signature = provider.sign(private, b"")
        self.assertEqual(signature, expected)
        self.assertTrue(provider.verify(public, b"", signature).accepted)
        self.assertEqual(provider.verify(public, b"x", signature).code, CheckCode.INVALID_SIGNATURE)

    def test_rfc7748_x25519_vector(self):
        scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        coordinate = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        actual = X25519PrivateKey.from_private_bytes(scalar).exchange(X25519PublicKey.from_public_bytes(coordinate))
        self.assertEqual(actual, expected)

    def test_rfc5869_hkdf_sha256_case_1(self):
        output = HKDF(
            algorithm=hashes.SHA256(), length=42,
            salt=bytes.fromhex("000102030405060708090a0b0c"),
            info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        ).derive(bytes.fromhex("0b" * 22))
        self.assertEqual(output.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865")

    def test_rfc8439_chacha20poly1305_vector(self):
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
            b"tip for the future, sunscreen would be it."
        )
        # RFC 8439 prints the 114-byte ciphertext followed by the 16-byte tag.
        expected = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600"
            "691"
        )
        self.assertEqual(ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad), expected)

    def test_context_bound_hybrid_roundtrip_and_tamper_rejection(self):
        provider = HybridEncryptionProvider()
        private, public = provider.generate_keypair()
        ciphertext = provider.encrypt(public, b"share", b"session/recipient/slot")
        self.assertEqual(provider.decrypt(private, ciphertext, b"session/recipient/slot"), b"share")
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            provider.decrypt(private, ciphertext, b"different-context")
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            provider.decrypt(private, tampered, b"session/recipient/slot")

    def test_malformed_ed25519_inputs_are_typed(self):
        provider = Ed25519SignatureProvider()
        self.assertEqual(provider.verify(b"short", b"m", b"x" * 64).code, CheckCode.MALFORMED)
        _, public = provider.generate_keypair()
        self.assertEqual(provider.verify(public, b"m", b"short").code, CheckCode.INVALID_SIGNATURE)

    def test_real_provider_crosses_packet_authentication_boundary(self):
        provider = Ed25519SignatureProvider()
        private_one, public_one = provider.generate_keypair()
        _, public_two = provider.generate_keypair()
        session = SessionContext(
            "EVID-DKG", 1, 1, 1, 2**255 - 19, b"batch05-session!!",
            Roster((Participant(1, public_one), Participant(2, public_two))),
        )
        metadata = AnchorMetadata(session.session_id, AnchorKind.AGREEMENT, 1, b"d" * 32)
        support = b"accepted:" + __import__("hashlib").sha256(metadata.encode()).digest()
        anchor = accept_anchor(metadata, support, IdealAnchorVerifier()).anchor
        self.assertIsNotNone(anchor)
        packet = Packet(
            session.session_id, metadata.reference_id, MessageKind.KEY, 1,
            KeyBody(b"x", b"y", b"proof"),
        ).sign(provider, private_one)
        result = authenticate_packet(packet.encode(), session, AnchorSet((anchor,)), provider)
        self.assertTrue(result.result.accepted)


if __name__ == "__main__":
    unittest.main()
