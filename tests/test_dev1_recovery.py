import unittest
from dataclasses import replace

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.signatures import Ed25519SignatureProvider
from accountable_dkg.execution.events import EventKind, EventSource, LogicalEvent
from accountable_dkg.protocol.acss import (
    EncryptedShare, RecoveryKeyUseRegistry, SignedAcssDealing, authenticate_dealing,
    create_dealing, inspect_share,
)
from accountable_dkg.protocol.recovery import (
    Dev1Delivery, Dev1Receipt, Dev1ReportingController, ImplicationEvidence, verify_implication,
)


def key_material(count):
    pairs = [HybridEncryptionProvider.generate_keypair() for _ in range(count)]
    return ({i + 1: pair[0] for i, pair in enumerate(pairs)},
            {i + 1: pair[1] for i, pair in enumerate(pairs)})


class Dev1RecoveryTests(unittest.TestCase):
    def test_recovery_keys_cannot_be_reused_across_dealings(self):
        private, public = key_material(4)
        registry = RecoveryKeyUseRegistry()
        create_dealing(b"s" * 32, 1, 1, 5, public, registry, nonce=b"first-dealing-key")
        with self.assertRaisesRegex(ValueError, "already bound"):
            create_dealing(b"s" * 32, 2, 1, 7, public, registry, nonce=b"second-dealingkey")
        del private

    def test_copied_ciphertext_is_bound_to_original_instance(self):
        private_a, public_a = key_material(4)
        private_b, public_b = key_material(4)
        registry = RecoveryKeyUseRegistry()
        honest = create_dealing(b"s" * 32, 1, 1, 13, public_a, registry, nonce=b"honest-instance!")
        corrupt = create_dealing(b"s" * 32, 2, 1, 29, public_b, registry, nonce=b"corrupt-instance")
        copied = list(corrupt.encrypted_shares)
        copied[0] = EncryptedShare(1, honest.encrypted_shares[0].ciphertext)
        copied_dealing = replace(corrupt, encrypted_shares=tuple(copied))
        check = inspect_share(copied_dealing, 1, private_b[1])
        self.assertFalse(check.valid)
        self.assertIsNone(check.share)
        verdict = verify_implication(
            copied_dealing,
            ImplicationEvidence(copied_dealing.dealing_id, 1, private_b[1]),
        )
        self.assertTrue(verdict.accepted)
        self.assertIsNone(verdict.check.share)
        # The exposed key for the corrupt-labelled instance cannot decrypt the
        # original honest ciphertext because the registered keys differ.
        self.assertFalse(inspect_share(honest, 1, private_b[1]).valid)
        self.assertTrue(inspect_share(honest, 1, private_a[1]).valid)

    def test_authenticated_dev1_controller_holds_retries_and_stops_terminally(self):
        private, public = key_material(4)
        dealing = create_dealing(
            b"d" * 32, 1, 1, 9, public, RecoveryKeyUseRegistry(), nonce=b"dev1-controller!"
        )
        items = list(dealing.encrypted_shares)
        bad = items[0].ciphertext[:-1] + bytes([items[0].ciphertext[-1] ^ 1])
        items[0] = EncryptedShare(1, bad)
        faulty = replace(dealing, encrypted_shares=tuple(items))
        signatures = Ed25519SignatureProvider()
        signing_key, verification_key = signatures.generate_keypair()
        signed = SignedAcssDealing.sign(faulty, signatures, signing_key)
        authenticated = authenticate_dealing(signed, signatures, verification_key).authenticated
        self.assertIsNotNone(authenticated)
        controller = Dev1ReportingController(1, b"d" * 32)
        delivery = Dev1Delivery(authenticated, 1, private[1])
        self.assertEqual(controller.step(LogicalEvent(1, 0, EventSource.NETWORK, EventKind.ACSS_DELIVERY, delivery)), ())
        first = controller.step(LogicalEvent(2, 1, EventSource.LEDGER, EventKind.WINDOW_OPEN, 1))
        self.assertEqual(len(first), 1)
        controller.step(LogicalEvent(3, 2, EventSource.LEDGER, EventKind.WINDOW_CLOSE, 1))
        second = controller.step(LogicalEvent(4, 3, EventSource.LEDGER, EventKind.WINDOW_OPEN, 2))
        self.assertEqual(len(second), 1)
        incident_id = first[0].incident.incident_id
        controller.step(LogicalEvent(5, 4, EventSource.LEDGER, EventKind.RECEIPT, Dev1Receipt(incident_id, True)))
        controller.step(LogicalEvent(6, 5, EventSource.LEDGER, EventKind.WINDOW_CLOSE, 2))
        self.assertEqual(controller.step(LogicalEvent(7, 6, EventSource.LEDGER, EventKind.WINDOW_OPEN, 3)), ())


if __name__ == "__main__":
    unittest.main()
