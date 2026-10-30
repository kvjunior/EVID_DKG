import unittest
from dataclasses import replace

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.protocol.acss import EncryptedShare, RecoveryKeyUseRegistry, create_dealing
from accountable_dkg.protocol.recovery import (
    ImplicationEvidence, RecoveryRelease, RecoverySession, verify_implication,
)


def key_material(count):
    pairs = [HybridEncryptionProvider.generate_keypair() for _ in range(count)]
    return ({i + 1: pair[0] for i, pair in enumerate(pairs)},
            {i + 1: pair[1] for i, pair in enumerate(pairs)})


def corrupt_ciphertext(dealing, recipient=1):
    items = list(dealing.encrypted_shares)
    original = items[recipient - 1]
    bad = original.ciphertext[:-1] + bytes([original.ciphertext[-1] ^ 1])
    items[recipient - 1] = EncryptedShare(recipient, bad)
    return replace(dealing, encrypted_shares=tuple(items))


class RecoveryExposureTests(unittest.TestCase):
    def setUp(self):
        self.private, public = key_material(7)
        self.dealing = create_dealing(
            b"r" * 32, 2, 2, 41, public, RecoveryKeyUseRegistry(),
            nonce=b"batch06-recovery", coefficients=(41, 3, 8), blindings=(5, 9, 12),
        )

    def test_false_implication_is_rejected(self):
        evidence = ImplicationEvidence(self.dealing.dealing_id, 1, self.private[1])
        verdict = verify_implication(self.dealing, evidence)
        self.assertFalse(verdict.accepted)
        self.assertIn("false implication", verdict.reason)
        with self.assertRaisesRegex(ValueError, "genuine implication"):
            RecoverySession(self.dealing, evidence)

    def test_genuine_implication_enables_threshold_recovery_and_counts_exposure(self):
        faulty = corrupt_ciphertext(self.dealing)
        evidence = ImplicationEvidence(faulty.dealing_id, 1, self.private[1])
        self.assertTrue(verify_implication(faulty, evidence).accepted)
        recovery = RecoverySession(faulty, evidence)
        for recipient in (2, 3, 4):
            self.assertTrue(recovery.add_release(RecoveryRelease(
                faulty.dealing_id, recipient, self.private[recipient]
            )))
        result = recovery.recover()
        self.assertEqual(result.secret, 41)
        self.assertEqual(result.exposed_recipients, (1, 2, 3, 4))
        self.assertEqual(result.exposed_key_bytes, 128)
        self.assertEqual(len(result.shares), 7)

    def test_duplicate_wrong_scope_and_insufficient_releases_fail(self):
        faulty = corrupt_ciphertext(self.dealing)
        recovery = RecoverySession(faulty, ImplicationEvidence(faulty.dealing_id, 1, self.private[1]))
        release = RecoveryRelease(faulty.dealing_id, 2, self.private[2])
        self.assertTrue(recovery.add_release(release))
        self.assertFalse(recovery.add_release(release))
        self.assertFalse(recovery.add_release(RecoveryRelease(b"x" * 32, 3, self.private[3])))
        with self.assertRaisesRegex(ValueError, "insufficient"):
            recovery.recover()


if __name__ == "__main__":
    unittest.main()
