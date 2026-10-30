import unittest
from dataclasses import replace

from accountable_dkg.protocol.finalization import (
    FinalizationCertificate, FinalizationValue, FinalizationVote,
    FinalizationVoteRegistry,
)

from batch07_helpers import complete_fixture


class FinalizationCertificateTests(unittest.TestCase):
    def setUp(self):
        self.session, self.provider, self.pairs, _, self.machines = complete_fixture()
        output = self.machines[1].output
        assert output is not None
        self.value = FinalizationValue.from_local_output(self.session.session_id, output)

    def votes(self, signers=(1, 2, 3)):
        return tuple(
            FinalizationVote.sign(signer, self.value, self.provider, self.pairs[signer - 1][0])
            for signer in signers
        )

    def test_quorum_certificate_roundtrip_and_verification(self):
        certificate = FinalizationCertificate.build(
            self.votes(), self.session, 1, self.provider
        )
        decoded = FinalizationCertificate.decode(certificate.encode())
        self.assertEqual(decoded, certificate)
        self.assertTrue(decoded.verify(self.session, 1, self.provider))
        self.assertLess(len(certificate.encode()), sum(len(vote.encode()) for vote in certificate.votes))

    def test_insufficient_or_badly_signed_votes_do_not_certify(self):
        with self.assertRaisesRegex(ValueError, "valid quorum"):
            FinalizationCertificate.build(self.votes((1, 2)), self.session, 1, self.provider)
        votes = list(self.votes())
        votes[2] = replace(votes[2], signature=bytes([votes[2].signature[0] ^ 1]) + votes[2].signature[1:])
        with self.assertRaisesRegex(ValueError, "valid quorum"):
            FinalizationCertificate.build(tuple(votes), self.session, 1, self.provider)

    def test_mixed_values_and_local_double_signing_are_rejected(self):
        alternate = replace(self.value, public_key=self.value.threshold_public_keys[0][1])
        registry = FinalizationVoteRegistry()
        registry.sign(1, self.value, self.provider, self.pairs[0][0])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            registry.sign(1, alternate, self.provider, self.pairs[0][0])
        mixed = self.votes((1, 2)) + (
            FinalizationVote.sign(3, alternate, self.provider, self.pairs[2][0]),
        )
        with self.assertRaisesRegex(ValueError, "conflicting"):
            FinalizationCertificate.build(mixed, self.session, 1, self.provider)


if __name__ == "__main__":
    unittest.main()
