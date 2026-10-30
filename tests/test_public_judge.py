import unittest
from dataclasses import replace

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.pedersen import Q, decode_scalar, encode_scalar
from accountable_dkg.execution.ledger_adapter import LedgerAdapter, LedgerAssumptions, LedgerWindow
from accountable_dkg.protocol.acss import (
    EncryptedShare, RecoveryKeyUseRegistry, SignedAcssDealing, authenticate_dealing,
    create_dealing,
)
from accountable_dkg.protocol.evidence_producer import Incident
from accountable_dkg.protocol.messages import AuthenticatedPacket, KeyBody, Packet, RandexBody
from accountable_dkg.protocol.public_evidence import PublicEvidence
from accountable_dkg.protocol.public_judge import JudgeCode, PublicJudge
from accountable_dkg.protocol.recovery import Dev1Incident, ImplicationEvidence

from batch07_helpers import complete_fixture


class PublicJudgeTests(unittest.TestCase):
    def setUp(self):
        self.session, self.provider, self.pairs, _, self.machines = complete_fixture()
        anchor = self.machines[1].anchor
        commitments = self.machines[1].commitments
        assert anchor is not None and commitments is not None
        self.judge = PublicJudge(self.session, anchor.reference_id, commitments, self.provider)

    def finalized_input(self, payload, actor=1):
        ledger = LedgerAdapter(frozenset({1, 2, 3, 4}), LedgerAssumptions(1 << 20))
        submission = ledger.submit(actor, payload, 0)
        inclusion = ledger.include(submission.tx_id, 1)
        receipt = ledger.issue_receipt(inclusion, LedgerWindow(0, 0, 4), actor)
        finality = ledger.finalize(inclusion, 2)
        return ledger, ledger.finalized_input(finality, receipt)

    @staticmethod
    def authenticated(packet):
        raw = packet.encode()
        return AuthenticatedPacket(packet, raw)

    def invalid_randex(self, sender=4, recipient=1):
        original = self.machines[sender].emit_randex()[recipient - 1]
        assert isinstance(original.body, RandexBody)
        bad_share = (decode_scalar(original.body.fragment) + 1) % Q
        return Packet(
            original.session_id, original.anchor_id, original.kind, sender,
            RandexBody(recipient, encode_scalar(bad_share), original.body.commitment_column, original.body.proof),
        ).sign(self.provider, self.pairs[sender - 1][0])

    def test_finalized_dev2_dev3_and_dev4_are_attributed(self):
        valid_randex = self.machines[4].emit_randex()[0]
        bad_randex = self.invalid_randex()
        dev2 = Incident(
            "Dev2", bad_randex.slot(),
            (self.authenticated(valid_randex), self.authenticated(bad_randex)),
        )
        _, finalized = self.finalized_input(PublicEvidence.packet(dev2).encode())
        verdict = self.judge.adjudicate(finalized)
        self.assertEqual((verdict.code, verdict.accused, verdict.deviation), (JudgeCode.ATTRIBUTED, 4, "Dev2"))

        dev3 = Incident("Dev3", bad_randex.slot(), (self.authenticated(bad_randex),))
        _, finalized = self.finalized_input(PublicEvidence.packet(dev3).encode())
        self.assertEqual(self.judge.adjudicate(finalized).accused, 4)

        original_key = self.machines[4].emit_key()
        assert isinstance(original_key.body, KeyBody)
        altered = bytes([original_key.body.proof[0] ^ 1]) + original_key.body.proof[1:]
        bad_key = Packet(
            original_key.session_id, original_key.anchor_id, original_key.kind, 4,
            KeyBody(original_key.body.public_x, original_key.body.public_y, altered),
        ).sign(self.provider, self.pairs[3][0])
        dev4 = Incident("Dev4", bad_key.slot(), (self.authenticated(bad_key),))
        _, finalized = self.finalized_input(PublicEvidence.packet(dev4).encode())
        self.assertEqual(self.judge.adjudicate(finalized).accused, 4)

    def test_invalid_signature_and_valid_packet_cannot_frame(self):
        valid = self.machines[4].emit_key()
        invalid_signature = replace(
            valid, signature=bytes([valid.signature[0] ^ 1]) + valid.signature[1:]
        )
        incident = Incident(
            "Dev4", invalid_signature.slot(), (self.authenticated(invalid_signature),)
        )
        _, finalized = self.finalized_input(PublicEvidence.packet(incident).encode())
        verdict = self.judge.adjudicate(finalized)
        self.assertEqual(verdict.code, JudgeCode.REJECTED)
        self.assertIsNone(verdict.accused)

        valid_incident = Incident("Dev4", valid.slot(), (self.authenticated(valid),))
        _, finalized = self.finalized_input(PublicEvidence.packet(valid_incident).encode())
        self.assertEqual(self.judge.adjudicate(finalized).code, JudgeCode.REJECTED)

    def test_genuine_dev1_is_attributed_but_false_implication_is_not(self):
        recovery_pairs = [HybridEncryptionProvider.generate_keypair() for _ in range(4)]
        private = {i + 1: pair[0] for i, pair in enumerate(recovery_pairs)}
        public = {i + 1: pair[1] for i, pair in enumerate(recovery_pairs)}
        dealing = create_dealing(
            self.session.session_id, 1, 1, 23, public, RecoveryKeyUseRegistry(),
            nonce=b"batch08-dev1-key", coefficients=(23, 5), blindings=(7, 11),
        )
        shares = list(dealing.encrypted_shares)
        ciphertext = shares[0].ciphertext
        shares[0] = EncryptedShare(1, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
        faulty = replace(dealing, encrypted_shares=tuple(shares))
        signed = SignedAcssDealing.sign(faulty, self.provider, self.pairs[0][0])
        authenticated = authenticate_dealing(signed, self.provider, self.pairs[0][1]).authenticated
        assert authenticated is not None
        incident = Dev1Incident(
            authenticated, ImplicationEvidence(faulty.dealing_id, 1, private[1])
        )
        _, finalized = self.finalized_input(PublicEvidence.dev1(incident).encode())
        verdict = self.judge.adjudicate(finalized)
        self.assertEqual((verdict.code, verdict.accused), (JudgeCode.ATTRIBUTED, 1))

        honest_signed = SignedAcssDealing.sign(dealing, self.provider, self.pairs[0][0])
        honest_authenticated = authenticate_dealing(
            honest_signed, self.provider, self.pairs[0][1]
        ).authenticated
        assert honest_authenticated is not None
        false_incident = Dev1Incident(
            honest_authenticated, ImplicationEvidence(dealing.dealing_id, 1, private[1])
        )
        _, finalized = self.finalized_input(PublicEvidence.dev1(false_incident).encode())
        self.assertEqual(self.judge.adjudicate(finalized).code, JudgeCode.REJECTED)

    def test_unfinalized_or_receipt_rejected_evidence_is_not_judge_input(self):
        bad = self.invalid_randex()
        incident = Incident("Dev3", bad.slot(), (self.authenticated(bad),))
        payload = PublicEvidence.packet(incident).encode()
        ledger = LedgerAdapter(frozenset({1}), LedgerAssumptions(1 << 20))
        submission = ledger.submit(1, payload, 0)
        inclusion = ledger.include(submission.tx_id, 5)
        receipt = ledger.issue_receipt(inclusion, LedgerWindow(0, 0, 5), 1)
        finality = ledger.finalize(inclusion, 6)
        verdict = self.judge.adjudicate(ledger.finalized_input(finality, receipt))
        self.assertEqual(verdict.code, JudgeCode.REJECTED)


if __name__ == "__main__":
    unittest.main()
