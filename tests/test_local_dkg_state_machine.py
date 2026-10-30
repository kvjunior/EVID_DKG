import unittest

from accountable_dkg.crypto.pedersen import Q, SCALAR_BYTES, decode_scalar, encode_scalar
from accountable_dkg.protocol.messages import KeyBody, Packet, RandexBody
from accountable_dkg.protocol.state_machine import LocalPhase

from batch07_helpers import build_fixture


class LocalDkgStateMachineTests(unittest.TestCase):
    def test_end_to_end_local_chain_produces_common_public_outputs(self):
        _, _, _, _, machines = build_fixture()
        anchors = [machine.accept_agreement((1, 2, 3, 4)).reference_id for machine in machines.values()]
        self.assertEqual(len(set(anchors)), 1)
        outbound = {sender: machines[sender].emit_randex() for sender in machines}
        for recipient, machine in machines.items():
            for sender in machines:
                self.assertTrue(machine.accept_randex(outbound[sender][recipient - 1]))
            self.assertEqual(machine.phase, LocalPhase.KEY)
        key_packets = {sender: machines[sender].emit_key() for sender in machines}
        for machine in machines.values():
            for sender in machines:
                self.assertTrue(machine.accept_key(key_packets[sender]))
            self.assertEqual(machine.phase, LocalPhase.COMPLETE)
        outputs = [machine.output for machine in machines.values()]
        self.assertTrue(all(output is not None for output in outputs))
        self.assertEqual(len({output.public_key for output in outputs}), 1)
        self.assertEqual(len({output.threshold_public_keys for output in outputs}), 1)

    def test_one_authentic_invalid_fragment_is_rejected_and_three_honest_reconstruct(self):
        session, provider, signing_pairs, _, machines = build_fixture()
        for machine in machines.values():
            machine.accept_agreement((1, 2, 3, 4))
        outbound = {sender: machines[sender].emit_randex() for sender in machines}
        recipient = 1
        target = machines[recipient]
        original = outbound[4][recipient - 1]
        assert isinstance(original.body, RandexBody)
        bad_share = (decode_scalar(original.body.fragment) + 1) % Q
        bad = Packet(
            original.session_id, original.anchor_id, original.kind, original.sender,
            RandexBody(recipient, encode_scalar(bad_share), original.body.commitment_column, original.body.proof),
        ).sign(provider, signing_pairs[3][0])
        self.assertFalse(target.accept_randex(bad))
        for sender in (1, 2, 3):
            self.assertTrue(target.accept_randex(outbound[sender][recipient - 1]))
        self.assertEqual(target.phase, LocalPhase.KEY)

    def test_randex_packets_received_before_agreement_are_replayed(self):
        _, _, _, _, machines = build_fixture()
        for sender in (1, 3, 4):
            machines[sender].accept_agreement((1, 2, 3, 4))
        outbound = {sender: machines[sender].emit_randex() for sender in (1, 3, 4)}
        target = machines[2]
        for sender in (1, 3, 4):
            self.assertFalse(target.accept_randex(outbound[sender][1]))
        self.assertEqual(target.phase, LocalPhase.SHARING)
        target.accept_agreement((1, 2, 3, 4))
        self.assertEqual(target.phase, LocalPhase.KEY)

    def test_excluded_dealer_is_zeroed_consistently_end_to_end(self):
        _, _, _, _, machines = build_fixture()
        for machine in machines.values():
            machine.accept_agreement((1, 2, 3))
        outbound = {sender: machines[sender].emit_randex() for sender in machines}
        for recipient, machine in machines.items():
            for sender in (1, 2, 3):
                self.assertTrue(machine.accept_randex(outbound[sender][recipient - 1]))
        keys = {sender: machines[sender].emit_key() for sender in machines}
        for machine in machines.values():
            for sender in (1, 2, 3):
                self.assertTrue(machine.accept_key(keys[sender]))
            self.assertEqual(machine.phase, LocalPhase.COMPLETE)
        outputs = [machine.output for machine in machines.values()]
        self.assertEqual(len({output.public_key for output in outputs if output is not None}), 1)

    def test_authentic_invalid_key_proof_is_rejected(self):
        _, provider, signing_pairs, _, machines = build_fixture()
        for machine in machines.values():
            machine.accept_agreement((1, 2, 3, 4))
        outbound = {sender: machines[sender].emit_randex() for sender in machines}
        target = machines[1]
        for recipient, machine in machines.items():
            for sender in (1, 2, 3):
                self.assertTrue(machine.accept_randex(outbound[sender][recipient - 1]))
        keys = {sender: machines[sender].emit_key() for sender in machines}
        original = keys[4]
        assert isinstance(original.body, KeyBody)
        altered = bytes([original.body.proof[0] ^ 1]) + original.body.proof[1:]
        bad = Packet(
            original.session_id, original.anchor_id, original.kind, original.sender,
            KeyBody(original.body.public_x, original.body.public_y, altered),
        ).sign(provider, signing_pairs[3][0])
        self.assertFalse(target.accept_key(bad))
        for sender in (1, 2, 3):
            self.assertTrue(target.accept_key(keys[sender]))
        self.assertEqual(target.phase, LocalPhase.COMPLETE)

    def test_session_field_uses_canonical_32_byte_group_order(self):
        session, _, _, _, _ = build_fixture()
        self.assertEqual(session.field_modulus, Q)
        self.assertEqual(SCALAR_BYTES, 32)
        self.assertEqual(decode_scalar(encode_scalar(Q - 1)), Q - 1)


if __name__ == "__main__":
    unittest.main()
