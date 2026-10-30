import unittest

from accountable_dkg.crypto.pedersen import Q
from accountable_dkg.protocol.finalization import (
    FinalizationCertificate, FinalizationValue, FinalizationVote,
)
from accountable_dkg.protocol.publication import CertificatePublication
from accountable_dkg.simulation.end_to_end import EndToEndSimulator, SimulationCapabilities
from accountable_dkg.simulation.ideal import IdealDkgOutput
from accountable_dkg.simulation.leakage import Exposure, ExposureKind, StaticLeakagePolicy

from batch07_helpers import complete_fixture


class Batch09EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.session, self.provider, self.pairs, _, self.machines = complete_fixture()
        outputs = [self.machines[index].output for index in (1, 2, 3, 4)]
        assert all(output is not None for output in outputs)
        shares = tuple((output.participant, output.secret_share) for output in outputs)
        self.policy = StaticLeakagePolicy(4, 1, 2, frozenset({1}), frozenset({2}))
        self.ideal = IdealDkgOutput.from_shares(Q, 2, shares, self.policy.revealed_final_shares)
        value = FinalizationValue.from_local_output(self.session.session_id, outputs[0])
        votes = tuple(
            FinalizationVote.sign(index, value, self.provider, self.pairs[index - 1][0])
            for index in (1, 2, 3)
        )
        certificate = FinalizationCertificate.build(votes, self.session, 1, self.provider)
        self.public = (self.session.session_id, value.encode(), CertificatePublication(certificate).encode())

    def test_current_concrete_chain_fails_closed_on_missing_simulation_capabilities(self):
        result = EndToEndSimulator(self.policy).simulate(self.ideal, self.public)
        self.assertTrue(result.audit.accepted)
        self.assertFalse(result.conditional_execution_complete)
        self.assertIn("concrete_crs_trapdoor", result.missing_capabilities)
        self.assertIn("ledger_joint", result.missing_capabilities)
        self.assertFalse(result.unconditional_security_proved)

    def test_all_adapters_yield_only_a_conditional_execution_not_a_theorem(self):
        assumed = SimulationCapabilities(True, True, True, True, True, True)
        result = EndToEndSimulator(self.policy, assumed).simulate(self.ideal, self.public)
        self.assertTrue(result.conditional_execution_complete)
        self.assertEqual(result.missing_capabilities, ())
        self.assertIsNotNone(result.simulated_view_digest)
        self.assertFalse(result.unconditional_security_proved)

    def test_honest_internal_state_breaks_the_ideal_leakage_contract(self):
        exposure = Exposure(ExposureKind.INTERNAL_STATE, 3, b"private", "honest-internal")
        result = EndToEndSimulator(self.policy).simulate(
            self.ideal, self.public, (exposure,)
        )
        self.assertFalse(result.audit.accepted)
        self.assertIsNone(result.simulated_view_digest)


if __name__ == "__main__":
    unittest.main()
