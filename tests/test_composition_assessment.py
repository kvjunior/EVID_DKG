import unittest

from accountable_dkg.simulation.composition import CompositionAssessment, ObligationStatus


class CompositionAssessmentTests(unittest.TestCase):
    def test_dependency_register_fails_closed(self):
        assessment = CompositionAssessment.batch09()
        statuses = {item.identifier: item.status for item in assessment.obligations}
        self.assertEqual(statuses["REPROGRAM-ALG"], ObligationStatus.PROVED_MODEL)
        self.assertEqual(statuses["DAS23-STATIC-SIM"], ObligationStatus.IMPORTED)
        self.assertEqual(statuses["LEDGER-JOINT"], ObligationStatus.UNRESOLVED)
        self.assertEqual(statuses["DEV1-RECOVERY-JOINT"], ObligationStatus.UNRESOLVED)
        self.assertEqual(statuses["ADAPTIVE-CORRUPTION"], ObligationStatus.OUT_OF_SCOPE)
        self.assertFalse(assessment.complete_security_theorem)
        with self.assertRaisesRegex(RuntimeError, "not established"):
            assessment.require_complete()


if __name__ == "__main__":
    unittest.main()
