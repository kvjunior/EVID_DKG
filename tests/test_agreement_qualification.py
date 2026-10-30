import unittest

from accountable_dkg.protocol.agreement import AgreementParameters, validate_external_decision
from accountable_dkg.protocol.qualification import qualify

from batch07_helpers import build_fixture


class AgreementQualificationTests(unittest.TestCase):
    def test_external_validity_and_canonical_anchor(self):
        session, _, _, contributions, machines = build_fixture()
        parameters = AgreementParameters(4, 1, 2)
        decision = validate_external_decision(parameters, (1, 2, 3), frozenset(contributions))
        available = {dealer: pair for dealer, pair in contributions.items()}
        anchor = qualify(session.session_id, decision, available)
        self.assertEqual(tuple(item.dealer for item in anchor.contributions), (1, 2, 3))
        self.assertEqual(len(anchor.reference_id), 32)
        self.assertEqual(machines[1].accept_agreement((1, 2, 3)).reference_id, anchor.reference_id)

    def test_invalid_agreement_outputs_are_rejected(self):
        parameters = AgreementParameters(4, 1, 2)
        for proposed, completed in (
            ((1, 2), frozenset({1, 2, 3, 4})),
            ((1, 1, 2), frozenset({1, 2, 3, 4})),
            ((1, 2, 4), frozenset({1, 2, 3})),
        ):
            with self.subTest(proposed=proposed):
                with self.assertRaises(ValueError):
                    validate_external_decision(parameters, proposed, completed)


if __name__ == "__main__":
    unittest.main()
