import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Batch10DecisionTests(unittest.TestCase):
    def test_decision_fails_closed(self):
        decision = json.loads((ROOT / "results/batch10/final_decision.json").read_text(encoding="utf-8"))
        self.assertEqual(decision["original_stoc_level_claim"], "not_established")
        self.assertFalse(decision["complete_async_dkg_theorem"])
        self.assertFalse(decision["all_security_obligations_resolved"])
        self.assertTrue(decision["unresolved_dependencies"])

    def test_cost_report_keeps_external_transport_null(self):
        costs = json.loads((ROOT / "results/batch10/costs.json").read_text(encoding="utf-8"))
        self.assertEqual(costs["version"], "0.9.1")
        for configuration in costs["configurations"]:
            self.assertIsNone(configuration["acss_transport_bytes"])


if __name__ == "__main__":
    unittest.main()
