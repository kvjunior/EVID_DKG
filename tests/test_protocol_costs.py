import unittest

from accountable_dkg.accounting.protocol_cost import CostParameters, measure_protocol_costs


class ProtocolCostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = measure_protocol_costs(CostParameters(4, 1, 2), chunk_payload=1024)

    def test_exact_message_counts_use_canonical_bytes(self):
        wire = self.report.wire
        self.assertGreater(wire.signed_acss_dealing_bytes, 0)
        self.assertEqual(wire.randex_private_delivery_bytes, 16 * wire.randex_packet_bytes)
        self.assertEqual(wire.key_source_bytes, 4 * wire.key_packet_bytes)
        self.assertEqual(wire.key_full_delivery_bytes, 12 * wire.key_packet_bytes)
        self.assertEqual(wire.publication_read_bytes_per_party, wire.publication_payload_bytes)

    def test_compact_certificate_does_not_repeat_standalone_values(self):
        wire = self.report.wire
        self.assertLess(wire.quorum_certificate_bytes, 3 * wire.standalone_vote_bytes)
        self.assertLess(wire.publication_payload_bytes, wire.all_vote_collection_bytes)

    def test_external_transport_is_not_invented(self):
        self.assertIsNone(self.report.acss_transport_bytes)
        self.assertIn("external", self.report.scope_note)

    def test_derived_operation_counts_match_reference_topology(self):
        operations = self.report.operations
        self.assertEqual(operations.acss_encryptions, 32)
        self.assertEqual(operations.randex_signatures, 16)
        self.assertEqual(operations.key_knowledge_proofs, 8)
        self.assertEqual(operations.certificate_signature_verifications_per_reader, 3)


if __name__ == "__main__":
    unittest.main()
