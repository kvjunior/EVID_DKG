import unittest

from accountable_dkg.crypto.pedersen import G, H
from accountable_dkg.crypto.schnorr import prove_knowledge, verify_knowledge


class KeyDerivationTests(unittest.TestCase):
    def test_context_bound_schnorr_proofs(self):
        public, proof = prove_knowledge(G, 12345, b"session/anchor/sender/G", nonce=77)
        self.assertTrue(verify_knowledge(G, public, proof.encode(), b"session/anchor/sender/G"))
        self.assertFalse(verify_knowledge(G, public, proof.encode(), b"different"))
        self.assertFalse(verify_knowledge(H, public, proof.encode(), b"session/anchor/sender/G"))

    def test_malformed_or_modified_proof_rejected(self):
        public, proof = prove_knowledge(G, 9, b"context", nonce=5)
        raw = proof.encode()
        self.assertFalse(verify_knowledge(G, public, raw[:-1], b"context"))
        changed = raw[:-1] + bytes([raw[-1] ^ 1])
        self.assertFalse(verify_knowledge(G, public, changed, b"context"))


if __name__ == "__main__":
    unittest.main()
