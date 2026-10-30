from dataclasses import replace
import unittest

from accountable_dkg.execution.chunking import ChunkAssembler, EvidenceChunk, chunk_evidence, whole_upload_by_deadline


class ChunkedEvidenceTests(unittest.TestCase):
    def test_canonical_roundtrip_and_shuffled_reassembly(self):
        payload = bytes(range(64))
        chunks = chunk_evidence(payload, 11)
        assembler = ChunkAssembler(chunks[0].upload_id, len(chunks))
        for chunk in reversed(chunks):
            self.assertEqual(EvidenceChunk.decode(chunk.encode()), chunk)
            assembler.add(chunk)
        self.assertTrue(assembler.complete)
        self.assertEqual(assembler.assemble(), payload)

    def test_duplicate_is_idempotent_but_conflict_is_rejected(self):
        chunks = chunk_evidence(b"abcdefgh", 4)
        assembler = ChunkAssembler(chunks[0].upload_id, len(chunks))
        self.assertTrue(assembler.add(chunks[0]))
        self.assertFalse(assembler.add(chunks[0]))
        with self.assertRaisesRegex(ValueError, "conflicting"):
            assembler.add(replace(chunks[0], payload=b"WXYZ"))

    def test_one_chunk_inclusion_bound_does_not_imply_whole_upload_bound(self):
        chunks = chunk_evidence(b"twelve-bytes", 4)
        self.assertFalse(whole_upload_by_deadline(chunks, {0: 3, 1: 4}, 6))
        included = {index: 3 + index for index in range(len(chunks))}
        self.assertTrue(whole_upload_by_deadline(chunks, included, 10))
        included[len(chunks) - 1] = 10
        self.assertFalse(whole_upload_by_deadline(chunks, included, 10))

    def test_wrong_upload_and_incomplete_assembly_fail(self):
        left = chunk_evidence(b"left", 3)
        right = chunk_evidence(b"right", 3)
        assembler = ChunkAssembler(left[0].upload_id, len(left))
        with self.assertRaisesRegex(ValueError, "another upload"):
            assembler.add(right[0])
        assembler.add(left[0])
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            assembler.assemble()


if __name__ == "__main__":
    unittest.main()
