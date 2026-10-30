import unittest

from accountable_dkg.evidence import Evidence, State


class EvidenceTests(unittest.TestCase):
    def test_answer_arrival_waits_for_dispute(self):
        e = Evidence(4, "share")
        self.assertFalse(e.attempt("answer"))
        self.assertIs(e.state, State.PENDING)
        self.assertTrue(e.attempt("dispute"))

    def test_rejection_allows_later_phase(self):
        e = Evidence(4, "share")
        self.assertTrue(e.attempt("complaint"))
        e.observe_rejection()
        self.assertFalse(e.attempt("complaint"))
        self.assertTrue(e.attempt("dispute"))

    def test_submission_does_not_mean_adjudication(self):
        e = Evidence(4, "pok")
        e.attempt("complaint")
        self.assertIs(e.state, State.SUBMITTED)
        e.observe_adjudication()
        self.assertFalse(e.attempt("dispute"))

    def test_no_legal_phase_after_close(self):
        self.assertFalse(Evidence(4, "share").attempt("closed"))
