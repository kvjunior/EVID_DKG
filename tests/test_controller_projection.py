from dataclasses import replace
from itertools import combinations
import unittest

from accountable_dkg.execution.events import EventKind, EventSource, LogicalEvent
from accountable_dkg.protocol.evidence_producer import (
    CheckedDelivery,
    ReceiptNotice,
    erase_honest_deliveries,
    run_controller,
)
from accountable_dkg.protocol.messages import AuthenticatedPacket, KeyBody, MessageKind, Packet, RandexBody

from batch03_helpers import accepted_anchor, session


def delivery(sender: int, *, relation_valid: bool = True, value: bytes = b"x", proof: bytes = b"p", recipient=None):
    ctx = session()
    anchor = accepted_anchor(ctx)
    if recipient is None:
        body = KeyBody(value, b"y", proof)
        kind = MessageKind.KEY
    else:
        body = RandexBody(recipient, value, b"column", proof)
        kind = MessageKind.RANDEX
    packet = Packet(ctx.session_id, anchor.metadata.reference_id, kind, sender, body, b"sig")
    return CheckedDelivery(AuthenticatedPacket(packet, packet.encode()), relation_valid)


def event(seq, kind, payload=None, time=None):
    return LogicalEvent(seq if time is None else time, seq, EventSource.LOCAL, kind, payload)


class ControllerProjectionTests(unittest.TestCase):
    def context(self):
        ctx = session()
        return ctx, accepted_anchor(ctx).metadata.reference_id

    def test_hold_retry_and_terminal_verdict_are_distinct(self):
        ctx, anchor = self.context()
        bad = delivery(3, relation_valid=False)
        prefix = (
            event(0, EventKind.PACKET_DELIVERY, bad),
            event(1, EventKind.ANCHOR_ACCEPTED, anchor),
            event(2, EventKind.WINDOW_OPEN, 0),
        )
        first = run_controller(prefix, 1, ctx.session_id)
        self.assertEqual([(item.time, item.window) for item in first], [(2, 0)])
        incident_id = first[0].incident.incident_id
        retry = prefix + (
            event(3, EventKind.RECEIPT, ReceiptNotice(incident_id, False)),
            event(4, EventKind.WINDOW_CLOSE, 0),
            event(5, EventKind.WINDOW_OPEN, 1),
        )
        self.assertEqual([item.window for item in run_controller(retry, 1, ctx.session_id)], [0, 1])
        terminal = retry + (event(6, EventKind.RECEIPT, ReceiptNotice(incident_id, True)), event(7, EventKind.WINDOW_OPEN, 2))
        self.assertEqual([item.window for item in run_controller(terminal, 1, ctx.session_id)], [0, 1])

    def test_projection_for_all_small_interleavings(self):
        ctx, anchor = self.context()
        corrupt = [
            event(0, EventKind.ANCHOR_ACCEPTED, anchor),
            event(1, EventKind.WINDOW_OPEN, 0),
            event(2, EventKind.PACKET_DELIVERY, delivery(3, relation_valid=False)),
        ]
        honest_payloads = [delivery(2), delivery(2, proof=b"rerandomized")]
        checked = 0
        for positions in combinations(range(5), 2):
            merged = []
            corrupt_index = honest_index = 0
            for index in range(5):
                if index in positions:
                    payload = honest_payloads[honest_index]
                    honest_index += 1
                    merged.append(event(index, EventKind.PACKET_DELIVERY, payload))
                else:
                    original = corrupt[corrupt_index]
                    corrupt_index += 1
                    merged.append(replace(original, time=index, sequence=index))
            tape = tuple(merged)
            self.assertEqual(
                run_controller(tape, 1, ctx.session_id),
                run_controller(erase_honest_deliveries(tape, frozenset({2})), 1, ctx.session_id),
            )
            checked += 1
        self.assertEqual(checked, 10)

    def test_invalid_erased_packet_is_a_counterexample_not_a_live_rule(self):
        ctx, anchor = self.context()
        tape = (
            event(0, EventKind.ANCHOR_ACCEPTED, anchor),
            event(1, EventKind.WINDOW_OPEN, 0),
            event(2, EventKind.PACKET_DELIVERY, delivery(2, relation_valid=False)),
        )
        self.assertNotEqual(
            run_controller(tape, 1, ctx.session_id),
            run_controller(erase_honest_deliveries(tape, frozenset({2})), 1, ctx.session_id),
        )

    def test_recipient_separation_and_key_proof_semantics(self):
        ctx, anchor = self.context()
        tape = (
            event(0, EventKind.ANCHOR_ACCEPTED, anchor),
            event(1, EventKind.WINDOW_OPEN, 0),
            event(2, EventKind.PACKET_DELIVERY, delivery(3, recipient=1)),
            event(3, EventKind.PACKET_DELIVERY, delivery(3, value=b"other", recipient=2)),
            event(4, EventKind.PACKET_DELIVERY, delivery(3, proof=b"one")),
            event(5, EventKind.PACKET_DELIVERY, delivery(3, proof=b"two")),
        )
        self.assertEqual(run_controller(tape, 1, ctx.session_id), ())


if __name__ == "__main__":
    unittest.main()
