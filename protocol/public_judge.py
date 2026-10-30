"""Deterministic public judge over finalized, receipt-accepted ledger inputs."""

from dataclasses import dataclass
from enum import Enum

from accountable_dkg.crypto.interfaces import SignatureProvider
from accountable_dkg.execution.ledger_adapter import FinalizedLedgerInput, ReceiptCode

from .acss import authenticate_dealing
from .evidence_producer import Incident
from .key_derivation import DerivedCommitments, verify_key_packet, verify_randex_relation
from .messages import MessageKind
from .public_evidence import PublicEvidence, PublicEvidenceKind
from .recovery import Dev1Incident, verify_implication
from .session import SessionContext


class JudgeCode(str, Enum):
    ATTRIBUTED = "attributed"
    REJECTED = "rejected"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class JudgeVerdict:
    code: JudgeCode
    accused: int | None
    deviation: str | None
    reason: str

    @property
    def accepted(self) -> bool:
        return self.code is JudgeCode.ATTRIBUTED


class PublicJudge:
    def __init__(
        self,
        session: SessionContext,
        anchor_id: bytes,
        commitments: DerivedCommitments,
        provider: SignatureProvider,
    ) -> None:
        if len(anchor_id) != 32:
            raise ValueError("judge anchor must contain 32 bytes")
        self.session = session
        self.anchor_id = anchor_id
        self.commitments = commitments
        self.provider = provider

    def adjudicate(self, finalized: FinalizedLedgerInput) -> JudgeVerdict:
        if finalized.receipt.code is not ReceiptCode.ACCEPTED_FOR_ADJUDICATION:
            return JudgeVerdict(JudgeCode.REJECTED, None, None, "ledger receipt rejected evidence")
        try:
            evidence = PublicEvidence.decode(finalized.payload)
            if evidence.kind is PublicEvidenceKind.DEV1:
                return self._dev1(Dev1Incident.decode(evidence.incident_bytes))
            return self._packet(Incident.decode(evidence.incident_bytes))
        except (TypeError, ValueError) as exc:
            return JudgeVerdict(JudgeCode.MALFORMED, None, None, str(exc))

    def _dev1(self, incident: Dev1Incident) -> JudgeVerdict:
        signed = incident.authenticated.signed
        dealing = signed.dealing
        if dealing.session_id != self.session.session_id:
            return JudgeVerdict(JudgeCode.REJECTED, None, "Dev1", "wrong session")
        member = self.session.roster.participant(dealing.dealer)
        if member is None:
            return JudgeVerdict(JudgeCode.REJECTED, None, "Dev1", "unknown dealer")
        authentication = authenticate_dealing(signed, self.provider, member.verification_key)
        if not authentication.result.accepted:
            return JudgeVerdict(JudgeCode.REJECTED, None, "Dev1", "dealer signature is invalid")
        verdict = verify_implication(dealing, incident.implication)
        if not verdict.accepted:
            return JudgeVerdict(JudgeCode.REJECTED, None, "Dev1", verdict.reason)
        return JudgeVerdict(JudgeCode.ATTRIBUTED, dealing.dealer, "Dev1", verdict.reason)

    def _packet(self, incident: Incident) -> JudgeVerdict:
        if incident.kind not in {"Dev2", "Dev3", "Dev4"}:
            return JudgeVerdict(JudgeCode.REJECTED, None, None, "unsupported packet deviation")
        packets = tuple(source.packet for source in incident.source_packets)
        if any(packet.session_id != self.session.session_id for packet in packets):
            return JudgeVerdict(JudgeCode.REJECTED, None, incident.kind, "wrong session")
        if any(packet.anchor_id != self.anchor_id for packet in packets):
            return JudgeVerdict(JudgeCode.REJECTED, None, incident.kind, "wrong anchor")
        sender = packets[-1].sender
        member = self.session.roster.participant(sender)
        if member is None:
            return JudgeVerdict(JudgeCode.REJECTED, None, incident.kind, "unknown sender")
        for packet in packets:
            if packet.sender != sender or not self.provider.verify(
                member.verification_key, packet.signed_statement(), packet.signature
            ).accepted:
                return JudgeVerdict(JudgeCode.REJECTED, None, incident.kind, "packet signature is invalid")
        if incident.kind == "Dev2":
            if len(packets) != 2 or packets[0].slot() != packets[1].slot():
                return JudgeVerdict(JudgeCode.REJECTED, None, "Dev2", "not one conflicting slot")
            if not packets[0].semantically_conflicts(packets[1]):
                return JudgeVerdict(JudgeCode.REJECTED, None, "Dev2", "packet semantics agree")
        elif incident.kind == "Dev3":
            if len(packets) != 1 or packets[0].kind is not MessageKind.RANDEX:
                return JudgeVerdict(JudgeCode.REJECTED, None, "Dev3", "wrong packet kind")
            if verify_randex_relation(packets[0], self.commitments, self.provider, member.verification_key):
                return JudgeVerdict(JudgeCode.REJECTED, None, "Dev3", "RANDEX relation is valid")
        else:
            if len(packets) != 1 or packets[0].kind is not MessageKind.KEY:
                return JudgeVerdict(JudgeCode.REJECTED, None, "Dev4", "wrong packet kind")
            if verify_key_packet(packets[0], self.commitments, self.provider, member.verification_key):
                return JudgeVerdict(JudgeCode.REJECTED, None, "Dev4", "KEY relation is valid")
        return JudgeVerdict(JudgeCode.ATTRIBUTED, sender, incident.kind, "signed deviation verified")
