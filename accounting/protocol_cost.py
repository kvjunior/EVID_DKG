"""Canonical byte measurements and derived operation counts for Batch 10."""

from dataclasses import asdict, dataclass
from hashlib import sha256

from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.pedersen import G, P, Q, encode_element
from accountable_dkg.crypto.signatures import Ed25519SignatureProvider
from accountable_dkg.execution.chunking import chunk_evidence
from accountable_dkg.protocol.acss import (
    AuthenticatedAcssDealing, RecoveryKeyUseRegistry, SignedAcssDealing, create_dealing,
)
from accountable_dkg.protocol.agreement import AgreementParameters
from accountable_dkg.protocol.evidence_producer import Incident
from accountable_dkg.protocol.finalization import (
    FinalizationCertificate, FinalizationValue, FinalizationVote,
)
from accountable_dkg.protocol.key_derivation import make_key_packet, make_randex_packet
from accountable_dkg.protocol.messages import AuthenticatedPacket
from accountable_dkg.protocol.public_evidence import PublicEvidence
from accountable_dkg.protocol.publication import CertificatePublication
from accountable_dkg.protocol.recovery import Dev1Incident, ImplicationEvidence
from accountable_dkg.protocol.session import Participant, Roster, SessionContext


@dataclass(frozen=True)
class CostParameters:
    participants: int
    faults: int
    degree: int

    def __post_init__(self) -> None:
        AgreementParameters(self.participants, self.faults, self.degree)


@dataclass(frozen=True)
class WireCost:
    signed_acss_dealing_bytes: int
    two_acss_vectors_source_bytes: int
    randex_packet_bytes: int
    randex_private_delivery_bytes: int
    key_packet_bytes: int
    key_source_bytes: int
    key_full_delivery_bytes: int
    finalization_value_bytes: int
    standalone_vote_bytes: int
    all_vote_collection_bytes: int
    quorum_certificate_bytes: int
    publication_payload_bytes: int
    publication_read_bytes_per_party: int
    dev1_evidence_bytes: int
    dev2_evidence_bytes: int
    dev3_evidence_bytes: int
    dev4_evidence_bytes: int
    evidence_chunk_overhead_bytes: int


@dataclass(frozen=True)
class OperationCost:
    acss_encryptions: int
    acss_dealing_signatures: int
    pedersen_commitment_exponentiations: int
    randex_signatures: int
    randex_relation_verifications: int
    key_knowledge_proofs: int
    key_signatures: int
    key_packet_verifications: int
    finalization_signatures: int
    certificate_signature_verifications_per_reader: int


@dataclass(frozen=True)
class ProtocolCostReport:
    parameters: CostParameters
    wire: WireCost
    operations: OperationCost
    acss_transport_bytes: None = None
    scope_note: str = (
        "ACSS signed payload bytes are exact; ACSS/RBC transport is external and therefore not totalled. "
        "KEY full-delivery counts point-to-point fanout, while source bytes count each sender once."
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _nonce(dealer: int, vector: int) -> bytes:
    return f"COST-{dealer:05d}-{vector}".encode("ascii").ljust(16, b"!")


def measure_protocol_costs(parameters: CostParameters, chunk_payload: int = 1024) -> ProtocolCostReport:
    n, t, ell = parameters.participants, parameters.faults, parameters.degree
    provider = Ed25519SignatureProvider()
    signing_pairs = [provider.generate_keypair() for _ in range(n)]
    roster = Roster(tuple(Participant(i + 1, signing_pairs[i][1]) for i in range(n)))
    session = SessionContext("EVID-DKG", 1, 10, ell, Q, b"batch10-cost-run", roster)
    registry = RecoveryKeyUseRegistry()
    signed_dealings = []
    first_authenticated = None
    first_private_key = None
    for dealer in range(1, n + 1):
        for vector in (0, 1):
            recovery_pairs = [HybridEncryptionProvider.generate_keypair() for _ in range(n)]
            private = {i + 1: recovery_pairs[i][0] for i in range(n)}
            public = {i + 1: recovery_pairs[i][1] for i in range(n)}
            base = 17 + dealer + 41 * vector
            values = tuple((base + 3 * index) % Q for index in range(t + 1))
            masks = tuple((base + 11 + 5 * index) % Q for index in range(t + 1))
            dealing = create_dealing(
                session.session_id, dealer, t, values[0], public, registry,
                nonce=_nonce(dealer, vector), coefficients=values, blindings=masks,
            )
            signed = SignedAcssDealing.sign(dealing, provider, signing_pairs[dealer - 1][0])
            signed_dealings.append(signed)
            if first_authenticated is None:
                first_authenticated = AuthenticatedAcssDealing(signed, signed.encode())
                first_private_key = private[1]

    anchor_id = sha256(b"EVID-DKG/Batch10/cost-anchor" + session.session_id).digest()
    randex = make_randex_packet(
        session.session_id, anchor_id, 1, 1, 3, 5, provider, signing_pairs[0][0]
    )
    key = make_key_packet(
        session.session_id, anchor_id, 1, 3, 5, provider, signing_pairs[0][0]
    )
    threshold_keys = tuple(
        (index, encode_element(pow(G, 100 + index, P))) for index in range(1, n + 1)
    )
    value = FinalizationValue(
        session.session_id, anchor_id, encode_element(pow(G, 99, P)), threshold_keys
    )
    votes = tuple(
        FinalizationVote.sign(index, value, provider, signing_pairs[index - 1][0])
        for index in range(1, n + 1)
    )
    certificate = FinalizationCertificate.build(
        votes[:n - t], session, t, provider
    )
    publication = CertificatePublication(certificate).encode()

    auth_key = AuthenticatedPacket(key, key.encode())
    auth_randex = AuthenticatedPacket(randex, randex.encode())
    dev2 = PublicEvidence.packet(Incident("Dev2", key.slot(), (auth_key, auth_key))).encode()
    dev3 = PublicEvidence.packet(Incident("Dev3", randex.slot(), (auth_randex,))).encode()
    dev4 = PublicEvidence.packet(Incident("Dev4", key.slot(), (auth_key,))).encode()
    assert first_authenticated is not None and first_private_key is not None
    dev1_incident = Dev1Incident(
        first_authenticated,
        ImplicationEvidence(first_authenticated.signed.dealing.dealing_id, 1, first_private_key),
    )
    dev1 = PublicEvidence.dev1(dev1_incident).encode()
    chunks = chunk_evidence(dev1, chunk_payload)
    chunk_overhead = sum(len(chunk.encode()) for chunk in chunks) - len(dev1)

    dealing_bytes = len(signed_dealings[0].encode())
    randex_bytes = len(randex.encode())
    key_bytes = len(key.encode())
    vote_bytes = len(votes[0].encode())
    wire = WireCost(
        dealing_bytes,
        sum(len(item.encode()) for item in signed_dealings),
        randex_bytes,
        n * n * randex_bytes,
        key_bytes,
        n * key_bytes,
        n * (n - 1) * key_bytes,
        len(value.encode()),
        vote_bytes,
        sum(len(vote.encode()) for vote in votes),
        len(certificate.encode()),
        len(publication),
        len(publication),
        len(dev1), len(dev2), len(dev3), len(dev4), chunk_overhead,
    )
    operations = OperationCost(
        acss_encryptions=2 * n * n,
        acss_dealing_signatures=2 * n,
        pedersen_commitment_exponentiations=4 * n * (t + 1),
        randex_signatures=n * n,
        randex_relation_verifications=n * n,
        key_knowledge_proofs=2 * n,
        key_signatures=n,
        key_packet_verifications=n * n,
        finalization_signatures=n,
        certificate_signature_verifications_per_reader=n - t,
    )
    return ProtocolCostReport(parameters, wire, operations)
