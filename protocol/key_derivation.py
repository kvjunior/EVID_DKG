"""RANDEX relations, Schnorr-bound KEY messages, and public-key interpolation."""

from dataclasses import dataclass

from accountable_dkg.crypto.interfaces import SignatureProvider
from accountable_dkg.crypto.pedersen import (
    ELEMENT_BYTES, SCALAR_BYTES, G, H, P, Q, decode_element, decode_scalar, encode_element, encode_scalar,
)
from accountable_dkg.crypto.schnorr import prove_knowledge, verify_knowledge
from accountable_dkg.crypto.transcript_domains import Domain, frame

from .encoding import u16
from .extraction import ExtractionMatrix
from .messages import KeyBody, MessageKind, Packet, RandexBody
from .qualification import QualificationAnchor


RANDEX_RELATION_TAG = b"PEDERSEN-RELATION-v1"


@dataclass(frozen=True)
class DerivedCommitments:
    """One degree-t commitment vector for each final polynomial coefficient."""

    coefficients: tuple[tuple[bytes, ...], ...]

    @property
    def sharing_degree(self) -> int:
        return len(self.coefficients[0]) - 1

    def recipient_column(self, recipient: int) -> tuple[bytes, ...]:
        output = []
        for sharing_coefficient in range(self.sharing_degree + 1):
            value = 1
            power = 1
            for coefficient in self.coefficients:
                value = value * pow(decode_element(coefficient[sharing_coefficient]), power, P) % P
                power = power * recipient % Q
            output.append(encode_element(value))
        return tuple(output)

    def key_commitment(self, participant: int) -> bytes:
        return self.recipient_column(participant)[0]


def derive_commitments(
    anchor: QualificationAnchor,
    matrix: ExtractionMatrix,
    participants: int,
    faults: int,
    degree: int,
) -> DerivedCommitments:
    by_dealer = {item.dealer: item for item in anchor.contributions}
    outputs: list[tuple[bytes, ...]] = []
    for output_index in range(degree + 1):
        use_first = output_index <= faults
        row = matrix.rows[output_index]
        result = []
        for coefficient_index in range(faults + 1):
            combined = 1
            for dealer in range(1, participants + 1):
                item = by_dealer.get(dealer)
                if item is None:
                    continue
                dealing = item.first if use_first else item.second
                element = decode_element(dealing.signed.dealing.commitment.elements[coefficient_index])
                combined = combined * pow(element, row[dealer - 1], P) % P
            result.append(encode_element(combined))
        outputs.append(tuple(result))
    return DerivedCommitments(tuple(outputs))


def verify_randex_relation(
    packet: Packet,
    commitments: DerivedCommitments,
    provider: SignatureProvider,
    verification_key: bytes,
) -> bool:
    if packet.kind is not MessageKind.RANDEX or not isinstance(packet.body, RandexBody):
        return False
    if not provider.verify(verification_key, packet.signed_statement(), packet.signature).accepted:
        return False
    if packet.body.proof != RANDEX_RELATION_TAG:
        return False
    try:
        share = decode_scalar(packet.body.fragment)
        mask = decode_scalar(packet.body.commitment_column)
        column = tuple(decode_element(item) for item in commitments.recipient_column(packet.body.recipient))
    except ValueError:
        return False
    left = pow(G, share, P) * pow(H, mask, P) % P
    right = 1
    power = 1
    for item in column:
        right = right * pow(item, power, P) % P
        power = power * packet.sender % Q
    return left == right


def make_randex_packet(
    session_id: bytes,
    anchor_id: bytes,
    sender: int,
    recipient: int,
    share: int,
    mask: int,
    provider: SignatureProvider,
    signing_key: bytes,
) -> Packet:
    body = RandexBody(recipient, encode_scalar(share), encode_scalar(mask), RANDEX_RELATION_TAG)
    return Packet(session_id, anchor_id, MessageKind.RANDEX, sender, body).sign(provider, signing_key)


def _proof_context(session_id: bytes, anchor_id: bytes, sender: int, label: bytes) -> bytes:
    return frame(Domain.PROOF_CHALLENGE, session_id, anchor_id, u16(sender), label)


def make_key_packet(
    session_id: bytes,
    anchor_id: bytes,
    sender: int,
    secret_share: int,
    mask_share: int,
    provider: SignatureProvider,
    signing_key: bytes,
) -> Packet:
    public_x, proof_x = prove_knowledge(G, secret_share, _proof_context(session_id, anchor_id, sender, b"G"))
    public_y, proof_y = prove_knowledge(H, mask_share, _proof_context(session_id, anchor_id, sender, b"H"))
    body = KeyBody(public_x, public_y, proof_x.encode() + proof_y.encode())
    return Packet(session_id, anchor_id, MessageKind.KEY, sender, body).sign(provider, signing_key)


def verify_key_packet(
    packet: Packet,
    commitments: DerivedCommitments,
    provider: SignatureProvider,
    verification_key: bytes,
) -> bool:
    if packet.kind is not MessageKind.KEY or not isinstance(packet.body, KeyBody):
        return False
    if not provider.verify(verification_key, packet.signed_statement(), packet.signature).accepted:
        return False
    proof_size = ELEMENT_BYTES + SCALAR_BYTES
    if len(packet.body.proof) != 2 * proof_size:
        return False
    proof_x, proof_y = packet.body.proof[:proof_size], packet.body.proof[proof_size:]
    if not verify_knowledge(G, packet.body.public_x, proof_x, _proof_context(packet.session_id, packet.anchor_id, packet.sender, b"G")):
        return False
    if not verify_knowledge(H, packet.body.public_y, proof_y, _proof_context(packet.session_id, packet.anchor_id, packet.sender, b"H")):
        return False
    try:
        product = decode_element(packet.body.public_x) * decode_element(packet.body.public_y) % P
        expected = decode_element(commitments.key_commitment(packet.sender))
    except ValueError:
        return False
    return product == expected


def _lagrange_weight(points: tuple[int, ...], target: int, point: int) -> int:
    numerator = 1
    denominator = 1
    for other in points:
        if other == point:
            continue
        numerator = numerator * (target - other) % Q
        denominator = denominator * (point - other) % Q
    return numerator * pow(denominator, -1, Q) % Q


def interpolate_group(values: dict[int, bytes], target: int, required: int) -> bytes:
    points = tuple(sorted(values)[:required])
    if len(points) < required:
        raise ValueError("insufficient public points for interpolation")
    result = 1
    for point in points:
        result = result * pow(decode_element(values[point]), _lagrange_weight(points, target, point), P) % P
    return encode_element(result)
