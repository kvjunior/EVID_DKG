"""Complete deterministic local DKG state machine after external MVBA output."""

from dataclasses import dataclass
from enum import Enum

from accountable_dkg.crypto.interfaces import SignatureProvider
from accountable_dkg.crypto.pedersen import G, P, decode_element, evaluate

from .acss import AuthenticatedAcssDealing, ShareCheck, inspect_share
from .agreement import AgreementDecision, AgreementParameters, validate_external_decision
from .extraction import cauchy_extraction_matrix, extract_coefficients
from .key_derivation import (
    DerivedCommitments, derive_commitments, interpolate_group, make_key_packet,
    make_randex_packet, verify_key_packet, verify_randex_relation,
)
from .messages import KeyBody, MessageKind, Packet, RandexBody
from .oec import online_error_correct_pair
from .qualification import QualificationAnchor, qualify
from .session import SessionContext


class LocalPhase(str, Enum):
    SHARING = "sharing"
    RANDEX = "randex"
    KEY = "key"
    COMPLETE = "complete"


@dataclass(frozen=True)
class LocalDkgOutput:
    participant: int
    secret_share: int
    public_key: bytes
    threshold_public_keys: tuple[tuple[int, bytes], ...]
    qualification_anchor: bytes


@dataclass(frozen=True)
class _LocalDealerPair:
    first: AuthenticatedAcssDealing
    second: AuthenticatedAcssDealing
    first_share: ShareCheck
    second_share: ShareCheck


class LocalDkgStateMachine:
    def __init__(
        self,
        session: SessionContext,
        participant: int,
        faults: int,
        reconstruction_threshold: int,
        provider: SignatureProvider,
        signing_key: bytes,
    ) -> None:
        if session.roster.participant(participant) is None:
            raise ValueError("local participant is not in the session roster")
        self.session = session
        self.participant = participant
        self.parameters = AgreementParameters(len(session.roster.participants), faults, reconstruction_threshold)
        self.provider = provider
        self.signing_key = signing_key
        self.phase = LocalPhase.SHARING
        self.local: dict[int, _LocalDealerPair] = {}
        self.anchor: QualificationAnchor | None = None
        self.commitments: DerivedCommitments | None = None
        self.coefficient_shares: tuple[int, ...] | None = None
        self.coefficient_masks: tuple[int, ...] | None = None
        self.randex: dict[int, tuple[int, int]] = {}
        self.key_points: dict[int, bytes] = {}
        self.secret_share: int | None = None
        self.mask_share: int | None = None
        self.output: LocalDkgOutput | None = None
        self._pending_randex: list[Packet] = []
        self._pending_keys: list[Packet] = []

    def register_dealer_pair(
        self,
        first: AuthenticatedAcssDealing,
        first_recovery_key: bytes,
        second: AuthenticatedAcssDealing,
        second_recovery_key: bytes,
    ) -> bool:
        if self.anchor is not None:
            return False
        first_dealing, second_dealing = first.signed.dealing, second.signed.dealing
        if first_dealing.dealer != second_dealing.dealer or first_dealing.session_id != self.session.session_id:
            return False
        if second_dealing.session_id != self.session.session_id:
            return False
        first_check = inspect_share(first_dealing, self.participant, first_recovery_key)
        second_check = inspect_share(second_dealing, self.participant, second_recovery_key)
        if not first_check.valid or not second_check.valid:
            return False
        self.local[first_dealing.dealer] = _LocalDealerPair(first, second, first_check, second_check)
        return True

    def accept_agreement(self, proposed: tuple[int, ...]) -> QualificationAnchor:
        decision: AgreementDecision = validate_external_decision(
            self.parameters, proposed, frozenset(self.local)
        )
        available = {dealer: (pair.first, pair.second) for dealer, pair in self.local.items()}
        self.anchor = qualify(self.session.session_id, decision, available)
        n = self.parameters.participants
        t = self.parameters.faults
        ell = self.parameters.reconstruction_threshold
        matrix = cauchy_extraction_matrix(n - t, n)
        first = tuple(self.local[d].first_share.share if d in decision.dealers else 0 for d in range(1, n + 1))
        second = tuple(self.local[d].second_share.share if d in decision.dealers else 0 for d in range(1, n + 1))
        first_masks = tuple(self.local[d].first_share.blinding_share if d in decision.dealers else 0 for d in range(1, n + 1))
        second_masks = tuple(self.local[d].second_share.blinding_share if d in decision.dealers else 0 for d in range(1, n + 1))
        if any(value is None for value in first + second + first_masks + second_masks):
            raise ValueError("qualified local ACSS share is unavailable")
        self.coefficient_shares = extract_coefficients(matrix, first, second, t, ell)
        self.coefficient_masks = extract_coefficients(matrix, first_masks, second_masks, t, ell)
        self.commitments = derive_commitments(self.anchor, matrix, n, t, ell)
        self.phase = LocalPhase.RANDEX
        pending_randex, self._pending_randex = self._pending_randex, []
        pending_keys, self._pending_keys = self._pending_keys, []
        for packet in pending_randex:
            self.accept_randex(packet)
        for packet in pending_keys:
            self.accept_key(packet)
        return self.anchor

    def emit_randex(self) -> tuple[Packet, ...]:
        if self.anchor is None or self.coefficient_shares is None or self.coefficient_masks is None:
            raise ValueError("agreement must precede RANDEX")
        return tuple(
            make_randex_packet(
                self.session.session_id, self.anchor.reference_id, self.participant, recipient,
                evaluate(self.coefficient_shares, recipient), evaluate(self.coefficient_masks, recipient),
                self.provider, self.signing_key,
            ) for recipient in range(1, self.parameters.participants + 1)
        )

    def accept_randex(self, packet: Packet) -> bool:
        if self.anchor is None or self.commitments is None:
            self._pending_randex.append(packet)
            return False
        if packet.session_id != self.session.session_id or packet.anchor_id != self.anchor.reference_id:
            return False
        if not isinstance(packet.body, RandexBody) or packet.body.recipient != self.participant:
            return False
        member = self.session.roster.participant(packet.sender)
        if member is None or not verify_randex_relation(packet, self.commitments, self.provider, member.verification_key):
            return False
        from accountable_dkg.crypto.pedersen import decode_scalar
        value = (decode_scalar(packet.body.fragment), decode_scalar(packet.body.commitment_column))
        previous = self.randex.get(packet.sender)
        if previous is not None and previous != value:
            return False
        self.randex[packet.sender] = value
        recovered = online_error_correct_pair(self.randex, self.parameters.faults)
        if recovered is not None and self.secret_share is None:
            self.secret_share, self.mask_share = recovered
            self.phase = LocalPhase.KEY
            self._try_finalize()
        return True

    def emit_key(self) -> Packet:
        if self.anchor is None or self.secret_share is None or self.mask_share is None:
            raise ValueError("RANDEX recovery must precede KEY")
        return make_key_packet(
            self.session.session_id, self.anchor.reference_id, self.participant,
            self.secret_share, self.mask_share, self.provider, self.signing_key,
        )

    def accept_key(self, packet: Packet) -> bool:
        if self.anchor is None or self.commitments is None:
            self._pending_keys.append(packet)
            return False
        if packet.session_id != self.session.session_id or packet.anchor_id != self.anchor.reference_id:
            return False
        member = self.session.roster.participant(packet.sender)
        if member is None or not verify_key_packet(packet, self.commitments, self.provider, member.verification_key):
            return False
        assert isinstance(packet.body, KeyBody)
        previous = self.key_points.get(packet.sender)
        if previous is not None and previous != packet.body.public_x:
            return False
        self.key_points[packet.sender] = packet.body.public_x
        self._try_finalize()
        return True

    def _try_finalize(self) -> None:
        required = self.parameters.reconstruction_threshold + 1
        if self.output is not None or self.anchor is None or self.secret_share is None or len(self.key_points) < required:
            return
        public_key = interpolate_group(self.key_points, 0, required)
        threshold_keys = tuple(
            (participant, interpolate_group(self.key_points, participant, required))
            for participant in range(1, self.parameters.participants + 1)
        )
        own = dict(threshold_keys)[self.participant]
        if decode_element(own) != pow(G, self.secret_share, P):
            raise ValueError("interpolated threshold key disagrees with local secret share")
        self.output = LocalDkgOutput(
            self.participant, self.secret_share, public_key, threshold_keys, self.anchor.reference_id
        )
        self.phase = LocalPhase.COMPLETE
