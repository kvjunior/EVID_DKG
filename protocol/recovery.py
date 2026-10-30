"""Evidence-safe, per-dealing ACSS implication and recovery model."""

from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from accountable_dkg.crypto.pedersen import Q, evaluate
from accountable_dkg.crypto.transcript_domains import Domain, frame
from accountable_dkg.execution.events import EventKind, LogicalEvent

from .acss import (
    AcssDealing, AuthenticatedAcssDealing, ShareCheck, SignedAcssDealing, inspect_share,
)
from .encoding import EncodingError, Reader, blob, u16


def _public_key(private_key: bytes) -> bytes:
    if len(private_key) != 32:
        raise ValueError("recovery private key must contain 32 bytes")
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


@dataclass(frozen=True)
class ImplicationEvidence:
    dealing_id: bytes
    recipient: int
    recovery_private_key: bytes

    @property
    def evidence_id(self) -> bytes:
        return sha256(frame(
            Domain.ACSS_RECOVERY, self.dealing_id, u16(self.recipient), self.recovery_private_key
        )).digest()


@dataclass(frozen=True)
class ImplicationVerdict:
    accepted: bool
    reason: str
    check: ShareCheck | None = None


def verify_implication(dealing: AcssDealing, evidence: ImplicationEvidence) -> ImplicationVerdict:
    if evidence.dealing_id != dealing.dealing_id:
        return ImplicationVerdict(False, "wrong dealing")
    expected = dealing.public_key(evidence.recipient)
    if expected is None:
        return ImplicationVerdict(False, "unknown recipient")
    try:
        if _public_key(evidence.recovery_private_key) != expected:
            return ImplicationVerdict(False, "recovery key is outside the registered scope")
    except ValueError as exc:
        return ImplicationVerdict(False, str(exc))
    check = inspect_share(dealing, evidence.recipient, evidence.recovery_private_key)
    if check.valid:
        return ImplicationVerdict(False, "false implication: recipient share is valid", check)
    return ImplicationVerdict(True, check.reason, check)


@dataclass(frozen=True)
class RecoveryRelease:
    dealing_id: bytes
    recipient: int
    recovery_private_key: bytes


@dataclass(frozen=True)
class RecoveryResult:
    secret: int
    shares: tuple[tuple[int, int], ...]
    exposed_recipients: tuple[int, ...]
    exposed_key_bytes: int


def _interpolate_coefficients(points: tuple[tuple[int, int], ...], degree: int) -> tuple[int, ...]:
    if len(points) != degree + 1:
        raise ValueError("exactly degree+1 points are required")
    matrix = [[pow(x, column, Q) for column in range(degree + 1)] + [y % Q] for x, y in points]
    for column in range(degree + 1):
        pivot = next((row for row in range(column, degree + 1) if matrix[row][column] % Q), None)
        if pivot is None:
            raise ValueError("recovery points are not independent")
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inverse = pow(matrix[column][column], -1, Q)
        matrix[column] = [(value * inverse) % Q for value in matrix[column]]
        for row in range(degree + 1):
            if row == column:
                continue
            factor = matrix[row][column]
            matrix[row] = [
                (value - factor * base) % Q
                for value, base in zip(matrix[row], matrix[column], strict=True)
            ]
    return tuple(matrix[row][-1] for row in range(degree + 1))


class RecoverySession:
    """Accepts releases only after a genuine, scoped implication."""

    def __init__(self, dealing: AcssDealing, implication: ImplicationEvidence) -> None:
        verdict = verify_implication(dealing, implication)
        if not verdict.accepted:
            raise ValueError(f"recovery requires genuine implication: {verdict.reason}")
        self.dealing = dealing
        self.implication = implication
        self._valid: dict[int, ShareCheck] = {}

    def add_release(self, release: RecoveryRelease) -> bool:
        if release.dealing_id != self.dealing.dealing_id or release.recipient in self._valid:
            return False
        expected = self.dealing.public_key(release.recipient)
        try:
            if expected is None or _public_key(release.recovery_private_key) != expected:
                return False
        except ValueError:
            return False
        check = inspect_share(self.dealing, release.recipient, release.recovery_private_key)
        if not check.valid:
            return False
        self._valid[release.recipient] = check
        return True

    @property
    def ready(self) -> bool:
        return len(self._valid) >= self.dealing.threshold + 1

    def recover(self) -> RecoveryResult:
        if not self.ready:
            raise ValueError("insufficient valid recovery releases")
        selected = tuple(self._valid[index] for index in sorted(self._valid)[:self.dealing.threshold + 1])
        value_points = tuple((item.recipient, item.share) for item in selected if item.share is not None)
        mask_points = tuple((item.recipient, item.blinding_share) for item in selected if item.blinding_share is not None)
        values = _interpolate_coefficients(value_points, self.dealing.threshold)
        masks = _interpolate_coefficients(mask_points, self.dealing.threshold)
        if not self.dealing.commitment.matches_polynomials(values, masks):
            raise ValueError("released shares do not reconstruct the committed polynomials")
        recipients = tuple(item.recipient for item in self.dealing.recovery_keys)
        shares = tuple((recipient, evaluate(values, recipient)) for recipient in recipients)
        exposed = tuple(sorted(set(self._valid) | {self.implication.recipient}))
        return RecoveryResult(values[0], shares, exposed, 32 * len(exposed))


@dataclass(frozen=True)
class Dev1Delivery:
    authenticated: AuthenticatedAcssDealing
    recipient: int
    recovery_private_key: bytes


@dataclass(frozen=True)
class Dev1Receipt:
    incident_id: bytes
    terminal: bool

    def __post_init__(self) -> None:
        if len(self.incident_id) != 32:
            raise ValueError("Dev1 incident id must contain 32 bytes")


@dataclass(frozen=True)
class Dev1Incident:
    authenticated: AuthenticatedAcssDealing
    implication: ImplicationEvidence

    def encode(self) -> bytes:
        return blob(self.authenticated.raw_bytes) + u16(self.implication.recipient) + self.implication.recovery_private_key

    @classmethod
    def decode(cls, raw: bytes) -> "Dev1Incident":
        reader = Reader(raw)
        signed_raw = reader.blob()
        signed = SignedAcssDealing.decode(signed_raw)
        recipient = reader.u16()
        private_key = reader.fixed(32)
        reader.finish()
        authenticated = AuthenticatedAcssDealing(signed, signed_raw)
        value = cls(
            authenticated,
            ImplicationEvidence(signed.dealing.dealing_id, recipient, private_key),
        )
        if value.encode() != raw:
            raise EncodingError("non-canonical Dev1 incident")
        return value

    @property
    def incident_id(self) -> bytes:
        return sha256(frame(Domain.EVIDENCE_SIGNATURE, self.encode())).digest()


@dataclass(frozen=True)
class Dev1SubmissionIntent:
    time: int
    reporter: int
    window: int
    incident: Dev1Incident

    @property
    def payload(self) -> bytes:
        return self.incident.encode()


class Dev1ReportingController:
    """Corruption-set-oblivious hold/retry controller for genuine Dev1 evidence."""

    def __init__(self, reporter: int, session_id: bytes) -> None:
        if not 1 <= reporter <= 0xFFFF or len(session_id) != 32:
            raise ValueError("invalid Dev1 controller context")
        self.reporter = reporter
        self.session_id = session_id
        self.candidates: dict[bytes, Dev1Incident] = {}
        self.terminal: set[bytes] = set()
        self.attempted: set[tuple[bytes, int]] = set()
        self.active_window: int | None = None
        self.last_window = -1
        self.outputs: list[Dev1SubmissionIntent] = []

    def _delivery(self, delivery: Dev1Delivery) -> None:
        dealing = delivery.authenticated.signed.dealing
        if dealing.session_id != self.session_id or delivery.recipient != self.reporter:
            return
        evidence = ImplicationEvidence(dealing.dealing_id, delivery.recipient, delivery.recovery_private_key)
        if verify_implication(dealing, evidence).accepted:
            incident = Dev1Incident(delivery.authenticated, evidence)
            self.candidates.setdefault(incident.incident_id, incident)

    def _flush(self, time: int) -> tuple[Dev1SubmissionIntent, ...]:
        if self.active_window is None:
            return ()
        outputs = []
        for incident_id in sorted(self.candidates):
            attempt = incident_id, self.active_window
            if incident_id not in self.terminal and attempt not in self.attempted:
                self.attempted.add(attempt)
                intent = Dev1SubmissionIntent(time, self.reporter, self.active_window, self.candidates[incident_id])
                self.outputs.append(intent)
                outputs.append(intent)
        return tuple(outputs)

    def step(self, event: LogicalEvent) -> tuple[Dev1SubmissionIntent, ...]:
        if event.kind is EventKind.ACSS_DELIVERY:
            if not isinstance(event.payload, Dev1Delivery):
                raise TypeError("ACSS delivery requires Dev1Delivery")
            self._delivery(event.payload)
        elif event.kind is EventKind.WINDOW_OPEN:
            window = int(event.payload)
            if window > self.last_window:
                self.last_window = window
                self.active_window = window
        elif event.kind is EventKind.WINDOW_CLOSE:
            if int(event.payload) == self.active_window:
                self.active_window = None
        elif event.kind is EventKind.RECEIPT:
            if not isinstance(event.payload, Dev1Receipt):
                raise TypeError("Dev1 receipt requires Dev1Receipt")
            if event.payload.terminal:
                self.terminal.add(event.payload.incident_id)
        elif event.kind not in {EventKind.TICK, EventKind.SUBMISSION, EventKind.INCLUSION, EventKind.VERDICT, EventKind.RECOVERY_RELEASE}:
            raise ValueError("unsupported Dev1 controller event")
        return self._flush(event.time)
