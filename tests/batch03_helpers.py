from hashlib import sha256

from accountable_dkg.protocol.anchors import AnchorKind, AnchorMetadata, AnchorSet, accept_anchor
from accountable_dkg.protocol.session import Participant, Roster, SessionContext

from ideal_providers import IdealAnchorVerifier, IdealHMACProvider


KEYS = (b"key-one", b"key-two", b"key-three")


def session(*, version: int = 1, nonce: bytes = b"0123456789abcdef") -> SessionContext:
    roster = Roster(tuple(Participant(i + 1, key) for i, key in enumerate(KEYS)))
    return SessionContext("EVID-DKG", version, 9, 1, 2**255 - 19, nonce, roster)


def accepted_anchor(ctx: SessionContext):
    metadata = AnchorMetadata(ctx.session_id, AnchorKind.AGREEMENT, 4, sha256(b"agreement").digest())
    support = b"accepted:" + sha256(metadata.encode()).digest()
    acceptance = accept_anchor(metadata, support, IdealAnchorVerifier())
    assert acceptance.anchor is not None
    return acceptance.anchor


def anchor_set(ctx: SessionContext) -> AnchorSet:
    return AnchorSet((accepted_anchor(ctx),))


PROVIDER = IdealHMACProvider()
