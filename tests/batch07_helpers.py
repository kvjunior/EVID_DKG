from accountable_dkg.crypto.encryption import HybridEncryptionProvider
from accountable_dkg.crypto.pedersen import Q
from accountable_dkg.crypto.signatures import Ed25519SignatureProvider
from accountable_dkg.protocol.acss import (
    RecoveryKeyUseRegistry, SignedAcssDealing, authenticate_dealing, create_dealing,
)
from accountable_dkg.protocol.session import Participant, Roster, SessionContext
from accountable_dkg.protocol.state_machine import LocalDkgStateMachine


def build_fixture():
    n, t, ell = 4, 1, 2
    provider = Ed25519SignatureProvider()
    signature_pairs = [provider.generate_keypair() for _ in range(n)]
    roster = Roster(tuple(Participant(i + 1, signature_pairs[i][1]) for i in range(n)))
    session = SessionContext("EVID-DKG", 1, 77, ell, Q, b"batch07-session!", roster)
    registry = RecoveryKeyUseRegistry()
    contributions = {}
    recovery_private = {}
    for dealer in range(1, n + 1):
        pair = []
        for which in (0, 1):
            recovery_pairs = [HybridEncryptionProvider.generate_keypair() for _ in range(n)]
            private = {i + 1: recovery_pairs[i][0] for i in range(n)}
            public = {i + 1: recovery_pairs[i][1] for i in range(n)}
            recovery_private[dealer, which] = private
            base = 10 + 40 * which + dealer
            masks = (base + 20, base + 30)
            nonce = f"B07-{dealer}-{which}-nonce!!!".encode()
            dealing = create_dealing(
                session.session_id, dealer, t, base, public, registry,
                nonce=nonce, coefficients=(base, base + 10), blindings=masks,
            )
            signed = SignedAcssDealing.sign(dealing, provider, signature_pairs[dealer - 1][0])
            authenticated = authenticate_dealing(signed, provider, signature_pairs[dealer - 1][1]).authenticated
            assert authenticated is not None
            pair.append(authenticated)
        contributions[dealer] = tuple(pair)
    machines = {}
    for participant in range(1, n + 1):
        machine = LocalDkgStateMachine(
            session, participant, t, ell, provider, signature_pairs[participant - 1][0]
        )
        for dealer, (first, second) in contributions.items():
            assert machine.register_dealer_pair(
                first, recovery_private[dealer, 0][participant],
                second, recovery_private[dealer, 1][participant],
            )
        machines[participant] = machine
    return session, provider, signature_pairs, contributions, machines


def complete_fixture(selected=(1, 2, 3, 4)):
    session, provider, signature_pairs, contributions, machines = build_fixture()
    for machine in machines.values():
        machine.accept_agreement(tuple(selected))
    randex = {sender: machines[sender].emit_randex() for sender in machines}
    for recipient, machine in machines.items():
        for sender in machines:
            machine.accept_randex(randex[sender][recipient - 1])
    keys = {sender: machines[sender].emit_key() for sender in machines}
    for machine in machines.values():
        for sender in machines:
            machine.accept_key(keys[sender])
        assert machine.output is not None
    return session, provider, signature_pairs, contributions, machines
