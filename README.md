# EVID-DKG: Distributed Key Generation with Public Evidence

**Current project name: EVID-DKG. Submission artifact, 30 October 2026.**

Anonymous review artifact: <https://anonymous.4open.science/r/EVID_DKG-8ADC/>

This archive contains the complete LaTeX source, bibliography, revised Figures
1--3, executable implementation, tests, proof/interface notes, and generated
results accompanying the paper. The paper PDF is
`output/pdf/EVID_DKG_STOC2027_submission.pdf`; the LaTeX entry point is
`paper/stoc2027_submission.tex`.

## Reproduction quick start

The artifact requires Python 3.11+ and the dependencies in `pyproject.toml`.
From the repository root:

    make test
    make integrated
    make reproduce

The last command regenerates the validation outputs, cost tables, manuscript,
and `MANIFEST.sha256`. The end-to-end composition assessment is deliberately
fail-closed: it reports the implemented deterministic checks and the named
imported/joint premises without converting unresolved premises into an
unconditional cryptographic theorem.

## Artifact layout

- `paper/`: complete LaTeX source, bibliography, and figure assets.
- `src/`: executable EVID-DKG implementation.
- `tests/`: unit and cross-batch integration tests.
- `proofs/` and `research/`: formal interfaces, obligations, and claim register.
- `results/`: generated validation, simulation, cost, and reproducibility files.
- `scripts/`: one-command validation, cost, paper, and packaging scripts.
This research workspace supersedes Batch 01 after independent review. It
incorporates Claude's adapter repairs and strengthens verification against the
hashes pinned by the handle. See `NAME.md`, `CLAUDE_PROMPT.md`, and
`research/rq1_interface_and_cost_spec.md` for the active name and next task.

Version 0.9.1 adds a complete 42-source literature evidence matrix, a
citation-integrated literature review, and a cross-file claim calibration
against peer-reviewed work through CRYPTO and PODC 2026. The review changes no
core algorithm or measured byte value: it confirms the simulator algebra while
retaining all concrete composition blockers. Version 0.9.0 added Batch 10:
exact canonical-byte and derived-operation cost
reports, a one-command reproducibility pipeline, the final contribution
decision, and a compiled research-artifact paper. It also removes repeated
finalization values from quorum-certificate encodings. Version 0.8.0 added
Batch 09: the executable static `C1/C2` ideal interface,
explicit leakage auditing, Das'23 trapdoor-reprogramming algebra, an exact
finite hybrid check, and a fail-closed conditional composition framework.
Version 0.7.0 added Batch 08: finalized-ledger Dev1–Dev4 public judging,
`n-t` signed output certificates, explicit ledger finality, canonical
publication, and deterministic publisher failover. Version 0.6.0 added Batch
07: validated external-MVBA decisions, canonical
qualification anchors, hyperinvertible extraction, RANDEX/OEC, proof-bound KEY
points, and the deterministic post-agreement local DKG state machine. Version
0.5.0 added Batch 06: the source-derived ACSS algebraic core,
authenticated encrypted dealings, per-dealing recovery keys, Dev1 implication
and recovery, exposure accounting, and capability-gated retained events.
Version 0.4.0 added Batch 05: pinned concrete signature, encryption, commitment,
point-validation and decryption-attestation adapters with real RFC vectors and
negative tests. Version 0.3.0 added Batch 04: the reviewed reporting-controller semantics,
deterministic joint event replay, explicit observation views, ledger lifecycle,
evidence chunking, and serialized communication counters. Version 0.2.0 added
Batch 03: the bounded canonical packet contract, fixed
session and roster context, anchor acceptance boundary, cryptographic provider
interfaces, RANDEX/KEY semantic slots, and authentication-before-attribution.
Batch 09 completes the scoped executable simulator/audit framework but does not
establish the complete theorem. The concrete setup exposes no simulation
trapdoor or proof simulator; Dev1/recovery and ledger-joint composition remain
open; MVBA/RBC/full ACSS are imported; and adaptive corruption is outside the
frozen model.

The former name DA-ADKG identifies historical records and the frozen
DA-ADKG-C baseline. Its original filenames and hashes remain meaningful.
The generic Python import `accountable_dkg` stays stable. The current package
distribution is `evid-dkg-research`.

Earlier batch records below are retained as history. The accepted 0.1.2
foundation remains preserved in the history. Batch 03's implementation is
tested, and its context-binding statement is conditional on the selected
signature and reference-binding assumptions. No complete protocol or
cryptographic theorem is claimed.

**Historical Batch 01, version 0.1.1 (25 Oct 2026):** isolated baseline execution and
exact committee sampling. See `../START_HERE.md` and `../REVIEW_PROMPT.md` for
this batch. The existing G1 decision and cryptographic proof statuses are
retained; this batch establishes no new DKG theorem.

**Status (25 Oct 2026): G1 novelty gate NOT passed.** The earlier broad
feasibility objective is implied by Chainlink DKG v2 plus a short judge argument
(Proposition A, `proofs/accountability_corollary.md`). See
`research/contribution_decision.md`. No candidate protocol is implemented.
Only the cost question RQ1 remains, and it is unresolved and not claimed open.

This is a working research foundation for investigating an accountability
transformation that preserves the joint uniform distribution of a DKG sharing
polynomial. It is not a complete DKG protocol or a submission-ready artifact.

## What runs now

- Exact small-field sampling for a uniform polynomial and for a polynomial
  constrained by adversary-selected corrupt shares.
- Exact enumeration of two known failure modes: rushing direct-sum dealing and
  selective exclusion after commitment. These are baseline counterexamples,
  not claimed contributions.
- An authenticated toy ledger with explicit capacity and acceptance windows.
- A pending/submitted/adjudicated evidence model.
- Tests that distinguish a rejected transaction from a private transaction:
  rejected payloads remain in the public observation model.

The repository uses Python 3.11+ and pins `cryptography==50.0.2` for Batch 05.
Optional legacy baseline execution additionally needs the frozen
source copy and its `cryptography` dependency in this interpreter's system or
virtual-environment site packages (`-I` ignores user-site installs).
Run the foundation without installing a package:

    make test
    make audit

Exact committee parameter search (sampling assumptions only):

    PYTHONPATH=src python3 -m accountable_dkg.committee --n 1000 --t 333 --failure-bits 128

To include all frozen-baseline integration checks, set `DA_ADKG_C_PATH` to the
corrected source directory before `make test`. Seven tests skip if it is absent.
The adapter executes a verified snapshot in a fresh process; `load()` returns
an execution handle rather than a module. See `baselines/README.md`.

Equivalent commands:

    PYTHONPATH=src python3 -m unittest discover -s tests -v
    PYTHONPATH=src python3 -m accountable_dkg

For the complete available cross-batch validation, including the archived
02.x finite diagnostics, run:

    python3 scripts/run_integrated_validation.py

To regenerate costs, validation, the paper, hashes, and the reproducibility
record in one command, run:

    python3 scripts/reproduce_release.py

`results/foundation_audit.json` is generated from this finite model. Its values
are exact counts, not cryptographic benchmarks. The small prime q=7 is for
enumeration only. The new protocol and accountability compiler are interfaces,
not implementations; the CLI explicitly records that fact.

## Added in Batch 03

- `protocol/session.py`: immutable authorized roster and canonical session id.
- `protocol/anchors.py`: unverified metadata separated from accepted anchors.
- `protocol/encoding.py` and `protocol/messages.py`: bounded injective encoding,
  canonical RANDEX/KEY packets and semantic slot rules.
- `crypto/interfaces.py` and `crypto/transcript_domains.py`: typed provider
  boundaries and purpose-separated transcripts.
- `research/protocol_contract_v1.md` and `proofs/wire_context_binding.md`: exact
  scope, assumptions, reduction and unresolved obligations.

## Added in Batch 04

- `execution/`: typed events, stable scheduler, explicit random tapes,
  visibility-separated observations, chunking and a ledger lifecycle adapter.
- `protocol/evidence_producer.py`: the reviewed Dev2--Dev4 controller on Batch
  03 authenticated packets, without a corruption-set oracle.
- `accounting/`: distinct submitted, included, rejected, read and private-byte
  counters.
- four test modules for projection, joint replay, chunks and public visibility.
- `proofs/reporter_projection.md` and `proofs/ledger_interface.md`: exact proved
  model properties and the remaining LEDGER-JOINT boundary.

## Added in Batch 05

- `crypto/signatures.py`: Ed25519 packet-signature provider.
- `crypto/encryption.py`: context-bound X25519/HKDF-SHA256/ChaCha20-Poly1305 envelope.
- `crypto/groups.py` and `crypto/validation.py`: strict X25519 and compressed
  SEC1 P-256 validation with purpose-separated policy.
- `crypto/commitments.py`: domain-separated SHA-256 byte commitment, explicitly
  not a polynomial commitment.
- `crypto/decryption_proofs.py`: signed decryption attestation, explicitly not
  a zero-knowledge proof.
- RFC vectors, malformed encodings, wrong contexts/keys, off-curve/low-order
  values, tampering, and packet-boundary integration tests.
- `research/crypto_assumptions.md` and `proofs/primitive_dependencies.md` record
  exact assumptions and non-claims.

## Added in Batch 06

- `crypto/pedersen.py`: executable Pedersen polynomial evaluation relation over
  RFC 5114 group 24, explicitly reference-only and not deployment audited.
- `protocol/acss.py`: canonical signed dealing, unique scoped recovery-key
  registration, per-recipient encryption and local relation checking.
- `protocol/recovery.py`: false-implication rejection, genuine Dev1 evidence,
  hold/retry/terminal reporting, threshold recovery and exposure inventory.
- `protocol/retained_events.py`: proof-capability access with digest-only public
  records and terminal erasure.
- four test modules covering ACSS relations, Dev1, key scoping, copied objects,
  recovery exposure and retained access.
- `research/batch06_contract.md`, `proofs/acss_interface.md`, and
  `proofs/recovery_exposure.md` state the proved interface properties and the
  still-open joint-exposure theorem.

## Added in Batch 07

- `protocol/agreement.py` and `protocol/qualification.py`: external-MVBA
  validity checks and canonical qualification anchors over two ACSS vectors.
- `protocol/extraction.py`: Cauchy hyperinvertible extraction over the session
  field, with identical weights for values, masks, and commitments.
- `protocol/oec.py` and `protocol/key_derivation.py`: finite OEC, verified
  RANDEX relations, context-bound Schnorr KEY proofs, and group interpolation.
- `protocol/state_machine.py`: deterministic local phases from qualified ACSS
  through common public and threshold keys, including early-packet replay.
- adversarial tests for invalid agreement outputs, fragments and KEY proofs,
  excluded dealers, and pre-agreement delivery.
- `research/batch07_contract.md`, `proofs/extraction_and_key_derivation.md`, and
  `proofs/local_state_machine.md` state the implemented properties and the
  external MVBA/ACSS/security-theorem boundary.

## Added in Batch 08

- `protocol/public_evidence.py` and `protocol/public_judge.py`: canonical
  evidence envelopes and authentication-before-attribution for finalized
  Dev1–Dev4 ledger evidence.
- `protocol/finalization.py`: sign-once output votes and canonical `n-t` quorum
  certificates binding the session, anchor, public key, and threshold keys.
- `protocol/publication.py`: canonical certificate publication, deterministic
  rotating publishers, per-window idempotence, and finalized-output checks.
- `execution/ledger_adapter.py`: explicit finality separated from submission,
  inclusion, receipt, and terminal adjudication.
- adversarial tests for false implications, forged signatures, valid-message
  framing attempts, mixed or insufficient certificates, late publication, and
  successful backup publication.
- `research/batch08_contract.md`, `proofs/public_judge.md`, and
  `proofs/finalization_publication.md` state the exact safety and liveness
  boundaries.

## Added in Batch 09

- `simulation/ideal.py`: static ideal polynomial sampling and reconstruction of
  the ideal polynomial represented by completed Batch 07 shares.
- `simulation/leakage.py`: typed public, final-share, internal-state,
  recovery, plaintext, and scheduler exposure inventory for fixed `C1/C2`.
- `simulation/hybrid.py`: executable trapdoor reprogramming and exact
  degree-one real/simulated finite-view comparison.
- `simulation/composition.py`: machine-readable dependency/status graph that
  fails closed on unresolved obligations.
- `simulation/end_to_end.py`: conditional adapter over actual Batch 07 outputs
  and Batch 08 certificates/publications; it never returns an unconditional
  security claim.
- `scripts/run_batch09_assessment.py`: reproducible JSON assessment in
  `results/batch09/simulation_assessment.json`.
- twelve focused tests covering ideal uniformity, leakage boundaries,
  reprogramming, finite hybrid equality, end-to-end traces, and fail-closed
  composition.
- `research/batch09_contract.md`, `proofs/static_simulator.md`,
  `proofs/leakage_inventory.md`, and `proofs/conditional_composition.md` record
  the exact conditional theorem and blockers.

## Added in Batch 10

- `accounting/protocol_cost.py`: exact canonical-byte measurements and derived
  operation counts for the implemented protocol objects, with external
  ACSS/RBC/MVBA transport explicitly excluded rather than estimated.
- `scripts/generate_batch10_costs.py`: reproducible JSON, CSV, and Markdown
  cost reports for `(n,t,ell)=(4,1,2),(7,2,4),(10,3,6)`.
- `scripts/reproduce_release.py`: one-command cost, validation, paper, and hash
  pipeline with a machine-readable reproducibility record.
- `research/final_contribution_decision.md`: final claim boundary and venue
  recommendation; the original STOC-level theorem remains not established.
- `paper/main.tex` and `output/pdf/EVID_DKG_research_artifact.pdf`: the scoped
  research artifact paper.
- `paper/stoc2027_submission.tex` and
  `output/pdf/EVID_DKG_STOC2027_submission.pdf`: the 11-point, letter-size
  STOC 2027 submission draft, including the multi-page literature matrix,
  architecture/evidence/composition figures, conditional theorem, and required
  AI-methodology statement. Build it with `make stoc-paper`.

## Added in the 25 Oct pass

- `structural.py`: exact enumerations for O1 (committee direct sum), interface bias
  (rushing direct sum vs hide-until-fixed) and completion conditioning.
- `baselines/da_adkg_c.py`: hash-verified adapter to the frozen corrected legacy
  copy (`DA_ADKG_C_PATH`). Its target is F*, and it is a smoke check only.
- `research/`: model v1, novelty matrix, G1 decision, theorem register.
- `proofs/`: Proposition A, scoped counterexamples N1–N4, updated obligations.
- See CHANGES.md for hashes.

## Research decision (original starter text)

Investigate whether a useful, nontrivial accountability transformation can
preserve full polynomial uniformity and final-share leakage security, while
giving a proved communication/evidence overhead. First establish whether this
has already been achieved by known constructions and wrappers. Do not proceed
to a large implementation if the result is already implied by prior work.

The repaired DA-ADKG-C realizes, at most on the present proof record, the weaker
adversary-programmed-corrupt-share target. It is a baseline. Its corrected source
is referenced in `baselines/manifest.json`; no historical paper results are
relabelled as measurements of this repository.

Read `RESEARCH_PLAN.md`, `ARCHITECTURE.md`, and `CLAUDE_PROMPT.md` before extending
the code. Files marked future in the architecture are intentional planned
deliverables and are not empty implementations hidden in this starter.
