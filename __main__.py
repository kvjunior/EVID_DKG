import json

from .attacks import late_commit, selective_exclusion
from .structural import committee_direct_sum, completion_conditioning, interface_bias
from .field import ToyField
from .interfaces import CANDIDATE_PROTOCOL_IMPLEMENTED


def main():
    print(json.dumps({
        "status": "foundation_plus_batches03_through10",
        "cryptographic_security_claim": False,
        "candidate_protocol_implemented": CANDIDATE_PROTOCOL_IMPLEMENTED,
        "batch03_packet_contract_implemented": True,
        "batch04_joint_event_infrastructure_implemented": True,
        "batch05_concrete_crypto_providers_implemented": True,
        "batch05_vess_or_nizk_implemented": False,
        "batch06_acss_relation_and_scoped_recovery_implemented": True,
        "batch06_full_async_acss_or_vess_implemented": False,
        "batch07_post_agreement_local_dkg_implemented": True,
        "batch07_async_mvba_implemented": False,
        "batch08_public_judge_implemented": True,
        "batch08_finalization_publication_failover_implemented": True,
        "batch08_ledger_consensus_or_inclusion_bound_implemented": False,
        "batch09_static_ideal_and_leakage_model_implemented": True,
        "batch09_conditional_composition_framework_implemented": True,
        "batch09_complete_security_theorem_established": False,
        "batch09_adaptive_corruption_supported": False,
        "batch10_exact_canonical_cost_model_implemented": True,
        "batch10_reproducibility_pipeline_implemented": True,
        "batch10_paper_artifact_present": True,
        "batch10_final_contribution_decision": "bounded artifact contribution; original STOC-level theorem not established",
        "complete_async_dkg_implemented": False,
        "all_planned_batches_present": True,
        "all_security_obligations_resolved": False,
        "q": 7,
        "late_commit": late_commit(ToyField(7)),
        "selective_exclusion": selective_exclusion(ToyField(7)),
        "o1_committee_direct_sum": committee_direct_sum(ToyField(7)),
        "interface_bias_direct_sum": interface_bias(ToyField(7), "DIRECT_SUM_RUSHING"),
        "interface_bias_hide_until_fixed": interface_bias(ToyField(7), "HIDE_UNTIL_FIXED"),
        "completion_conditioning": completion_conditioning(ToyField(7)),
        "novelty_gate_G1": "not passed: see research/final_contribution_decision.md",
    }, indent=2))


if __name__ == "__main__":
    main()
