from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

path = (
    ROOT
    / "protocols"
    / "qvra-native-entity-resolution-v1.json"
)

data = json.loads(
    path.read_text(
        encoding="utf-8"
    )
)

assert (
    data["schema"]
    == "qvra-native-entity-resolution-preregistration/v1"
)

assert (
    data["status"]
    == "PREREGISTERED_NOT_IMPLEMENTED"
)

assert (
    data["baseline_main"]
    == "c8b16f32e1f38cd1aff7f2ee9204f26f38c14d77"
)

assert (
    data["baseline_replication_capsule_sha256"]
    == "5103b577150d845f3d1e3aa913774546c6d5e1e0af9d29fd29d4ef58340d0c8d"
)

assert data["system_id"] == "qvra-native-er-v1"

assert (
    data["runtime"]["test_truth_access"]
    is False
)

assert (
    data["runtime"]["external_model_api_access"]
    is False
)

assert (
    data["inputs"]["truth_json_available_to_adapter"]
    is False
)

assert (
    data["threshold_selection"]["source"]
    == "training_data_only"
)

assert (
    data["threshold_selection"][
        "test_metric_feedback_allowed"
    ]
    is False
)

assert (
    data["pair_model"]["family"]
    == "deterministic_logistic_regression"
)

assert (
    data["clustering"]["method"]
    == "connected_components"
)

assert data["execution"]["runs"] == 3
assert data["execution"]["seed"] == 20260925
assert data["execution"]["corpus_entities"] == 500

assert (
    data["execution"][
        "same_corpus_as_external_baseline"
    ]
    is True
)

assert (
    data["execution"][
        "same_evaluator_as_external_baseline"
    ]
    is True
)

assert (
    data["comparison_policy"]["single_global_score"]
    is False
)

assert (
    data["comparison_policy"]["winner_label"]
    is False
)

assert (
    data["comparison_policy"][
        "global_superiority_claim_allowed"
    ]
    is False
)

constraints = data[
    "implementation_constraints"
]

for key in (
    "algorithm_family_locked_before_implementation",
    "feature_set_locked_before_implementation",
    "candidate_generation_locked_before_implementation",
    "threshold_rule_locked_before_implementation",
    "clustering_rule_locked_before_implementation",
    "test_truth_tuning_forbidden",
    "external_baseline_retuning_forbidden",
):
    assert constraints[key] is True

assert (
    data["claim_state"]["qvra_system_compared"]
    is False
)

assert (
    data["claim_state"]["qvra_result_available"]
    is False
)

assert (
    data["claim_state"]["global_superiority_claim"]
    is False
)

print("QVRA_NATIVE_PREREGISTRATION=PASS")
print("TEST_TRUTH_ACCESS=false")
print("TRAIN_ONLY_THRESHOLD_SELECTION=PASS")
print("ALGORITHM_FAMILY_LOCKED=PASS")
print("FEATURE_SET_LOCKED=PASS")
print("CANDIDATE_GENERATION_LOCKED=PASS")
print("CLUSTERING_RULE_LOCKED=PASS")
print("EXTERNAL_BASELINE_RETUNING=false")
print("QVRA_SYSTEM_COMPARED=false")
