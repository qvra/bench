#!/usr/bin/env python3

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-v1.json"
)

d = json.loads(
    PROTOCOL.read_text(
        encoding="utf-8"
    )
)

assert d["schema"] == (
    "qvra-entity-resolution-ambiguity-execution/v1"
)

assert d["benchmark_family"] == (
    "entity-resolution-ambiguity-v1"
)

assert d["benchmark_main"] == (
    "5b949a195f1433d53e66969ef7167a628a4e7588"
)

source = d["source_binding"]

assert source["generator_sha256"] == (
    "b34a05b1ccacd109f4b1fd98daf3a4eb48d04cb6262f555ac8ff9fd72d865e13"
)

assert source["materializer_sha256"] == (
    "1d54f8f444cf5517986338f4d9ce7f6b9e6bb24bb5d6b4b204bf1696b5c8a15d"
)

assert source["projected_corpus_sha256"] == (
    "a113df4a08d57ec522cbf47682d3d23aefe9da58fedebb555faedd82d74d9c2d"
)

assert source[
    "materialization_receipt_sha256"
] == (
    "d734721fa8f40b779c4fa297a5be4c0e5d1287b8836a8b1d56899f121137ef94"
)

corpus = d["corpus_binding"]

assert corpus["selected_seed"] == 20260926
assert corpus["records"] == 2323
assert corpus["train_records"] == 709
assert corpus["test_records"] == 1614
assert corpus["truth_records"] == 1614

assert corpus["files"] == {
    "manifest.json":
        "27c5e7bcd3d3f75f87b095cedd4c996bf02575299c1ed1412eec9571676e3708",
    "records.csv":
        "06651e82991cc8e2a6c23a8e05eaa79ba56474f61060d8b0b7dc2d3b249e43df",
    "split.json":
        "7c1871b414aad1b7612c758b704a968a19d7dd13ea64bc06f59f9cd486fd5d86",
    "test.csv":
        "6e98690c2ee302bc16f7deda59a3e332e872f076925d0380c926d8f74e20fadb",
    "train.csv":
        "9ea26585df5fe663c5a5cbcaf261a5e063d021d10b9a3795a672ea624c881815",
    "truth.json":
        "d412e2705d556b7e8196d02290d6f7d15678381353baae5dbd30935a96e33e7d",
}

assert d["systems"] == [
    "qvra-native-er-v1",
    "splink",
    "dedupe",
]

execution = d["execution"]

assert execution["runs_per_system"] == 3

assert execution["system_inputs"] == {
    "train": "train.csv",
    "test": "test.csv",
}

assert execution["system_truth_access"] is False

assert (
    execution[
        "truth_available_only_to_evaluator"
    ]
    is True
)

for key in (
    "qvra_retuning",
    "splink_retuning",
    "dedupe_retuning",
    "configuration_may_depend_on_system_order",
    "configuration_may_depend_on_other_system_output",
    "configuration_may_depend_on_quality_result",
):
    assert execution[key] is False

for key in (
    "all_system_raw_runs_before_any_truth_scoring",
    "failed_run_retention",
    "raw_output_retention",
    "stdout_retention",
    "stderr_retention",
    "raw_outputs_hash_bound_before_truth_reveal",
):
    assert execution[key] is True

evaluation = d["evaluation"]

assert evaluation["truth"] == "truth.json"

assert evaluation["metrics"] == [
    "pair_precision",
    "pair_recall",
    "pair_f1",
    "cluster_exact_match_rate",
]

assert evaluation["primary_aggregation"] == "mean"
assert evaluation["secondary_aggregation"] == "median"

assert (
    evaluation[
        "score_only_after_all_raw_runs_frozen"
    ]
    is True
)

assert (
    evaluation[
        "same_evaluator_contract_for_all_systems"
    ]
    is True
)

assert (
    evaluation[
        "unsupported_metrics_must_not_be_invented"
    ]
    is True
)

claim = d["claim_boundary"]

assert claim["suite_specific_only"] is True
assert claim["cross_suite_generalization"] is False
assert claim["global_superiority_claim"] is False

assert d["pre_execution_state"] == {
    "comparison_performed": False,
    "quality_result_available": False,
    "system_execution": False,
    "truth_scoring": False,
}

print("FAMILY_2_EXECUTION_CAPSULE=PASS")
print("CORPUS_BINDING=PASS")
print("THREE_SYSTEM_CONTRACT=PASS")
print("RUNS_PER_SYSTEM=3")
print("SYSTEM_TRUTH_ACCESS=false")
print("ALL_SYSTEM_RAW_RUNS_BEFORE_SCORING=true")
print("RAW_OUTPUTS_HASH_BOUND_BEFORE_TRUTH_REVEAL=true")
print("RETUNING=false")
print("FAILED_RUN_RETENTION=true")
print("RAW_OUTPUT_RETENTION=true")
print("CLAIM_BOUNDARY=PASS")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
