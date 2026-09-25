import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

path = (
    ROOT
    / "evidence"
    / "three-system-comparison"
    / "capsule-v1.json"
)

data = json.loads(path.read_text(encoding="utf-8"))

assert data["schema"] == "qvra-three-system-comparative-capsule/v1"
assert data["suite"] == "entity-resolution-real-v3"

method = data["methodology"]

assert method["same_corpus"] is True
assert method["same_truth"] is True
assert method["same_metric_semantics"] is True
assert method["runs_per_system"] == 3
assert method["qvra_result_fixed_before_comparison"] is True
assert method["external_results_fixed_before_qvra_implementation"] is True
assert method["system_execution_during_comparison"] is False

assert set(data["systems"]) == {
    "qvra-native-er-v1",
    "splink",
    "dedupe",
}

assert set(data["common_metrics"]) == {
    "pair_precision",
    "pair_recall",
    "pair_f1",
    "cluster_exact_match_rate",
}

q = data["systems"]["qvra-native-er-v1"]["metrics"]
s = data["systems"]["splink"]["metrics"]
d = data["systems"]["dedupe"]["metrics"]

assert q["pair_f1"]["mean"] == 0.9916640938561284
assert s["pair_f1"]["mean"] == 0.24973204715969988
assert d["pair_f1"]["mean"] == 0.123895595329848

assert q["cluster_exact_match_rate"]["mean"] == 0.9714285714285714
assert s["cluster_exact_match_rate"]["mean"] == 0.06285714285714286
assert d["cluster_exact_match_rate"]["mean"] == 0.09142857142857143

claim = data["claim_boundary"]

assert claim["claim_level"] == "SUITE_SPECIFIC_COMPARATIVE_RESULT"
assert claim["global_superiority_claim"] is False
assert claim["cross_suite_generalization"] is False
assert claim["publication_status"] == "UNPUBLISHED"

print("THREE_SYSTEM_CAPSULE=PASS")
print("SYSTEM_COUNT=3")
print("COMMON_METRIC_COUNT=4")
print("SAME_CORPUS=PASS")
print("SAME_TRUTH=PASS")
print("GLOBAL_SUPERIORITY_CLAIM=false")
print("PUBLICATION_STATUS=UNPUBLISHED")
