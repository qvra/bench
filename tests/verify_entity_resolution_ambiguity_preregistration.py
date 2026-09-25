import hashlib
import json
from pathlib import Path

R = Path(__file__).resolve().parents[1]
P = R / "protocols/entity-resolution-ambiguity-v1.json"
Q = R / "adapters/native/qvra_er_v1.py"

d = json.loads(P.read_text(encoding="utf-8"))

assert d["schema"] == "qvra-entity-resolution-ambiguity-preregistration/v1"
assert d["suite_id"] == "entity-resolution-ambiguity-v1"
assert d["status"] == "PREREGISTERED_NOT_IMPLEMENTED"

f = d["family_relationship"]
assert f["family_1"] == "entity-resolution-real-v3"
assert f["family_1_results_known"] is True
assert f["family_2_distribution_frozen_after_family_1"] is True
assert f["generator_not_implemented_at_preregistration"] is True
assert f["test_truth_not_generated_at_preregistration"] is True

s = d["systems"]
qsha = hashlib.sha256(Q.read_bytes()).hexdigest()
assert s["qvra"]["implementation_sha256"] == qsha
assert s["qvra"]["retuning_allowed"] is False
assert s["splink"]["version"] == "4.0.17"
assert s["splink"]["retuning_allowed"] is False
assert s["dedupe"]["version"] == "3.0.3"
assert s["dedupe"]["compatibility_binding"] == "BTrees==6.4"
assert s["dedupe"]["retuning_allowed"] is False

p = d["population_model"]
assert (p["latent_entities"], p["train_entities"], p["test_entities"]) == (600, 180, 420)
assert p["split_unit"] == "latent_entity"
assert p["split_before_record_corruption"] is True
assert p["entity_overlap_between_train_and_test"] is False
assert p["seed_schedule"] == [20260926, 20260927, 20260928, 20260929, 20260930]
assert abs(sum(p["records_per_entity_distribution"]["probabilities"]) - 1.0) < 1e-12

l = d["latent_identity_model"]
assert l["identity_generated_before_records"] is True
assert l["same_full_name_distinct_entities_allowed"] is True
assert l["email_is_not_perfect_identifier"] is True
assert l["shared_email_allowed"] is True
assert l["recycled_email_allowed"] is True
assert l["email_local_part_must_not_encode_entity_id"] is True

c = d["collision_model"]
assert c["created_before_record_corruption"] is True
assert c["single_observed_field_global_identifier_prohibited"] is True
assert "multi_field_hard_negative" in c["group_types"]

g = d["record_generation_model"]
assert g["clean_record_generated_first"] is True
assert g["independent_of_system_outputs"] is True
assert g["independent_of_family_1_errors"] is True
assert g["independent_of_test_truth_scoring"] is True
assert abs(sum(g["corruption_count_distribution"]["probabilities"]) - 1.0) < 1e-12

for name, value in d["sampling_invariants"].items():
    assert value is True, name

a = d["corpus_acceptance"]
assert a["performed_before_any_system_execution"] is True
assert a["first_seed_passing_all_invariants_must_be_used"] is True
assert a["system_performance_may_not_be_used_for_acceptance"] is True

e = d["evaluation"]
assert e["runs_per_system"] == 3
assert e["primary_metrics"] == [
    "pair_precision",
    "pair_recall",
    "pair_f1",
    "cluster_exact_match_rate",
]
assert e["primary_aggregation"] == "mean"
assert e["secondary_aggregation"] == "median"
assert e["timing_is_quality_gate"] is False

r = d["runtime_policy"]
assert r["authoring_python_is_not_execution_runtime"] is True
assert r["observed_authoring_python"] == "3.14.3"
assert r["execution_runtime_frozen_before_first_run"] is True
assert r["existing_system_environments_must_be_reproduced"] is True

for name, value in d["mutation_policy"].items():
    assert value is False, name

claim = d["claim_policy"]
assert claim["family_2_result_is_suite_specific"] is True
assert claim["cross_family_descriptive_analysis_after_family_2"] is True
assert claim["global_superiority_claim"] is False
assert claim["universal_generalization_claim"] is False
assert claim["publication_before_governance"] is False

for name, value in d["execution_state"].items():
    assert value is False, name

print("FAMILY_2_PREREGISTRATION=PASS")
print("GENERATIVE_MODEL_LOCK=PASS")
print("SEED_ACCEPTANCE_RULE=PASS")
print("QVRA_RETUNING=false")
print("EXTERNAL_RETUNING=false")
print("SYSTEM_EXECUTION=false")
print("GLOBAL_SUPERIORITY_CLAIM=false")
