from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

path = (
    ROOT
    / "evidence"
    / "external-entity-resolution"
    / "replication-capsule-v1.json"
)

capsule = json.loads(
    path.read_text(
        encoding="utf-8"
    )
)

assert (
    capsule["schema"]
    == "qvra-external-replication-capsule/v1"
)

declared = capsule.pop("capsule_sha256")

actual = hashlib.sha256(
    json.dumps(
        capsule,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()

assert actual == declared

assert capsule["benchmark_commit"] == (
    "d5c70a572f895e562ad96b2d14f437b097f8013f"
)

assert capsule["governed_result_capsule_main"] == (
    "cf04658f9b8905dbbd39f77a55e6d7ac9b72e99e"
)

assert capsule["original_result_capsule_sha256"] == (
    "460fc01ec7eb82403b1309ecf3d48debfdf1ba06a548977a67b5a8f9e82e9c48"
)

assert capsule["quality_replication_sha256"] == (
    "a99fcabdccb336a58b221a0e635993b254f93555626bd675f91b45c7d4868cb3"
)

assert capsule["raw_replication_receipt_sha256"] == (
    "8bdc06a230e004d7dbc81009baf2e55a40e95c6247bdd6e87d147149f6d5b630"
)

assert (
    capsule["replication_scope"]
    == "clean-environment-same-machine"
)

assert capsule["runs_per_system"] == 3
assert capsule["quality_tolerance"] == 0.01
assert capsule["timing_is_replication_gate"] is False
assert capsule["claim_level"] == "REPLICATED_RESULT"
assert capsule["qvra_system_compared"] is False
assert capsule["cross_machine_replication"] is False
assert capsule["global_superiority_claim"] is False
assert capsule["publication_status"] == "UNPUBLISHED"

print("REPLICATION_CAPSULE_DIGEST=PASS")
print("ORIGINAL_CAPSULE_BINDING=PASS")
print("QUALITY_REPLICATION_BINDING=PASS")
print("RAW_REPLICATION_BINDING=PASS")
print("CLAIM_LEVEL=REPLICATED_RESULT")
print("CROSS_MACHINE_REPLICATION=false")
print("QVRA_SYSTEM_COMPARED=false")
print("GLOBAL_SUPERIORITY_CLAIM=false")
