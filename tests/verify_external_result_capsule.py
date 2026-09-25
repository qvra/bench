from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

path = (
    ROOT
    / "evidence"
    / "external-entity-resolution"
    / "capsule-v1.json"
)

capsule = json.loads(
    path.read_text(
        encoding="utf-8"
    )
)

assert (
    capsule["schema"]
    == "qvra-external-result-capsule/v1"
)

declared = capsule.pop(
    "capsule_sha256"
)

canonical = json.dumps(
    capsule,
    sort_keys=True,
    separators=(",", ":"),
).encode()

actual = hashlib.sha256(
    canonical
).hexdigest()

assert actual == declared

assert (
    capsule["benchmark_commit"]
    == "d5c70a572f895e562ad96b2d14f437b097f8013f"
)

assert (
    capsule["claim_level"]
    == "COMPARATIVE_RESULT_VERIFIED"
)

assert (
    capsule["qvra_system_compared"]
    is False
)

assert (
    capsule["global_superiority_claim"]
    is False
)

assert (
    capsule["publication_status"]
    == "UNPUBLISHED"
)

print("CAPSULE_DIGEST=PASS")
print("BENCHMARK_COMMIT=PASS")
print("CLAIM_BOUNDARY=PASS")
print("PUBLICATION_STATUS=UNPUBLISHED")
