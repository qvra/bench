from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

registry_path = ROOT / "challengers/registry.json"
protocol_path = ROOT / "protocols/publication-v1.json"
schema_path = ROOT / "schemas/challenger.schema.json"

registry = json.loads(
    registry_path.read_text(encoding="utf-8")
)

protocol = json.loads(
    protocol_path.read_text(encoding="utf-8")
)

schema = json.loads(
    schema_path.read_text(encoding="utf-8")
)

assert registry["schema"] == "qvra-challenger-registry/v1"
assert isinstance(registry["challengers"], list)

assert protocol["schema"] == "qvra-publication-protocol/v1"
assert protocol["status"] == "PRE_EXTERNAL_EXECUTION"

required_publication = set(
    protocol["required_for_publication"]
)

assert "all_scheduled_runs_retained" in required_publication
assert "failed_runs_retained" in required_publication
assert "challenger_versions_bound" in required_publication
assert "result_capsule_verified" in required_publication
assert "limitations_declared" in required_publication

forbidden = set(protocol["forbidden"])

assert "granting_qvra_owned_systems_privileged_scoring" in forbidden
assert "reporting_best_run_as_typical" in forbidden
assert "claiming_global_superiority_from_one_suite" in forbidden
assert "claiming external comparison before external challenger execution" in forbidden

levels = protocol["claim_levels"]

assert set(levels) == {
    "HARNESS_VALIDATED",
    "EXTERNAL_RUN_OBSERVED",
    "COMPARATIVE_RESULT_VERIFIED",
    "REPLICATED_RESULT",
}

assert schema["title"] == "qvra external challenger"

required = set(schema["required"])

assert required == {
    "system_id",
    "kind",
    "source",
    "version",
    "adapter",
    "execution",
    "status",
}

mutation_rule = (
    schema["properties"]
    ["execution"]
    ["properties"]
    ["mutation_allowed"]
)

assert mutation_rule["const"] is False

for path in (
    registry_path,
    protocol_path,
    schema_path,
):
    digest = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()

    assert len(digest) == 64

    print(
        path.relative_to(ROOT),
        digest,
    )

print("CHALLENGER_REGISTRY=PASS")
print("PUBLICATION_PROTOCOL=PASS")
print("VERSION_BINDING_REQUIRED=PASS")
print("FAILED_RUN_RETENTION_REQUIRED=PASS")
print("NO_PRIVILEGED_QVRA_SCORING=PASS")
print("NO_SINGLE_SUITE_GLOBAL_SUPERIORITY=PASS")
print("MUTATION_ALLOWED_FALSE=PASS")
print("CLAIM_LADDER=PASS")
