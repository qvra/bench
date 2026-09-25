from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from qvra_bench.kernel import (
    aggregate_runs,
    build_result_capsule,
    evaluate_run,
    execute_adapter,
    precision_recall_f1,
    verify_result_capsule,
)

root = Path(__file__).resolve().parents[1]

fixture_path = (
    root / "fixtures/gold/entity-discovery.json"
)

fixture = json.loads(
    fixture_path.read_text(encoding="utf-8")
)

expected = fixture["expected_items"]

fixture_sha = hashlib.sha256(
    fixture_path.read_bytes()
).hexdigest()

manifest = json.loads(
    (
        root
        / "suites/cross-system-capability/manifest.json"
    ).read_text(encoding="utf-8")
)

assert manifest["fixture"]["sha256"] == fixture_sha
assert manifest["status"] == "CONTROLLED_HARNESS_VALIDATION"

exact = precision_recall_f1(
    expected,
    expected,
)

assert exact["precision"] == 1.0
assert exact["recall"] == 1.0
assert exact["f1"] == 1.0

systems = {
    "reference": "reference.py",
    "imperfect": "imperfect.py",
    "no-provenance": "no_provenance.py",
    "invalid-output": "invalid_output.py",
    "mutation-declared": "mutation_declared.py",
}

rows = []

for system_id, adapter in systems.items():
    for run_number in range(1, 4):
        run = execute_adapter(
            system_id,
            [
                sys.executable,
                str(root / "adapters" / adapter),
                str(fixture_path),
            ],
            timeout_seconds=5,
        )

        row = evaluate_run(
            run,
            expected,
        )

        row["run_number"] = run_number
        rows.append(row)

by_id = {}

for row in rows:
    by_id.setdefault(
        row["system_id"],
        [],
    ).append(row)

for row in by_id["reference"]:
    assert row["contract_valid"]
    assert row["provenance_complete"]
    assert row["mutation_performed"] is False
    assert row["metrics"]["f1"] == 1.0

for row in by_id["imperfect"]:
    assert abs(
        row["metrics"]["f1"] - 0.8
    ) < 1e-12

for row in by_id["no-provenance"]:
    assert row["provenance_complete"] is False

for row in by_id["invalid-output"]:
    assert row["contract_valid"] is False

for row in by_id["mutation-declared"]:
    assert row["mutation_performed"] is True

aggregates = aggregate_runs(rows)

assert len(aggregates) == 5

capsule = build_result_capsule(
    suite_id="permanent-kernel-verification",
    fixture_sha256=fixture_sha,
    evaluated_runs=rows,
)

assert verify_result_capsule(
    capsule
)["valid"]

tampered = copy.deepcopy(capsule)
tampered["payload"]["runs"][0][
    "duration_ms"
] = 0

tampered_result = verify_result_capsule(
    tampered
)

assert tampered_result["valid"] is False
assert tampered_result["reason"] == "DIGEST_MISMATCH"

print("MANIFEST_BINDING=PASS")
print("METRIC_KERNEL=PASS")
print("THREE_RUN_MINIMUM=PASS")
print("REFERENCE_CONTROL=PASS")
print("IMPERFECT_CONTROL=PASS")
print("PROVENANCE_CONTROL=PASS")
print("INVALID_OUTPUT_CONTROL=PASS")
print("MUTATION_CONTROL=PASS")
print("AGGREGATION_CONTROL=PASS")
print("CAPSULE_VERIFICATION=PASS")
print("TAMPER_CONTROL=PASS")
