#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

AUTH = ROOT / (
    "protocols/"
    "entity-resolution-ambiguity-execution-authorization-v1.json"
)

SCHEMA = ROOT / (
    "schemas/"
    "entity-resolution-ambiguity-execution-authorization.schema.json"
)

LAUNCHER = ROOT / (
    "suites/"
    "entity-resolution-ambiguity-v1/"
    "process_launcher.py"
)

DESCRIPTOR = ROOT / (
    "protocols/"
    "entity-resolution-ambiguity-command-descriptors-v1.json"
)

EXPECTED_MAIN = (
    "44c73431941c5b866d774f99077a7b54ea2043c7"
)

EXPECTED_LAUNCHER_SHA = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_DESCRIPTOR_SHA = (
    "817d3e1eae8babb26eb49792b5778898"
    "793235042020c9f904cad0057e8549ac"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


auth = json.loads(
    AUTH.read_text(
        encoding="utf-8"
    )
)

schema = json.loads(
    SCHEMA.read_text(
        encoding="utf-8"
    )
)

assert schema["type"] == "object"
assert schema["additionalProperties"] is False

assert auth["schema"] == \
    "qvra-family-2-execution-authorization/v1"

assert auth["benchmark"] == \
    "entity-resolution-ambiguity-v1"

assert auth["family"] == 2

assert auth["authorization_kind"] == \
    "one-shot-nine-run-execution"

scope = auth["scope"]

assert scope["benchmark_main"] == EXPECTED_MAIN

assert scope[
    "process_launcher_sha256"
] == EXPECTED_LAUNCHER_SHA

assert scope[
    "command_descriptor_sha256"
] == EXPECTED_DESCRIPTOR_SHA

assert sha256(LAUNCHER) == EXPECTED_LAUNCHER_SHA
assert sha256(DESCRIPTOR) == EXPECTED_DESCRIPTOR_SHA

assert scope["systems"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert scope["runs_per_system"] == 3
assert scope["total_required_raw_runs"] == 9

firewall = auth["execution_firewall"]

assert firewall["truth_input_allowed"] is False
assert firewall["retuning_allowed"] is False
assert firewall["runtime_mutation_allowed"] is False
assert firewall["network_required"] is False
assert firewall["all_raw_runs_before_scoring"] is True
assert firewall[
    "raw_outputs_hash_bound_before_truth_reveal"
] is True

one_shot = auth["one_shot_semantics"]

assert one_shot["authorization_reusable"] is False

assert one_shot[
    "partial_execution_reauthorization_allowed"
] is False

assert one_shot[
    "failed_run_retention_required"
] is True

assert one_shot[
    "raw_output_retention_required"
] is True

controller = auth["controller_binding"]

assert controller[
    "execution_controller_created"
] is False

assert controller[
    "execution_controller_sha256"
] is None

assert controller[
    "authorization_consumable"
] is False

state = auth["state"]

assert state["reviewed"] is False
assert state["execution_authorized"] is False
assert state["authorization_consumed"] is False
assert state["raw_runs_produced"] == 0
assert state["system_execution"] is False
assert state["truth_scoring"] is False
assert state["quality_result_available"] is False

launcher_source = LAUNCHER.read_text(
    encoding="utf-8"
)

tree = ast.parse(launcher_source)

auth_assignments = []

for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id
                == "EXECUTION_AUTHORIZED"
            ):
                auth_assignments.append(
                    node.value
                )

assert len(auth_assignments) == 1

assert isinstance(
    auth_assignments[0],
    ast.Constant,
)

assert auth_assignments[0].value is False

for forbidden in (
    "authorization_path",
    "--authorize",
    "--execute",
):
    assert forbidden not in launcher_source

print("FAMILY_2_EXECUTION_AUTHORIZATION=PASS")
print("AUTHORIZATION_SCOPE=PASS")
print("LAUNCHER_BINDING=PASS")
print("DESCRIPTOR_BINDING=PASS")
print("ONE_SHOT_SEMANTICS=PASS")
print("AUTHORIZATION_REUSABLE=false")
print("AUTHORIZATION_CONSUMABLE=false")
print("EXECUTION_CONTROLLER_CREATED=false")
print("EXECUTION_AUTHORIZED=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
