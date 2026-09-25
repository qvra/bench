#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

ACTIVATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-activation-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-execution-activation.schema.json"
)

PERMIT = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-one-shot-execution-permit-v1.json"
)

BINDING = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-controller-binding-v1.json"
)

AUTHORIZATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-authorization-v1.json"
)

CONTROLLER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_controller.py"
)

LAUNCHER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "process_launcher.py"
)

DESCRIPTOR = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-command-descriptors-v1.json"
)

EXPECTED_MAIN = (
    "ecdf3a21bf857e67fb47a5f70a8463bc967a67c9"
)

EXPECTED_ACTIVATION_SHA = (
    "d418c4d21865f50c7a1d949777d22dca"
    "793eb51a79965bfa941017f892f2f2ea"
)

EXPECTED_SCHEMA_SHA = (
    "4ca6d44678d37f3b37fdcb1aa3603f18"
    "5739fbc7991907ea8b18c8c0fd649561"
)

EXPECTED_PERMIT_SHA = (
    "7cef4548b571940a2fe34e3a4025afe8"
    "fe632a90c4af38b9fbd00b1b5794a8d3"
)

EXPECTED_BINDING_SHA = (
    "f11beabbbd55b9f36ab924fcd767e985"
    "eee3e218d70a5520047997b4e3cb6f57"
)

EXPECTED_AUTH_SHA = (
    "30890b1ac027caf4c3175e6c602581ad"
    "3c9e544d932435bff045884b795e5728"
)

EXPECTED_CONTROLLER_SHA = (
    "2b9e0026ed756468432c8d07edca9ebc"
    "49ef3b727defbc39f3b55cb9319d9661"
)

EXPECTED_PLAN_SHA = (
    "df1fbeab0a2c89c16fb9530aaf4f5545"
    "d62a4dab3f44f160dacdc231a3463ac7"
)

EXPECTED_LAUNCHER_SHA = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_DESCRIPTOR_SHA = (
    "817d3e1eae8babb26eb49792b5778898"
    "793235042020c9f904cad0057e8549ac"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def validate_schema_subset(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
) -> None:
    if "const" in schema:
        assert value == schema["const"], (
            path,
            value,
            schema["const"],
        )

    if schema.get("type") == "object":
        assert isinstance(value, dict)

        required = schema.get(
            "required",
            [],
        )

        for key in required:
            assert key in value, (
                path,
                key,
            )

        properties = schema.get(
            "properties",
            {},
        )

        if (
            schema.get(
                "additionalProperties"
            )
            is False
        ):
            assert set(value) <= set(
                properties
            )

        for key, child in value.items():
            if key in properties:
                validate_schema_subset(
                    child,
                    properties[key],
                    f"{path}.{key}",
                )


assert sha256_file(ACTIVATION) == EXPECTED_ACTIVATION_SHA
assert sha256_file(SCHEMA) == EXPECTED_SCHEMA_SHA

assert sha256_file(PERMIT) == EXPECTED_PERMIT_SHA
assert sha256_file(BINDING) == EXPECTED_BINDING_SHA
assert sha256_file(AUTHORIZATION) == EXPECTED_AUTH_SHA
assert sha256_file(CONTROLLER) == EXPECTED_CONTROLLER_SHA
assert sha256_file(LAUNCHER) == EXPECTED_LAUNCHER_SHA
assert sha256_file(DESCRIPTOR) == EXPECTED_DESCRIPTOR_SHA

activation = load_json(ACTIVATION)
schema = load_json(SCHEMA)

validate_schema_subset(
    activation,
    schema,
)

assert activation[
    "schema"
] == "qvra-family-2-execution-activation/v1"

assert activation[
    "activation_kind"
] == "exact-one-shot-nine-run-execution-activation"

bindings = activation["bindings"]

assert bindings["governed_main"] == EXPECTED_MAIN
assert bindings["permit"]["sha256"] == EXPECTED_PERMIT_SHA

assert (
    bindings[
        "controller_binding_attestation_sha256"
    ]
    == EXPECTED_BINDING_SHA
)

assert (
    bindings["authorization_sha256"]
    == EXPECTED_AUTH_SHA
)

assert (
    bindings["controller_sha256"]
    == EXPECTED_CONTROLLER_SHA
)

assert (
    bindings["portable_plan_sha256"]
    == EXPECTED_PLAN_SHA
)

assert (
    bindings["process_launcher_sha256"]
    == EXPECTED_LAUNCHER_SHA
)

assert (
    bindings["command_descriptor_sha256"]
    == EXPECTED_DESCRIPTOR_SHA
)

scope = activation["scope"]

assert scope["systems"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert scope["runs_per_system"] == 3
assert scope["run_numbers"] == [1, 2, 3]
assert scope["total_required_raw_runs"] == 9

effect = activation["activation_effect"]

assert effect["permit_active"] is True
assert effect["permit_consumable"] is True
assert effect["execution_authorized"] is True
assert effect["one_shot"] is True
assert effect["maximum_execution_batches"] == 1

gate = activation["governance_gate"]

assert gate["independent_review_required"] is True
assert gate["exact_head_review_required"] is True
assert gate["mainline_merge_required"] is True

assert (
    gate[
        "activation_not_effective_before_gate_completion"
    ]
    is True
)

firewall = activation[
    "effectuation_firewall"
]

assert firewall["self_executing"] is False
assert firewall["process_launch_on_artifact_creation"] is False
assert firewall["process_launch_on_commit"] is False
assert firewall["process_launch_on_merge"] is False

assert firewall["execution_bridge_required"] is True
assert firewall["execution_bridge_created"] is False

assert firewall["launcher_mutation_performed"] is False
assert firewall["controller_mutation_performed"] is False
assert firewall["subprocess_invocation"] is False

one_shot = activation[
    "one_shot_semantics"
]

assert one_shot["activation_reusable"] is False
assert one_shot["permit_reusable"] is False

assert (
    one_shot[
        "partial_execution_reauthorization_allowed"
    ]
    is False
)

assert (
    one_shot[
        "second_activation_requires_new_artifact"
    ]
    is True
)

assert one_shot["all_nine_runs_required"] is True

state = activation[
    "preexecution_state"
]

assert state["activation_consumed"] is False
assert state["permit_consumed"] is False
assert state["raw_runs_produced"] == 0
assert state["system_execution"] is False
assert state["truth_scoring"] is False
assert state["quality_result_available"] is False

# Reproduce the already-reviewed portable plan.
controller_spec = importlib.util.spec_from_file_location(
    "qvra_activation_controller",
    CONTROLLER,
)

assert controller_spec is not None
assert controller_spec.loader is not None

controller = importlib.util.module_from_spec(
    controller_spec
)

sys.modules[
    controller_spec.name
] = controller

controller_spec.loader.exec_module(
    controller
)

with tempfile.TemporaryDirectory(
    prefix="qvra-activation-verifier-"
) as temporary:
    temp = Path(temporary)

    corpus = temp / "corpus"
    raw = temp / "raw"

    corpus.mkdir()
    raw.mkdir()

    (corpus / "train.csv").write_text(
        "record_id,entity_id\n",
        encoding="utf-8",
    )

    (corpus / "test.csv").write_text(
        "record_id\n",
        encoding="utf-8",
    )

    before = sorted(
        p.relative_to(temp).as_posix()
        for p in temp.rglob("*")
        if p.is_file()
    )

    plan = controller.build_plan(
        repo_root=ROOT,
        corpus_root=corpus,
        raw_root=raw,
    )

    observed_plan_sha = (
        controller.plan_sha256(
            plan
        )
    )

    after = sorted(
        p.relative_to(temp).as_posix()
        for p in temp.rglob("*")
        if p.is_file()
    )

assert before == after
assert observed_plan_sha == EXPECTED_PLAN_SHA
assert len(plan.runs) == 9

# Independently prove the launcher gate is still closed.
launcher_source = LAUNCHER.read_text(
    encoding="utf-8"
)

launcher_tree = ast.parse(
    launcher_source
)

execution_authorized = None

for node in launcher_tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id
                == "EXECUTION_AUTHORIZED"
            ):
                execution_authorized = (
                    ast.literal_eval(
                        node.value
                    )
                )

assert execution_authorized is False

# Therefore the activation intent exists, but it cannot
# currently be effectuated by the governed launcher.
activation_currently_effective = False

assert activation_currently_effective is False

print("FAMILY_2_EXECUTION_ACTIVATION=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("ACTIVATION_IDENTITY=PASS")
print("PERMIT_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("PORTABLE_PLAN_IDENTITY=PASS")
print("ACTIVATION_EFFECT_DEFINED=PASS")
print("INDEPENDENT_REVIEW_REQUIRED=true")
print("MAINLINE_MERGE_REQUIRED=true")
print("ACTIVATION_EFFECT_PERMIT_ACTIVE=true")
print("ACTIVATION_EFFECT_PERMIT_CONSUMABLE=true")
print("ACTIVATION_EFFECT_EXECUTION_AUTHORIZED=true")
print("ACTIVATION_CURRENTLY_EFFECTIVE=false")
print("EXECUTION_BRIDGE_REQUIRED=true")
print("EXECUTION_BRIDGE_CREATED=false")
print("LAUNCHER_EXECUTION_AUTHORIZED=false")
print("SUBPROCESS_INVOCATION=false")
print("ACTIVATION_CONSUMED=false")
print("PERMIT_CONSUMED=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
