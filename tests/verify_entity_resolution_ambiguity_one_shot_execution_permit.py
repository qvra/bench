#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

PERMIT = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-one-shot-execution-permit-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-one-shot-execution-permit.schema.json"
)

AUTHORIZATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-authorization-v1.json"
)

BINDING_ATTESTATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-controller-binding-v1.json"
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
    "dd1076a28fbb480ec4b381da77175005f4070b99"
)

EXPECTED_PERMIT_SHA256 = (
    "7cef4548b571940a2fe34e3a4025afe8"
    "fe632a90c4af38b9fbd00b1b5794a8d3"
)

EXPECTED_SCHEMA_SHA256 = (
    "662103d7d2613130a42193e62eedb1f8"
    "429d31d4bb0e3e220b55948950482296"
)

EXPECTED_AUTHORIZATION_SHA256 = (
    "30890b1ac027caf4c3175e6c602581ad"
    "3c9e544d932435bff045884b795e5728"
)

EXPECTED_BINDING_SHA256 = (
    "f11beabbbd55b9f36ab924fcd767e985"
    "eee3e218d70a5520047997b4e3cb6f57"
)

EXPECTED_CONTROLLER_SHA256 = (
    "2b9e0026ed756468432c8d07edca9ebc"
    "49ef3b727defbc39f3b55cb9319d9661"
)

EXPECTED_PLAN_SHA256 = (
    "df1fbeab0a2c89c16fb9530aaf4f5545"
    "d62a4dab3f44f160dacdc231a3463ac7"
)

EXPECTED_LAUNCHER_SHA256 = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_DESCRIPTOR_SHA256 = (
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

    expected_type = schema.get("type")

    if expected_type == "object":
        assert isinstance(value, dict), (
            path,
            type(value),
        )

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
            ), (
                path,
                sorted(
                    set(value)
                    - set(properties)
                ),
            )

        for key, child in value.items():
            if key in properties:
                validate_schema_subset(
                    child,
                    properties[key],
                    f"{path}.{key}",
                )


assert sha256_file(PERMIT) == EXPECTED_PERMIT_SHA256
assert sha256_file(SCHEMA) == EXPECTED_SCHEMA_SHA256

assert (
    sha256_file(AUTHORIZATION)
    == EXPECTED_AUTHORIZATION_SHA256
)

assert (
    sha256_file(BINDING_ATTESTATION)
    == EXPECTED_BINDING_SHA256
)

assert (
    sha256_file(CONTROLLER)
    == EXPECTED_CONTROLLER_SHA256
)

assert (
    sha256_file(LAUNCHER)
    == EXPECTED_LAUNCHER_SHA256
)

assert (
    sha256_file(DESCRIPTOR)
    == EXPECTED_DESCRIPTOR_SHA256
)

permit = load_json(PERMIT)
schema = load_json(SCHEMA)

validate_schema_subset(
    permit,
    schema,
)

assert permit["schema"] == (
    "qvra-family-2-one-shot-execution-permit/v1"
)

assert permit["benchmark"] == (
    "entity-resolution-ambiguity-v1"
)

assert permit["family"] == 2

assert permit["permit_kind"] == (
    "one-shot-nine-run-execution-permit"
)

bindings = permit["bindings"]

assert bindings["governed_main"] == EXPECTED_MAIN

assert (
    bindings["authorization"]["sha256"]
    == EXPECTED_AUTHORIZATION_SHA256
)

assert (
    bindings["authorization"]["immutable"]
    is True
)

assert (
    bindings[
        "controller_binding_attestation"
    ]["sha256"]
    == EXPECTED_BINDING_SHA256
)

assert (
    bindings[
        "controller_binding_attestation"
    ]["immutable"]
    is True
)

assert (
    bindings["controller"]["sha256"]
    == EXPECTED_CONTROLLER_SHA256
)

assert bindings["controller"]["immutable"] is True

assert (
    bindings["portable_plan"]["sha256"]
    == EXPECTED_PLAN_SHA256
)

assert (
    bindings["portable_plan"]["immutable"]
    is True
)

assert (
    bindings["process_launcher_sha256"]
    == EXPECTED_LAUNCHER_SHA256
)

assert (
    bindings["command_descriptor_sha256"]
    == EXPECTED_DESCRIPTOR_SHA256
)

scope = permit["scope"]

assert scope["systems"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert scope["runs_per_system"] == 3
assert scope["total_required_raw_runs"] == 9
assert scope["run_numbers"] == [1, 2, 3]

contract = permit["execution_contract"]

assert contract["truth_input_allowed"] is False
assert contract["retuning_allowed"] is False
assert contract["runtime_mutation_allowed"] is False
assert contract["network_required"] is False

assert (
    contract["all_raw_runs_before_scoring"]
    is True
)

assert (
    contract[
        "raw_outputs_hash_bound_before_truth_reveal"
    ]
    is True
)

assert (
    contract["failed_run_retention_required"]
    is True
)

assert (
    contract["raw_output_retention_required"]
    is True
)

one_shot = permit["one_shot_semantics"]

assert one_shot["permit_reusable"] is False

assert (
    one_shot[
        "partial_execution_reauthorization_allowed"
    ]
    is False
)

assert one_shot["single_nine_run_batch"] is True

assert (
    one_shot["second_use_requires_new_permit"]
    is True
)

activation = permit["activation_boundary"]

assert activation["review_required"] is True

assert (
    activation[
        "separate_activation_artifact_required"
    ]
    is True
)

assert activation["self_activating"] is False
assert activation["permit_active"] is False
assert activation["permit_consumable"] is False
assert activation["execution_authorized"] is False

state = permit["preexecution_state"]

assert state["permit_consumed"] is False
assert state["raw_runs_produced"] == 0
assert state["system_execution"] is False
assert state["truth_scoring"] is False

assert (
    state["quality_result_available"]
    is False
)

# Reproduce the reviewed portable plan.
# build_plan only prepares launch specifications;
# it does not invoke the launch primitive.
spec = importlib.util.spec_from_file_location(
    "qvra_nonexecuting_permit_controller",
    CONTROLLER,
)

assert spec is not None
assert spec.loader is not None

module = importlib.util.module_from_spec(
    spec
)

sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(
    prefix="qvra-nonexecuting-permit-"
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

    plan = module.build_plan(
        repo_root=ROOT,
        corpus_root=corpus,
        raw_root=raw,
    )

    observed_plan_sha = (
        module.plan_sha256(plan)
    )

    after = sorted(
        p.relative_to(temp).as_posix()
        for p in temp.rglob("*")
        if p.is_file()
    )

assert before == after
assert observed_plan_sha == EXPECTED_PLAN_SHA256

assert len(plan.runs) == 9
assert plan.authorization_consumable is False
assert plan.execution_authorized is False

for run in plan.runs:
    assert "truth.json" not in run.argv

# Confirm the process launcher remains hard disabled.
launcher_spec = importlib.util.spec_from_file_location(
    "qvra_nonexecuting_permit_launcher",
    LAUNCHER,
)

assert launcher_spec is not None
assert launcher_spec.loader is not None

launcher = importlib.util.module_from_spec(
    launcher_spec
)

sys.modules[
    launcher_spec.name
] = launcher

launcher_spec.loader.exec_module(
    launcher
)

assert launcher.EXECUTION_AUTHORIZED is False

print("FAMILY_2_ONE_SHOT_EXECUTION_PERMIT=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("PERMIT_IDENTITY=PASS")
print("AUTHORIZATION_IDENTITY=PASS")
print("BINDING_ATTESTATION_IDENTITY=PASS")
print("CONTROLLER_IDENTITY=PASS")
print("LAUNCHER_IDENTITY=PASS")
print("DESCRIPTOR_IDENTITY=PASS")
print("PORTABLE_PLAN_IDENTITY=PASS")
print("PERMIT_SCOPE=PASS")
print("PERMIT_ONE_SHOT_SEMANTICS=PASS")
print("SEPARATE_ACTIVATION_REQUIRED=true")
print("PERMIT_ACTIVE=false")
print("PERMIT_CONSUMABLE=false")
print("EXECUTION_AUTHORIZED=false")
print("PERMIT_CONSUMED=false")
print("SYSTEM_TRUTH_ACCESS=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
print("SUBPROCESS_REACHED=false")
