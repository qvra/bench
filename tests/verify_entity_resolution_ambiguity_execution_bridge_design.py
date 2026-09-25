#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-bridge-design-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-execution-bridge-design.schema.json"
)

ACTIVATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-activation-v1.json"
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

BRIDGE_IMPLEMENTATION = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_bridge.py"
)

EXPECTED_MAIN = (
    "8f58bf509cc7e9ad138b088a8c92af54a09e4a36"
)

EXPECTED_ACTIVATION_REVIEWED_HEAD = (
    "6aef28b98e1c5fe7d6935ce01366b5197a08737f"
)

EXPECTED_DESIGN_SHA = (
    "2d4875b94cf7467f591201436c6fbd9e"
    "ab19e879282c4d03d7500720699c5afe"
)

EXPECTED_SCHEMA_SHA = (
    "fa5582c90e129f3184b073b6a1f189a3"
    "da65d5b68ad658b33ea4eba84c97519c"
)

EXPECTED_ACTIVATION_SHA = (
    "d418c4d21865f50c7a1d949777d22dca"
    "793eb51a79965bfa941017f892f2f2ea"
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


def validate_exact_schema(
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
        return

    if schema.get("type") == "object":
        assert isinstance(value, dict), path

        required = schema.get(
            "required",
            [],
        )

        assert set(required) <= set(value), (
            path,
            required,
            value.keys(),
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
            assert set(value) == set(properties), (
                path,
                value.keys(),
                properties.keys(),
            )

        for key in value:
            validate_exact_schema(
                value[key],
                properties[key],
                f"{path}.{key}",
            )


assert sha256_file(DESIGN) == EXPECTED_DESIGN_SHA
assert sha256_file(SCHEMA) == EXPECTED_SCHEMA_SHA

assert sha256_file(ACTIVATION) == EXPECTED_ACTIVATION_SHA
assert sha256_file(PERMIT) == EXPECTED_PERMIT_SHA
assert sha256_file(BINDING) == EXPECTED_BINDING_SHA
assert sha256_file(AUTHORIZATION) == EXPECTED_AUTH_SHA
assert sha256_file(CONTROLLER) == EXPECTED_CONTROLLER_SHA
assert sha256_file(LAUNCHER) == EXPECTED_LAUNCHER_SHA
assert sha256_file(DESCRIPTOR) == EXPECTED_DESCRIPTOR_SHA

assert not BRIDGE_IMPLEMENTATION.exists()

design = load_json(DESIGN)
schema = load_json(SCHEMA)

validate_exact_schema(
    design,
    schema,
)

assert (
    design["schema"]
    == "qvra-family-2-execution-bridge-design/v1"
)

assert (
    design["benchmark"]
    == "entity-resolution-ambiguity-v1"
)

assert design["family"] == 2

assert (
    design["bridge_kind"]
    == "exact-one-shot-nine-run-execution-bridge"
)

bindings = design["bindings"]

assert bindings["governed_main"] == EXPECTED_MAIN

activation_binding = bindings["activation"]

assert activation_binding["sha256"] == EXPECTED_ACTIVATION_SHA
assert activation_binding["immutable"] is True

assert (
    activation_binding["reviewed_head"]
    == EXPECTED_ACTIVATION_REVIEWED_HEAD
)

assert activation_binding["merged_main"] == EXPECTED_MAIN

assert bindings["permit_sha256"] == EXPECTED_PERMIT_SHA

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

scope = design["scope"]

assert scope["systems"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert scope["run_numbers"] == [1, 2, 3]
assert scope["runs_per_system"] == 3
assert scope["total_required_raw_runs"] == 9
assert scope["all_nine_runs_required"] is True

contract = design[
    "future_implementation_contract"
]

assert contract[
    "module_path"
] == (
    "suites/"
    "entity-resolution-ambiguity-v1/"
    "execution_bridge.py"
)

for key in (
    "must_verify_activation_identity",
    "must_verify_permit_identity",
    "must_verify_controller_identity",
    "must_verify_portable_plan_identity",
    "must_verify_launcher_identity",
    "must_require_exact_nine_run_topology",
    "must_refuse_partial_execution",
    "must_refuse_second_execution",
    "must_forbid_truth_input",
    "must_forbid_retuning",
    "must_forbid_runtime_mutation",
    "must_require_network_disabled",
    "must_retain_failed_runs",
    "must_retain_raw_outputs",
    "must_capture_stdout",
    "must_capture_stderr",
    "must_hash_raw_outputs_before_truth_reveal",
    "must_complete_all_raw_runs_before_scoring",
):
    assert contract[key] is True, key

order = design[
    "execution_order_contract"
]

assert order["system_order"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert order["run_order"] == [1, 2, 3]
assert order["total_launches"] == 9
assert order["launches_must_match_portable_plan"] is True

boundary = design[
    "implementation_boundary"
]

assert boundary["bridge_design_created"] is True
assert boundary["bridge_implementation_created"] is False
assert boundary["bridge_execution_capability_present"] is False
assert boundary["launcher_mutation_performed"] is False
assert boundary["launcher_execution_authorized"] is False
assert boundary["controller_mutation_performed"] is False
assert boundary["process_launch_enabled"] is False
assert boundary["subprocess_invocation"] is False

gate = design["governance_gate"]

assert gate["implementation_requires_separate_commit"] is True
assert gate["implementation_requires_independent_review"] is True
assert gate["implementation_requires_exact_head_review"] is True
assert gate["implementation_requires_mainline_merge"] is True
assert gate["execution_requires_separate_explicit_run_step"] is True

state = design["preexecution_state"]

assert state["activation_consumed"] is False
assert state["permit_consumed"] is False
assert state["raw_runs_produced"] == 0
assert state["system_execution"] is False
assert state["truth_scoring"] is False
assert state["quality_result_available"] is False

# Prove the launcher remains hard-disabled without importing
# or invoking the launcher.
launcher_tree = ast.parse(
    LAUNCHER.read_text(
        encoding="utf-8"
    )
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
                execution_authorized = ast.literal_eval(
                    node.value
                )

assert execution_authorized is False

# Install a hard tripwire before loading the controller.
# Any accidental subprocess.run call fails this verifier.
subprocess_reached = False
original_run = subprocess.run


def forbidden_run(*args: Any, **kwargs: Any) -> Any:
    global subprocess_reached
    subprocess_reached = True
    raise AssertionError(
        "subprocess.run reached by nonexecuting bridge verifier"
    )


subprocess.run = forbidden_run

try:
    controller_spec = importlib.util.spec_from_file_location(
        "qvra_bridge_design_controller",
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
        prefix="qvra-bridge-design-verifier-"
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

finally:
    subprocess.run = original_run


assert before == after
assert observed_plan_sha == EXPECTED_PLAN_SHA
assert len(plan.runs) == 9
assert subprocess_reached is False

assert not BRIDGE_IMPLEMENTATION.exists()

print("FAMILY_2_EXECUTION_BRIDGE_DESIGN=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("BRIDGE_DESIGN_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("PORTABLE_PLAN_IDENTITY=PASS")
print("EXACT_NINE_RUN_SCOPE=PASS")
print("ONE_SHOT_EXECUTION_CONTRACT=PASS")
print("BRIDGE_DESIGN_CREATED=true")
print("BRIDGE_IMPLEMENTATION_CREATED=false")
print("BRIDGE_EXECUTION_CAPABILITY_PRESENT=false")
print("LAUNCHER_EXECUTION_AUTHORIZED=false")
print("PROCESS_LAUNCH_ENABLED=false")
print("SUBPROCESS_REACHED=false")
print("ACTIVATION_CONSUMED=false")
print("PERMIT_CONSUMED=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
