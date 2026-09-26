#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction-design-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction-design.schema.json"
)

BRIDGE = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_bridge.py"
)

BRIDGE_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_execution_bridge.py"
)

BRIDGE_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-bridge-design-v1.json"
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

RUNTIME = (
    ROOT
    / "protocols"
    / "runtime-v1.json"
)

EXECUTION_PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-v1.json"
)

FUTURE_RUNNER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_runner.py"
)

FUTURE_NETWORK_ATTESTATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-v1.json"
)

FUTURE_RAW_RECEIPT = (
    ROOT
    / "evidence"
    / "entity-resolution-ambiguity-v1"
    / "raw-execution-receipt-v1.json"
)


EXPECTED_DESIGN_SHA = (
    "9d3f25f267e935588d96c796f78fb084"
    "1493ea7275f7d34d8b5b60e085b9a77f"
)

EXPECTED_SCHEMA_SHA = (
    "e56724ff339ab2a41807b4efbdeceb88"
    "c260526ef8e39b5b19c6b30936f29b59"
)

EXPECTED_BRIDGE_SHA = (
    "f0aaa7706f92d99ee80f152a199b2e8f"
    "31dd12cf0c6494c8733e51a962b807be"
)

EXPECTED_BRIDGE_VERIFY_SHA = (
    "6585aa8e09b58925027882d0dfed62fc"
    "5412deba3f3d9c5a311c051576f3d491"
)

EXPECTED_BRIDGE_DESIGN_SHA = (
    "2d4875b94cf7467f591201436c6fbd9e"
    "ab19e879282c4d03d7500720699c5afe"
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

EXPECTED_RUNTIME_SHA = (
    "0ae9913e36bc3109ea36f7da93219852"
    "760a8f347bc5d802aaacde313ddefced"
)

EXPECTED_EXECUTION_PROTOCOL_SHA = (
    "5d44ee19992fdd71a25c19ca0bb9f276"
    "ba07ea809f016068d6db6cb338610fe7"
)

EXPECTED_TRAIN_SHA = (
    "9ea26585df5fe663c5a5cbcaf261a5e06"
    "3d021d10b9a3795a672ea624c881815"
)

EXPECTED_TEST_SHA = (
    "6e98690c2ee302bc16f7deda59a3e332"
    "e872f076925d0380c926d8f74e20fadb"
)

EXPECTED_MANIFEST_SHA = (
    "27c5e7bcd3d3f75f87b095cedd4c996b"
    "f02575299c1ed1412eec9571676e3708"
)

EXPECTED_TRUTH_SHA = (
    "d412e2705d556b7e8196d02290d6f7d1"
    "5678381353baae5dbd30935a96e33e7d"
)

EXPECTED_MATERIALIZATION_RECEIPT_SHA = (
    "d734721fa8f40b779c4fa297a5be4c0e"
    "5d1287b8836a8b1d56899f121137ef94"
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

        properties = schema.get(
            "properties",
            {},
        )

        required = schema.get(
            "required",
            [],
        )

        assert set(required) == set(
            properties
        )

        assert set(value) == set(
            properties
        ), (
            path,
            value.keys(),
            properties.keys(),
        )

        assert (
            schema.get(
                "additionalProperties"
            )
            is False
        )

        for key in value:
            validate_exact_schema(
                value[key],
                properties[key],
                f"{path}.{key}",
            )


assert sha256_file(DESIGN) == EXPECTED_DESIGN_SHA
assert sha256_file(SCHEMA) == EXPECTED_SCHEMA_SHA

assert sha256_file(BRIDGE) == EXPECTED_BRIDGE_SHA
assert sha256_file(BRIDGE_VERIFY) == EXPECTED_BRIDGE_VERIFY_SHA
assert sha256_file(BRIDGE_DESIGN) == EXPECTED_BRIDGE_DESIGN_SHA

assert sha256_file(ACTIVATION) == EXPECTED_ACTIVATION_SHA
assert sha256_file(PERMIT) == EXPECTED_PERMIT_SHA
assert sha256_file(BINDING) == EXPECTED_BINDING_SHA
assert sha256_file(AUTHORIZATION) == EXPECTED_AUTH_SHA

assert sha256_file(CONTROLLER) == EXPECTED_CONTROLLER_SHA
assert sha256_file(LAUNCHER) == EXPECTED_LAUNCHER_SHA
assert sha256_file(DESCRIPTOR) == EXPECTED_DESCRIPTOR_SHA
assert sha256_file(RUNTIME) == EXPECTED_RUNTIME_SHA
assert (
    sha256_file(EXECUTION_PROTOCOL)
    == EXPECTED_EXECUTION_PROTOCOL_SHA
)

assert not FUTURE_RUNNER.exists()
assert not FUTURE_NETWORK_ATTESTATION.exists()
assert not FUTURE_RAW_RECEIPT.exists()

design = load_json(DESIGN)
schema = load_json(SCHEMA)

validate_exact_schema(
    design,
    schema,
)

assert design["schema"] == (
    "qvra-family-2-explicit-execution-run-transaction-design/v1"
)

assert design["benchmark"] == (
    "entity-resolution-ambiguity-v1"
)

assert design["family"] == 2

assert design["transaction_kind"] == (
    "exact-one-shot-nine-run-explicit-execution"
)

bindings = design["bindings"]

assert bindings["hard_disabled_bridge"]["sha256"] == (
    EXPECTED_BRIDGE_SHA
)

assert bindings[
    "hard_disabled_bridge"
]["verifier_sha256"] == (
    EXPECTED_BRIDGE_VERIFY_SHA
)

assert bindings["bridge_design_sha256"] == (
    EXPECTED_BRIDGE_DESIGN_SHA
)

assert bindings["activation_sha256"] == (
    EXPECTED_ACTIVATION_SHA
)

assert bindings["permit_sha256"] == (
    EXPECTED_PERMIT_SHA
)

assert bindings[
    "controller_binding_attestation_sha256"
] == EXPECTED_BINDING_SHA

assert bindings["authorization_sha256"] == (
    EXPECTED_AUTH_SHA
)

assert bindings["controller_sha256"] == (
    EXPECTED_CONTROLLER_SHA
)

assert bindings["portable_plan_sha256"] == (
    EXPECTED_PLAN_SHA
)

assert bindings["process_launcher_sha256"] == (
    EXPECTED_LAUNCHER_SHA
)

assert bindings["command_descriptor_sha256"] == (
    EXPECTED_DESCRIPTOR_SHA
)

assert bindings["runtime_policy_sha256"] == (
    EXPECTED_RUNTIME_SHA
)

assert bindings["execution_protocol_sha256"] == (
    EXPECTED_EXECUTION_PROTOCOL_SHA
)

# Cross-check corpus bindings against the already-governed
# execution protocol, without reading evaluator-only truth bytes.
execution_protocol = load_json(
    EXECUTION_PROTOCOL
)

corpus = execution_protocol[
    "corpus_binding"
]

design_corpus = design[
    "corpus_contract"
]

assert design_corpus["selected_seed"] == (
    corpus["selected_seed"]
)

assert design_corpus["train_records"] == (
    corpus["train_records"]
)

assert design_corpus["test_records"] == (
    corpus["test_records"]
)

assert design_corpus["total_records"] == (
    corpus["records"]
)

files = design_corpus["files"]

assert files["train.csv"] == EXPECTED_TRAIN_SHA
assert files["test.csv"] == EXPECTED_TEST_SHA
assert files["manifest.json"] == EXPECTED_MANIFEST_SHA
assert files["truth.json"] == EXPECTED_TRUTH_SHA

assert files["train.csv"] == (
    corpus["files"]["train.csv"]
)

assert files["test.csv"] == (
    corpus["files"]["test.csv"]
)

assert files["manifest.json"] == (
    corpus["files"]["manifest.json"]
)

assert files["truth.json"] == (
    corpus["files"]["truth.json"]
)

assert design_corpus[
    "materialization_receipt_sha256"
] == EXPECTED_MATERIALIZATION_RECEIPT_SHA

assert execution_protocol[
    "source_binding"
][
    "materialization_receipt_sha256"
] == EXPECTED_MATERIALIZATION_RECEIPT_SHA

assert design_corpus["system_inputs"] == [
    "train.csv",
    "test.csv",
]

assert design_corpus["truth_role"] == (
    "evaluator-only"
)

assert design_corpus["truth_system_access"] is False
assert design_corpus["truth_input_allowed"] is False

assert design_corpus[
    "concrete_corpus_root_bound_at_design_time"
] is False

assert design_corpus[
    "concrete_corpus_root_must_be_hash_verified_before_run"
] is True

scope = design["scope"]

assert scope["systems"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert scope["system_order"] == [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

assert scope["run_numbers"] == [
    1,
    2,
    3,
]

assert scope["runs_per_system"] == 3
assert scope["total_required_raw_runs"] == 9
assert scope["raw_artifacts_per_run"] == 3
assert scope["total_required_raw_artifacts"] == 27

root_contract = design["root_contract"]

assert root_contract["raw_root_relative_path"] == (
    "family-2-raw-runs"
)

assert root_contract[
    "raw_root_must_be_empty_before_run"
] is True

assert root_contract[
    "existing_raw_files_allowed"
] is False

assert root_contract[
    "partial_existing_transaction_allowed"
] is False

assert root_contract[
    "raw_root_may_not_contain_truth"
] is True

execution = design[
    "execution_semantics"
]

assert execution["all_nine_runs_required"] is True
assert execution["continue_after_nonzero_exit"] is True
assert execution["failed_run_retention_required"] is True
assert execution["retry_within_transaction_allowed"] is False
assert execution["retuning_allowed"] is False
assert execution["runtime_mutation_allowed"] is False

assert execution[
    "configuration_may_depend_on_prior_run_output"
] is False

assert execution[
    "configuration_may_depend_on_quality_result"
] is False

assert execution[
    "configuration_may_depend_on_system_order"
] is False

assert execution[
    "second_execution_requires_new_transaction"
] is True

assert execution["maximum_execution_batches"] == 1

raw = design[
    "raw_evidence_contract"
]

assert raw["output_json_required"] is True
assert raw["stdout_required"] is True
assert raw["stderr_required"] is True
assert raw["raw_output_retention_required"] is True

assert raw[
    "raw_outputs_hash_bound_before_truth_reveal"
] is True

assert raw[
    "all_raw_runs_before_truth_scoring"
] is True

assert raw[
    "raw_execution_receipt_required"
] is True

assert raw[
    "raw_execution_receipt_created"
] is False

assert raw[
    "truth_scoring_locked_until_receipt_frozen"
] is True

network = design[
    "network_isolation_gate"
]

assert network["network_disabled_required"] is True

assert network[
    "network_isolation_mechanism_selected"
] is False

assert network[
    "network_isolation_attestation_required"
] is True

assert network[
    "network_isolation_attestation_created"
] is False

assert network[
    "execution_forbidden_without_attestation"
] is True

executor = design[
    "future_executor_contract"
]

assert executor["executor_created"] is False
assert executor["process_launch_capability_present"] is False

for key in (
    "must_consume_exact_bridge_transaction",
    "must_verify_all_upstream_hashes",
    "must_verify_corpus_hashes",
    "must_verify_raw_root_empty",
    "must_verify_network_isolation_attestation",
    "must_not_mutate_bridge",
    "must_not_mutate_launcher",
    "must_not_mutate_controller",
    "must_not_retune",
    "must_not_access_truth",
    "must_attempt_exactly_nine_runs",
    "must_retain_nonzero_exit_runs",
    "must_not_retry_failed_run",
    "must_hash_raw_artifacts_before_scoring",
):
    assert executor[key] is True, key

issuance = design[
    "issuance_gate"
]

assert issuance["execution_transaction_issued"] is False
assert issuance["runner_mainline_required"] is True
assert issuance["runner_independent_review_required"] is True

assert issuance[
    "network_isolation_attestation_mainline_required"
] is True

assert issuance[
    "corpus_hash_audit_required"
] is True

assert issuance[
    "raw_root_empty_audit_required"
] is True

assert issuance[
    "separate_explicit_operator_run_step_required"
] is True

assert issuance[
    "transaction_currently_executable"
] is False

effect = design[
    "current_effectuation_state"
]

assert effect["run_transaction_design_created"] is True
assert effect["execution_runner_created"] is False

assert effect[
    "network_isolation_attestation_created"
] is False

assert effect["execution_transaction_issued"] is False
assert effect["bridge_effectuation_authorized"] is False
assert effect["process_launch_capability_present"] is False
assert effect["launcher_execution_authorized"] is False
assert effect["subprocess_invocation"] is False

pre = design[
    "preexecution_state"
]

assert pre["activation_consumed"] is False
assert pre["permit_consumed"] is False
assert pre["raw_runs_produced"] == 0
assert pre["raw_artifacts_produced"] == 0
assert pre["raw_execution_receipt_created"] is False
assert pre["system_execution"] is False
assert pre["truth_scoring"] is False
assert pre["quality_result_available"] is False

# Independently prove the merged bridge and launcher remain
# hard disabled using static AST inspection only.
bridge_tree = ast.parse(
    BRIDGE.read_text(
        encoding="utf-8"
    )
)

bridge_assignments: dict[str, Any] = {}

for node in bridge_tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                try:
                    bridge_assignments[
                        target.id
                    ] = ast.literal_eval(
                        node.value
                    )
                except Exception:
                    pass

assert bridge_assignments[
    "BRIDGE_EFFECTUATION_AUTHORIZED"
] is False

assert bridge_assignments[
    "PROCESS_LAUNCH_CAPABILITY_PRESENT"
] is False

for node in ast.walk(
    bridge_tree
):
    if isinstance(node, ast.Import):
        for alias in node.names:
            assert alias.name != "subprocess"

    if isinstance(node, ast.ImportFrom):
        assert node.module != "subprocess"

    if isinstance(node, ast.Call):
        fn = node.func

        if isinstance(fn, ast.Attribute):
            assert fn.attr not in {
                "launch",
                "run",
                "Popen",
                "call",
                "check_call",
                "check_output",
                "system",
            }

launcher_tree = ast.parse(
    LAUNCHER.read_text(
        encoding="utf-8"
    )
)

launcher_authorized = None

for node in launcher_tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id
                == "EXECUTION_AUTHORIZED"
            ):
                launcher_authorized = (
                    ast.literal_eval(
                        node.value
                    )
                )

assert launcher_authorized is False

assert not FUTURE_RUNNER.exists()
assert not FUTURE_NETWORK_ATTESTATION.exists()
assert not FUTURE_RAW_RECEIPT.exists()

print("FAMILY_2_EXPLICIT_RUN_TRANSACTION_DESIGN=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("RUN_TRANSACTION_DESIGN_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("EXECUTION_PROTOCOL_CROSSCHECK=PASS")
print("CORPUS_BINDING_CROSSCHECK=PASS")
print("PORTABLE_PLAN_IDENTITY=PASS")
print("EXACT_NINE_RUN_SCOPE=PASS")
print("RAW_ARTIFACT_TOPOLOGY=27")
print("TRUTH_SYSTEM_ACCESS=false")
print("RETUNING_ALLOWED=false")
print("RUNTIME_MUTATION_ALLOWED=false")
print("RETRY_WITHIN_TRANSACTION_ALLOWED=false")
print("FAILED_RUN_RETENTION_REQUIRED=true")
print("NETWORK_DISABLED_REQUIRED=true")
print("NETWORK_ISOLATION_ATTESTATION_CREATED=false")
print("RAW_EXECUTION_RECEIPT_CREATED=false")
print("EXECUTION_RUNNER_CREATED=false")
print("EXECUTION_TRANSACTION_ISSUED=false")
print("TRANSACTION_CURRENTLY_EXECUTABLE=false")
print("BRIDGE_EFFECTUATION_AUTHORIZED=false")
print("PROCESS_LAUNCH_CAPABILITY_PRESENT=false")
print("LAUNCHER_EXECUTION_AUTHORIZED=false")
print("SUBPROCESS_INVOCATION=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
