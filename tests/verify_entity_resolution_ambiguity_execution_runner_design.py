#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import json
import os

from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-runner-design-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-execution-runner-design.schema.json"
)

ATTESTATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-v1.json"
)

ATTESTATION_SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation.schema.json"
)

ATTESTATION_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_attestation.py"
)

RUN_TRANSACTION_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction-design-v1.json"
)

EXECUTION_PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-v1.json"
)

AUTHORIZATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-authorization-v1.json"
)

PERMIT = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-one-shot-execution-permit-v1.json"
)

ACTIVATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-activation-v1.json"
)

BRIDGE_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-bridge-design-v1.json"
)

BRIDGE = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_bridge.py"
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

DESCRIPTORS = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-command-descriptors-v1.json"
)

RUNTIME = (
    ROOT
    / "protocols"
    / "runtime-v1.json"
)

FUTURE_RUNNER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_runner.py"
)

FUTURE_RUNNER_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_execution_runner.py"
)

FUTURE_TRANSACTION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction-v1.json"
)

FUTURE_TRANSACTION_SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction.schema.json"
)

FUTURE_TRANSACTION_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_explicit_execution_run_transaction.py"
)

RAW_RECEIPT = (
    ROOT
    / "evidence"
    / "entity-resolution-ambiguity-v1"
    / "raw-execution-receipt-v1.json"
)

RAW_ROOT = (
    ROOT
    / "family-2-raw-runs"
)

SANDBOX_EXEC = Path(
    "/usr/bin/sandbox-exec"
)


EXPECTED_MAIN = (
    "e79523d4a43f0c4efff38637beee5898796d76b3"
)

EXPECTED_DESIGN_SHA = (
    "e038cfd6aeeb97f4c45d5f1728e26866"
    "4bde61bb067ec264624a977a8eb23d9d"
)

EXPECTED_SCHEMA_SHA = (
    "51e5233b01a3ca339a0668b06853a943"
    "12774d36248fecf7504cc0c173d54f7b"
)

EXPECTED_ATTESTATION_SHA = (
    "fb7240a55c46363b118e6da54ac6ef39"
    "3ff40979215bc99d9fc5d75f863d0208"
)

EXPECTED_ATTESTATION_SCHEMA_SHA = (
    "de564da8692aa22cbfee005c04dffcde"
    "2e09f25a392e561862f97c4e5dd44051"
)

EXPECTED_ATTESTATION_VERIFY_SHA = (
    "35cd6b79f161ea4f98548b6f1e0b492"
    "3d65a94fbfd9e0d4013c4c698531b2bc1"
)

EXPECTED_RUN_TRANSACTION_DESIGN_SHA = (
    "9d3f25f267e935588d96c796f78fb084"
    "1493ea7275f7d34d8b5b60e085b9a77f"
)

EXPECTED_EXECUTION_PROTOCOL_SHA = (
    "5d44ee19992fdd71a25c19ca0bb9f276"
    "ba07ea809f016068d6db6cb338610fe7"
)

EXPECTED_AUTHORIZATION_SHA = (
    "30890b1ac027caf4c3175e6c602581ad"
    "3c9e544d932435bff045884b795e5728"
)

EXPECTED_PERMIT_SHA = (
    "7cef4548b571940a2fe34e3a4025afe8"
    "fe632a90c4af38b9fbd00b1b5794a8d3"
)

EXPECTED_ACTIVATION_SHA = (
    "d418c4d21865f50c7a1d949777d22dca"
    "793eb51a79965bfa941017f892f2f2ea"
)

EXPECTED_BRIDGE_DESIGN_SHA = (
    "2d4875b94cf7467f591201436c6fbd9e"
    "ab19e879282c4d03d7500720699c5afe"
)

EXPECTED_BRIDGE_SHA = (
    "f0aaa7706f92d99ee80f152a199b2e8"
    "f31dd12cf0c6494c8733e51a962b807be"
)

EXPECTED_CONTROLLER_SHA = (
    "2b9e0026ed756468432c8d07edca9ebc"
    "49ef3b727defbc39f3b55cb9319d9661"
)

EXPECTED_LAUNCHER_SHA = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_DESCRIPTORS_SHA = (
    "817d3e1eae8babb26eb49792b5778898"
    "793235042020c9f904cad0057e8549ac"
)

EXPECTED_RUNTIME_SHA = (
    "0ae9913e36bc3109ea36f7da93219852"
    "760a8f347bc5d802aaacde313ddefced"
)

EXPECTED_SANDBOX_EXEC_SHA = (
    "8290e4be7387a0df83cd1559e86afd88"
    "0464f269450573d012795761fe298f16"
)

EXPECTED_PROFILE_SHA = (
    "5c358b8d847211333e7ba22df82d84f7"
    "96b5f30a41a2682209a949d783adbd08"
)

EXPECTED_PROFILE_TEXT = (
    "(version 1)\n"
    "(allow default)\n"
    "(deny network*)\n"
)

SYSTEMS = [
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
]

RUN_NUMBERS = [
    1,
    2,
    3,
]


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


def exact_validate(
    value: Any,
    rule: dict[str, Any],
    path: str = "$",
) -> None:
    if "const" in rule:
        assert value == rule["const"], (
            path,
            value,
            rule["const"],
        )
        return

    assert rule.get("type") == "object", path
    assert rule.get("additionalProperties") is False, path
    assert isinstance(value, dict), path

    properties = rule["properties"]
    required = rule["required"]

    assert set(required) == set(properties), path
    assert set(value) == set(properties), path

    for key in value:
        exact_validate(
            value[key],
            properties[key],
            f"{path}.{key}",
        )


def module_constant(
    path: Path,
    name: str,
) -> Any:
    tree = ast.parse(
        path.read_text(
            encoding="utf-8"
        ),
        filename=str(path),
    )

    for node in tree.body:
        if not isinstance(
            node,
            ast.Assign,
        ):
            continue

        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == name
            ):
                return ast.literal_eval(
                    node.value
                )

    raise AssertionError(
        f"constant not found: {name}"
    )


def top_level_functions(
    path: Path,
) -> set[str]:
    tree = ast.parse(
        path.read_text(
            encoding="utf-8"
        ),
        filename=str(path),
    )

    return {
        node.name
        for node in tree.body
        if isinstance(
            node,
            ast.FunctionDef,
        )
    }


# Exact byte identities.
expected_hashes = {
    DESIGN:
        EXPECTED_DESIGN_SHA,

    SCHEMA:
        EXPECTED_SCHEMA_SHA,

    ATTESTATION:
        EXPECTED_ATTESTATION_SHA,

    ATTESTATION_SCHEMA:
        EXPECTED_ATTESTATION_SCHEMA_SHA,

    ATTESTATION_VERIFY:
        EXPECTED_ATTESTATION_VERIFY_SHA,

    RUN_TRANSACTION_DESIGN:
        EXPECTED_RUN_TRANSACTION_DESIGN_SHA,

    EXECUTION_PROTOCOL:
        EXPECTED_EXECUTION_PROTOCOL_SHA,

    AUTHORIZATION:
        EXPECTED_AUTHORIZATION_SHA,

    PERMIT:
        EXPECTED_PERMIT_SHA,

    ACTIVATION:
        EXPECTED_ACTIVATION_SHA,

    BRIDGE_DESIGN:
        EXPECTED_BRIDGE_DESIGN_SHA,

    BRIDGE:
        EXPECTED_BRIDGE_SHA,

    CONTROLLER:
        EXPECTED_CONTROLLER_SHA,

    LAUNCHER:
        EXPECTED_LAUNCHER_SHA,

    DESCRIPTORS:
        EXPECTED_DESCRIPTORS_SHA,

    RUNTIME:
        EXPECTED_RUNTIME_SHA,

    SANDBOX_EXEC:
        EXPECTED_SANDBOX_EXEC_SHA,
}

for path, expected in expected_hashes.items():
    assert path.is_file(), path
    assert sha256_file(path) == expected, path

assert os.access(
    SANDBOX_EXEC,
    os.X_OK,
)

# Future execution objects must remain absent.
for path in (
    FUTURE_RUNNER,
    FUTURE_RUNNER_VERIFY,
    FUTURE_TRANSACTION,
    FUTURE_TRANSACTION_SCHEMA,
    FUTURE_TRANSACTION_VERIFY,
    RAW_RECEIPT,
):
    assert not path.exists(), path

if RAW_ROOT.exists():
    assert RAW_ROOT.is_dir()
    assert not any(
        path.is_file()
        for path in RAW_ROOT.rglob("*")
    )

design = load_json(
    DESIGN
)

schema = load_json(
    SCHEMA
)

attestation = load_json(
    ATTESTATION
)

run_design = load_json(
    RUN_TRANSACTION_DESIGN
)

execution_protocol = load_json(
    EXECUTION_PROTOCOL
)

authorization = load_json(
    AUTHORIZATION
)

permit = load_json(
    PERMIT
)

activation = load_json(
    ACTIVATION
)

bridge_design = load_json(
    BRIDGE_DESIGN
)

descriptors = load_json(
    DESCRIPTORS
)

runtime = load_json(
    RUNTIME
)

# Exact closed schema.
assert schema["$schema"] == (
    "https://json-schema.org/draft/2020-12/schema"
)

assert schema["$id"] == (
    "qvra-family-2-execution-runner-design.schema.json"
)

exact_validate(
    design,
    schema,
)

# Design identity and active network-isolation gate.
assert design["schema"] == (
    "qvra-family-2-execution-runner-design/v1"
)

assert design["benchmark"] == (
    "entity-resolution-ambiguity-v1"
)

assert design["family"] == 2

assert design["design_kind"] == (
    "review-before-implementation-exact-nine-run-sandboxed-runner"
)

bindings = design["bindings"]

assert bindings["governed_main"] == EXPECTED_MAIN

network = bindings[
    "network_isolation_attestation"
]

assert network["sha256"] == EXPECTED_ATTESTATION_SHA
assert network["schema_sha256"] == EXPECTED_ATTESTATION_SCHEMA_SHA
assert network["verifier_sha256"] == EXPECTED_ATTESTATION_VERIFY_SHA
assert network["merged_main"] == EXPECTED_MAIN
assert network["result"] == "PASS"
assert network["exact_host_only"] is True

assert attestation[
    "attestation_claim"
]["result"] == "PASS"

assert attestation[
    "attestation_claim"
]["network_isolation_attested_by_frozen_probe_evidence"] is True

assert attestation[
    "scope"
]["exact_host_only"] is True

assert attestation[
    "scope"
]["cross_host_generalization"] is False

assert attestation[
    "scope"
]["future_macos_version_generalization"] is False

assert attestation[
    "governance"
]["governed_execution_effect_activates_on_mainline_merge"] is True

# Historical chain must remain byte-identical and hard disabled.
assert bindings[
    "explicit_run_transaction_design_sha256"
] == EXPECTED_RUN_TRANSACTION_DESIGN_SHA

assert bindings[
    "execution_protocol_sha256"
] == EXPECTED_EXECUTION_PROTOCOL_SHA

assert bindings[
    "authorization_sha256"
] == EXPECTED_AUTHORIZATION_SHA

assert bindings[
    "permit_sha256"
] == EXPECTED_PERMIT_SHA

assert bindings[
    "activation_sha256"
] == EXPECTED_ACTIVATION_SHA

assert bindings[
    "bridge_design_sha256"
] == EXPECTED_BRIDGE_DESIGN_SHA

bridge_binding = bindings[
    "execution_bridge"
]

assert bridge_binding[
    "sha256"
] == EXPECTED_BRIDGE_SHA

assert bridge_binding[
    "must_remain_unmodified"
] is True

assert bridge_binding[
    "effectuation_authorized"
] is False

assert bridge_binding[
    "process_launch_capability_present"
] is False

controller_binding = bindings[
    "execution_controller"
]

assert controller_binding[
    "sha256"
] == EXPECTED_CONTROLLER_SHA

assert controller_binding[
    "must_remain_unmodified"
] is True

launcher_binding = bindings[
    "process_launcher"
]

assert launcher_binding[
    "sha256"
] == EXPECTED_LAUNCHER_SHA

assert launcher_binding[
    "must_remain_unmodified"
] is True

assert launcher_binding[
    "execution_authorized"
] is False

assert module_constant(
    BRIDGE,
    "BRIDGE_EFFECTUATION_AUTHORIZED",
) is False

assert module_constant(
    BRIDGE,
    "PROCESS_LAUNCH_CAPABILITY_PRESENT",
) is False

assert module_constant(
    LAUNCHER,
    "EXECUTION_AUTHORIZED",
) is False

bridge_functions = top_level_functions(
    BRIDGE
)

launcher_functions = top_level_functions(
    LAUNCHER
)

assert "prepare_transaction" in bridge_functions
assert "effectuate" in bridge_functions
assert "prepare_launch" in launcher_functions
assert "launch" in launcher_functions

# The activation is authorized historically, but effectuation remains
# separated from the immutable hard-disabled bridge/launcher.
effect = activation[
    "activation_effect"
]

assert effect[
    "execution_authorized"
] is True

assert effect[
    "one_shot"
] is True

assert effect[
    "maximum_execution_batches"
] == 1

assert permit[
    "one_shot_semantics"
]["permit_reusable"] is False

assert authorization[
    "one_shot_semantics"
]["authorization_reusable"] is False

assert authorization[
    "state"
]["execution_authorized"] is False

# Runner implementation remains absent and inert.
target = design[
    "implementation_target"
]

assert target["created"] is False
assert target["import_side_effects_allowed"] is False
assert target["default_invocation_must_refuse"] is True
assert target["execution_requires_explicit_operator_flag"] is True
assert target["execution_flag"] == (
    "--execute-nine-run-transaction"
)
assert target["shell_execution_allowed"] is False
assert target["central_subprocess_run_site_required"] is True
assert target[
    "direct_adapter_execution_outside_central_runner_allowed"
] is False

for key in (
    "bridge_mutation_allowed",
    "controller_mutation_allowed",
    "launcher_mutation_allowed",
    "historical_authorization_mutation_allowed",
    "historical_permit_mutation_allowed",
    "historical_activation_mutation_allowed",
    "truth_access_allowed",
    "retuning_allowed",
    "runtime_mutation_allowed",
    "network_access_allowed",
    "scoring_allowed",
):
    assert target[key] is False, key

# Bridge is consumed only as an exact nonexecuting transaction planner.
bridge_contract = design[
    "bridge_consumption_contract"
]

assert bridge_contract[
    "must_import_exact_execution_bridge"
] is True

assert bridge_contract[
    "must_call"
] == "execution_bridge.prepare_transaction"

assert bridge_contract[
    "must_not_call"
] == [
    "execution_bridge.effectuate",
    "process_launcher.launch",
]

assert bridge_contract[
    "prepared_bridge_transaction_must_remain_nonexecuting_snapshot"
] is True

assert bridge_contract[
    "runner_is_separate_execution_capability"
] is True

assert bridge_contract[
    "runner_may_launch_only_after_all_runner_and_transaction_gates"
] is True

bridge_flags = bridge_contract[
    "required_bridge_transaction_flags"
]

assert bridge_flags[
    "bridge_effectuation_authorized"
] is False

assert bridge_flags[
    "process_launch_capability_present"
] is False

assert bridge_flags[
    "network_disabled_required"
] is True

assert bridge_flags[
    "runtime_mutation_allowed"
] is False

assert bridge_flags[
    "retuning_allowed"
] is False

assert bridge_flags[
    "raw_outputs_hash_before_truth_required"
] is True

assert bridge_flags[
    "all_raw_before_scoring_required"
] is True

assert bridge_flags[
    "total_required_raw_runs"
] == 9

# Separate future transaction is mandatory even after runner mainline.
future_tx = design[
    "future_transaction_contract"
]

assert future_tx["created"] is False
assert future_tx["issued"] is False
assert future_tx["reviewed"] is False
assert future_tx["mainline"] is False
assert future_tx["consumable"] is False
assert future_tx["consumed"] is False

for key in (
    "separate_artifact_required_after_runner_mainline",
    "independent_exact_head_review_required",
    "mainline_merge_required",
    "must_bind_exact_runner_sha256",
    "must_bind_runner_reviewed_head",
    "must_bind_runner_merged_main",
    "must_bind_network_isolation_attestation_sha256",
    "must_bind_network_isolation_attestation_mainline",
    "must_bind_exact_system_order",
    "must_bind_exact_run_numbers",
    "must_bind_exact_corpus_hashes",
    "must_bind_corpus_audit_receipt",
    "must_bind_raw_root_relative_path",
    "must_bind_maximum_execution_batches_one",
    "must_assert_zero_existing_raw_runs",
    "must_assert_raw_execution_receipt_absent",
    "must_assert_truth_scoring_false",
    "runner_mainline_alone_must_not_make_execution_possible",
):
    assert future_tx[key] is True, key

# Operator gate.
cli = design[
    "operator_cli_contract"
]

assert cli["required_execute_flag"] == (
    "--execute-nine-run-transaction"
)

assert cli["required_transaction_argument"] == (
    "--transaction"
)

assert cli[
    "required_transaction_sha_argument"
] == "--expect-transaction-sha256"

assert cli["required_main_argument"] == (
    "--expect-main-commit"
)

assert cli["required_runner_sha_argument"] == (
    "--expect-runner-sha256"
)

assert cli["required_corpus_root_argument"] == (
    "--corpus-root"
)

assert cli["no_raw_root_override"] is True
assert cli["raw_root_relative_path"] == (
    "family-2-raw-runs"
)
assert cli["unknown_arguments_must_refuse"] is True
assert cli[
    "missing_required_argument_must_refuse_before_any_raw_write"
] is True
assert cli[
    "default_invocation_must_refuse_before_any_raw_write"
] is True

# All gates must precede raw writes/process execution.
preflight = design[
    "preflight_contract"
]

for key in (
    "all_preflight_before_raw_root_creation",
    "all_preflight_before_first_adapter_process",
    "must_verify_current_git_head_against_operator_argument",
    "must_verify_current_git_head_is_local_origin_main",
    "must_verify_runner_sha256",
    "must_verify_transaction_sha256",
    "must_verify_transaction_mainline",
    "must_verify_transaction_not_consumed",
    "must_verify_attestation_sha256",
    "must_verify_attestation_is_ancestor_mainline",
    "must_verify_bridge_sha256",
    "must_verify_controller_sha256",
    "must_verify_launcher_sha256",
    "must_verify_bridge_hard_disabled",
    "must_verify_launcher_hard_disabled",
    "must_verify_command_descriptor_sha256",
    "must_verify_runtime_policy_sha256",
    "must_verify_activation_sha256",
    "must_verify_permit_sha256",
    "must_verify_authorization_sha256",
    "must_verify_source_clean_except_local_evidence",
    "must_verify_raw_root_absent_or_empty",
    "must_verify_raw_execution_receipt_absent",
    "must_verify_truth_scoring_false",
):
    assert preflight[key] is True, key

assert preflight[
    "git_fetch_during_execution_allowed"
] is False

assert preflight[
    "preflight_failure_may_create_raw_root"
] is False

assert preflight[
    "preflight_failure_may_launch_adapter"
] is False

assert preflight[
    "preflight_failure_consumes_transaction"
] is False

# Corpus bindings and truth firewall.
corpus = design[
    "corpus_contract"
]

expected_direct = {
    "manifest.json":
        "27c5e7bcd3d3f75f87b095cedd4c996bf02575299c1ed1412eec9571676e3708",

    "train.csv":
        "9ea26585df5fe663c5a5cbcaf261a5e063d021d10b9a3795a672ea624c881815",

    "test.csv":
        "6e98690c2ee302bc16f7deda59a3e332e872f076925d0380c926d8f74e20fadb",
}

expected_full = {
    "manifest.json":
        "27c5e7bcd3d3f75f87b095cedd4c996bf02575299c1ed1412eec9571676e3708",

    "records.csv":
        "06651e82991cc8e2a6c23a8e05eaa79ba56474f61060d8b0b7dc2d3b249e43df",

    "split.json":
        "7c1871b414aad1b7612c758b704a968a19d7dd13ea64bc06f59f9cd486fd5d86",

    "test.csv":
        "6e98690c2ee302bc16f7deda59a3e332e872f076925d0380c926d8f74e20fadb",

    "train.csv":
        "9ea26585df5fe663c5a5cbcaf261a5e063d021d10b9a3795a672ea624c881815",

    "truth.json":
        "d412e2705d556b7e8196d02290d6f7d15678381353baae5dbd30935a96e33e7d",
}

assert corpus[
    "concrete_root_bound_at_runner_design_time"
] is False

assert corpus[
    "operator_supplies_concrete_root"
] is True

assert corpus[
    "future_transaction_must_include_full_corpus_audit"
] is True

assert corpus[
    "runner_must_not_open_truth_json"
] is True

assert corpus[
    "runner_direct_hash_checks"
] == expected_direct

assert corpus[
    "future_transaction_full_corpus_hashes"
] == expected_full

assert corpus[
    "materialization_receipt_sha256"
] == (
    "d734721fa8f40b779c4fa297a5be4c0e"
    "5d1287b8836a8b1d56899f121137ef94"
)

assert corpus["runner_truth_input_allowed"] is False
assert corpus["system_truth_input_allowed"] is False
assert corpus["truth_role"] == "evaluator-only"
assert corpus[
    "truth_scoring_during_runner_execution_allowed"
] is False

# Cross-check the existing execution protocol corpus.
protocol_corpus = execution_protocol[
    "corpus_binding"
]["files"]

for name, digest in expected_full.items():
    assert protocol_corpus[name] == digest

# Exact 3x3 run topology.
topology = design[
    "execution_topology"
]

assert topology["systems"] == SYSTEMS
assert topology["system_order"] == SYSTEMS
assert topology["run_numbers"] == RUN_NUMBERS
assert topology["runs_per_system"] == 3
assert topology["total_required_raw_runs"] == 9
assert topology["raw_artifacts_per_run"] == 3
assert topology["total_required_raw_artifact_slots"] == 27
assert topology["raw_root_relative_path"] == (
    "family-2-raw-runs"
)
assert topology[
    "execution_order_must_equal_bridge_transaction_order"
] is True
assert topology[
    "configuration_may_depend_on_prior_run_output"
] is False
assert topology[
    "configuration_may_depend_on_system_order"
] is False
assert topology[
    "configuration_may_depend_on_quality_result"
] is False
assert topology[
    "retry_within_transaction_allowed"
] is False
assert topology["retuning_allowed"] is False
assert topology["runtime_mutation_allowed"] is False
assert topology[
    "continue_after_system_nonzero_exit"
] is True
assert topology[
    "failed_run_retention_required"
] is True
assert topology[
    "all_nine_runs_attempted_after_successful_preflight"
] is True

# Every adapter subprocess must inherit the attested sandbox.
sandbox = design[
    "sandbox_execution_contract"
]

assert sandbox[
    "every_adapter_process_must_be_sandboxed"
] is True

assert sandbox["sandbox_exec_path"] == (
    "/usr/bin/sandbox-exec"
)

assert sandbox[
    "sandbox_exec_sha256"
] == EXPECTED_SANDBOX_EXEC_SHA

assert sandbox[
    "profile_sha256"
] == EXPECTED_PROFILE_SHA

assert sandbox[
    "profile_text"
] == EXPECTED_PROFILE_TEXT

assert sandbox[
    "sandbox_exec_invocations_for_complete_transaction"
] == 9

assert sandbox[
    "unsandboxed_adapter_fallback_allowed"
] is False

assert sandbox["shell"] is False
assert sandbox["timeout_policy"] == (
    "no_runner_imposed_timeout"
)
assert sandbox["child_environment_source"] == (
    "exact_bridge_run_env"
)
assert sandbox["child_cwd_source"] == (
    "exact_bridge_run_cwd"
)
assert sandbox[
    "sandbox_inheritance_required_for_adapter_children"
] is True
assert sandbox["external_network_allowed"] is False

# Raw evidence behavior.
raw = design[
    "raw_artifact_contract"
]

for key in (
    "runner_must_create_run_directory_before_each_launch",
    "output_path_must_equal_bridge_output_path",
    "stdout_path_must_equal_bridge_stdout_path",
    "stderr_path_must_equal_bridge_stderr_path",
    "output_path_must_not_preexist_before_launch",
    "stdout_path_must_not_preexist_before_launch",
    "stderr_path_must_not_preexist_before_launch",
    "stdout_bytes_must_be_retained_exactly",
    "stderr_bytes_must_be_retained_exactly",
    "adapter_created_output_bytes_must_be_retained_exactly",
    "missing_output_after_failed_process_requires_failure_envelope",
    "failure_envelope_system_output_missing",
    "failure_envelope_runner_generated",
    "existing_adapter_output_must_never_be_overwritten",
    "all_27_artifact_slots_must_exist_before_receipt",
    "all_raw_artifact_hashes_before_truth_scoring",
):
    assert raw[key] is True, key

assert raw["failure_envelope_written_to"] == (
    "output.json"
)

assert raw["failure_envelope_schema"] == (
    "qvra-family-2-missing-system-output/v1"
)

assert topology["required_raw_artifact_names"] == [
    "output.json",
    "stdout.txt",
    "stderr.txt",
]

# Per-run execution record.
process_result = design[
    "process_result_contract"
]

assert process_result[
    "per_run_record_must_include"
] == [
    "ordinal",
    "system_id",
    "run_number",
    "sandbox_argv",
    "cwd",
    "environment",
    "started_at_utc",
    "ended_at_utc",
    "exit_code",
    "stdout_sha256",
    "stderr_sha256",
    "output_sha256",
    "output_origin",
    "nonzero_exit",
]

assert process_result[
    "output_origin_values"
] == [
    "adapter",
    "runner_failure_envelope",
]

assert process_result[
    "nonzero_exit_is_retained_not_retried"
] is True

assert process_result[
    "system_nonzero_exit_does_not_abort_remaining_runs"
] is True

# Receipt must freeze raw output before scoring.
receipt = design[
    "raw_execution_receipt_contract"
]

assert receipt["path"] == (
    "evidence/entity-resolution-ambiguity-v1/"
    "raw-execution-receipt-v1.json"
)

for key in (
    "created_by_runner_after_raw_execution",
    "must_not_preexist",
    "written_only_after_raw_artifacts_hashed",
    "must_bind_runner_sha256",
    "must_bind_transaction_sha256",
    "must_bind_main_commit",
    "must_bind_network_isolation_attestation_sha256",
    "must_bind_corpus_audit",
    "must_include_all_run_records",
    "must_include_all_27_raw_artifact_hashes",
    "must_record_transaction_consumed",
    "must_record_all_nine_runs_attempted",
    "must_record_complete_or_incomplete_execution",
    "receipt_requires_later_freeze_before_scoring",
    "receipt_requires_independent_review_before_scoring",
    "receipt_requires_mainline_merge_before_scoring",
):
    assert receipt[key] is True, key

assert receipt[
    "transaction_consumed_value"
] is True

assert receipt["truth_scoring"] is False
assert receipt["quality_result_available"] is False

# No same-transaction recovery after raw output begins.
failure = design[
    "interruption_and_failure_contract"
]

assert failure["system_nonzero_exit"] == (
    "retain-run-and-continue"
)

assert failure[
    "runner_internal_failure_after_raw_write"
] == (
    "write-incomplete-receipt-if-possible-and-consume-transaction"
)

assert failure[
    "operator_interrupt_after_first_raw_write"
] == (
    "transaction-consumed-no-retry-without-new-transaction"
)

assert failure[
    "raw_root_nonempty_after_any_attempt"
] == (
    "same-transaction-rerun-forbidden"
)

assert failure[
    "receipt_exists_after_any_attempt"
] == (
    "same-transaction-rerun-forbidden"
)

assert failure[
    "partial_existing_transaction_recovery_by_retry"
] is False

assert failure[
    "new_transaction_required_after_incomplete_attempt"
] is True

# Truth remains unavailable until later receipt governance completes.
truth = design[
    "truth_firewall"
]

for key in (
    "runner_may_open_truth_json",
    "runner_may_pass_truth_path_to_adapter",
    "runner_may_import_evaluator",
    "runner_may_score",
    "runner_may_read_quality_result",
):
    assert truth[key] is False, key

assert truth[
    "truth_scoring_locked_until_raw_receipt_mainline"
] is True

# Existing governed transaction design requires exactly these future gates.
future_executor = run_design[
    "future_executor_contract"
]

assert future_executor["executor_created"] is False
assert future_executor[
    "module_path"
] == (
    "suites/entity-resolution-ambiguity-v1/"
    "execution_runner.py"
)

for key in (
    "must_attempt_exactly_nine_runs",
    "must_consume_exact_bridge_transaction",
    "must_hash_raw_artifacts_before_scoring",
    "must_not_access_truth",
    "must_not_mutate_bridge",
    "must_not_mutate_controller",
    "must_not_mutate_launcher",
    "must_not_retry_failed_run",
    "must_not_retune",
    "must_retain_nonzero_exit_runs",
    "must_verify_all_upstream_hashes",
    "must_verify_corpus_hashes",
    "must_verify_network_isolation_attestation",
    "must_verify_raw_root_empty",
):
    assert future_executor[key] is True, key

issuance = run_design[
    "issuance_gate"
]

assert issuance[
    "network_isolation_attestation_mainline_required"
] is True
assert issuance[
    "runner_independent_review_required"
] is True
assert issuance[
    "runner_mainline_required"
] is True
assert issuance[
    "separate_explicit_operator_run_step_required"
] is True
assert issuance[
    "execution_transaction_issued"
] is False
assert issuance[
    "transaction_currently_executable"
] is False

# Descriptor/runtime identities are frozen and execution-independent.
assert bindings[
    "command_descriptors_sha256"
] == EXPECTED_DESCRIPTORS_SHA

assert bindings[
    "runtime_policy_sha256"
] == EXPECTED_RUNTIME_SHA

assert descriptors[
    "benchmark_family"
] == "entity-resolution-ambiguity-v1"

assert descriptors[
    "policy"
]["retuning_allowed"] is False

assert descriptors[
    "policy"
]["truth_input_allowed"] is False

assert descriptors[
    "policy"
]["system_execution"] is False

assert set(
    descriptors["systems"]
) == set(SYSTEMS)

for system_id in SYSTEMS:
    system = descriptors[
        "systems"
    ][system_id]

    assert "truth.json" in system[
        "forbidden_inputs"
    ]

assert runtime["schema"] == (
    "qvra-runtime-policy/v1"
)

assert runtime[
    "policy"
]["dependency_freeze_retained"] is True

assert runtime[
    "policy"
]["isolated_virtual_environments"] is True

assert runtime[
    "policy"
]["package_versions_exact"] is True

assert runtime[
    "python"
]["major_minor"] == "3.12"

# Review and post-mainline runner semantics.
review = design[
    "review_contract"
]

for key in (
    "runner_design_requires_strict_schema",
    "runner_design_requires_nonexecuting_verifier",
    "runner_design_requires_independent_exact_head_review",
    "runner_design_requires_mainline_merge",
    "runner_implementation_requires_static_semantic_verifier",
    "runner_implementation_requires_independent_exact_head_review",
    "runner_implementation_requires_mainline_merge",
    "runner_review_must_not_execute_runner",
    "runner_review_must_not_execute_adapter",
    "runner_review_must_not_invoke_sandbox_exec",
    "runner_review_must_static_check_single_process_launch_site",
    "runner_review_must_static_check_every_adapter_launch_wrapped",
    "runner_review_must_static_check_truth_firewall",
    "runner_review_must_static_check_no_retry",
):
    assert review[key] is True, key

post = design[
    "post_runner_mainline_contract"
]

for key in (
    "runner_mainline_does_not_issue_transaction",
    "runner_mainline_does_not_make_transaction_executable",
    "future_transaction_artifact_is_next_gate",
    "future_transaction_requires_separate_review",
    "future_transaction_requires_mainline",
    "future_execution_requires_separate_explicit_operator_step",
    "benchmark_execution_before_transaction_mainline_forbidden",
):
    assert post[key] is True, key

# Claim boundary.
claim = design[
    "claim_boundary"
]

assert claim["global_superiority_claim"] is False
assert claim["cross_suite_generalization"] is False
assert claim["suite_specific_only"] is True
assert claim[
    "runner_design_is_not_quality_evidence"
] is True

# Current state remains completely pre-runner/pre-transaction.
state = design[
    "current_state"
]

assert state[
    "network_isolation_attestation_mainline"
] is True

assert state[
    "network_isolation_effect_active"
] is True

assert state[
    "runner_design_created"
] is True

for key in (
    "execution_runner_created",
    "execution_runner_reviewed",
    "execution_runner_mainline",
    "execution_transaction_created",
    "execution_transaction_issued",
    "execution_transaction_reviewed",
    "execution_transaction_mainline",
    "transaction_currently_executable",
    "raw_execution_receipt_created",
    "system_execution",
    "truth_scoring",
    "quality_result_available",
):
    assert state[key] is False, key

assert state["raw_runs_produced"] == 0
assert state["raw_artifacts_produced"] == 0

print("FAMILY_2_EXECUTION_RUNNER_DESIGN=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("RUNNER_DESIGN_IDENTITY=PASS")
print("GOVERNED_UPSTREAM_BINDINGS=PASS")
print("NETWORK_ISOLATION_MAINLINE_GATE=PASS")
print("HISTORICAL_BRIDGE_HARD_DISABLED=PASS")
print("HISTORICAL_LAUNCHER_HARD_DISABLED=PASS")
print("HISTORICAL_EXECUTION_CHAIN_IMMUTABLE=PASS")
print("BRIDGE_PREPARE_TRANSACTION_CONSUMPTION=PASS")
print("BRIDGE_EFFECTUATE_FORBIDDEN=PASS")
print("SEPARATE_TRANSACTION_GATE=PASS")
print("PREFLIGHT_BEFORE_RAW_WRITE=PASS")
print("CORPUS_BINDING=PASS")
print("TRUTH_FIREWALL=PASS")
print("EXACT_NINE_RUN_TOPOLOGY=PASS")
print("FUTURE_SYSTEM_RUN_COUNT=9")
print("FUTURE_RAW_ARTIFACT_SLOT_COUNT=27")
print("SANDBOX_EVERY_ADAPTER_PROCESS=PASS")
print("FUTURE_SANDBOX_EXEC_INVOCATION_COUNT=9")
print("NO_RETRY_POLICY=PASS")
print("FAILED_RUN_RETENTION=PASS")
print("RAW_RECEIPT_BEFORE_SCORING=PASS")
print("RUNNER_REVIEW_BEFORE_EXECUTION=PASS")
print("EXECUTION_RUNNER_CREATED=false")
print("EXECUTION_TRANSACTION_CREATED=false")
print("EXECUTION_TRANSACTION_ISSUED=false")
print("RAW_EXECUTION_RECEIPT_CREATED=false")
print("TRANSACTION_CURRENTLY_EXECUTABLE=false")
print("RAW_RUNS_PRODUCED=0")
print("RAW_ARTIFACTS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
print("QUALITY_RESULT_AVAILABLE=false")
