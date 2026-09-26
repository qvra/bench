#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design.schema.json"
)

PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol-v1.json"
)

PROTOCOL_SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol.schema.json"
)

PROTOCOL_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_attestation_probe_protocol.py"
)

NETWORK_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-design-v1.json"
)

SANDBOX_EXEC = Path(
    "/usr/bin/sandbox-exec"
)

PROBE_PYTHON = Path(
    "/opt/homebrew/opt/python@3.12/bin/python3.12"
)

FUTURE_HARNESS = (
    ROOT
    / "tests"
    / "attest_entity_resolution_ambiguity_network_isolation.py"
)

FUTURE_HARNESS_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_probe_harness.py"
)

FUTURE_ATTESTATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-v1.json"
)

FUTURE_RUNNER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_runner.py"
)

FUTURE_RECEIPT = (
    ROOT
    / "evidence"
    / "entity-resolution-ambiguity-v1"
    / "raw-execution-receipt-v1.json"
)


EXPECTED_DESIGN_SHA = (
    "d2413019f7dd414fca6caad9e7fe074f"
    "a7b2325a50dd69bf09364d2fc3aa7ea4"
)

EXPECTED_SCHEMA_SHA = (
    "1d61ff9364c9cc418d2c451c2e89555b"
    "b7542ff8a8925c23354def3eed32fac2"
)

EXPECTED_PROTOCOL_SHA = (
    "35d997ea115bbc3e6622c5e0f5b9f520"
    "53fc30d0249200439f33bc372cf224fa"
)

EXPECTED_PROTOCOL_SCHEMA_SHA = (
    "4b522e9a0df8ea85cca6948d91f51873"
    "00092d0348b2b5f0f23fa94193146af2"
)

EXPECTED_PROTOCOL_VERIFY_SHA = (
    "7eff4371946a735975da6c54cad4f665"
    "16e12832aa29c832fadf891e83ecb729"
)

EXPECTED_NETWORK_DESIGN_SHA = (
    "67949db7523dafebb0e6b6c9b876580c"
    "7457196c4f41adef8d97c498d54393d0"
)

EXPECTED_PROBE_PYTHON_SHA = (
    "fe46716a94d8efa4514feb3c39ba3e27"
    "0deee2187556986f6ddcff54aba7bb9a"
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

EXPECTED_PROBE_ORDER = [
    "profile_acceptance",
    "tcp_loopback_connect",
    "udp_loopback_send",
    "tcp_inbound_bind_listen",
    "child_process_tcp_connect",
    "unix_stream_connect",
    "unix_stream_bind",
]

EXPECTED_WORKER_MODES = [
    "tcp-connect",
    "udp-send",
    "tcp-bind-listen",
    "child-process-tcp-connect",
    "unix-stream-connect",
    "unix-stream-bind",
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


def exact_schema(
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

    assert schema.get("type") == "object", path
    assert isinstance(value, dict), path
    assert schema.get("additionalProperties") is False

    properties = schema["properties"]
    required = schema["required"]

    assert set(required) == set(properties)
    assert set(value) == set(properties)

    for key in value:
        exact_schema(
            value[key],
            properties[key],
            f"{path}.{key}",
        )


assert sha256_file(DESIGN) == EXPECTED_DESIGN_SHA
assert sha256_file(SCHEMA) == EXPECTED_SCHEMA_SHA

assert sha256_file(PROTOCOL) == EXPECTED_PROTOCOL_SHA
assert (
    sha256_file(PROTOCOL_SCHEMA)
    == EXPECTED_PROTOCOL_SCHEMA_SHA
)
assert (
    sha256_file(PROTOCOL_VERIFY)
    == EXPECTED_PROTOCOL_VERIFY_SHA
)

assert (
    sha256_file(NETWORK_DESIGN)
    == EXPECTED_NETWORK_DESIGN_SHA
)

assert SANDBOX_EXEC.is_file()
assert os.access(SANDBOX_EXEC, os.X_OK)
assert (
    sha256_file(SANDBOX_EXEC)
    == EXPECTED_SANDBOX_EXEC_SHA
)

assert PROBE_PYTHON.is_file()
assert os.access(PROBE_PYTHON, os.X_OK)
assert (
    sha256_file(PROBE_PYTHON)
    == EXPECTED_PROBE_PYTHON_SHA
)

assert not FUTURE_HARNESS.exists()
assert not FUTURE_HARNESS_VERIFY.exists()
assert not FUTURE_ATTESTATION.exists()
assert not FUTURE_RUNNER.exists()
assert not FUTURE_RECEIPT.exists()

design = load_json(DESIGN)
schema = load_json(SCHEMA)
protocol = load_json(PROTOCOL)
network_design = load_json(NETWORK_DESIGN)

exact_schema(
    design,
    schema,
)

assert design["schema"] == (
    "qvra-family-2-network-isolation-attestation-probe-harness-design/v1"
)

assert design["benchmark"] == (
    "entity-resolution-ambiguity-v1"
)

assert design["family"] == 2

assert design["design_kind"] == (
    "review-before-implementation-local-network-probe-harness"
)

bindings = design["bindings"]

assert bindings["governed_main"] == (
    "05c01c18b976a7cc5cd8e4fab0753a877b400df4"
)

assert bindings[
    "probe_protocol_sha256"
] == EXPECTED_PROTOCOL_SHA

assert bindings[
    "probe_protocol_schema_sha256"
] == EXPECTED_PROTOCOL_SCHEMA_SHA

assert bindings[
    "probe_protocol_verifier_sha256"
] == EXPECTED_PROTOCOL_VERIFY_SHA

assert bindings[
    "probe_protocol_reviewed_head"
] == (
    "bd8d06bf7c2db8ef46ec60761d214a3f2ddac0c3"
)

assert bindings[
    "probe_protocol_merged_main"
] == (
    "05c01c18b976a7cc5cd8e4fab0753a877b400df4"
)

assert bindings[
    "network_isolation_design_sha256"
] == EXPECTED_NETWORK_DESIGN_SHA

assert bindings[
    "sandbox_exec_path"
] == "/usr/bin/sandbox-exec"

assert bindings[
    "sandbox_exec_sha256"
] == EXPECTED_SANDBOX_EXEC_SHA

assert bindings[
    "probe_python_path"
] == (
    "/opt/homebrew/opt/python@3.12/bin/python3.12"
)

assert bindings[
    "probe_python_sha256"
] == EXPECTED_PROBE_PYTHON_SHA

assert bindings[
    "profile_sha256"
] == EXPECTED_PROFILE_SHA

assert bindings[
    "profile_text"
] == EXPECTED_PROFILE_TEXT

# Cross-check governed protocol rather than duplicated design fields.
assert protocol[
    "bindings"
]["sandbox_exec_sha256"] == bindings["sandbox_exec_sha256"]

assert protocol[
    "bindings"
]["probe_python_sha256"] == bindings["probe_python_sha256"]

assert protocol[
    "bindings"
]["profile_sha256"] == bindings["profile_sha256"]

assert protocol[
    "bindings"
]["profile_text"] == bindings["profile_text"]

assert protocol[
    "current_state"
]["probe_harness_created"] is False

assert protocol[
    "current_state"
]["sandbox_exec_invocation_count"] == 0

assert protocol[
    "current_state"
]["network_probe_count"] == 0

assert protocol[
    "current_state"
]["network_isolation_attestation_created"] is False

assert protocol[
    "current_state"
]["system_execution"] is False

# Cross-check governed network-isolation design remains unattested.
assert network_design[
    "pre_attestation_state"
]["network_isolation_attestation_created"] is False

assert network_design[
    "pre_attestation_state"
]["network_isolation_attested"] is False

target = design[
    "implementation_target"
]

assert target["created"] is False
assert target["language"] == "python-3.12"
assert target["import_side_effects_allowed"] is False
assert target["default_invocation_must_refuse"] is True
assert target["execution_flag"] == "--execute-attestation-probes"
assert target["execution_requires_explicit_flag"] is True
assert target["shell_execution_allowed"] is False
assert target["shell_true_allowed"] is False
assert target["absolute_executable_paths_required"] is True
assert target["central_process_runner_required"] is True
assert target["sandbox_exec_invocations_must_use_central_runner"] is True
assert target["network_operations_must_exist_only_in_worker_modes"] is True
assert target["attestation_creation_allowed"] is False
assert target["benchmark_execution_allowed"] is False

cli = design[
    "operator_cli_contract"
]

assert cli["required_execute_flag"] == "--execute-attestation-probes"
assert cli["required_expected_main_argument"] == "--expect-main-commit"
assert cli["required_expected_harness_hash_argument"] == "--expect-harness-sha256"
assert cli["required_evidence_output_argument"] == "--evidence-output"
assert cli["no_default_evidence_output"] is True
assert cli["unknown_arguments_must_refuse"] is True
assert cli["missing_required_argument_must_refuse_before_probe"] is True
assert cli["default_no_argument_invocation_must_refuse_before_probe"] is True

preflight = design[
    "preflight_contract"
]

for key in (
    "all_preflight_checks_before_first_sandbox_invocation",
    "must_verify_protocol_sha256",
    "must_verify_network_design_sha256",
    "must_verify_sandbox_exec_sha256",
    "must_verify_probe_python_sha256",
    "must_verify_profile_sha256",
    "must_verify_own_harness_sha256_against_operator_argument",
    "must_verify_current_git_head_against_operator_argument",
    "must_verify_current_git_head_is_local_origin_main",
    "must_verify_source_clean_except_local_evidence",
    "must_verify_raw_root_absent_or_empty",
    "must_verify_truth_not_accessed",
    "must_verify_no_existing_attestation",
    "must_verify_evidence_output_absent",
):
    assert preflight[key] is True, key

assert preflight["git_fetch_during_probe_run_allowed"] is False
assert preflight["preflight_failure_allows_sandbox_invocation"] is False
assert preflight["preflight_failure_allows_network_probe"] is False

evidence = design[
    "evidence_output_contract"
]

assert evidence["allowed_root"] == (
    ".qvra-local-evidence/network-isolation"
)

assert evidence["output_must_be_inside_allowed_root"] is True
assert evidence["output_must_not_preexist"] is True
assert evidence["parent_directory_may_be_created"] is True
assert evidence["tracked_repository_files_may_be_modified"] is False
assert evidence["benchmark_raw_root_may_be_touched"] is False
assert evidence["truth_may_be_accessed"] is False

assert evidence["write_strategy"] == (
    "temporary-file-fsync-atomic-os-replace"
)

assert evidence["partial_execution_evidence_required"] is True

assert evidence["completion_states"] == [
    "COMPLETE_PASS",
    "COMPLETE_FAIL",
    "INCOMPLETE_HARNESS_FAILURE",
]

assert evidence["attestation_ready_only_for_state"] == "COMPLETE_PASS"
assert evidence["evidence_file_sha256_must_be_reported"] is True

process = design[
    "process_model"
]

assert process["controller_role"] == "unsandboxed-harness-parent"
assert process["sandbox_target_role"] == "same-file-worker-mode"
assert process["worker_executable"] == bindings["probe_python_path"]
assert process["worker_entry_argument"] == "--worker"
assert process["nested_child_entry_argument"] == "--nested-child"
assert process["shell"] is False
assert process["environment_policy"] == "minimal-explicit-environment"
assert process["proxy_environment_variables_must_be_removed"] is True
assert process["command_paths_must_be_absolute"] is True

assert process["required_environment"] == {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "LC_ALL": "C",
    "LANG": "C",
}

worker_modes = design[
    "worker_modes"
]

assert [
    item["mode"]
    for item in worker_modes
] == EXPECTED_WORKER_MODES

for item in worker_modes[:4]:
    assert item["endpoint_policy"] == "127.0.0.1-only"

for item in worker_modes[4:]:
    assert item["path_policy"] == (
        "operator-created-unique-temp-directory-outside-repository"
    )

mapping = design[
    "probe_mapping"
]

assert [
    item["probe_id"]
    for item in mapping
] == EXPECTED_PROBE_ORDER

assert sum(
    item["sandbox_exec_invocations"]
    for item in mapping
) == 7

assert mapping[0]["positive_control"] is False
assert mapping[0]["network_probe"] is False

for item in mapping[1:]:
    assert item["positive_control"] is True
    assert item["network_probe"] is True

cardinality = design[
    "exact_execution_cardinality"
]

assert cardinality["probe_record_count"] == 7
assert cardinality["profile_acceptance_probe_count"] == 1
assert cardinality["network_probe_count"] == 6
assert cardinality["positive_control_count"] == 6
assert cardinality["sandbox_exec_invocation_count"] == 7
assert cardinality["retry_count"] == 0
assert cardinality["probe_reordering_allowed"] is False
assert cardinality[
    "all_probes_must_be_attempted_once_after_successful_preflight"
] is True
assert cardinality["continue_after_probe_failure"] is True

denial = design[
    "denial_evaluation"
]

assert denial["accepted_errno_names"] == [
    "EPERM",
    "EACCES",
]

assert denial["accepted_errno_values"] == [1, 13]
assert denial["permission_denial_required"] is True
assert denial["host_observer_must_show_no_sandbox_activity"] is True

for key in (
    "timeout_counts_as_denial",
    "connection_refused_counts_as_denial",
    "network_unreachable_counts_as_denial",
    "host_unreachable_counts_as_denial",
    "dns_failure_counts_as_denial",
    "observer_absence_alone_counts_as_denial",
):
    assert denial[key] is False, key

assert denial["successful_sandbox_network_operation_is_failure"] is True
assert denial["unexpected_errno_is_failure"] is True

worker_result = design[
    "worker_result_contract"
]

assert worker_result["serialization"] == "single-json-object-to-stdout"
assert worker_result["stderr_reserved_for_runtime_diagnostics"] is True
assert worker_result["network_worker_success_under_sandbox_must_fail_probe"] is True
assert worker_result["permission_denial_requires_errno_field"] is True

assert worker_result["required_fields"] == [
    "operation",
    "success",
    "denied",
    "denial_stage",
    "errno_name",
    "errno_value",
    "exception_type",
    "detail",
]

probe_record = design[
    "probe_record_contract"
]

assert probe_record["required_fields"] == [
    "probe_id",
    "sequence",
    "started_at_utc",
    "ended_at_utc",
    "control",
    "sandbox",
    "observer",
    "passed",
    "failure_code",
]

assert probe_record["sandbox_record_required_for_all_seven_probes"] is True
assert probe_record["control_record_required_for_six_network_probes"] is True
assert probe_record["failed_probe_record_must_be_retained"] is True

safety = design[
    "safety_firewall"
]

for key in (
    "external_network_allowed",
    "dns_resolution_allowed",
    "hostname_endpoint_allowed",
    "non_loopback_ip_allowed",
    "benchmark_adapter_import_allowed",
    "benchmark_adapter_execution_allowed",
    "benchmark_raw_root_access_allowed",
    "truth_access_allowed",
    "host_firewall_mutation_allowed",
    "network_service_mutation_allowed",
    "dns_configuration_mutation_allowed",
    "route_table_mutation_allowed",
    "interface_mutation_allowed",
    "root_privilege_allowed",
):
    assert safety[key] is False, key

review = design[
    "future_harness_review_contract"
]

for key in (
    "implementation_must_match_this_design",
    "implementation_requires_semantic_verifier",
    "implementation_requires_independent_exact_head_review",
    "implementation_requires_mainline_merge_before_execution",
    "review_must_not_execute_harness",
    "review_must_not_invoke_sandbox_exec",
    "review_must_not_perform_network_probe",
    "review_must_static_check_process_launch_sites",
    "review_must_static_check_socket_sites",
    "review_must_static_check_no_external_endpoint_literals",
    "review_must_prove_default_invocation_refuses",
):
    assert review[key] is True, key

operator = design[
    "post_mainline_operator_contract"
]

for key in (
    "probe_execution_is_separate_explicit_operator_step",
    "operator_must_supply_exact_main_commit",
    "operator_must_supply_exact_harness_sha256",
    "operator_must_supply_evidence_output",
    "execution_may_begin_only_after_harness_independent_review",
    "attestation_creation_is_separate_after_probe_execution",
    "execution_runner_remains_forbidden",
    "benchmark_execution_remains_forbidden",
):
    assert operator[key] is True, key

state = design[
    "current_state"
]

assert state["harness_design_created"] is True
assert state["harness_implementation_created"] is False
assert state["harness_verifier_created"] is False
assert state["profile_syntax_validated"] is False
assert state["sandbox_exec_invoked"] is False
assert state["sandbox_exec_invocation_count"] == 0
assert state["network_probe_performed"] is False
assert state["network_probe_count"] == 0
assert state["probe_evidence_created"] is False
assert state["network_isolation_attestation_created"] is False
assert state["network_isolation_attested"] is False
assert state["execution_runner_created"] is False
assert state["execution_transaction_issued"] is False
assert state["transaction_currently_executable"] is False
assert state["raw_runs_produced"] == 0
assert state["system_execution"] is False
assert state["truth_scoring"] is False

print("FAMILY_2_ATTESTATION_PROBE_HARNESS_DESIGN=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("HARNESS_DESIGN_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("PROBE_PROTOCOL_CROSSCHECK=PASS")
print("NETWORK_DESIGN_CROSSCHECK=PASS")
print("EXPLICIT_OPERATOR_GATE=PASS")
print("PREFLIGHT_ZERO_ACTION_REFUSAL=PASS")
print("ATOMIC_LOCAL_EVIDENCE_CONTRACT=PASS")
print("SAME_FILE_WORKER_MODEL=PASS")
print("OBSERVER_MODEL=PASS")
print("EXACT_FUTURE_CARDINALITY=PASS")
print("FUTURE_PROBE_RECORD_COUNT=7")
print("FUTURE_NETWORK_PROBE_COUNT=6")
print("FUTURE_POSITIVE_CONTROL_COUNT=6")
print("FUTURE_SANDBOX_EXEC_INVOCATION_COUNT=7")
print("STRICT_DENIAL_EVALUATION=PASS")
print("SAFETY_FIREWALL=PASS")
print("HARNESS_REVIEW_BEFORE_EXECUTION=PASS")
print("HARNESS_IMPLEMENTATION_CREATED=false")
print("HARNESS_VERIFIER_CREATED=false")
print("PROFILE_SYNTAX_VALIDATED=false")
print("SANDBOX_EXEC_INVOKED=false")
print("SANDBOX_EXEC_INVOCATION_COUNT=0")
print("NETWORK_PROBE_PERFORMED=false")
print("NETWORK_PROBE_COUNT=0")
print("PROBE_EVIDENCE_CREATED=false")
print("NETWORK_ISOLATION_ATTESTATION_CREATED=false")
print("NETWORK_ISOLATION_ATTESTED=false")
print("EXECUTION_RUNNER_CREATED=false")
print("EXECUTION_TRANSACTION_ISSUED=false")
print("TRANSACTION_CURRENTLY_EXECUTABLE=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
