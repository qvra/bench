#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol.schema.json"
)

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-design-v1.json"
)

DESIGN_SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-design.schema.json"
)

DESIGN_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_design.py"
)

RUN_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction-design-v1.json"
)

RUN_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_explicit_execution_run_transaction_design.py"
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


EXPECTED_PROTOCOL_SHA = (
    "35d997ea115bbc3e6622c5e0f5b9f520"
    "53fc30d0249200439f33bc372cf224fa"
)

EXPECTED_SCHEMA_SHA = (
    "4b522e9a0df8ea85cca6948d91f51873"
    "00092d0348b2b5f0f23fa94193146af2"
)

EXPECTED_DESIGN_SHA = (
    "67949db7523dafebb0e6b6c9b876580c"
    "7457196c4f41adef8d97c498d54393d0"
)

EXPECTED_DESIGN_SCHEMA_SHA = (
    "2610c4512cf7f12635651af88a7c9c23"
    "df05499d960ddf6bc43220a94f1cad07"
)

EXPECTED_DESIGN_VERIFY_SHA = (
    "cf931f5afb03efae5394cbae613c2653"
    "baf08192de81cc86c02516a93536d922"
)

EXPECTED_RUN_DESIGN_SHA = (
    "9d3f25f267e935588d96c796f78fb084"
    "1493ea7275f7d34d8b5b60e085b9a77f"
)

EXPECTED_RUN_VERIFY_SHA = (
    "06ac62ae771abe090dc41e46f5707285"
    "12126ce5a6d9e840bf7f927b6d2e6cf3"
)

EXPECTED_SANDBOX_EXEC_SHA = (
    "8290e4be7387a0df83cd1559e86afd88"
    "0464f269450573d012795761fe298f16"
)

EXPECTED_PROBE_PYTHON_SHA = (
    "fe46716a94d8efa4514feb3c39ba3e27"
    "0deee2187556986f6ddcff54aba7bb9a"
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


assert sha256_file(PROTOCOL) == EXPECTED_PROTOCOL_SHA
assert sha256_file(SCHEMA) == EXPECTED_SCHEMA_SHA

assert sha256_file(DESIGN) == EXPECTED_DESIGN_SHA
assert sha256_file(DESIGN_SCHEMA) == EXPECTED_DESIGN_SCHEMA_SHA
assert sha256_file(DESIGN_VERIFY) == EXPECTED_DESIGN_VERIFY_SHA

assert sha256_file(RUN_DESIGN) == EXPECTED_RUN_DESIGN_SHA
assert sha256_file(RUN_VERIFY) == EXPECTED_RUN_VERIFY_SHA

assert SANDBOX_EXEC.is_file()
assert os.access(
    SANDBOX_EXEC,
    os.X_OK,
)
assert sha256_file(
    SANDBOX_EXEC
) == EXPECTED_SANDBOX_EXEC_SHA

assert PROBE_PYTHON.is_file()
assert os.access(
    PROBE_PYTHON,
    os.X_OK,
)
assert sha256_file(
    PROBE_PYTHON
) == EXPECTED_PROBE_PYTHON_SHA

assert not FUTURE_HARNESS.exists()
assert not FUTURE_ATTESTATION.exists()
assert not FUTURE_RUNNER.exists()
assert not FUTURE_RECEIPT.exists()

protocol = load_json(PROTOCOL)
schema = load_json(SCHEMA)
design = load_json(DESIGN)
run_design = load_json(RUN_DESIGN)

exact_schema(
    protocol,
    schema,
)

assert protocol["schema"] == (
    "qvra-family-2-network-isolation-attestation-probe-protocol/v1"
)

assert protocol["benchmark"] == (
    "entity-resolution-ambiguity-v1"
)

assert protocol["family"] == 2

assert protocol["protocol_kind"] == (
    "pre-attestation-exact-network-denial-probe-plan"
)

bindings = protocol["bindings"]

assert bindings[
    "governed_main"
] == (
    "15b9dc8a114ecf914c9c4b694a29851d82c8ec8a"
)

assert bindings[
    "network_isolation_design_sha256"
] == EXPECTED_DESIGN_SHA

assert bindings[
    "network_isolation_design_schema_sha256"
] == EXPECTED_DESIGN_SCHEMA_SHA

assert bindings[
    "network_isolation_design_verifier_sha256"
] == EXPECTED_DESIGN_VERIFY_SHA

assert bindings[
    "network_isolation_design_reviewed_head"
] == (
    "e8c81697105c0d3686aa7723e1759ecfb26db37b"
)

assert bindings[
    "network_isolation_design_merged_main"
] == (
    "15b9dc8a114ecf914c9c4b694a29851d82c8ec8a"
)

assert bindings[
    "explicit_run_transaction_design_sha256"
] == EXPECTED_RUN_DESIGN_SHA

assert bindings[
    "sandbox_exec_path"
] == "/usr/bin/sandbox-exec"

assert bindings[
    "sandbox_exec_sha256"
] == EXPECTED_SANDBOX_EXEC_SHA

assert bindings[
    "profile_sha256"
] == EXPECTED_PROFILE_SHA

assert bindings[
    "profile_text"
] == EXPECTED_PROFILE_TEXT

assert bindings[
    "probe_python_path"
] == (
    "/opt/homebrew/opt/python@3.12/bin/python3.12"
)

assert bindings[
    "probe_python_sha256"
] == EXPECTED_PROBE_PYTHON_SHA

# Cross-check the governed isolation design rather than merely
# trusting duplicated values in this protocol.
selected = design["selected_mechanism"]

assert selected[
    "sandbox_exec_path"
] == bindings["sandbox_exec_path"]

assert selected[
    "sandbox_exec_sha256"
] == bindings["sandbox_exec_sha256"]

assert selected[
    "profile_sha256"
] == bindings["profile_sha256"]

assert selected[
    "profile_text"
] == bindings["profile_text"]

assert design[
    "pre_attestation_state"
]["network_isolation_attested"] is False

assert design[
    "pre_attestation_state"
]["network_isolation_attestation_created"] is False

# Cross-check the governed run transaction remains closed.
network_gate = run_design[
    "network_isolation_gate"
]

assert network_gate[
    "network_disabled_required"
] is True

assert network_gate[
    "network_isolation_attestation_required"
] is True

assert network_gate[
    "network_isolation_attestation_created"
] is False

assert network_gate[
    "execution_forbidden_without_attestation"
] is True

assert run_design[
    "issuance_gate"
]["transaction_currently_executable"] is False

scope = protocol[
    "probe_scope"
]

for key in (
    "external_network_allowed",
    "dns_lookup_allowed",
    "internet_endpoint_allowed",
    "benchmark_adapter_use_allowed",
    "benchmark_raw_root_access_allowed",
    "truth_access_allowed",
    "host_firewall_mutation_allowed",
    "root_privilege_allowed",
):
    assert scope[key] is False, key

assert scope[
    "allowed_ip_endpoint"
] == "127.0.0.1"

assert scope[
    "allowed_unix_socket_location"
] == (
    "unique-temporary-directory-outside-repository"
)

assert scope[
    "control_execution_required"
] is True

assert scope[
    "sandbox_execution_required"
] is True

assert scope[
    "sandbox_profile_delivery"
] == (
    "sandbox-exec--p-inline-exact-profile-text"
)

denial = protocol[
    "denial_semantics"
]

assert denial[
    "accepted_errno_names"
] == [
    "EPERM",
    "EACCES",
]

assert denial[
    "accepted_errno_values"
] == [
    1,
    13,
]

for key in (
    "timeout_counts_as_denial",
    "connection_refused_counts_as_denial",
    "network_unreachable_counts_as_denial",
    "host_unreachable_counts_as_denial",
    "dns_failure_counts_as_denial",
    "observer_absence_alone_counts_as_denial",
    "sandbox_success_for_network_operation_allowed",
):
    assert denial[key] is False, key

assert denial[
    "permission_denial_required"
] is True

assert denial[
    "positive_unsandboxed_control_required"
] is True

evidence = protocol[
    "evidence_contract"
]

for key in (
    "record_exact_command_argv",
    "record_process_exit_code",
    "record_stdout_text",
    "record_stderr_text",
    "record_stdout_sha256",
    "record_stderr_sha256",
    "record_denial_stage",
    "record_errno_name",
    "record_errno_value",
    "record_host_observer_result",
    "record_control_result",
    "record_sandbox_result",
    "record_probe_start_timestamp",
    "record_probe_end_timestamp",
    "record_host_platform",
    "record_host_build",
    "record_sandbox_exec_sha256",
    "record_probe_python_sha256",
    "record_profile_sha256",
    "preserve_failed_probe_evidence",
):
    assert evidence[key] is True, key

probes = protocol["probes"]

assert len(probes) == 7

probe_ids = [
    probe["id"]
    for probe in probes
]

assert probe_ids == EXPECTED_PROBE_ORDER

assert protocol[
    "probe_execution_order"
] == EXPECTED_PROBE_ORDER

by_id = {
    probe["id"]: probe
    for probe in probes
}

profile = by_id[
    "profile_acceptance"
]

assert profile[
    "control_required"
] is False

assert profile[
    "sandbox_invocation_required"
] is True

assert profile[
    "network_operation"
] is False

assert profile[
    "sandbox_target"
] == "/usr/bin/true"

assert profile[
    "expected_exit_code"
] == 0

assert profile[
    "satisfies"
] == [
    "profile_syntax_validated",
]

tcp = by_id[
    "tcp_loopback_connect"
]

assert tcp[
    "control_required"
] is True

assert tcp[
    "satisfies"
] == [
    "outbound_tcp_denied",
    "loopback_tcp_denied",
]

udp = by_id[
    "udp_loopback_send"
]

assert udp[
    "control_required"
] is True

assert udp[
    "satisfies"
] == [
    "outbound_udp_denied",
]

listen = by_id[
    "tcp_inbound_bind_listen"
]

assert listen[
    "control_required"
] is True

assert listen[
    "satisfies"
] == [
    "inbound_listen_denied",
]

child = by_id[
    "child_process_tcp_connect"
]

assert child[
    "control_required"
] is True

assert child[
    "satisfies"
] == [
    "child_process_network_denied",
]

unix_connect = by_id[
    "unix_stream_connect"
]

assert unix_connect[
    "control_required"
] is True

assert unix_connect[
    "satisfies"
] == [
    "unix_domain_socket_policy_tested",
    "unix_domain_connect_denied",
]

unix_bind = by_id[
    "unix_stream_bind"
]

assert unix_bind[
    "control_required"
] is True

assert unix_bind[
    "satisfies"
] == [
    "unix_domain_socket_policy_tested",
    "unix_domain_bind_denied",
]

cardinality = protocol[
    "execution_cardinality"
]

assert cardinality[
    "mandatory_probe_count"
] == 7

assert cardinality[
    "expected_sandbox_exec_invocations"
] == 7

assert cardinality[
    "retry_allowed"
] is False

assert cardinality[
    "probe_reordering_allowed"
] is False

assert cardinality[
    "partial_attestation_allowed"
] is False

assert cardinality[
    "continue_after_probe_failure"
] is True

assert cardinality[
    "all_probe_evidence_must_be_retained"
] is True

harness = protocol[
    "future_probe_harness_contract"
]

assert harness["created"] is False

for key in (
    "must_bind_exact_protocol_sha256",
    "must_bind_exact_design_sha256",
    "must_bind_exact_sandbox_exec_sha256",
    "must_bind_exact_probe_python_sha256",
    "must_bind_exact_profile_sha256",
    "must_use_only_controlled_local_endpoints",
    "must_run_all_probes_once",
    "must_not_retry_failed_probe",
    "must_retain_failed_probe_evidence",
):
    assert harness[key] is True, key

assert harness[
    "may_invoke_sandbox_exec"
] is True

for key in (
    "may_access_external_network",
    "may_resolve_dns",
    "may_use_benchmark_adapters",
    "may_touch_benchmark_raw_root",
    "may_access_truth",
    "may_mutate_host_network_configuration",
):
    assert harness[key] is False, key

attestation = protocol[
    "future_attestation_contract"
]

assert attestation["created"] is False
assert attestation["attested"] is False

for key in (
    "may_be_created_only_after_probe_harness_mainline",
    "must_bind_exact_protocol_sha256",
    "must_bind_exact_probe_harness_sha256",
    "must_bind_exact_design_sha256",
    "must_bind_exact_sandbox_exec_sha256",
    "must_bind_exact_probe_python_sha256",
    "must_bind_exact_profile_sha256",
    "must_include_all_seven_probe_records",
    "all_seven_probes_must_pass",
    "any_probe_failure_forces_attestation_false",
    "independent_review_required",
    "mainline_merge_required",
):
    assert attestation[key] is True, key

failure = protocol[
    "failure_policy"
]

assert failure[
    "profile_acceptance_failure"
] == "FAIL_STOP_ATTESTATION"

assert failure[
    "positive_control_failure"
] == "FAIL_INVALID_PROBE_NO_ATTESTATION"

assert failure[
    "sandbox_network_success"
] == "FAIL_ISOLATION_MECHANISM"

assert failure[
    "unexpected_errno"
] == "FAIL_ISOLATION_MECHANISM"

assert failure[
    "timeout"
] == "FAIL_NOT_PROOF_OF_ISOLATION"

assert failure[
    "observer_detects_sandbox_network_activity"
] == "FAIL_ISOLATION_MECHANISM"

assert failure[
    "unix_domain_operation_allowed"
] == "FAIL_ISOLATION_MECHANISM_REDESIGN_REQUIRED"

gate = protocol[
    "governance_gate"
]

for key in (
    "protocol_requires_schema",
    "protocol_requires_semantic_verifier",
    "protocol_requires_independent_exact_head_review",
    "protocol_requires_mainline_merge",
    "probe_harness_forbidden_before_protocol_mainline",
    "sandbox_invocation_forbidden_before_probe_harness_mainline",
    "network_probe_forbidden_before_probe_harness_mainline",
    "attestation_forbidden_before_completed_probe_execution",
    "execution_runner_forbidden_before_attestation_mainline",
    "benchmark_execution_forbidden_before_attestation_mainline",
):
    assert gate[key] is True, key

state = protocol[
    "current_state"
]

assert state[
    "probe_protocol_created"
] is True

assert state[
    "probe_harness_created"
] is False

assert state[
    "profile_syntax_validated"
] is False

assert state[
    "sandbox_exec_invoked"
] is False

assert state[
    "sandbox_exec_invocation_count"
] == 0

assert state[
    "network_probe_performed"
] is False

assert state[
    "network_probe_count"
] == 0

assert state[
    "network_isolation_attestation_created"
] is False

assert state[
    "network_isolation_attested"
] is False

assert state[
    "execution_runner_created"
] is False

assert state[
    "execution_transaction_issued"
] is False

assert state[
    "transaction_currently_executable"
] is False

assert state[
    "raw_runs_produced"
] == 0

assert state[
    "system_execution"
] is False

assert state[
    "truth_scoring"
] is False

print("FAMILY_2_NETWORK_ISOLATION_ATTESTATION_PROBE_PROTOCOL=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("PROTOCOL_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("NETWORK_ISOLATION_DESIGN_CROSSCHECK=PASS")
print("RUN_TRANSACTION_CROSSCHECK=PASS")
print("LOCAL_ONLY_PROBE_SCOPE=PASS")
print("STRICT_PERMISSION_DENIAL_SEMANTICS=PASS")
print("POSITIVE_CONTROLS_REQUIRED=PASS")
print("EVIDENCE_CONTRACT=PASS")
print("EXACT_SEVEN_PROBE_PLAN=PASS")
print("MANDATORY_PROBE_COUNT=7")
print("EXPECTED_FUTURE_SANDBOX_INVOCATIONS=7")
print("NO_RETRY_POLICY=PASS")
print("UNIX_DOMAIN_POLICY_EXPLICIT=PASS")
print("PROBE_HARNESS_CREATED=false")
print("PROFILE_SYNTAX_VALIDATED=false")
print("SANDBOX_EXEC_INVOKED=false")
print("SANDBOX_EXEC_INVOCATION_COUNT=0")
print("NETWORK_PROBE_PERFORMED=false")
print("NETWORK_PROBE_COUNT=0")
print("NETWORK_ISOLATION_ATTESTATION_CREATED=false")
print("NETWORK_ISOLATION_ATTESTED=false")
print("EXECUTION_RUNNER_CREATED=false")
print("EXECUTION_TRANSACTION_ISSUED=false")
print("TRANSACTION_CURRENTLY_EXECUTABLE=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
