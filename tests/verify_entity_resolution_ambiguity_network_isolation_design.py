#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import json
import os
import plistlib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-design-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-design.schema.json"
)

RUN_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-explicit-execution-run-transaction-design-v1.json"
)

BRIDGE = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_bridge.py"
)

LAUNCHER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "process_launcher.py"
)

SANDBOX_EXEC = Path(
    "/usr/bin/sandbox-exec"
)

SYSTEM_VERSION = Path(
    "/System/Library/CoreServices/SystemVersion.plist"
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
    "67949db7523dafebb0e6b6c9b876580c"
    "7457196c4f41adef8d97c498d54393d0"
)

EXPECTED_SCHEMA_SHA = (
    "2610c4512cf7f12635651af88a7c9c23"
    "df05499d960ddf6bc43220a94f1cad07"
)

EXPECTED_RUN_DESIGN_SHA = (
    "9d3f25f267e935588d96c796f78fb084"
    "1493ea7275f7d34d8b5b60e085b9a77f"
)

EXPECTED_BRIDGE_SHA = (
    "f0aaa7706f92d99ee80f152a199b2e8f"
    "31dd12cf0c6494c8733e51a962b807be"
)

EXPECTED_LAUNCHER_SHA = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_SANDBOX_EXEC_SHA = (
    "8290e4be7387a0df83cd1559e86afd88"
    "0464f269450573d012795761fe298f16"
)

EXPECTED_PROFILE_SHA = (
    "5c358b8d847211333e7ba22df82d84f7"
    "96b5f30a41a2682209a949d783adbd08"
)

EXPECTED_PROFILE = (
    "(version 1)\n"
    "(allow default)\n"
    "(deny network*)\n"
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
assert sha256_file(RUN_DESIGN) == EXPECTED_RUN_DESIGN_SHA
assert sha256_file(BRIDGE) == EXPECTED_BRIDGE_SHA
assert sha256_file(LAUNCHER) == EXPECTED_LAUNCHER_SHA

assert SANDBOX_EXEC.is_file()
assert os.access(
    SANDBOX_EXEC,
    os.X_OK,
)
assert (
    sha256_file(SANDBOX_EXEC)
    == EXPECTED_SANDBOX_EXEC_SHA
)

assert not FUTURE_ATTESTATION.exists()
assert not FUTURE_RUNNER.exists()
assert not FUTURE_RECEIPT.exists()

design = load_json(DESIGN)
schema = load_json(SCHEMA)

exact_schema(
    design,
    schema,
)

assert design["schema"] == (
    "qvra-family-2-network-isolation-design/v1"
)

assert design["benchmark"] == (
    "entity-resolution-ambiguity-v1"
)

assert design["family"] == 2

assert design["design_kind"] == (
    "macos-process-network-isolation"
)

bindings = design["bindings"]

assert bindings[
    "explicit_run_transaction_design_sha256"
] == EXPECTED_RUN_DESIGN_SHA

assert bindings[
    "execution_bridge_sha256"
] == EXPECTED_BRIDGE_SHA

assert bindings[
    "process_launcher_sha256"
] == EXPECTED_LAUNCHER_SHA

host = design["host_observation"]

assert host["platform"] == "Darwin"
assert host["architecture"] == "arm64"
assert host["observation_read_only"] is True

uname = os.uname()

assert uname.sysname == "Darwin"
assert uname.machine == "arm64"

# Read the host build/version directly from the system plist.
# This performs no command or subprocess invocation.
with SYSTEM_VERSION.open("rb") as handle:
    system_version = plistlib.load(handle)

assert (
    system_version["ProductVersion"]
    == host["macos_product_version"]
)

assert (
    system_version["ProductBuildVersion"]
    == host["macos_build_version"]
)

mechanism = design[
    "selected_mechanism"
]

assert mechanism["mechanism_selected"] is True

assert mechanism["mechanism_kind"] == (
    "macos-sandbox-exec-seatbelt-profile"
)

assert mechanism["sandbox_exec_path"] == (
    "/usr/bin/sandbox-exec"
)

assert mechanism["sandbox_exec_sha256"] == (
    EXPECTED_SANDBOX_EXEC_SHA
)

assert mechanism["profile_text"] == (
    EXPECTED_PROFILE
)

observed_profile_sha = hashlib.sha256(
    mechanism[
        "profile_text"
    ].encode("utf-8")
).hexdigest()

assert observed_profile_sha == EXPECTED_PROFILE_SHA

assert mechanism["profile_sha256"] == (
    EXPECTED_PROFILE_SHA
)

assert mechanism["profile_intent"] == (
    "allow-default-deny-all-network"
)

assert mechanism[
    "all_network_operations_denied_required"
] is True

assert mechanism[
    "loopback_network_denied_required"
] is True

assert mechanism[
    "unix_domain_socket_policy"
] == (
    "must-be-explicitly-tested-before-attestation"
)

assert mechanism[
    "child_processes_must_remain_inside_sandbox"
] is True

boundary = design[
    "design_boundary"
]

assert boundary["sandbox_exec_discovered"] is True
assert boundary["sandbox_exec_invoked"] is False
assert boundary["profile_materialized"] is False
assert boundary["profile_syntax_validated"] is False
assert boundary["network_denial_probe_performed"] is False
assert boundary["network_isolation_attested"] is False
assert boundary["network_isolation_attestation_created"] is False
assert boundary["execution_runner_created"] is False
assert boundary["execution_transaction_issued"] is False
assert boundary["process_launch_capability_present"] is False
assert boundary["benchmark_system_execution"] is False

attestation = design[
    "future_attestation_contract"
]

for key in (
    "must_bind_exact_design_sha256",
    "must_bind_exact_sandbox_exec_sha256",
    "must_bind_exact_profile_sha256",
    "must_bind_host_platform_and_build",
    "must_validate_profile_syntax",
    "must_prove_outbound_tcp_denied",
    "must_prove_outbound_udp_denied",
    "must_prove_inbound_listen_denied",
    "must_prove_loopback_tcp_denied",
    "must_prove_child_process_network_denied",
    "must_record_probe_commands",
    "must_record_probe_exit_codes",
    "must_record_probe_stdout",
    "must_record_probe_stderr",
    "benchmark_adapters_may_not_be_used_as_network_probes",
    "benchmark_raw_root_may_not_be_touched",
):
    assert attestation[key] is True, key

runner = design[
    "future_runner_contract"
]

assert runner["runner_created"] is False
assert runner["must_refuse_without_mainline_attestation"] is True
assert runner["must_verify_attestation_identity"] is True
assert runner["must_verify_sandbox_exec_identity"] is True
assert runner["must_verify_profile_identity"] is True

assert runner[
    "must_wrap_every_system_process_in_exact_isolation_mechanism"
] is True

assert runner[
    "must_not_offer_unsandboxed_fallback"
] is True

assert runner[
    "must_not_mutate_host_firewall"
] is True

assert runner[
    "must_not_require_root"
] is True

mutation = design[
    "host_mutation_policy"
]

for key in (
    "pf_firewall_mutation_allowed",
    "network_service_mutation_allowed",
    "interface_disable_allowed",
    "dns_configuration_mutation_allowed",
    "route_table_mutation_allowed",
    "root_privilege_required",
):
    assert mutation[key] is False, key

gate = design[
    "governance_gate"
]

for key in (
    "design_requires_independent_review",
    "design_requires_exact_head_review",
    "design_requires_mainline_merge",
    "attestation_requires_separate_commit",
    "attestation_requires_independent_review",
    "attestation_requires_mainline_merge",
    "runner_forbidden_before_attestation_mainline",
    "execution_forbidden_before_attestation_mainline",
):
    assert gate[key] is True, key

state = design[
    "pre_attestation_state"
]

assert state["network_isolation_mechanism_selected"] is True
assert state["network_isolation_attestation_created"] is False
assert state["network_isolation_attested"] is False
assert state["execution_runner_created"] is False
assert state["execution_transaction_issued"] is False
assert state["transaction_currently_executable"] is False
assert state["raw_runs_produced"] == 0
assert state["system_execution"] is False
assert state["truth_scoring"] is False

# Static proof that the governed bridge and launcher remain closed.
bridge_tree = ast.parse(
    BRIDGE.read_text(
        encoding="utf-8"
    )
)

bridge_values: dict[str, Any] = {}

for node in bridge_tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                try:
                    bridge_values[
                        target.id
                    ] = ast.literal_eval(
                        node.value
                    )
                except Exception:
                    pass

assert bridge_values[
    "BRIDGE_EFFECTUATION_AUTHORIZED"
] is False

assert bridge_values[
    "PROCESS_LAUNCH_CAPABILITY_PRESENT"
] is False

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

print("FAMILY_2_NETWORK_ISOLATION_DESIGN=PASS")
print("STRICT_SCHEMA_VALIDATION=PASS")
print("NETWORK_ISOLATION_DESIGN_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("HOST_BINDING=PASS")
print("SANDBOX_EXEC_IDENTITY=PASS")
print("PROFILE_IDENTITY=PASS")
print("NETWORK_ISOLATION_MECHANISM_SELECTED=true")
print("PROFILE_SYNTAX_VALIDATED=false")
print("SANDBOX_EXEC_INVOKED=false")
print("NETWORK_PROBE_PERFORMED=false")
print("NETWORK_ISOLATION_ATTESTED=false")
print("NETWORK_ISOLATION_ATTESTATION_CREATED=false")
print("EXECUTION_RUNNER_CREATED=false")
print("EXECUTION_TRANSACTION_ISSUED=false")
print("TRANSACTION_CURRENTLY_EXECUTABLE=false")
print("BRIDGE_EFFECTUATION_AUTHORIZED=false")
print("PROCESS_LAUNCH_CAPABILITY_PRESENT=false")
print("LAUNCHER_EXECUTION_AUTHORIZED=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
