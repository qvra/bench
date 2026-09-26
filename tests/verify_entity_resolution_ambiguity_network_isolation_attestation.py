#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os

from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

ATTESTATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation.schema.json"
)

EVIDENCE = (
    ROOT
    / ".qvra-local-evidence"
    / "network-isolation"
    / "entity-resolution-ambiguity-v1-probe-evidence-209a7806258e6b6bfb933f3663f6598fdc8129e4.json"
)

NETWORK_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-design-v1.json"
)

PROBE_PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol-v1.json"
)

HARNESS_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design-v1.json"
)

HARNESS = (
    ROOT
    / "tests"
    / "attest_entity_resolution_ambiguity_network_isolation.py"
)

HARNESS_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_probe_harness.py"
)

EXECUTION_RUNNER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_runner.py"
)

RAW_EXECUTION_RECEIPT = (
    ROOT
    / "evidence"
    / "entity-resolution-ambiguity-v1"
    / "raw-execution-receipt-v1.json"
)

RAW_ROOT = (
    ROOT
    / "family-2-raw-runs"
)

PROBE_PYTHON = Path(
    "/opt/homebrew/opt/python@3.12/bin/python3.12"
)

SANDBOX_EXEC = Path(
    "/usr/bin/sandbox-exec"
)


EXPECTED_MAIN = (
    "209a7806258e6b6bfb933f3663f6598fdc8129e4"
)

EXPECTED_ATTESTATION_SHA = (
    "fb7240a55c46363b118e6da54ac6ef39"
    "3ff40979215bc99d9fc5d75f863d0208"
)

EXPECTED_SCHEMA_SHA = (
    "de564da8692aa22cbfee005c04dffcde"
    "2e09f25a392e561862f97c4e5dd44051"
)

EXPECTED_EVIDENCE_SHA = (
    "5ee527f4a90686ffbacb5b054439cbe1"
    "5acad2b0766aea52deab2fed04846ec9"
)

EXPECTED_NETWORK_DESIGN_SHA = (
    "67949db7523dafebb0e6b6c9b876580c"
    "7457196c4f41adef8d97c498d54393d0"
)

EXPECTED_PROBE_PROTOCOL_SHA = (
    "35d997ea115bbc3e6622c5e0f5b9f520"
    "53fc30d0249200439f33bc372cf224fa"
)

EXPECTED_HARNESS_DESIGN_SHA = (
    "d2413019f7dd414fca6caad9e7fe074f"
    "a7b2325a50dd69bf09364d2fc3aa7ea4"
)

EXPECTED_HARNESS_SHA = (
    "bf5ae02328cb665cae1956105b40bd83"
    "d4e49430a24441e735972c22366737e4"
)

EXPECTED_HARNESS_VERIFY_SHA = (
    "75787895ceab9b0267b779d1e51ffde7"
    "3e4e966b6c06624538516dd26205e2a0"
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

ACCEPTED_ERRNO_NAMES = {
    "EPERM",
    "EACCES",
}

ACCEPTED_ERRNO_VALUES = {
    1,
    13,
}


def sha256_file(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_json(
    path: Path,
) -> Any:
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

    assert rule.get(
        "type"
    ) == "object", path

    assert isinstance(
        value,
        dict,
    ), path

    assert rule.get(
        "additionalProperties"
    ) is False, path

    properties = rule[
        "properties"
    ]

    required = rule[
        "required"
    ]

    assert set(
        required
    ) == set(
        properties
    ), path

    assert set(
        value
    ) == set(
        properties
    ), path

    for key in value:
        exact_validate(
            value[key],
            properties[key],
            f"{path}.{key}",
        )


def assert_process_record(
    record: dict[str, Any],
) -> None:
    required = {
        "argv",
        "exit_code",
        "timed_out",
        "stdout_text",
        "stdout_sha256",
        "stderr_text",
        "stderr_sha256",
    }

    assert required <= set(
        record
    )

    assert hashlib.sha256(
        record[
            "stdout_text"
        ].encode(
            "utf-8"
        )
    ).hexdigest() == record[
        "stdout_sha256"
    ]

    assert hashlib.sha256(
        record[
            "stderr_text"
        ].encode(
            "utf-8"
        )
    ).hexdigest() == record[
        "stderr_sha256"
    ]


def assert_worker_result(
    result: dict[str, Any],
) -> None:
    assert set(
        result
    ) == {
        "operation",
        "success",
        "denied",
        "denial_stage",
        "errno_name",
        "errno_value",
        "exception_type",
        "detail",
    }


assert sha256_file(
    ATTESTATION
) == EXPECTED_ATTESTATION_SHA

assert sha256_file(
    SCHEMA
) == EXPECTED_SCHEMA_SHA

assert sha256_file(
    EVIDENCE
) == EXPECTED_EVIDENCE_SHA

assert sha256_file(
    NETWORK_DESIGN
) == EXPECTED_NETWORK_DESIGN_SHA

assert sha256_file(
    PROBE_PROTOCOL
) == EXPECTED_PROBE_PROTOCOL_SHA

assert sha256_file(
    HARNESS_DESIGN
) == EXPECTED_HARNESS_DESIGN_SHA

assert sha256_file(
    HARNESS
) == EXPECTED_HARNESS_SHA

assert sha256_file(
    HARNESS_VERIFY
) == EXPECTED_HARNESS_VERIFY_SHA

assert PROBE_PYTHON.is_file()
assert os.access(
    PROBE_PYTHON,
    os.X_OK,
)

assert sha256_file(
    PROBE_PYTHON
) == EXPECTED_PROBE_PYTHON_SHA

assert SANDBOX_EXEC.is_file()
assert os.access(
    SANDBOX_EXEC,
    os.X_OK,
)

assert sha256_file(
    SANDBOX_EXEC
) == EXPECTED_SANDBOX_EXEC_SHA

assert not EXECUTION_RUNNER.exists()
assert not RAW_EXECUTION_RECEIPT.exists()

if RAW_ROOT.exists():
    assert RAW_ROOT.is_dir()
    assert not any(
        RAW_ROOT.iterdir()
    )

attestation = load_json(
    ATTESTATION
)

schema = load_json(
    SCHEMA
)

evidence = load_json(
    EVIDENCE
)

network_design = load_json(
    NETWORK_DESIGN
)

probe_protocol = load_json(
    PROBE_PROTOCOL
)

harness_design = load_json(
    HARNESS_DESIGN
)

exact_validate(
    attestation,
    schema,
)

assert attestation[
    "schema"
] == (
    "qvra-family-2-network-isolation-attestation/v1"
)

assert attestation[
    "benchmark"
] == "entity-resolution-ambiguity-v1"

assert attestation[
    "family"
] == 2

assert attestation[
    "attestation_kind"
] == (
    "exact-host-reviewed-network-isolation-probe-attestation"
)

scope = attestation[
    "scope"
]

assert scope[
    "exact_host_only"
] is True

assert scope[
    "exact_sandbox_binary_only"
] is True

assert scope[
    "exact_profile_only"
] is True

assert scope[
    "cross_host_generalization"
] is False

assert scope[
    "future_macos_version_generalization"
] is False

assert scope[
    "benchmark_quality_claim"
] is False

assert scope[
    "benchmark_system_execution_claim"
] is False

bindings = attestation[
    "bindings"
]

assert bindings[
    "governed_main_at_probe_execution"
] == EXPECTED_MAIN

assert bindings[
    "network_isolation_design_sha256"
] == EXPECTED_NETWORK_DESIGN_SHA

assert bindings[
    "probe_protocol_sha256"
] == EXPECTED_PROBE_PROTOCOL_SHA

assert bindings[
    "probe_harness_design_sha256"
] == EXPECTED_HARNESS_DESIGN_SHA

assert bindings[
    "probe_harness_sha256"
] == EXPECTED_HARNESS_SHA

assert bindings[
    "probe_harness_verifier_sha256"
] == EXPECTED_HARNESS_VERIFY_SHA

assert bindings[
    "probe_python_path"
] == str(
    PROBE_PYTHON
)

assert bindings[
    "probe_python_sha256"
] == EXPECTED_PROBE_PYTHON_SHA

assert bindings[
    "sandbox_exec_path"
] == str(
    SANDBOX_EXEC
)

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
    "probe_evidence_sha256"
] == EXPECTED_EVIDENCE_SHA

assert bindings[
    "harness_reviewed_head"
] == (
    "d232cbe59cf665b1fa8a91fcf64e40c06bf7a80e"
)

assert bindings[
    "harness_merged_main"
] == EXPECTED_MAIN

assert bindings[
    "independent_harness_reviewer"
] == "verifrax-systems"

# Frozen evidence identity and result.
assert evidence[
    "schema"
] == (
    "qvra-family-2-network-isolation-probe-evidence/v1"
)

assert evidence[
    "benchmark"
] == attestation[
    "benchmark"
]

assert evidence[
    "family"
] == attestation[
    "family"
]

assert evidence[
    "completion_state"
] == "COMPLETE_PASS"

assert evidence[
    "attestation_ready"
] is True

assert evidence[
    "bindings"
]["expected_main_commit"] == EXPECTED_MAIN

assert evidence[
    "bindings"
]["harness_sha256"] == EXPECTED_HARNESS_SHA

assert evidence[
    "bindings"
]["design_sha256"] == EXPECTED_HARNESS_DESIGN_SHA

assert evidence[
    "bindings"
]["protocol_sha256"] == EXPECTED_PROBE_PROTOCOL_SHA

assert evidence[
    "bindings"
]["network_design_sha256"] == EXPECTED_NETWORK_DESIGN_SHA

assert evidence[
    "bindings"
]["probe_python_sha256"] == EXPECTED_PROBE_PYTHON_SHA

assert evidence[
    "bindings"
]["sandbox_exec_sha256"] == EXPECTED_SANDBOX_EXEC_SHA

assert evidence[
    "bindings"
]["profile_sha256"] == EXPECTED_PROFILE_SHA

assert evidence[
    "probe_order"
] == EXPECTED_PROBE_ORDER

counts = evidence[
    "counts"
]

assert counts[
    "probe_record_count"
] == 7

assert counts[
    "network_probe_count"
] == 6

assert counts[
    "positive_control_count"
] == 6

assert counts[
    "sandbox_exec_invocation_count"
] == 7

assert counts[
    "retry_count"
] == 0

probes = evidence[
    "probes"
]

assert len(
    probes
) == 7

assert [
    item["probe_id"]
    for item in probes
] == EXPECTED_PROBE_ORDER

assert [
    item["sequence"]
    for item in probes
] == list(
    range(
        1,
        8,
    )
)

assert all(
    item["passed"] is True
    for item in probes
)

assert all(
    item["failure_code"] is None
    for item in probes
)

# Attestation must preserve exact probe evidence and safety state.
assert attestation[
    "probe_records"
] == probes

assert attestation[
    "safety_state"
] == evidence[
    "safety_state"
]

summary = attestation[
    "execution_summary"
]

assert summary[
    "completion_state"
] == evidence[
    "completion_state"
]

assert summary[
    "attestation_ready_from_probe_evidence"
] == evidence[
    "attestation_ready"
]

assert summary[
    "probe_record_count"
] == counts[
    "probe_record_count"
]

assert summary[
    "network_probe_count"
] == counts[
    "network_probe_count"
]

assert summary[
    "positive_control_count"
] == counts[
    "positive_control_count"
]

assert summary[
    "sandbox_exec_invocation_count"
] == counts[
    "sandbox_exec_invocation_count"
]

assert summary[
    "retry_count"
] == counts[
    "retry_count"
]

assert summary[
    "probe_start_timestamp"
] == evidence[
    "started_at_utc"
]

assert summary[
    "probe_end_timestamp"
] == evidence[
    "ended_at_utc"
]

# Exact host binding.
host = evidence[
    "host"
]

assert attestation[
    "host_identity"
] == host

design_host = network_design[
    "host_observation"
]

assert host[
    "system"
] == design_host[
    "platform"
]

assert host[
    "machine"
] == design_host[
    "architecture"
]

assert host[
    "macos_product_version"
] == design_host[
    "macos_product_version"
]

assert host[
    "macos_build_version"
] == design_host[
    "macos_build_version"
]

# Upstream profile/mechanism cross-check.
mechanism = network_design[
    "selected_mechanism"
]

assert mechanism[
    "sandbox_exec_path"
] == str(
    SANDBOX_EXEC
)

assert mechanism[
    "sandbox_exec_sha256"
] == EXPECTED_SANDBOX_EXEC_SHA

assert mechanism[
    "profile_sha256"
] == EXPECTED_PROFILE_SHA

assert mechanism[
    "profile_text"
] == EXPECTED_PROFILE_TEXT

assert mechanism[
    "unix_domain_socket_policy"
] == (
    "must-be-explicitly-tested-before-attestation"
)

assert probe_protocol[
    "bindings"
]["sandbox_exec_sha256"] == EXPECTED_SANDBOX_EXEC_SHA

assert probe_protocol[
    "bindings"
]["probe_python_sha256"] == EXPECTED_PROBE_PYTHON_SHA

assert probe_protocol[
    "bindings"
]["profile_sha256"] == EXPECTED_PROFILE_SHA

assert probe_protocol[
    "bindings"
]["profile_text"] == EXPECTED_PROFILE_TEXT

assert harness_design[
    "bindings"
]["probe_protocol_sha256"] == EXPECTED_PROBE_PROTOCOL_SHA

assert harness_design[
    "bindings"
]["network_isolation_design_sha256"] == EXPECTED_NETWORK_DESIGN_SHA

# Validate actual probe evidence, not merely aggregate booleans.
profile_probe = probes[0]

assert profile_probe[
    "probe_id"
] == "profile_acceptance"

assert profile_probe[
    "control"
] is None

assert_process_record(
    profile_probe[
        "sandbox"
    ]
)

assert profile_probe[
    "sandbox"
]["argv"] == [
    "/usr/bin/sandbox-exec",
    "-p",
    EXPECTED_PROFILE_TEXT,
    "/usr/bin/true",
]

assert profile_probe[
    "sandbox"
]["exit_code"] == 0

assert profile_probe[
    "sandbox"
]["timed_out"] is False

for probe in probes[1:]:
    control = probe[
        "control"
    ]

    sandbox = probe[
        "sandbox"
    ]

    observer = probe[
        "observer"
    ]

    assert control is not None

    assert_process_record(
        control
    )

    assert_process_record(
        sandbox
    )

    assert control[
        "argv"
    ][0] == str(
        PROBE_PYTHON
    )

    assert control[
        "exit_code"
    ] == 0

    assert control[
        "timed_out"
    ] is False

    assert sandbox[
        "argv"
    ][0] == str(
        SANDBOX_EXEC
    )

    assert sandbox[
        "argv"
    ][1] == "-p"

    assert sandbox[
        "argv"
    ][2] == EXPECTED_PROFILE_TEXT

    assert sandbox[
        "timed_out"
    ] is False

    control_worker = control[
        "worker_result"
    ]

    sandbox_worker = sandbox[
        "worker_result"
    ]

    assert_worker_result(
        control_worker
    )

    assert_worker_result(
        sandbox_worker
    )

    assert control_worker[
        "success"
    ] is True

    assert control_worker[
        "denied"
    ] is False

    assert sandbox_worker[
        "success"
    ] is False

    assert sandbox_worker[
        "denied"
    ] is True

    assert sandbox_worker[
        "errno_name"
    ] in ACCEPTED_ERRNO_NAMES

    assert sandbox_worker[
        "errno_value"
    ] in ACCEPTED_ERRNO_VALUES

    if "sandbox_activity_detected" in observer:
        assert observer[
            "sandbox_activity_detected"
        ] is False

# Unix bind specifically must leave no sandbox socket node.
unix_bind = probes[
    EXPECTED_PROBE_ORDER.index(
        "unix_stream_bind"
    )
]

assert unix_bind[
    "observer"
]["sandbox_path_created"] is False

# Safety state remains benchmark-clean.
safety = evidence[
    "safety_state"
]

assert safety[
    "external_network_used"
] is False

assert safety[
    "dns_resolution_used"
] is False

assert safety[
    "benchmark_adapter_used"
] is False

assert safety[
    "benchmark_raw_root_touched"
] is False

assert safety[
    "truth_accessed"
] is False

assert safety[
    "host_network_configuration_mutated"
] is False

assert safety[
    "root_privilege_used"
] is False

assert safety[
    "network_isolation_attestation_created"
] is False

assert safety[
    "execution_runner_created"
] is False

assert safety[
    "execution_transaction_issued"
] is False

assert safety[
    "raw_runs_produced"
] == 0

assert safety[
    "system_execution"
] is False

assert safety[
    "truth_scoring"
] is False

requirements = attestation[
    "attested_requirements"
]

assert all(
    value is True
    for value in requirements.values()
)

claim = attestation[
    "attestation_claim"
]

assert claim[
    "result"
] == "PASS"

assert claim[
    "network_isolation_attested_by_frozen_probe_evidence"
] is True

assert claim[
    "all_seven_required_probes_passed"
] is True

assert claim[
    "permission_denial_semantics_satisfied"
] is True

assert claim[
    "positive_controls_satisfied"
] is True

assert claim[
    "zero_retry_requirement_satisfied"
] is True

assert claim[
    "benchmark_execution_occurred"
] is False

assert claim[
    "truth_access_occurred"
] is False

assert claim[
    "external_network_access_occurred"
] is False

governance = attestation[
    "governance"
]

assert governance[
    "independent_exact_head_review_required"
] is True

assert governance[
    "mainline_merge_required"
] is True

assert governance[
    "execution_runner_forbidden_before_attestation_mainline"
] is True

assert governance[
    "benchmark_execution_forbidden_before_attestation_mainline"
] is True

assert governance[
    "attestation_candidate_created"
] is True

assert governance[
    "attestation_candidate_independently_reviewed"
] is False

assert governance[
    "attestation_candidate_mainline"
] is False

assert governance[
    "governed_execution_effect_active_before_mainline"
] is False

assert governance[
    "governed_execution_effect_activates_on_mainline_merge"
] is True

state = attestation[
    "creation_state"
]

assert state[
    "probe_execution_completed"
] is True

assert state[
    "probe_execution_retried"
] is False

assert state[
    "probe_evidence_created"
] is True

assert state[
    "network_isolation_attestation_created"
] is True

assert state[
    "network_isolation_attestation_reviewed"
] is False

assert state[
    "network_isolation_attestation_mainline"
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

print(
    "FAMILY_2_NETWORK_ISOLATION_ATTESTATION=PASS"
)
print(
    "STRICT_SCHEMA_VALIDATION=PASS"
)
print(
    "ATTESTATION_IDENTITY=PASS"
)
print(
    "FROZEN_PROBE_EVIDENCE_IDENTITY=PASS"
)
print(
    "GOVERNED_UPSTREAM_BINDINGS=PASS"
)
print(
    "EXACT_HOST_BINDING=PASS"
)
print(
    "EXACT_SANDBOX_BINARY_BINDING=PASS"
)
print(
    "EXACT_PROFILE_BINDING=PASS"
)
print(
    "COMPLETE_PASS_EVIDENCE=PASS"
)
print(
    "EXACT_SEVEN_PROBES=PASS"
)
print(
    "ALL_SEVEN_PROBES_PASSED=PASS"
)
print(
    "POSITIVE_CONTROLS=PASS"
)
print(
    "STRICT_PERMISSION_DENIAL_SEMANTICS=PASS"
)
print(
    "UNIX_DOMAIN_CONNECT_DENIED=PASS"
)
print(
    "UNIX_DOMAIN_BIND_DENIED=PASS"
)
print(
    "SANDBOX_EXEC_INVOCATION_COUNT=7"
)
print(
    "NETWORK_PROBE_COUNT=6"
)
print(
    "RETRY_COUNT=0"
)
print(
    "EVIDENCE_PRESERVED_EXACTLY=PASS"
)
print(
    "CROSS_HOST_GENERALIZATION=false"
)
print(
    "FUTURE_MACOS_GENERALIZATION=false"
)
print(
    "NETWORK_ISOLATION_ATTESTATION_CREATED=true"
)
print(
    "NETWORK_ISOLATION_ATTESTATION_REVIEWED=false"
)
print(
    "NETWORK_ISOLATION_ATTESTATION_MAINLINE=false"
)
print(
    "GOVERNED_EXECUTION_EFFECT_ACTIVE=false"
)
print(
    "EXECUTION_RUNNER_CREATED=false"
)
print(
    "EXECUTION_TRANSACTION_ISSUED=false"
)
print(
    "TRANSACTION_CURRENTLY_EXECUTABLE=false"
)
print(
    "RAW_RUNS_PRODUCED=0"
)
print(
    "SYSTEM_EXECUTION=false"
)
print(
    "TRUTH_SCORING=false"
)
