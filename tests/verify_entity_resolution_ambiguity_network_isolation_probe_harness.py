#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import json
import os
import re

from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

HARNESS = (
    ROOT
    / "tests"
    / "attest_entity_resolution_ambiguity_network_isolation.py"
)

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design-v1.json"
)

DESIGN_SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design.schema.json"
)

DESIGN_VERIFY = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_attestation_probe_harness_design.py"
)

PROTOCOL = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol-v1.json"
)

NETWORK_DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-design-v1.json"
)

ATTESTATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-v1.json"
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

LOCAL_EVIDENCE_ROOT = (
    ROOT
    / ".qvra-local-evidence"
    / "network-isolation"
)

PROBE_PYTHON = Path(
    "/opt/homebrew/opt/python@3.12/bin/python3.12"
)

SANDBOX_EXEC = Path(
    "/usr/bin/sandbox-exec"
)


EXPECTED_HARNESS_SHA = (
    "bf5ae02328cb665cae1956105b40bd83"
    "d4e49430a24441e735972c22366737e4"
)

EXPECTED_DESIGN_SHA = (
    "d2413019f7dd414fca6caad9e7fe074f"
    "a7b2325a50dd69bf09364d2fc3aa7ea4"
)

EXPECTED_DESIGN_SCHEMA_SHA = (
    "1d61ff9364c9cc418d2c451c2e89555b"
    "b7542ff8a8925c23354def3eed32fac2"
)

EXPECTED_DESIGN_VERIFY_SHA = (
    "bea2e6f668476b0b85bc2c9d48b9e7cb"
    "f8261e1fed18205749ac53e9639dc56b"
)

EXPECTED_PROTOCOL_SHA = (
    "35d997ea115bbc3e6622c5e0f5b9f520"
    "53fc30d0249200439f33bc372cf224fa"
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

EXPECTED_PROBE_ORDER = (
    "profile_acceptance",
    "tcp_loopback_connect",
    "udp_loopback_send",
    "tcp_inbound_bind_listen",
    "child_process_tcp_connect",
    "unix_stream_connect",
    "unix_stream_bind",
)

EXPECTED_PROBE_FUNCTIONS = (
    "run_profile_acceptance_probe",
    "run_tcp_loopback_connect_probe",
    "run_udp_loopback_send_probe",
    "run_tcp_inbound_bind_listen_probe",
    "run_child_process_tcp_connect_probe",
    "run_unix_stream_connect_probe",
    "run_unix_stream_bind_probe",
)

NETWORK_PROBE_FUNCTIONS = EXPECTED_PROBE_FUNCTIONS[1:]

EXPECTED_SOCKET_SITES = {
    "_worker_tcp_connect",
    "_worker_udp_send",
    "_worker_tcp_bind_listen",
    "_worker_unix_stream_connect",
    "_worker_unix_stream_bind",
    "_start_tcp_observer",
    "_start_udp_observer",
    "_start_unix_observer",
}


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


def call_name(
    call: ast.Call,
) -> str | None:
    function = call.func

    if isinstance(
        function,
        ast.Name,
    ):
        return function.id

    if isinstance(
        function,
        ast.Attribute,
    ):
        if (
            isinstance(
                function.value,
                ast.Name,
            )
            and function.value.id
            in {
                "subprocess",
                "os",
                "socket",
            }
        ):
            return (
                function.value.id
                + "."
                + function.attr
            )

        return function.attr

    return None


def function_calls(
    function: ast.FunctionDef,
) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(
            function
        )
        if isinstance(
            node,
            ast.Call,
        )
    ]


def count_call(
    function: ast.FunctionDef,
    name: str,
) -> int:
    return sum(
        1
        for call in function_calls(
            function
        )
        if call_name(call) == name
    )


def source_segment(
    source: str,
    node: ast.AST,
) -> str:
    segment = ast.get_source_segment(
        source,
        node,
    )

    assert segment is not None

    return segment


def returned_dict_keys(
    function: ast.FunctionDef,
) -> set[str]:
    for node in ast.walk(
        function
    ):
        if not isinstance(
            node,
            ast.Return,
        ):
            continue

        if not isinstance(
            node.value,
            ast.Dict,
        ):
            continue

        keys = []

        for key in node.value.keys:
            assert isinstance(
                key,
                ast.Constant,
            )
            assert isinstance(
                key.value,
                str,
            )
            keys.append(
                key.value
            )

        return set(
            keys
        )

    raise AssertionError(
        f"no returned dict in {function.name}"
    )


assert sha256_file(
    HARNESS
) == EXPECTED_HARNESS_SHA

assert sha256_file(
    DESIGN
) == EXPECTED_DESIGN_SHA

assert sha256_file(
    DESIGN_SCHEMA
) == EXPECTED_DESIGN_SCHEMA_SHA

assert sha256_file(
    DESIGN_VERIFY
) == EXPECTED_DESIGN_VERIFY_SHA

assert sha256_file(
    PROTOCOL
) == EXPECTED_PROTOCOL_SHA

assert sha256_file(
    NETWORK_DESIGN
) == EXPECTED_NETWORK_DESIGN_SHA

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

assert not ATTESTATION.exists()
assert not EXECUTION_RUNNER.exists()
assert not RAW_EXECUTION_RECEIPT.exists()
assert not LOCAL_EVIDENCE_ROOT.exists()

if RAW_ROOT.exists():
    assert RAW_ROOT.is_dir()
    assert not any(
        RAW_ROOT.iterdir()
    )

design = load_json(
    DESIGN
)

protocol = load_json(
    PROTOCOL
)

network_design = load_json(
    NETWORK_DESIGN
)

source = HARNESS.read_text(
    encoding="utf-8"
)

tree = ast.parse(
    source,
    filename=str(
        HARNESS
    ),
)

functions = {
    node.name: node
    for node in tree.body
    if isinstance(
        node,
        ast.FunctionDef,
    )
}

constants: dict[str, Any] = {}

for node in tree.body:
    if not isinstance(
        node,
        ast.Assign,
    ):
        continue

    if len(
        node.targets
    ) != 1:
        continue

    target = node.targets[0]

    if not isinstance(
        target,
        ast.Name,
    ):
        continue

    try:
        value = ast.literal_eval(
            node.value
        )
    except Exception:
        continue

    constants[
        target.id
    ] = value


expected_constants = {
    "DESIGN_SHA256":
        EXPECTED_DESIGN_SHA,

    "DESIGN_SCHEMA_SHA256":
        EXPECTED_DESIGN_SCHEMA_SHA,

    "DESIGN_VERIFY_SHA256":
        EXPECTED_DESIGN_VERIFY_SHA,

    "PROTOCOL_SHA256":
        EXPECTED_PROTOCOL_SHA,

    "NETWORK_DESIGN_SHA256":
        EXPECTED_NETWORK_DESIGN_SHA,

    "PROBE_PYTHON_SHA256":
        EXPECTED_PROBE_PYTHON_SHA,

    "SANDBOX_EXEC_SHA256":
        EXPECTED_SANDBOX_EXEC_SHA,

    "PROFILE_SHA256":
        EXPECTED_PROFILE_SHA,

    "PROFILE_TEXT":
        EXPECTED_PROFILE_TEXT,

    "LOOPBACK":
        "127.0.0.1",

    "PROBE_ORDER":
        EXPECTED_PROBE_ORDER,

    "PROBE_PYTHON":
        "/opt/homebrew/opt/python@3.12/bin/python3.12",

    "SANDBOX_EXEC":
        "/usr/bin/sandbox-exec",

    "TRUE_EXECUTABLE":
        "/usr/bin/true",

    "GIT":
        "/opt/homebrew/bin/git",
}

for name, expected in expected_constants.items():
    assert constants[
        name
    ] == expected, (
        name,
        constants.get(
            name
        ),
        expected,
    )

assert constants[
    "REQUIRED_ENVIRONMENT"
] == {
    "PYTHONDONTWRITEBYTECODE":
        "1",

    "PYTHONNOUSERSITE":
        "1",

    "LC_ALL":
        "C",

    "LANG":
        "C",
}

assert constants[
    "ACCEPTED_ERRNO_NAMES"
] == {
    "EPERM",
    "EACCES",
}

# Historical reviewed design bindings.
assert design[
    "bindings"
]["probe_protocol_sha256"] == EXPECTED_PROTOCOL_SHA

assert design[
    "bindings"
]["network_isolation_design_sha256"] == EXPECTED_NETWORK_DESIGN_SHA

assert design[
    "bindings"
]["probe_python_sha256"] == EXPECTED_PROBE_PYTHON_SHA

assert design[
    "bindings"
]["sandbox_exec_sha256"] == EXPECTED_SANDBOX_EXEC_SHA

assert design[
    "bindings"
]["profile_sha256"] == EXPECTED_PROFILE_SHA

assert design[
    "bindings"
]["profile_text"] == EXPECTED_PROFILE_TEXT

assert design[
    "implementation_target"
]["path"] == (
    "tests/attest_entity_resolution_ambiguity_network_isolation.py"
)

assert design[
    "implementation_target"
]["execution_flag"] == (
    "--execute-attestation-probes"
)

assert design[
    "implementation_target"
]["default_invocation_must_refuse"] is True

assert design[
    "implementation_target"
]["shell_execution_allowed"] is False

assert design[
    "implementation_target"
]["central_process_runner_required"] is True

assert design[
    "implementation_target"
]["sandbox_exec_invocations_must_use_central_runner"] is True

assert design[
    "future_harness_review_contract"
]["review_must_not_execute_harness"] is True

assert design[
    "future_harness_review_contract"
]["review_must_not_invoke_sandbox_exec"] is True

assert design[
    "future_harness_review_contract"
]["review_must_not_perform_network_probe"] is True

# Protocol cross-check.
assert protocol[
    "bindings"
]["probe_python_sha256"] == EXPECTED_PROBE_PYTHON_SHA

assert protocol[
    "bindings"
]["sandbox_exec_sha256"] == EXPECTED_SANDBOX_EXEC_SHA

assert protocol[
    "bindings"
]["profile_sha256"] == EXPECTED_PROFILE_SHA

assert protocol[
    "bindings"
]["profile_text"] == EXPECTED_PROFILE_TEXT

assert protocol[
    "execution_cardinality"
]["mandatory_probe_count"] == 7

assert protocol[
    "execution_cardinality"
]["expected_sandbox_exec_invocations"] == 7

assert protocol[
    "execution_cardinality"
]["retry_allowed"] is False

assert protocol[
    "execution_cardinality"
]["probe_reordering_allowed"] is False

assert protocol[
    "denial_semantics"
]["accepted_errno_names"] == [
    "EPERM",
    "EACCES",
]

assert protocol[
    "denial_semantics"
]["accepted_errno_values"] == [
    1,
    13,
]

# Network design remains an exact historical upstream binding.
assert network_design[
    "selected_mechanism"
]["sandbox_exec_path"] == (
    "/usr/bin/sandbox-exec"
)

# The harness itself is parsed only. It is never imported.
import_roots = set()

for node in tree.body:
    if isinstance(
        node,
        ast.Import,
    ):
        for alias in node.names:
            import_roots.add(
                alias.name.split(
                    "."
                )[0]
            )

    if isinstance(
        node,
        ast.ImportFrom,
    ):
        if node.module:
            import_roots.add(
                node.module.split(
                    "."
                )[0]
            )

assert "subprocess" in import_roots
assert "socket" in import_roots

for forbidden in (
    "requests",
    "urllib",
    "http",
    "aiohttp",
):
    assert forbidden not in import_roots

# Exactly one direct subprocess.run site, centralized.
subprocess_sites = []

for name, function in functions.items():
    count = count_call(
        function,
        "subprocess.run",
    )

    subprocess_sites.extend(
        [name]
        * count
    )

assert subprocess_sites == [
    "run_process"
], subprocess_sites

run_process = functions[
    "run_process"
]

run_calls = [
    call
    for call in function_calls(
        run_process
    )
    if call_name(
        call
    ) == "subprocess.run"
]

assert len(
    run_calls
) == 1

run_call = run_calls[0]

keywords = {
    item.arg: item.value
    for item in run_call.keywords
    if item.arg
}

for key, expected in (
    (
        "shell",
        False,
    ),
    (
        "check",
        False,
    ),
    (
        "capture_output",
        True,
    ),
):
    assert isinstance(
        keywords[key],
        ast.Constant,
    )
    assert (
        keywords[key].value
        is expected
    )

assert isinstance(
    keywords[
        "env"
    ],
    ast.Call,
)

assert call_name(
    keywords[
        "env"
    ]
) == "minimal_environment"

for call in ast.walk(
    tree
):
    if not isinstance(
        call,
        ast.Call,
    ):
        continue

    name = call_name(
        call
    )

    assert name not in {
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "os.execl",
        "os.execv",
        "os.spawnv",
    }

# Minimal environment must not inherit the operator environment.
minimal_env_source = source_segment(
    source,
    functions[
        "minimal_environment"
    ],
)

assert "os.environ" not in minimal_env_source
assert "os.getenv" not in minimal_env_source

# Exact socket-construction sites.
socket_sites = set()
socket_site_count = 0

for name, function in functions.items():
    count = count_call(
        function,
        "socket.socket",
    )

    if count:
        socket_sites.add(
            name
        )
        socket_site_count += count

assert socket_sites == EXPECTED_SOCKET_SITES, (
    socket_sites,
    EXPECTED_SOCKET_SITES,
)

assert socket_site_count == 8

# Network operations may occur only in the reviewed worker/observer sites.
allowed_operation_sites = EXPECTED_SOCKET_SITES

for name, function in functions.items():
    for call in function_calls(
        function
    ):
        operation = call_name(
            call
        )

        if operation in {
            "connect",
            "sendto",
            "bind",
            "listen",
            "accept",
            "recvfrom",
        }:
            assert name in allowed_operation_sites, (
                name,
                operation,
            )

# No DNS API, URL, hostname endpoint, external IP, truth input,
# or host-network mutation command is present.
for forbidden in (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "socket.create_connection",
    "http://",
    "https://",
    "localhost",
    "truth.json",
    "pfctl",
    "networksetup",
    "ifconfig",
    "route add",
    "route delete",
    "qvra_er_v1",
    "splink_v4",
    "dedupe_v3",
):
    assert forbidden not in source, forbidden

ipv4_literals = set(
    re.findall(
        r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])",
        source,
    )
)

assert ipv4_literals <= {
    "127.0.0.1",
}, ipv4_literals

# Operator gate is explicit.
for literal in (
    "--execute-attestation-probes",
    "--expect-main-commit",
    "--expect-harness-sha256",
    "--evidence-output",
    "--worker",
    "--nested-child",
):
    assert literal in source

operator_source = source_segment(
    source,
    functions[
        "operator_dispatch"
    ],
)

assert (
    "if not args.execute_attestation_probes"
    in operator_source
)

# Worker-only modes require exact harness-bound internal authorization.
for name in (
    "worker_dispatch",
    "nested_child_dispatch",
):
    function = functions[
        name
    ]

    first = function.body[0]

    assert isinstance(
        first,
        ast.Expr,
    )

    assert isinstance(
        first.value,
        ast.Call,
    )

    assert call_name(
        first.value
    ) == (
        "require_internal_authorization"
    )

assert count_call(
    functions[
        "_worker_child_process_tcp_connect"
    ],
    "require_internal_authorization",
) == 1

# Preflight must be the first transaction operation.
transaction = functions[
    "run_governed_probe_transaction"
]

first = transaction.body[0]

assert isinstance(
    first,
    ast.Assign,
)

assert isinstance(
    first.value,
    ast.Call,
)

assert call_name(
    first.value
) == "preflight"

preflight_calls = {
    call_name(
        call
    )
    for call in function_calls(
        functions[
            "preflight"
        ]
    )
}

assert "sandbox_worker" not in preflight_calls
assert "sandbox_argv" not in preflight_calls
assert "socket.socket" not in preflight_calls

preflight_source = source_segment(
    source,
    functions[
        "preflight"
    ],
)

for required in (
    "expected_main_commit",
    "expected_harness_sha256",
    "resolve_evidence_output",
    "verify_source_clean",
    "verify_raw_root_empty",
    "ATTESTATION_PATH.exists",
    "EXECUTION_RUNNER_PATH.exists",
    "RAW_EXECUTION_RECEIPT_PATH.exists",
    "refs/remotes/origin/main",
):
    assert required in preflight_source, required

# Exact sandbox construction.
sandbox_argv_source = source_segment(
    source,
    functions[
        "sandbox_argv"
    ],
)

for required in (
    "SANDBOX_EXEC",
    '"-p"',
    "PROFILE_TEXT",
):
    assert required in sandbox_argv_source

assert count_call(
    functions[
        "sandbox_worker"
    ],
    "run_process",
) == 1

assert count_call(
    functions[
        "sandbox_worker"
    ],
    "sandbox_argv",
) == 1

# Exact seven-probe transaction order.
probe_functions_assignment = None

for node in transaction.body:
    if not isinstance(
        node,
        ast.Assign,
    ):
        continue

    if len(
        node.targets
    ) != 1:
        continue

    target = node.targets[0]

    if (
        isinstance(
            target,
            ast.Name,
        )
        and target.id
        == "probe_functions"
    ):
        probe_functions_assignment = node
        break

assert probe_functions_assignment is not None

probe_tuple = probe_functions_assignment.value

assert isinstance(
    probe_tuple,
    ast.Tuple,
)

assert len(
    probe_tuple.elts
) == 7

actual_probe_functions = []

for item in probe_tuple.elts:
    assert isinstance(
        item,
        ast.Lambda,
    )

    assert isinstance(
        item.body,
        ast.Call,
    )

    name = call_name(
        item.body
    )

    assert name is not None

    actual_probe_functions.append(
        name
    )

assert tuple(
    actual_probe_functions
) == EXPECTED_PROBE_FUNCTIONS

# Profile acceptance: one sandbox path, no positive control.
profile_function = functions[
    "run_profile_acceptance_probe"
]

assert count_call(
    profile_function,
    "sandbox_argv",
) == 1

assert count_call(
    profile_function,
    "run_process",
) == 1

assert count_call(
    profile_function,
    "control_worker",
) == 0

assert count_call(
    profile_function,
    "sandbox_worker",
) == 0

# Six network probes: one control and one sandbox invocation each.
for name in NETWORK_PROBE_FUNCTIONS:
    function = functions[
        name
    ]

    assert count_call(
        function,
        "control_worker",
    ) == 1, name

    assert count_call(
        function,
        "sandbox_worker",
    ) == 1, name

# Therefore reviewed future cardinality is exactly 7 / 6 / 6 / 7.
assert len(
    EXPECTED_PROBE_FUNCTIONS
) == 7

assert len(
    NETWORK_PROBE_FUNCTIONS
) == 6

# No probe retry helper exists.
assert not any(
    "retry" in name.lower()
    for name in functions
)

# Strict permission-denial semantics.
sandbox_failure_source = source_segment(
    source,
    functions[
        "sandbox_failure_code"
    ],
)

for required in (
    "FAIL_NOT_PROOF_OF_ISOLATION",
    "FAIL_ISOLATION_MECHANISM",
    "FAIL_ISOLATION_MECHANISM_REDESIGN_REQUIRED",
    "ACCEPTED_ERRNO_NAMES",
    "ACCEPTED_ERRNO_VALUES",
    "observer_activity",
    "forbidden_path_created",
):
    assert required in sandbox_failure_source

assert (
    "if result.timed_out"
    in sandbox_failure_source
)

# Explicit Unix-domain probes are implemented separately.
for name in (
    "_worker_unix_stream_connect",
    "_worker_unix_stream_bind",
    "run_unix_stream_connect_probe",
    "run_unix_stream_bind_probe",
):
    assert name in functions

assert "socket.AF_UNIX" in source

# Required worker result fields.
worker_fields = {
    "operation",
    "success",
    "denied",
    "denial_stage",
    "errno_name",
    "errno_value",
    "exception_type",
    "detail",
}

assert returned_dict_keys(
    functions[
        "worker_success"
    ]
) == worker_fields

assert returned_dict_keys(
    functions[
        "worker_failure"
    ]
) == worker_fields

probe_fields = {
    "probe_id",
    "sequence",
    "started_at_utc",
    "ended_at_utc",
    "control",
    "sandbox",
    "observer",
    "passed",
    "failure_code",
}

assert returned_dict_keys(
    functions[
        "probe_record"
    ]
) == probe_fields

# Evidence process records include exact argv, exit, stdout/stderr
# text and SHA-256.
for required in (
    '"argv"',
    '"exit_code"',
    '"stdout_text"',
    '"stdout_sha256"',
    '"stderr_text"',
    '"stderr_sha256"',
    '"timed_out"',
    '"started_at_utc"',
    '"ended_at_utc"',
    '"host"',
    '"macos_build_version"',
    '"probe_python_sha256"',
    '"sandbox_exec_sha256"',
    '"profile_sha256"',
):
    assert required in source, required

# Evidence writes are only to the resolved operator output.
atomic_calls = [
    call
    for call in ast.walk(
        transaction
    )
    if isinstance(
        call,
        ast.Call,
    )
    and call_name(
        call
    ) == "atomic_write_json"
]

assert len(
    atomic_calls
) >= 3

for call in atomic_calls:
    assert call.args
    assert isinstance(
        call.args[0],
        ast.Name,
    )
    assert (
        call.args[0].id
        == "output"
    )

atomic_source = source_segment(
    source,
    functions[
        "atomic_write_json"
    ],
)

for required in (
    "os.O_EXCL",
    "os.fsync",
    "os.replace",
):
    assert required in atomic_source

# The implementation must not create attestation, runner, raw receipt,
# benchmark raw artifacts, or perform truth scoring.
for forbidden in (
    "ATTESTATION_PATH.write",
    "EXECUTION_RUNNER_PATH.write",
    "RAW_EXECUTION_RECEIPT_PATH.write",
    "RAW_ROOT.mkdir",
):
    assert forbidden not in source

assert (
    'network_isolation_attestation_created": False'
    in source
)

assert (
    'execution_runner_created": False'
    in source
)

assert (
    '"raw_runs_produced": 0'
    in source
)

assert (
    '"system_execution": False'
    in source
)

assert (
    '"truth_scoring": False'
    in source
)

assert (
    'if __name__ == "__main__":'
    in source
)

print(
    "FAMILY_2_NETWORK_ISOLATION_PROBE_HARNESS_IMPLEMENTATION=PASS"
)
print(
    "HARNESS_IDENTITY=PASS"
)
print(
    "GOVERNED_DESIGN_BINDING=PASS"
)
print(
    "PROTOCOL_BINDING=PASS"
)
print(
    "HARNESS_AST_ONLY_REVIEW=PASS"
)
print(
    "HARNESS_IMPORTED=false"
)
print(
    "HARNESS_EXECUTED=false"
)
print(
    "CENTRAL_PROCESS_RUNNER=PASS"
)
print(
    "PROCESS_LAUNCH_SITE_COUNT=1"
)
print(
    "SHELL_EXECUTION=false"
)
print(
    "MINIMAL_PROCESS_ENVIRONMENT=PASS"
)
print(
    "SOCKET_SITE_POLICY=PASS"
)
print(
    "SOCKET_CONSTRUCTION_SITE_COUNT=8"
)
print(
    "DNS_API_USAGE=false"
)
print(
    "EXTERNAL_ENDPOINT_LITERAL=false"
)
print(
    "NON_LOOPBACK_IP_LITERAL=false"
)
print(
    "OPERATOR_GATE=PASS"
)
print(
    "INTERNAL_WORKER_GATE=PASS"
)
print(
    "PREFLIGHT_BEFORE_SANDBOX=PASS"
)
print(
    "EXACT_SEVEN_PROBE_IMPLEMENTATION=PASS"
)
print(
    "IMPLEMENTED_PROBE_RECORD_COUNT=7"
)
print(
    "IMPLEMENTED_NETWORK_PROBE_COUNT=6"
)
print(
    "IMPLEMENTED_POSITIVE_CONTROL_COUNT=6"
)
print(
    "FUTURE_SANDBOX_EXEC_INVOCATION_COUNT=7"
)
print(
    "NO_RETRY_POLICY=PASS"
)
print(
    "STRICT_DENIAL_SEMANTICS=PASS"
)
print(
    "UNIX_DOMAIN_POLICY_EXPLICIT=PASS"
)
print(
    "EVIDENCE_CONTRACT=PASS"
)
print(
    "ATOMIC_EVIDENCE_WRITE=PASS"
)
print(
    "TRUTH_ACCESS=false"
)
print(
    "BENCHMARK_ADAPTER_ACCESS=false"
)
print(
    "RAW_ROOT_WRITE=false"
)
print(
    "NETWORK_ISOLATION_ATTESTATION_CREATED=false"
)
print(
    "EXECUTION_RUNNER_CREATED=false"
)
print(
    "PROFILE_SYNTAX_VALIDATED=false"
)
print(
    "SANDBOX_EXEC_INVOKED=false"
)
print(
    "SANDBOX_EXEC_INVOCATION_COUNT=0"
)
print(
    "NETWORK_PROBE_PERFORMED=false"
)
print(
    "NETWORK_PROBE_COUNT=0"
)
print(
    "PROBE_EVIDENCE_CREATED=false"
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
