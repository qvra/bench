#!/usr/bin/env python3

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
HARNESS_PATH = Path(__file__).resolve()

DESIGN_PATH = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design-v1.json"
)

DESIGN_SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-harness-design.schema.json"
)

DESIGN_VERIFY_PATH = (
    ROOT
    / "tests"
    / "verify_entity_resolution_ambiguity_network_isolation_attestation_probe_harness_design.py"
)

PROTOCOL_PATH = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-probe-protocol-v1.json"
)

NETWORK_DESIGN_PATH = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-design-v1.json"
)

ATTESTATION_PATH = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-network-isolation-attestation-v1.json"
)

EXECUTION_RUNNER_PATH = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_runner.py"
)

RAW_EXECUTION_RECEIPT_PATH = (
    ROOT
    / "evidence"
    / "entity-resolution-ambiguity-v1"
    / "raw-execution-receipt-v1.json"
)

RAW_ROOT = ROOT / "family-2-raw-runs"

LOCAL_EVIDENCE_ROOT = (
    ROOT
    / ".qvra-local-evidence"
    / "network-isolation"
)

GIT = "/opt/homebrew/bin/git"
PROBE_PYTHON = "/opt/homebrew/opt/python@3.12/bin/python3.12"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
TRUE_EXECUTABLE = "/usr/bin/true"
SW_VERS = "/usr/bin/sw_vers"

DESIGN_SHA256 = (
    "d2413019f7dd414fca6caad9e7fe074f"
    "a7b2325a50dd69bf09364d2fc3aa7ea4"
)

DESIGN_SCHEMA_SHA256 = (
    "1d61ff9364c9cc418d2c451c2e89555b"
    "b7542ff8a8925c23354def3eed32fac2"
)

DESIGN_VERIFY_SHA256 = (
    "bea2e6f668476b0b85bc2c9d48b9e7cb"
    "f8261e1fed18205749ac53e9639dc56b"
)

PROTOCOL_SHA256 = (
    "35d997ea115bbc3e6622c5e0f5b9f520"
    "53fc30d0249200439f33bc372cf224fa"
)

NETWORK_DESIGN_SHA256 = (
    "67949db7523dafebb0e6b6c9b876580c"
    "7457196c4f41adef8d97c498d54393d0"
)

PROBE_PYTHON_SHA256 = (
    "fe46716a94d8efa4514feb3c39ba3e27"
    "0deee2187556986f6ddcff54aba7bb9a"
)

SANDBOX_EXEC_SHA256 = (
    "8290e4be7387a0df83cd1559e86afd88"
    "0464f269450573d012795761fe298f16"
)

PROFILE_SHA256 = (
    "5c358b8d847211333e7ba22df82d84f7"
    "96b5f30a41a2682209a949d783adbd08"
)

PROFILE_TEXT = (
    "(version 1)\n"
    "(allow default)\n"
    "(deny network*)\n"
)

LOOPBACK = "127.0.0.1"

UDP_PAYLOAD = "QVRA-NETWORK-ISOLATION-PROBE-V1"

INTERNAL_MODE_ENV = "QVRA_NETWORK_PROBE_INTERNAL"
INTERNAL_HASH_ENV = "QVRA_NETWORK_PROBE_HARNESS_SHA256"

ACCEPTED_ERRNO_NAMES = {"EPERM", "EACCES"}
ACCEPTED_ERRNO_VALUES = {errno.EPERM, errno.EACCES}

REQUIRED_ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "LC_ALL": "C",
    "LANG": "C",
}

PROBE_ORDER = (
    "profile_acceptance",
    "tcp_loopback_connect",
    "udp_loopback_send",
    "tcp_inbound_bind_listen",
    "child_process_tcp_connect",
    "unix_stream_connect",
    "unix_stream_bind",
)

SANDBOX_EXEC_INVOCATION_COUNT = 0


class HarnessRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool

    def evidence(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_text": self.stdout.decode(
                "utf-8",
                errors="replace",
            ),
            "stdout_sha256": hashlib.sha256(
                self.stdout
            ).hexdigest(),
            "stderr_text": self.stderr.decode(
                "utf-8",
                errors="replace",
            ),
            "stderr_sha256": hashlib.sha256(
                self.stderr
            ).hexdigest(),
        }


@dataclass
class Observer:
    sock: socket.socket
    thread: threading.Thread
    stop_event: threading.Event
    events: list[Any]
    lock: threading.Lock

    def count(self) -> int:
        with self.lock:
            return len(self.events)

    def snapshot(self) -> list[Any]:
        with self.lock:
            return list(self.events)

    def stop(self) -> None:
        self.stop_event.set()

        try:
            self.sock.close()
        except OSError:
            pass

        self.thread.join(timeout=2.0)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat().replace(
        "+00:00",
        "Z",
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(
        path.read_bytes()
    )


def minimal_environment(
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    env = dict(REQUIRED_ENVIRONMENT)

    if extra:
        env.update(extra)

    return env


def run_process(
    argv: Sequence[str],
    *,
    timeout: float = 10.0,
    extra_env: dict[str, str] | None = None,
) -> ProcessResult:
    global SANDBOX_EXEC_INVOCATION_COUNT

    command = tuple(
        str(item)
        for item in argv
    )

    if not command:
        raise HarnessRefused(
            "empty process argv"
        )

    executable = Path(command[0])

    if not executable.is_absolute():
        raise HarnessRefused(
            "process executable must be absolute"
        )

    if command[0] == SANDBOX_EXEC:
        SANDBOX_EXEC_INVOCATION_COUNT += 1

    try:
        completed = subprocess.run(
            list(command),
            shell=False,
            check=False,
            capture_output=True,
            timeout=timeout,
            env=minimal_environment(
                extra_env
            ),
        )

        return ProcessResult(
            argv=command,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
        )

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""

        if isinstance(stdout, str):
            stdout = stdout.encode(
                "utf-8",
                errors="replace",
            )

        if isinstance(stderr, str):
            stderr = stderr.encode(
                "utf-8",
                errors="replace",
            )

        return ProcessResult(
            argv=command,
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )


def internal_environment(
    harness_sha256: str,
) -> dict[str, str]:
    return {
        INTERNAL_MODE_ENV: "1",
        INTERNAL_HASH_ENV: harness_sha256,
    }


def require_internal_authorization() -> str:
    expected = os.environ.get(
        INTERNAL_HASH_ENV,
        "",
    )

    if os.environ.get(
        INTERNAL_MODE_ENV
    ) != "1":
        raise HarnessRefused(
            "worker mode requires internal authorization"
        )

    if len(expected) != 64:
        raise HarnessRefused(
            "worker mode missing harness binding"
        )

    if sha256_file(
        HARNESS_PATH
    ) != expected:
        raise HarnessRefused(
            "worker harness identity mismatch"
        )

    return expected


def errno_name(
    value: int | None,
) -> str | None:
    if value is None:
        return None

    return errno.errorcode.get(
        value,
        f"ERRNO_{value}",
    )


def worker_success(
    operation: str,
    detail: Any = None,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "success": True,
        "denied": False,
        "denial_stage": None,
        "errno_name": None,
        "errno_value": None,
        "exception_type": None,
        "detail": detail,
    }


def worker_failure(
    operation: str,
    stage: str,
    exc: BaseException,
) -> dict[str, Any]:
    value = getattr(
        exc,
        "errno",
        None,
    )

    name = errno_name(value)

    denied = (
        value in ACCEPTED_ERRNO_VALUES
        and name in ACCEPTED_ERRNO_NAMES
    )

    return {
        "operation": operation,
        "success": False,
        "denied": denied,
        "denial_stage": stage,
        "errno_name": name,
        "errno_value": value,
        "exception_type": type(exc).__name__,
        "detail": str(exc),
    }


def require_loopback(
    host: str,
) -> None:
    if host != LOOPBACK:
        raise HarnessRefused(
            "only exact IPv4 loopback is allowed"
        )


def require_port(
    text: str,
) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise HarnessRefused(
            "invalid port"
        ) from exc

    if not 1 <= port <= 65535:
        raise HarnessRefused(
            "invalid port"
        )

    return port


def require_temp_unix_path(
    value: str,
) -> Path:
    candidate = Path(
        value
    ).resolve()

    repository = ROOT.resolve()
    private_tmp = Path(
        "/private/tmp"
    ).resolve()
    public_tmp = Path(
        "/tmp"
    ).resolve()

    try:
        candidate.relative_to(
            repository
        )
    except ValueError:
        pass
    else:
        raise HarnessRefused(
            "Unix socket path must be outside repository"
        )

    allowed = False

    for root in (
        private_tmp,
        public_tmp,
    ):
        try:
            candidate.relative_to(
                root
            )
            allowed = True
            break
        except ValueError:
            continue

    if not allowed:
        raise HarnessRefused(
            "Unix socket path must be under system temporary root"
        )

    return candidate


def _worker_tcp_connect(
    host: str,
    port_text: str,
) -> dict[str, Any]:
    operation = "tcp-connect"
    require_loopback(host)
    port = require_port(port_text)

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
    except OSError as exc:
        return worker_failure(
            operation,
            "socket",
            exc,
        )

    try:
        sock.settimeout(2.0)

        try:
            sock.connect(
                (
                    host,
                    port,
                )
            )
        except OSError as exc:
            return worker_failure(
                operation,
                "connect",
                exc,
            )

        return worker_success(
            operation,
            {
                "host": host,
                "port": port,
            },
        )

    finally:
        sock.close()


def _worker_udp_send(
    host: str,
    port_text: str,
    payload: str,
) -> dict[str, Any]:
    operation = "udp-send"
    require_loopback(host)
    port = require_port(port_text)

    if payload != UDP_PAYLOAD:
        raise HarnessRefused(
            "unexpected UDP payload"
        )

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )
    except OSError as exc:
        return worker_failure(
            operation,
            "socket",
            exc,
        )

    try:
        try:
            sent = sock.sendto(
                payload.encode(
                    "ascii"
                ),
                (
                    host,
                    port,
                ),
            )
        except OSError as exc:
            return worker_failure(
                operation,
                "sendto",
                exc,
            )

        return worker_success(
            operation,
            {
                "host": host,
                "port": port,
                "bytes_sent": sent,
            },
        )

    finally:
        sock.close()


def _worker_tcp_bind_listen() -> dict[str, Any]:
    operation = "tcp-bind-listen"

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
    except OSError as exc:
        return worker_failure(
            operation,
            "socket",
            exc,
        )

    try:
        try:
            sock.bind(
                (
                    LOOPBACK,
                    0,
                )
            )
        except OSError as exc:
            return worker_failure(
                operation,
                "bind",
                exc,
            )

        try:
            sock.listen(1)
        except OSError as exc:
            return worker_failure(
                operation,
                "listen",
                exc,
            )

        address = sock.getsockname()

        return worker_success(
            operation,
            {
                "host": address[0],
                "port": address[1],
            },
        )

    finally:
        sock.close()


def _worker_child_process_tcp_connect(
    host: str,
    port_text: str,
) -> dict[str, Any]:
    operation = "child-process-tcp-connect"
    require_loopback(host)
    port = require_port(port_text)

    harness_sha = require_internal_authorization()

    argv = [
        PROBE_PYTHON,
        str(HARNESS_PATH),
        "--nested-child",
        "tcp-connect",
        host,
        str(port),
    ]

    try:
        result = run_process(
            argv,
            timeout=5.0,
            extra_env=internal_environment(
                harness_sha
            ),
        )
    except OSError as exc:
        return worker_failure(
            operation,
            "spawn",
            exc,
        )

    parsed = parse_worker_json(
        result
    )

    if parsed is None:
        return {
            "operation": operation,
            "success": False,
            "denied": False,
            "denial_stage": "nested-child-result",
            "errno_name": None,
            "errno_value": None,
            "exception_type": (
                "TimeoutExpired"
                if result.timed_out
                else "InvalidNestedChildResult"
            ),
            "detail": result.evidence(),
        }

    return {
        "operation": operation,
        "success": parsed["success"],
        "denied": parsed["denied"],
        "denial_stage": parsed["denial_stage"],
        "errno_name": parsed["errno_name"],
        "errno_value": parsed["errno_value"],
        "exception_type": parsed["exception_type"],
        "detail": {
            "nested_result": parsed,
            "nested_process": result.evidence(),
        },
    }


def _worker_unix_stream_connect(
    path_text: str,
) -> dict[str, Any]:
    operation = "unix-stream-connect"
    path = require_temp_unix_path(
        path_text
    )

    try:
        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
    except OSError as exc:
        return worker_failure(
            operation,
            "socket",
            exc,
        )

    try:
        sock.settimeout(2.0)

        try:
            sock.connect(
                str(path)
            )
        except OSError as exc:
            return worker_failure(
                operation,
                "connect",
                exc,
            )

        return worker_success(
            operation,
            {
                "path": str(path),
            },
        )

    finally:
        sock.close()


def _worker_unix_stream_bind(
    path_text: str,
) -> dict[str, Any]:
    operation = "unix-stream-bind"
    path = require_temp_unix_path(
        path_text
    )

    if path.exists():
        raise HarnessRefused(
            "Unix bind target already exists"
        )

    try:
        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
    except OSError as exc:
        return worker_failure(
            operation,
            "socket",
            exc,
        )

    try:
        try:
            sock.bind(
                str(path)
            )
        except OSError as exc:
            return worker_failure(
                operation,
                "bind",
                exc,
            )

        return worker_success(
            operation,
            {
                "path": str(path),
            },
        )

    finally:
        sock.close()


def emit_worker_result(
    result: dict[str, Any],
) -> int:
    sys.stdout.write(
        json.dumps(
            result,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
        )
        + "\n"
    )

    return 0


def worker_dispatch(
    argv: list[str],
) -> int:
    require_internal_authorization()

    if not argv:
        raise HarnessRefused(
            "worker mode missing operation"
        )

    mode = argv[0]
    args = argv[1:]

    if mode == "tcp-connect":
        if len(args) != 2:
            raise HarnessRefused(
                "tcp-connect requires host and port"
            )

        return emit_worker_result(
            _worker_tcp_connect(
                args[0],
                args[1],
            )
        )

    if mode == "udp-send":
        if len(args) != 3:
            raise HarnessRefused(
                "udp-send requires host, port, payload"
            )

        return emit_worker_result(
            _worker_udp_send(
                args[0],
                args[1],
                args[2],
            )
        )

    if mode == "tcp-bind-listen":
        if args:
            raise HarnessRefused(
                "tcp-bind-listen accepts no arguments"
            )

        return emit_worker_result(
            _worker_tcp_bind_listen()
        )

    if mode == "child-process-tcp-connect":
        if len(args) != 2:
            raise HarnessRefused(
                "child-process-tcp-connect requires host and port"
            )

        return emit_worker_result(
            _worker_child_process_tcp_connect(
                args[0],
                args[1],
            )
        )

    if mode == "unix-stream-connect":
        if len(args) != 1:
            raise HarnessRefused(
                "unix-stream-connect requires path"
            )

        return emit_worker_result(
            _worker_unix_stream_connect(
                args[0]
            )
        )

    if mode == "unix-stream-bind":
        if len(args) != 1:
            raise HarnessRefused(
                "unix-stream-bind requires path"
            )

        return emit_worker_result(
            _worker_unix_stream_bind(
                args[0]
            )
        )

    raise HarnessRefused(
        "unknown worker operation"
    )


def nested_child_dispatch(
    argv: list[str],
) -> int:
    require_internal_authorization()

    if len(argv) != 3:
        raise HarnessRefused(
            "nested child requires tcp-connect host port"
        )

    if argv[0] != "tcp-connect":
        raise HarnessRefused(
            "nested child only supports tcp-connect"
        )

    return emit_worker_result(
        _worker_tcp_connect(
            argv[1],
            argv[2],
        )
    )


def parse_worker_json(
    result: ProcessResult,
) -> dict[str, Any] | None:
    if result.timed_out:
        return None

    if result.exit_code != 0:
        return None

    try:
        parsed = json.loads(
            result.stdout.decode(
                "utf-8"
            ).strip()
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(
        parsed,
        dict,
    ):
        return None

    required = {
        "operation",
        "success",
        "denied",
        "denial_stage",
        "errno_name",
        "errno_value",
        "exception_type",
        "detail",
    }

    if set(parsed) != required:
        return None

    return parsed


def worker_process_evidence(
    result: ProcessResult,
) -> dict[str, Any]:
    record = result.evidence()
    record["worker_result"] = parse_worker_json(
        result
    )
    return record


def wait_for_count(
    observer: Observer,
    minimum_count: int,
    timeout: float,
) -> bool:
    deadline = (
        time.monotonic()
        + timeout
    )

    while time.monotonic() < deadline:
        if observer.count() >= minimum_count:
            return True

        time.sleep(0.01)

    return (
        observer.count()
        >= minimum_count
    )


def _start_tcp_observer() -> tuple[Observer, int]:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    sock.bind(
        (
            LOOPBACK,
            0,
        )
    )

    sock.listen(8)
    sock.settimeout(0.1)

    port = sock.getsockname()[1]

    stop_event = threading.Event()
    events: list[Any] = []
    lock = threading.Lock()

    def target() -> None:
        while not stop_event.is_set():
            try:
                conn, address = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                with lock:
                    events.append(
                        {
                            "host": address[0],
                            "port": address[1],
                        }
                    )
            finally:
                conn.close()

    thread = threading.Thread(
        target=target,
        daemon=True,
        name="qvra-tcp-observer",
    )

    thread.start()

    return (
        Observer(
            sock=sock,
            thread=thread,
            stop_event=stop_event,
            events=events,
            lock=lock,
        ),
        port,
    )


def _start_udp_observer() -> tuple[Observer, int]:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    sock.bind(
        (
            LOOPBACK,
            0,
        )
    )

    sock.settimeout(0.1)

    port = sock.getsockname()[1]

    stop_event = threading.Event()
    events: list[Any] = []
    lock = threading.Lock()

    def target() -> None:
        while not stop_event.is_set():
            try:
                payload, address = sock.recvfrom(
                    4096
                )
            except socket.timeout:
                continue
            except OSError:
                break

            with lock:
                events.append(
                    {
                        "payload": payload,
                        "host": address[0],
                        "port": address[1],
                    }
                )

    thread = threading.Thread(
        target=target,
        daemon=True,
        name="qvra-udp-observer",
    )

    thread.start()

    return (
        Observer(
            sock=sock,
            thread=thread,
            stop_event=stop_event,
            events=events,
            lock=lock,
        ),
        port,
    )


def udp_payload_count(
    observer: Observer,
    payload: bytes,
) -> int:
    return sum(
        1
        for event in observer.snapshot()
        if event["payload"] == payload
    )


def wait_for_udp_payload_count(
    observer: Observer,
    payload: bytes,
    minimum_count: int,
    timeout: float,
) -> bool:
    deadline = (
        time.monotonic()
        + timeout
    )

    while time.monotonic() < deadline:
        if (
            udp_payload_count(
                observer,
                payload,
            )
            >= minimum_count
        ):
            return True

        time.sleep(0.01)

    return (
        udp_payload_count(
            observer,
            payload,
        )
        >= minimum_count
    )


def _start_unix_observer(
    path: Path,
) -> Observer:
    if path.exists():
        raise HarnessRefused(
            "Unix observer path already exists"
        )

    sock = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    sock.bind(
        str(path)
    )

    sock.listen(8)
    sock.settimeout(0.1)

    stop_event = threading.Event()
    events: list[Any] = []
    lock = threading.Lock()

    def target() -> None:
        while not stop_event.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                with lock:
                    events.append(
                        {
                            "accepted": True,
                        }
                    )
            finally:
                conn.close()

    thread = threading.Thread(
        target=target,
        daemon=True,
        name="qvra-unix-observer",
    )

    thread.start()

    return Observer(
        sock=sock,
        thread=thread,
        stop_event=stop_event,
        events=events,
        lock=lock,
    )


def sandbox_argv(
    target_argv: Sequence[str],
) -> list[str]:
    return [
        SANDBOX_EXEC,
        "-p",
        PROFILE_TEXT,
        *[
            str(item)
            for item in target_argv
        ],
    ]


def control_worker(
    harness_sha256: str,
    mode: str,
    *args: str,
) -> ProcessResult:
    return run_process(
        [
            PROBE_PYTHON,
            str(HARNESS_PATH),
            "--worker",
            mode,
            *args,
        ],
        timeout=8.0,
        extra_env=internal_environment(
            harness_sha256
        ),
    )


def sandbox_worker(
    harness_sha256: str,
    mode: str,
    *args: str,
) -> ProcessResult:
    return run_process(
        sandbox_argv(
            [
                PROBE_PYTHON,
                str(HARNESS_PATH),
                "--worker",
                mode,
                *args,
            ]
        ),
        timeout=8.0,
        extra_env=internal_environment(
            harness_sha256
        ),
    )


def control_passed(
    result: ProcessResult,
) -> bool:
    parsed = parse_worker_json(
        result
    )

    return bool(
        not result.timed_out
        and result.exit_code == 0
        and parsed is not None
        and parsed["success"] is True
        and parsed["denied"] is False
    )


def sandbox_failure_code(
    result: ProcessResult,
    *,
    observer_activity: bool = False,
    unix_domain_probe: bool = False,
    forbidden_path_created: bool = False,
) -> str | None:
    if result.timed_out:
        return "FAIL_NOT_PROOF_OF_ISOLATION"

    parsed = parse_worker_json(
        result
    )

    if parsed is None:
        return "FAIL_ISOLATION_MECHANISM"

    exception_type = parsed[
        "exception_type"
    ]

    if exception_type in {
        "TimeoutError",
        "timeout",
    }:
        return "FAIL_NOT_PROOF_OF_ISOLATION"

    if parsed["success"] is True:
        if unix_domain_probe:
            return (
                "FAIL_ISOLATION_MECHANISM_REDESIGN_REQUIRED"
            )

        return "FAIL_ISOLATION_MECHANISM"

    if parsed["denied"] is not True:
        return "FAIL_ISOLATION_MECHANISM"

    if (
        parsed["errno_name"]
        not in ACCEPTED_ERRNO_NAMES
    ):
        return "FAIL_ISOLATION_MECHANISM"

    if (
        parsed["errno_value"]
        not in ACCEPTED_ERRNO_VALUES
    ):
        return "FAIL_ISOLATION_MECHANISM"

    if observer_activity:
        return "FAIL_ISOLATION_MECHANISM"

    if forbidden_path_created:
        return (
            "FAIL_ISOLATION_MECHANISM_REDESIGN_REQUIRED"
        )

    return None


def probe_record(
    *,
    probe_id: str,
    sequence: int,
    started_at: str,
    control: dict[str, Any] | None,
    sandbox: dict[str, Any],
    observer: dict[str, Any],
    passed: bool,
    failure_code: str | None,
) -> dict[str, Any]:
    return {
        "probe_id": probe_id,
        "sequence": sequence,
        "started_at_utc": started_at,
        "ended_at_utc": utc_now(),
        "control": control,
        "sandbox": sandbox,
        "observer": observer,
        "passed": passed,
        "failure_code": failure_code,
    }


def run_profile_acceptance_probe(
    sequence: int,
) -> dict[str, Any]:
    started_at = utc_now()

    result = run_process(
        sandbox_argv(
            [
                TRUE_EXECUTABLE,
            ]
        ),
        timeout=5.0,
    )

    stderr_text = result.stderr.decode(
        "utf-8",
        errors="replace",
    ).lower()

    passed = bool(
        not result.timed_out
        and result.exit_code == 0
        and "syntax error" not in stderr_text
        and "parse error" not in stderr_text
    )

    return probe_record(
        probe_id="profile_acceptance",
        sequence=sequence,
        started_at=started_at,
        control=None,
        sandbox=result.evidence(),
        observer={
            "type": "not-applicable",
            "network_activity_observed": False,
        },
        passed=passed,
        failure_code=(
            None
            if passed
            else "FAIL_STOP_ATTESTATION"
        ),
    )


def run_tcp_loopback_connect_probe(
    sequence: int,
    harness_sha256: str,
) -> dict[str, Any]:
    started_at = utc_now()
    observer, port = _start_tcp_observer()

    try:
        control_before = observer.count()

        control = control_worker(
            harness_sha256,
            "tcp-connect",
            LOOPBACK,
            str(port),
        )

        control_activity = wait_for_count(
            observer,
            control_before + 1,
            1.0,
        )

        sandbox_before = observer.count()

        sandbox = sandbox_worker(
            harness_sha256,
            "tcp-connect",
            LOOPBACK,
            str(port),
        )

        sandbox_activity = wait_for_count(
            observer,
            sandbox_before + 1,
            0.5,
        )

        control_ok = bool(
            control_passed(control)
            and control_activity
        )

        failure = None

        if not control_ok:
            failure = (
                "FAIL_INVALID_PROBE_NO_ATTESTATION"
            )
        else:
            failure = sandbox_failure_code(
                sandbox,
                observer_activity=sandbox_activity,
            )

        return probe_record(
            probe_id="tcp_loopback_connect",
            sequence=sequence,
            started_at=started_at,
            control=worker_process_evidence(
                control
            ),
            sandbox=worker_process_evidence(
                sandbox
            ),
            observer={
                "type": "host-owned-tcp-listener",
                "host": LOOPBACK,
                "port": port,
                "control_activity_detected": (
                    control_activity
                ),
                "sandbox_activity_detected": (
                    sandbox_activity
                ),
                "accepted_connection_count": (
                    observer.count()
                ),
            },
            passed=failure is None,
            failure_code=failure,
        )

    finally:
        observer.stop()


def run_udp_loopback_send_probe(
    sequence: int,
    harness_sha256: str,
) -> dict[str, Any]:
    started_at = utc_now()
    observer, port = _start_udp_observer()
    payload = UDP_PAYLOAD.encode(
        "ascii"
    )

    try:
        control_before = udp_payload_count(
            observer,
            payload,
        )

        control = control_worker(
            harness_sha256,
            "udp-send",
            LOOPBACK,
            str(port),
            UDP_PAYLOAD,
        )

        control_activity = (
            wait_for_udp_payload_count(
                observer,
                payload,
                control_before + 1,
                1.0,
            )
        )

        sandbox_before = udp_payload_count(
            observer,
            payload,
        )

        sandbox = sandbox_worker(
            harness_sha256,
            "udp-send",
            LOOPBACK,
            str(port),
            UDP_PAYLOAD,
        )

        sandbox_activity = (
            wait_for_udp_payload_count(
                observer,
                payload,
                sandbox_before + 1,
                0.5,
            )
        )

        control_ok = bool(
            control_passed(control)
            and control_activity
        )

        failure = None

        if not control_ok:
            failure = (
                "FAIL_INVALID_PROBE_NO_ATTESTATION"
            )
        else:
            failure = sandbox_failure_code(
                sandbox,
                observer_activity=sandbox_activity,
            )

        return probe_record(
            probe_id="udp_loopback_send",
            sequence=sequence,
            started_at=started_at,
            control=worker_process_evidence(
                control
            ),
            sandbox=worker_process_evidence(
                sandbox
            ),
            observer={
                "type": "host-owned-udp-receiver",
                "host": LOOPBACK,
                "port": port,
                "payload_sha256": sha256_bytes(
                    payload
                ),
                "control_activity_detected": (
                    control_activity
                ),
                "sandbox_activity_detected": (
                    sandbox_activity
                ),
                "matching_datagram_count": (
                    udp_payload_count(
                        observer,
                        payload,
                    )
                ),
            },
            passed=failure is None,
            failure_code=failure,
        )

    finally:
        observer.stop()


def run_tcp_inbound_bind_listen_probe(
    sequence: int,
    harness_sha256: str,
) -> dict[str, Any]:
    started_at = utc_now()

    control = control_worker(
        harness_sha256,
        "tcp-bind-listen",
    )

    sandbox = sandbox_worker(
        harness_sha256,
        "tcp-bind-listen",
    )

    control_ok = control_passed(
        control
    )

    failure = None

    if not control_ok:
        failure = (
            "FAIL_INVALID_PROBE_NO_ATTESTATION"
        )
    else:
        failure = sandbox_failure_code(
            sandbox
        )

    return probe_record(
        probe_id="tcp_inbound_bind_listen",
        sequence=sequence,
        started_at=started_at,
        control=worker_process_evidence(
            control
        ),
        sandbox=worker_process_evidence(
            sandbox
        ),
        observer={
            "type": "child-probe-result-only",
            "sandbox_activity_detected": False,
        },
        passed=failure is None,
        failure_code=failure,
    )


def run_child_process_tcp_connect_probe(
    sequence: int,
    harness_sha256: str,
) -> dict[str, Any]:
    started_at = utc_now()
    observer, port = _start_tcp_observer()

    try:
        control_before = observer.count()

        control = control_worker(
            harness_sha256,
            "child-process-tcp-connect",
            LOOPBACK,
            str(port),
        )

        control_activity = wait_for_count(
            observer,
            control_before + 1,
            1.0,
        )

        sandbox_before = observer.count()

        sandbox = sandbox_worker(
            harness_sha256,
            "child-process-tcp-connect",
            LOOPBACK,
            str(port),
        )

        sandbox_activity = wait_for_count(
            observer,
            sandbox_before + 1,
            0.5,
        )

        control_ok = bool(
            control_passed(control)
            and control_activity
        )

        failure = None

        if not control_ok:
            failure = (
                "FAIL_INVALID_PROBE_NO_ATTESTATION"
            )
        else:
            failure = sandbox_failure_code(
                sandbox,
                observer_activity=sandbox_activity,
            )

        return probe_record(
            probe_id="child_process_tcp_connect",
            sequence=sequence,
            started_at=started_at,
            control=worker_process_evidence(
                control
            ),
            sandbox=worker_process_evidence(
                sandbox
            ),
            observer={
                "type": "host-owned-tcp-listener",
                "host": LOOPBACK,
                "port": port,
                "control_activity_detected": (
                    control_activity
                ),
                "sandbox_activity_detected": (
                    sandbox_activity
                ),
                "accepted_connection_count": (
                    observer.count()
                ),
            },
            passed=failure is None,
            failure_code=failure,
        )

    finally:
        observer.stop()


def make_temp_probe_directory(
    prefix: str,
) -> Path:
    directory = Path(
        tempfile.mkdtemp(
            prefix=prefix,
            dir="/tmp",
        )
    ).resolve()

    try:
        directory.relative_to(
            ROOT.resolve()
        )
    except ValueError:
        pass
    else:
        shutil.rmtree(
            directory
        )
        raise HarnessRefused(
            "temporary probe directory resolved inside repository"
        )

    return directory


def run_unix_stream_connect_probe(
    sequence: int,
    harness_sha256: str,
) -> dict[str, Any]:
    started_at = utc_now()
    directory = make_temp_probe_directory(
        "qvra-unix-connect-"
    )

    listener_path = (
        directory
        / "listener.sock"
    )

    observer = _start_unix_observer(
        listener_path
    )

    try:
        control_before = observer.count()

        control = control_worker(
            harness_sha256,
            "unix-stream-connect",
            str(listener_path),
        )

        control_activity = wait_for_count(
            observer,
            control_before + 1,
            1.0,
        )

        sandbox_before = observer.count()

        sandbox = sandbox_worker(
            harness_sha256,
            "unix-stream-connect",
            str(listener_path),
        )

        sandbox_activity = wait_for_count(
            observer,
            sandbox_before + 1,
            0.5,
        )

        control_ok = bool(
            control_passed(control)
            and control_activity
        )

        failure = None

        if not control_ok:
            failure = (
                "FAIL_INVALID_PROBE_NO_ATTESTATION"
            )
        else:
            failure = sandbox_failure_code(
                sandbox,
                observer_activity=sandbox_activity,
                unix_domain_probe=True,
            )

        return probe_record(
            probe_id="unix_stream_connect",
            sequence=sequence,
            started_at=started_at,
            control=worker_process_evidence(
                control
            ),
            sandbox=worker_process_evidence(
                sandbox
            ),
            observer={
                "type": "host-owned-af-unix-listener",
                "path": str(listener_path),
                "control_activity_detected": (
                    control_activity
                ),
                "sandbox_activity_detected": (
                    sandbox_activity
                ),
                "accepted_connection_count": (
                    observer.count()
                ),
            },
            passed=failure is None,
            failure_code=failure,
        )

    finally:
        observer.stop()

        try:
            listener_path.unlink()
        except FileNotFoundError:
            pass

        shutil.rmtree(
            directory,
            ignore_errors=True,
        )


def run_unix_stream_bind_probe(
    sequence: int,
    harness_sha256: str,
) -> dict[str, Any]:
    started_at = utc_now()
    directory = make_temp_probe_directory(
        "qvra-unix-bind-"
    )

    control_path = (
        directory
        / "control.sock"
    )

    sandbox_path = (
        directory
        / "sandbox.sock"
    )

    try:
        control = control_worker(
            harness_sha256,
            "unix-stream-bind",
            str(control_path),
        )

        control_path_created = (
            control_path.exists()
        )

        try:
            control_path.unlink()
        except FileNotFoundError:
            pass

        sandbox = sandbox_worker(
            harness_sha256,
            "unix-stream-bind",
            str(sandbox_path),
        )

        sandbox_path_created = (
            sandbox_path.exists()
        )

        control_ok = bool(
            control_passed(control)
            and control_path_created
        )

        failure = None

        if not control_ok:
            failure = (
                "FAIL_INVALID_PROBE_NO_ATTESTATION"
            )
        else:
            failure = sandbox_failure_code(
                sandbox,
                unix_domain_probe=True,
                forbidden_path_created=(
                    sandbox_path_created
                ),
            )

        return probe_record(
            probe_id="unix_stream_bind",
            sequence=sequence,
            started_at=started_at,
            control=worker_process_evidence(
                control
            ),
            sandbox=worker_process_evidence(
                sandbox
            ),
            observer={
                "type": (
                    "filesystem-path-existence-plus-child-result"
                ),
                "control_path": str(
                    control_path
                ),
                "sandbox_path": str(
                    sandbox_path
                ),
                "control_path_created": (
                    control_path_created
                ),
                "sandbox_path_created": (
                    sandbox_path_created
                ),
                "sandbox_activity_detected": (
                    sandbox_path_created
                ),
            },
            passed=failure is None,
            failure_code=failure,
        )

    finally:
        for path in (
            control_path,
            sandbox_path,
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

        shutil.rmtree(
            directory,
            ignore_errors=True,
        )


def git_result(
    *args: str,
) -> ProcessResult:
    return run_process(
        [
            GIT,
            *args,
        ],
        timeout=10.0,
    )


def require_process_success(
    result: ProcessResult,
    label: str,
) -> bytes:
    if (
        result.timed_out
        or result.exit_code != 0
    ):
        raise HarnessRefused(
            f"{label} failed"
        )

    return result.stdout


def git_text(
    *args: str,
) -> str:
    result = git_result(
        *args
    )

    return require_process_success(
        result,
        "git command",
    ).decode(
        "utf-8"
    ).strip()


def source_status_paths() -> set[str]:
    result = git_result(
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )

    raw = require_process_success(
        result,
        "git status",
    )

    entries = [
        item
        for item in raw.split(b"\0")
        if item
    ]

    paths: set[str] = set()
    index = 0

    while index < len(entries):
        entry = entries[index]

        if len(entry) < 4:
            raise HarnessRefused(
                "invalid git status record"
            )

        status = entry[:2].decode(
            "ascii"
        )

        current = [
            entry[3:].decode(
                "utf-8",
                errors="surrogateescape",
            )
        ]

        if (
            status[0] in ("R", "C")
            or status[1] in ("R", "C")
        ):
            index += 1

            if index >= len(entries):
                raise HarnessRefused(
                    "invalid rename status record"
                )

            current.append(
                entries[index].decode(
                    "utf-8",
                    errors="surrogateescape",
                )
            )

        paths.update(
            current
        )

        index += 1

    return paths


def verify_source_clean() -> None:
    unexpected = {
        path
        for path in source_status_paths()
        if not path.startswith(
            ".qvra-local-evidence/"
        )
    }

    if unexpected:
        raise HarnessRefused(
            "repository source is not clean"
        )


def verify_raw_root_empty() -> None:
    if not RAW_ROOT.exists():
        return

    if not RAW_ROOT.is_dir():
        raise HarnessRefused(
            "raw root exists and is not directory"
        )

    try:
        next(
            RAW_ROOT.iterdir()
        )
    except StopIteration:
        return

    raise HarnessRefused(
        "raw root is not empty"
    )


def resolve_evidence_output(
    value: str,
) -> Path:
    supplied = Path(value)

    if supplied.is_absolute():
        candidate = supplied.resolve()
    else:
        candidate = (
            ROOT
            / supplied
        ).resolve()

    allowed = (
        LOCAL_EVIDENCE_ROOT
    ).resolve()

    try:
        relative = candidate.relative_to(
            allowed
        )
    except ValueError as exc:
        raise HarnessRefused(
            "evidence output must be under governed local evidence root"
        ) from exc

    if not relative.parts:
        raise HarnessRefused(
            "evidence output must be a file"
        )

    if candidate.suffix != ".json":
        raise HarnessRefused(
            "evidence output must have .json suffix"
        )

    if candidate.exists():
        raise HarnessRefused(
            "evidence output already exists"
        )

    return candidate


def assert_expected_hash(
    path: Path,
    expected: str,
    label: str,
) -> None:
    if not path.is_file():
        raise HarnessRefused(
            f"{label} missing"
        )

    actual = sha256_file(
        path
    )

    if actual != expected:
        raise HarnessRefused(
            f"{label} hash mismatch"
        )


def validate_hex(
    value: str,
    length: int,
    label: str,
) -> None:
    if len(value) != length:
        raise HarnessRefused(
            f"{label} has invalid length"
        )

    allowed = set(
        "0123456789abcdef"
    )

    if any(
        char not in allowed
        for char in value
    ):
        raise HarnessRefused(
            f"{label} must be lowercase hexadecimal"
        )


def preflight(
    *,
    expected_main_commit: str,
    expected_harness_sha256: str,
    evidence_output: str,
) -> tuple[Path, dict[str, Any]]:
    validate_hex(
        expected_main_commit,
        40,
        "expected main commit",
    )

    validate_hex(
        expected_harness_sha256,
        64,
        "expected harness sha256",
    )

    output = resolve_evidence_output(
        evidence_output
    )

    assert_expected_hash(
        DESIGN_PATH,
        DESIGN_SHA256,
        "harness design",
    )

    assert_expected_hash(
        DESIGN_SCHEMA_PATH,
        DESIGN_SCHEMA_SHA256,
        "harness design schema",
    )

    assert_expected_hash(
        DESIGN_VERIFY_PATH,
        DESIGN_VERIFY_SHA256,
        "harness design verifier",
    )

    assert_expected_hash(
        PROTOCOL_PATH,
        PROTOCOL_SHA256,
        "probe protocol",
    )

    assert_expected_hash(
        NETWORK_DESIGN_PATH,
        NETWORK_DESIGN_SHA256,
        "network design",
    )

    assert_expected_hash(
        Path(PROBE_PYTHON),
        PROBE_PYTHON_SHA256,
        "probe Python",
    )

    assert_expected_hash(
        Path(SANDBOX_EXEC),
        SANDBOX_EXEC_SHA256,
        "sandbox-exec",
    )

    if sha256_bytes(
        PROFILE_TEXT.encode(
            "utf-8"
        )
    ) != PROFILE_SHA256:
        raise HarnessRefused(
            "sandbox profile hash mismatch"
        )

    harness_sha = sha256_file(
        HARNESS_PATH
    )

    if (
        harness_sha
        != expected_harness_sha256
    ):
        raise HarnessRefused(
            "operator harness hash does not match source"
        )

    repository_root = git_text(
        "rev-parse",
        "--show-toplevel",
    )

    if Path(
        repository_root
    ).resolve() != ROOT.resolve():
        raise HarnessRefused(
            "unexpected repository root"
        )

    current_head = git_text(
        "rev-parse",
        "HEAD",
    )

    local_origin_main = git_text(
        "rev-parse",
        "refs/remotes/origin/main",
    )

    if current_head != expected_main_commit:
        raise HarnessRefused(
            "current HEAD does not match operator expected main"
        )

    if local_origin_main != expected_main_commit:
        raise HarnessRefused(
            "local origin/main does not match operator expected main"
        )

    if current_head != local_origin_main:
        raise HarnessRefused(
            "execution requires exact local origin/main"
        )

    verify_source_clean()
    verify_raw_root_empty()

    if ATTESTATION_PATH.exists():
        raise HarnessRefused(
            "network-isolation attestation already exists"
        )

    if EXECUTION_RUNNER_PATH.exists():
        raise HarnessRefused(
            "execution runner must remain absent"
        )

    if RAW_EXECUTION_RECEIPT_PATH.exists():
        raise HarnessRefused(
            "raw execution receipt must remain absent"
        )

    return (
        output,
        {
            "expected_main_commit": (
                expected_main_commit
            ),
            "current_head": current_head,
            "local_origin_main": (
                local_origin_main
            ),
            "harness_sha256": (
                harness_sha
            ),
            "design_sha256": (
                DESIGN_SHA256
            ),
            "protocol_sha256": (
                PROTOCOL_SHA256
            ),
            "network_design_sha256": (
                NETWORK_DESIGN_SHA256
            ),
            "probe_python_sha256": (
                PROBE_PYTHON_SHA256
            ),
            "sandbox_exec_sha256": (
                SANDBOX_EXEC_SHA256
            ),
            "profile_sha256": (
                PROFILE_SHA256
            ),
            "source_clean": True,
            "raw_root_empty": True,
            "truth_accessed": False,
            "attestation_preexisting": False,
            "execution_runner_preexisting": False,
            "raw_execution_receipt_preexisting": (
                False
            ),
        },
    )


def sw_vers_value(
    argument: str,
) -> str:
    result = run_process(
        [
            SW_VERS,
            argument,
        ],
        timeout=5.0,
    )

    output = require_process_success(
        result,
        "sw_vers",
    )

    return output.decode(
        "utf-8"
    ).strip()


def host_identity() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "macos_product_version": (
            sw_vers_value(
                "-productVersion"
            )
        ),
        "macos_build_version": (
            sw_vers_value(
                "-buildVersion"
            )
        ),
    }


def atomic_write_json(
    path: Path,
    document: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = (
        path.parent
        / (
            "."
            + path.name
            + f".tmp.{os.getpid()}"
        )
    )

    if temporary.exists():
        raise HarnessRefused(
            "temporary evidence file already exists"
        )

    payload = (
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode(
        "utf-8"
    )

    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL,
        0o600,
    )

    try:
        with os.fdopen(
            descriptor,
            "wb",
            closefd=True,
        ) as handle:
            handle.write(
                payload
            )
            handle.flush()
            os.fsync(
                handle.fileno()
            )

        os.replace(
            temporary,
            path,
        )

        directory_fd = os.open(
            path.parent,
            os.O_RDONLY,
        )

        try:
            os.fsync(
                directory_fd
            )
        finally:
            os.close(
                directory_fd
            )

    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def update_evidence_counts(
    evidence: dict[str, Any],
) -> None:
    probes = evidence["probes"]

    evidence["counts"] = {
        "probe_record_count": len(
            probes
        ),
        "network_probe_count": sum(
            1
            for probe in probes
            if probe["probe_id"]
            != "profile_acceptance"
        ),
        "positive_control_count": sum(
            1
            for probe in probes
            if probe["control"]
            is not None
        ),
        "sandbox_exec_invocation_count": (
            SANDBOX_EXEC_INVOCATION_COUNT
        ),
        "retry_count": 0,
    }


def run_governed_probe_transaction(
    *,
    expected_main_commit: str,
    expected_harness_sha256: str,
    evidence_output: str,
) -> int:
    output, preflight_record = preflight(
        expected_main_commit=(
            expected_main_commit
        ),
        expected_harness_sha256=(
            expected_harness_sha256
        ),
        evidence_output=(
            evidence_output
        ),
    )

    host = host_identity()

    evidence: dict[str, Any] = {
        "schema": (
            "qvra-family-2-network-isolation-probe-evidence/v1"
        ),
        "benchmark": (
            "entity-resolution-ambiguity-v1"
        ),
        "family": 2,
        "started_at_utc": utc_now(),
        "ended_at_utc": None,
        "completion_state": (
            "INCOMPLETE_HARNESS_FAILURE"
        ),
        "attestation_ready": False,
        "bindings": {
            "expected_main_commit": (
                expected_main_commit
            ),
            "harness_sha256": (
                expected_harness_sha256
            ),
            "design_sha256": (
                DESIGN_SHA256
            ),
            "protocol_sha256": (
                PROTOCOL_SHA256
            ),
            "network_design_sha256": (
                NETWORK_DESIGN_SHA256
            ),
            "probe_python_sha256": (
                PROBE_PYTHON_SHA256
            ),
            "sandbox_exec_sha256": (
                SANDBOX_EXEC_SHA256
            ),
            "profile_sha256": (
                PROFILE_SHA256
            ),
        },
        "host": host,
        "preflight": preflight_record,
        "probe_order": list(
            PROBE_ORDER
        ),
        "probes": [],
        "counts": {
            "probe_record_count": 0,
            "network_probe_count": 0,
            "positive_control_count": 0,
            "sandbox_exec_invocation_count": 0,
            "retry_count": 0,
        },
        "safety_state": {
            "external_network_used": False,
            "dns_resolution_used": False,
            "benchmark_adapter_used": False,
            "benchmark_raw_root_touched": False,
            "truth_accessed": False,
            "host_network_configuration_mutated": False,
            "root_privilege_used": False,
            "network_isolation_attestation_created": False,
            "execution_runner_created": False,
            "execution_transaction_issued": False,
            "raw_runs_produced": 0,
            "system_execution": False,
            "truth_scoring": False,
        },
        "error": None,
    }

    atomic_write_json(
        output,
        evidence,
    )

    probe_functions = (
        lambda: run_profile_acceptance_probe(
            1
        ),
        lambda: run_tcp_loopback_connect_probe(
            2,
            expected_harness_sha256,
        ),
        lambda: run_udp_loopback_send_probe(
            3,
            expected_harness_sha256,
        ),
        lambda: run_tcp_inbound_bind_listen_probe(
            4,
            expected_harness_sha256,
        ),
        lambda: run_child_process_tcp_connect_probe(
            5,
            expected_harness_sha256,
        ),
        lambda: run_unix_stream_connect_probe(
            6,
            expected_harness_sha256,
        ),
        lambda: run_unix_stream_bind_probe(
            7,
            expected_harness_sha256,
        ),
    )

    try:
        for probe_function in probe_functions:
            record = probe_function()

            evidence[
                "probes"
            ].append(
                record
            )

            update_evidence_counts(
                evidence
            )

            atomic_write_json(
                output,
                evidence,
            )

        if [
            probe["probe_id"]
            for probe in evidence["probes"]
        ] != list(PROBE_ORDER):
            raise RuntimeError(
                "probe order invariant failed"
            )

        update_evidence_counts(
            evidence
        )

        if (
            evidence["counts"][
                "probe_record_count"
            ]
            != 7
        ):
            raise RuntimeError(
                "probe cardinality invariant failed"
            )

        if (
            evidence["counts"][
                "network_probe_count"
            ]
            != 6
        ):
            raise RuntimeError(
                "network probe cardinality invariant failed"
            )

        if (
            evidence["counts"][
                "positive_control_count"
            ]
            != 6
        ):
            raise RuntimeError(
                "positive control cardinality invariant failed"
            )

        if (
            evidence["counts"][
                "sandbox_exec_invocation_count"
            ]
            != 7
        ):
            raise RuntimeError(
                "sandbox invocation cardinality invariant failed"
            )

        all_passed = all(
            probe["passed"]
            for probe in evidence[
                "probes"
            ]
        )

        evidence[
            "completion_state"
        ] = (
            "COMPLETE_PASS"
            if all_passed
            else "COMPLETE_FAIL"
        )

        evidence[
            "attestation_ready"
        ] = all_passed

        evidence[
            "ended_at_utc"
        ] = utc_now()

        atomic_write_json(
            output,
            evidence,
        )

    except BaseException as exc:
        update_evidence_counts(
            evidence
        )

        evidence[
            "completion_state"
        ] = (
            "INCOMPLETE_HARNESS_FAILURE"
        )

        evidence[
            "attestation_ready"
        ] = False

        evidence[
            "ended_at_utc"
        ] = utc_now()

        evidence["error"] = {
            "type": type(
                exc
            ).__name__,
            "message": str(
                exc
            ),
        }

        atomic_write_json(
            output,
            evidence,
        )

        raise

    evidence_sha256 = sha256_file(
        output
    )

    print(
        "NETWORK_ISOLATION_PROBE_EVIDENCE="
        + evidence[
            "completion_state"
        ]
    )

    print(
        "EVIDENCE_PATH="
        + str(
            output
        )
    )

    print(
        "EVIDENCE_SHA256="
        + evidence_sha256
    )

    print(
        "PROBE_RECORD_COUNT="
        + str(
            evidence["counts"][
                "probe_record_count"
            ]
        )
    )

    print(
        "NETWORK_PROBE_COUNT="
        + str(
            evidence["counts"][
                "network_probe_count"
            ]
        )
    )

    print(
        "POSITIVE_CONTROL_COUNT="
        + str(
            evidence["counts"][
                "positive_control_count"
            ]
        )
    )

    print(
        "SANDBOX_EXEC_INVOCATION_COUNT="
        + str(
            evidence["counts"][
                "sandbox_exec_invocation_count"
            ]
        )
    )

    print(
        "ATTESTATION_READY="
        + str(
            evidence[
                "attestation_ready"
            ]
        ).lower()
    )

    print(
        "SYSTEM_EXECUTION=false"
    )

    return (
        0
        if evidence[
            "completion_state"
        ] == "COMPLETE_PASS"
        else 1
    )


def build_operator_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Governed local-only network-isolation attestation probe harness"
        ),
        allow_abbrev=False,
    )

    parser.add_argument(
        "--execute-attestation-probes",
        action="store_true",
        help=(
            "explicitly authorize the reviewed seven-probe local transaction"
        ),
    )

    parser.add_argument(
        "--expect-main-commit",
        required=True,
    )

    parser.add_argument(
        "--expect-harness-sha256",
        required=True,
    )

    parser.add_argument(
        "--evidence-output",
        required=True,
    )

    return parser


def operator_dispatch(
    argv: list[str],
) -> int:
    parser = build_operator_parser()
    args = parser.parse_args(
        argv
    )

    if not args.execute_attestation_probes:
        raise HarnessRefused(
            "explicit --execute-attestation-probes flag required"
        )

    return run_governed_probe_transaction(
        expected_main_commit=(
            args.expect_main_commit
        ),
        expected_harness_sha256=(
            args.expect_harness_sha256
        ),
        evidence_output=(
            args.evidence_output
        ),
    )


def main(
    argv: list[str] | None = None,
) -> int:
    arguments = list(
        sys.argv[1:]
        if argv is None
        else argv
    )

    try:
        if (
            arguments
            and arguments[0]
            == "--worker"
        ):
            return worker_dispatch(
                arguments[1:]
            )

        if (
            arguments
            and arguments[0]
            == "--nested-child"
        ):
            return nested_child_dispatch(
                arguments[1:]
            )

        return operator_dispatch(
            arguments
        )

    except HarnessRefused as exc:
        sys.stderr.write(
            "REFUSED: "
            + str(exc)
            + "\n"
        )

        return 64


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
