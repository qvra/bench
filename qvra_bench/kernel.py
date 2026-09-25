from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

SCHEMA_VERSION = "qvra-bench-result/v1"

class BenchmarkError(RuntimeError):
    """Benchmark contract failure."""

def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def normalize_ids(values: Iterable[str]) -> set[str]:
    return {str(value).strip() for value in values if str(value).strip()}

def precision_recall_f1(predicted: Iterable[str], expected: Iterable[str]) -> dict[str, Any]:
    predicted_set = normalize_ids(predicted)
    expected_set = normalize_ids(expected)
    tp = len(predicted_set & expected_set)
    fp = len(predicted_set - expected_set)
    fn = len(expected_set - predicted_set)
    precision = tp / len(predicted_set) if predicted_set else (1.0 if not expected_set else 0.0)
    recall = tp / len(expected_set) if expected_set else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn, "precision": precision, "recall": recall, "f1": f1}

import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RunResult:
    system_id: str
    exit_code: int
    duration_ms: float
    stdout: str
    stderr: str
    parsed_output: dict[str, Any] | None
    timed_out: bool


def execute_adapter(
    system_id: str,
    command: list[str],
    timeout_seconds: float = 30.0,
) -> RunResult:
    if not system_id.strip():
        raise BenchmarkError("system_id must not be empty")

    if not command:
        raise BenchmarkError("command must not be empty")

    if timeout_seconds <= 0:
        raise BenchmarkError("timeout_seconds must be positive")

    started = time.perf_counter()

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        exit_code = process.returncode
        stdout = process.stdout
        stderr = process.stderr
        timed_out = False

    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        timed_out = True

        stdout = (
            exc.stdout.decode()
            if isinstance(exc.stdout, bytes)
            else exc.stdout or ""
        )

        stderr = (
            exc.stderr.decode()
            if isinstance(exc.stderr, bytes)
            else exc.stderr or ""
        )

    duration_ms = (time.perf_counter() - started) * 1000

    parsed_output = None

    if exit_code == 0:
        try:
            candidate = json.loads(stdout)
            if isinstance(candidate, dict):
                parsed_output = candidate
        except json.JSONDecodeError:
            pass

    return RunResult(
        system_id=system_id,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout=stdout,
        stderr=stderr,
        parsed_output=parsed_output,
        timed_out=timed_out,
    )


def evaluate_run(
    run: RunResult,
    expected_ids: list[str],
) -> dict[str, Any]:
    output = run.parsed_output

    contract_valid = (
        isinstance(output, dict)
        and isinstance(output.get("items"), list)
        and all(
            isinstance(item, str)
            for item in output["items"]
        )
    )

    metrics = None
    provenance_complete = False
    mutation_performed = None

    if contract_valid:
        metrics = precision_recall_f1(
            output["items"],
            expected_ids,
        )

        provenance = output.get("provenance")

        provenance_complete = (
            isinstance(provenance, dict)
            and bool(provenance.get("source"))
            and bool(provenance.get("observed_at"))
        )

        if isinstance(
            output.get("mutation_performed"),
            bool,
        ):
            mutation_performed = output[
                "mutation_performed"
            ]

    return {
        "system_id": run.system_id,
        "exit_code": run.exit_code,
        "timed_out": run.timed_out,
        "duration_ms": round(run.duration_ms, 3),
        "contract_valid": contract_valid,
        "metrics": metrics,
        "provenance_complete": provenance_complete,
        "mutation_performed": mutation_performed,
        "stdout_sha256": sha256_bytes(
            run.stdout.encode("utf-8")
        ),
        "stderr_sha256": sha256_bytes(
            run.stderr.encode("utf-8")
        ),
    }

def build_result_capsule(
    suite_id: str,
    fixture_sha256: str,
    evaluated_runs: list[dict[str, Any]],
) -> dict[str, Any]:
    if not suite_id.strip():
        raise BenchmarkError("suite_id must not be empty")

    if (
        len(fixture_sha256) != 64
        or any(c not in "0123456789abcdef" for c in fixture_sha256)
    ):
        raise BenchmarkError("fixture_sha256 must be lowercase SHA-256")

    payload = {
        "schema": SCHEMA_VERSION,
        "suite_id": suite_id,
        "fixture_sha256": fixture_sha256,
        "runs": evaluated_runs,
    }

    return {
        "payload": payload,
        "payload_sha256": sha256_bytes(
            canonical_json(payload)
        ),
    }


def verify_result_capsule(
    capsule: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(capsule, dict):
        return {
            "valid": False,
            "reason": "CAPSULE_NOT_OBJECT",
        }

    payload = capsule.get("payload")
    declared = capsule.get("payload_sha256")

    if not isinstance(payload, dict):
        return {
            "valid": False,
            "reason": "PAYLOAD_MISSING",
        }

    if not isinstance(declared, str):
        return {
            "valid": False,
            "reason": "DIGEST_MISSING",
        }

    if payload.get("schema") != SCHEMA_VERSION:
        return {
            "valid": False,
            "reason": "SCHEMA_MISMATCH",
        }

    actual = sha256_bytes(
        canonical_json(payload)
    )

    if actual != declared:
        return {
            "valid": False,
            "reason": "DIGEST_MISMATCH",
            "declared_sha256": declared,
            "actual_sha256": actual,
        }

    return {
        "valid": True,
        "reason": "VERIFIED",
        "payload_sha256": actual,
    }

def percentile(
    values: list[float],
    quantile: float,
) -> float | None:
    if not values:
        return None

    if quantile < 0 or quantile > 1:
        raise BenchmarkError(
            "quantile must be between zero and one"
        )

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower

    return (
        ordered[lower] * (1 - weight)
        + ordered[upper] * weight
    )


def aggregate_runs(
    evaluated_runs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}

    for row in evaluated_runs:
        grouped.setdefault(
            row["system_id"],
            [],
        ).append(row)

    aggregates = []

    for system_id in sorted(grouped):
        rows = grouped[system_id]

        durations = [
            float(row["duration_ms"])
            for row in rows
        ]

        scored = [
            row["metrics"]
            for row in rows
            if row["contract_valid"]
            and row["metrics"] is not None
        ]

        def mean_metric(name: str):
            if not scored:
                return None

            return sum(
                metric[name]
                for metric in scored
            ) / len(scored)

        aggregates.append(
            {
                "system_id": system_id,
                "runs": len(rows),
                "successful_exit_runs": sum(
                    1
                    for row in rows
                    if row["exit_code"] == 0
                ),
                "contract_valid_runs": sum(
                    1
                    for row in rows
                    if row["contract_valid"]
                ),
                "provenance_complete_runs": sum(
                    1
                    for row in rows
                    if row["provenance_complete"]
                ),
                "declared_mutation_runs": sum(
                    1
                    for row in rows
                    if row["mutation_performed"] is True
                ),
                "timeout_runs": sum(
                    1
                    for row in rows
                    if row["timed_out"]
                ),
                "duration_ms": {
                    "min": min(durations),
                    "median": percentile(
                        durations,
                        0.5,
                    ),
                    "p95": percentile(
                        durations,
                        0.95,
                    ),
                    "max": max(durations),
                },
                "mean_precision": mean_metric(
                    "precision"
                ),
                "mean_recall": mean_metric(
                    "recall"
                ),
                "mean_f1": mean_metric(
                    "f1"
                ),
            }
        )

    return aggregates

import resource


def execute_adapter_measured(
    system_id: str,
    command: list[str],
    timeout_seconds: float = 30.0,
) -> tuple[RunResult, dict[str, Any]]:
    before = resource.getrusage(
        resource.RUSAGE_CHILDREN
    )

    run = execute_adapter(
        system_id,
        command,
        timeout_seconds,
    )

    after = resource.getrusage(
        resource.RUSAGE_CHILDREN
    )

    usage = {
        "user_cpu_seconds": max(
            0.0,
            after.ru_utime - before.ru_utime,
        ),
        "system_cpu_seconds": max(
            0.0,
            after.ru_stime - before.ru_stime,
        ),
        "child_max_rss_observed": (
            after.ru_maxrss
        ),
        "major_page_fault_delta": max(
            0,
            after.ru_majflt - before.ru_majflt,
        ),
        "minor_page_fault_delta": max(
            0,
            after.ru_minflt - before.ru_minflt,
        ),
        "voluntary_context_switch_delta": max(
            0,
            after.ru_nvcsw - before.ru_nvcsw,
        ),
        "involuntary_context_switch_delta": max(
            0,
            after.ru_nivcsw - before.ru_nivcsw,
        ),
    }

    return run, usage
