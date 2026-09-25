#!/usr/bin/env python3

"""
Family-2 governed execution plan.

STRUCTURAL ONLY.

This module deliberately cannot execute benchmark
systems and cannot access truth.json.

Execution capability must be introduced only after
this plan is independently reviewed and merged.
"""

from dataclasses import dataclass
from pathlib import PurePosixPath


SYSTEMS = (
    "qvra-native-er-v1",
    "splink",
    "dedupe",
)

RUNS_PER_SYSTEM = 3

TRAIN_INPUT = PurePosixPath(
    "train.csv"
)

TEST_INPUT = PurePosixPath(
    "test.csv"
)

FORBIDDEN_INPUTS = frozenset({
    "truth.json",
})

RAW_ROOT = PurePosixPath(
    "family-2-raw-runs"
)


@dataclass(frozen=True)
class RunPlan:
    system: str
    run: int
    train_input: PurePosixPath
    test_input: PurePosixPath
    output_json: PurePosixPath
    stdout: PurePosixPath
    stderr: PurePosixPath


def build_run_plan() -> tuple[RunPlan, ...]:
    runs = []

    for system in SYSTEMS:
        for run in range(1, RUNS_PER_SYSTEM + 1):
            root = (
                RAW_ROOT
                / system
                / f"run-{run}"
            )

            runs.append(
                RunPlan(
                    system=system,
                    run=run,
                    train_input=TRAIN_INPUT,
                    test_input=TEST_INPUT,
                    output_json=(
                        root / "output.json"
                    ),
                    stdout=(
                        root / "stdout.txt"
                    ),
                    stderr=(
                        root / "stderr.txt"
                    ),
                )
            )

    return tuple(runs)


def validate_run_plan(
    plan: tuple[RunPlan, ...],
) -> None:
    assert len(plan) == 9

    expected_pairs = {
        (system, run)
        for system in SYSTEMS
        for run in range(
            1,
            RUNS_PER_SYSTEM + 1,
        )
    }

    actual_pairs = {
        (item.system, item.run)
        for item in plan
    }

    assert actual_pairs == expected_pairs

    outputs = set()

    for item in plan:
        assert item.train_input == TRAIN_INPUT
        assert item.test_input == TEST_INPUT

        assert (
            str(item.train_input)
            not in FORBIDDEN_INPUTS
        )

        assert (
            str(item.test_input)
            not in FORBIDDEN_INPUTS
        )

        assert "truth.json" not in (
            str(item.output_json),
            str(item.stdout),
            str(item.stderr),
        )

        for path in (
            item.output_json,
            item.stdout,
            item.stderr,
        ):
            assert path not in outputs
            outputs.add(path)

    assert len(outputs) == 27


def main() -> int:
    plan = build_run_plan()

    validate_run_plan(plan)

    print(
        "FAMILY_2_EXECUTION_PLAN=PASS"
    )
    print(
        "SYSTEM_COUNT=3"
    )
    print(
        "RUNS_PER_SYSTEM=3"
    )
    print(
        "TOTAL_RAW_RUNS=9"
    )
    print(
        "RAW_ARTIFACT_PATHS=27"
    )
    print(
        "TRUTH_INPUT=false"
    )
    print(
        "EXECUTION_CAPABILITY=false"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
