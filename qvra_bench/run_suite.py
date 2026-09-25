from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from qvra_bench.kernel import (
    aggregate_runs,
    build_result_capsule,
    evaluate_run,
    execute_adapter,
    verify_result_capsule,
)


def digest(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--runs",
        type=int,
        default=7,
    )

    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path(
            "fixtures/gold/entity-discovery.json"
        ),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "results/multi-run-entity-discovery-v1.json"
        ),
    )

    args = parser.parse_args()

    if args.runs < 3:
        raise SystemExit(
            "minimum repetitions: 3"
        )

    fixture = json.loads(
        args.fixture.read_text(
            encoding="utf-8"
        )
    )

    expected = fixture["expected_items"]

    systems = {
        "reference": "reference.py",
        "imperfect": "imperfect.py",
        "no-provenance": "no_provenance.py",
        "invalid-output": "invalid_output.py",
        "mutation-declared": "mutation_declared.py",
    }

    evaluated = []

    for system_id, adapter in systems.items():
        for run_number in range(
            1,
            args.runs + 1,
        ):
            run = execute_adapter(
                system_id,
                [
                    sys.executable,
                    "adapters/" + adapter,
                    str(args.fixture),
                ],
                timeout_seconds=5,
            )

            row = evaluate_run(
                run,
                expected,
            )

            row["run_number"] = run_number
            evaluated.append(row)

    aggregates = aggregate_runs(
        evaluated
    )

    capsule = build_result_capsule(
        suite_id=(
            "cross-system-entity-discovery-"
            "multi-run-v1"
        ),
        fixture_sha256=digest(
            args.fixture
        ),
        evaluated_runs=evaluated,
    )

    capsule["payload"]["repetitions"] = (
        args.runs
    )

    capsule["payload"]["aggregates"] = (
        aggregates
    )

    from qvra_bench.kernel import (
        canonical_json,
        sha256_bytes,
    )

    capsule["payload_sha256"] = (
        sha256_bytes(
            canonical_json(
                capsule["payload"]
            )
        )
    )

    verification = (
        verify_result_capsule(
            capsule
        )
    )

    if not verification["valid"]:
        raise SystemExit(
            "capsule verification failed"
        )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.output.write_text(
        json.dumps(
            capsule,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    for row in aggregates:
        print(
            row["system_id"],
            json.dumps(
                row,
                sort_keys=True,
            ),
        )

    print(
        "MULTI_RUN_CAPSULE_SHA256="
        + capsule["payload_sha256"]
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
