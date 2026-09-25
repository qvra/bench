#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SCHEMA = "qvra-family-2-execution-controller-plan/v1"

AUTHORIZATION_PATH = Path(
    "protocols/"
    "entity-resolution-ambiguity-execution-authorization-v1.json"
)

LAUNCHER_PATH = Path(
    "suites/"
    "entity-resolution-ambiguity-v1/"
    "process_launcher.py"
)

EXPECTED_AUTHORIZATION_SHA256 = (
    "30890b1ac027caf4c3175e6c602581ad"
    "3c9e544d932435bff045884b795e5728"
)

EXPECTED_LAUNCHER_SHA256 = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

SYSTEMS = (
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
)

RUN_NUMBERS = (1, 2, 3)


class ControllerRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class PlannedRun:
    ordinal: int
    system_id: str
    run_number: int
    argv: tuple[str, ...]
    cwd: str
    env: tuple[tuple[str, str], ...]
    output_path: str


@dataclass(frozen=True)
class ExecutionPlan:
    schema: str
    authorization_sha256: str
    launcher_sha256: str
    authorization_consumable: bool
    execution_authorized: bool
    total_required_raw_runs: int
    runs: tuple[PlannedRun, ...]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def verify_authorization(
    repo_root: Path,
) -> dict[str, Any]:

    path = repo_root / AUTHORIZATION_PATH

    if sha256_file(path) != EXPECTED_AUTHORIZATION_SHA256:
        raise ControllerRefused(
            "authorization identity mismatch"
        )

    authorization = load_json(path)

    if authorization["authorization_kind"] != (
        "one-shot-nine-run-execution"
    ):
        raise ControllerRefused(
            "authorization kind mismatch"
        )

    scope = authorization["scope"]

    if scope["systems"] != list(SYSTEMS):
        raise ControllerRefused(
            "system topology mismatch"
        )

    if scope["runs_per_system"] != 3:
        raise ControllerRefused(
            "run-count contract mismatch"
        )

    if scope["total_required_raw_runs"] != 9:
        raise ControllerRefused(
            "total run contract mismatch"
        )

    one_shot = authorization[
        "one_shot_semantics"
    ]

    if one_shot[
        "authorization_reusable"
    ] is not False:
        raise ControllerRefused(
            "authorization unexpectedly reusable"
        )

    if one_shot[
        "partial_execution_reauthorization_allowed"
    ] is not False:
        raise ControllerRefused(
            "partial reauthorization allowed"
        )

    binding = authorization[
        "controller_binding"
    ]

    if binding[
        "execution_controller_created"
    ] is not False:
        raise ControllerRefused(
            "controller already bound"
        )

    if binding[
        "execution_controller_sha256"
    ] is not None:
        raise ControllerRefused(
            "unexpected controller identity"
        )

    if binding[
        "authorization_consumable"
    ] is not False:
        raise ControllerRefused(
            "authorization unexpectedly consumable"
        )

    state = authorization["state"]

    if state[
        "execution_authorized"
    ] is not False:
        raise ControllerRefused(
            "execution unexpectedly authorized"
        )

    if state[
        "authorization_consumed"
    ] is not False:
        raise ControllerRefused(
            "authorization already consumed"
        )

    if state["raw_runs_produced"] != 0:
        raise ControllerRefused(
            "raw execution already recorded"
        )

    if state["system_execution"] is not False:
        raise ControllerRefused(
            "system execution already recorded"
        )

    if state["truth_scoring"] is not False:
        raise ControllerRefused(
            "truth scoring already recorded"
        )

    return authorization


def load_governed_launcher(
    repo_root: Path,
):
    path = repo_root / LAUNCHER_PATH

    if sha256_file(path) != EXPECTED_LAUNCHER_SHA256:
        raise ControllerRefused(
            "launcher identity mismatch"
        )

    spec = importlib.util.spec_from_file_location(
        "qvra_family2_governed_launcher",
        path,
    )

    if spec is None or spec.loader is None:
        raise ControllerRefused(
            "launcher import unavailable"
        )

    module = importlib.util.module_from_spec(spec)

    # dataclasses resolves the defining module
    # through sys.modules during execution.
    sys.modules[spec.name] = module

    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(
            spec.name,
            None,
        )
        raise

    if module.EXECUTION_AUTHORIZED is not False:
        raise ControllerRefused(
            "launcher is not hard disabled"
        )

    return module


def build_plan(
    *,
    repo_root: Path,
    corpus_root: Path,
    raw_root: Path,
) -> ExecutionPlan:

    verify_authorization(
        repo_root
    )

    launcher = load_governed_launcher(
        repo_root
    )

    planned: list[PlannedRun] = []

    ordinal = 0

    for system_id in SYSTEMS:
        for run_number in RUN_NUMBERS:
            ordinal += 1

            prepared = launcher.prepare_launch(
                repo_root=repo_root,
                corpus_root=corpus_root,
                raw_root=raw_root,
                system_id=system_id,
                run_number=run_number,
            )

            planned.append(
                PlannedRun(
                    ordinal=ordinal,
                    system_id=system_id,
                    run_number=run_number,
                    argv=prepared.argv,
                    cwd=prepared.cwd,
                    env=prepared.env,
                    output_path=prepared.output_path,
                )
            )

    if len(planned) != 9:
        raise ControllerRefused(
            "nine-run topology violated"
        )

    return ExecutionPlan(
        schema=SCHEMA,
        authorization_sha256=(
            EXPECTED_AUTHORIZATION_SHA256
        ),
        launcher_sha256=(
            EXPECTED_LAUNCHER_SHA256
        ),
        authorization_consumable=False,
        execution_authorized=False,
        total_required_raw_runs=9,
        runs=tuple(planned),
    )


def canonical_plan_bytes(
    plan: ExecutionPlan,
) -> bytes:

    payload = asdict(plan)
    runs = payload["runs"]

    if not runs:
        raise ControllerRefused(
            "cannot canonicalize empty plan"
        )

    # Discover every concrete root from the
    # unmodified plan before rewriting anything.
    cwd_values = {
        run["cwd"]
        for run in runs
    }

    if len(cwd_values) != 1:
        raise ControllerRefused(
            "nonuniform repository cwd"
        )

    repo_root = next(iter(cwd_values))

    corpus_roots = set()
    raw_roots = set()

    for run in runs:
        output = Path(
            run["output_path"]
        )

        # .../<raw>/<system>/run-N/output.json
        raw_roots.add(
            str(output.parents[2])
        )

        for token in run["argv"]:
            if not isinstance(token, str):
                continue

            if (
                token.endswith("/train.csv")
                or token.endswith("/test.csv")
            ):
                corpus_roots.add(
                    str(Path(token).parent)
                )

    if len(corpus_roots) != 1:
        raise ControllerRefused(
            "nonuniform corpus root"
        )

    if len(raw_roots) != 1:
        raise ControllerRefused(
            "nonuniform raw root"
        )

    replacements = (
        (
            str(next(iter(corpus_roots))),
            "${CORPUS_ROOT}",
        ),
        (
            str(next(iter(raw_roots))),
            "${RAW_ROOT}",
        ),
        (
            str(repo_root),
            "${REPO_ROOT}",
        ),
    )

    replacements = tuple(
        sorted(
            replacements,
            key=lambda item: len(item[0]),
            reverse=True,
        )
    )

    def normalize_path(
        value: str,
    ) -> str:

        for concrete, symbolic in replacements:
            if value == concrete:
                return symbolic

            if value.startswith(
                concrete + "/"
            ):
                return (
                    symbolic
                    + value[len(concrete):]
                )

        return value

    for run in runs:
        run["cwd"] = normalize_path(
            run["cwd"]
        )

        run["output_path"] = normalize_path(
            run["output_path"]
        )

        run["argv"] = [
            normalize_path(token)
            if isinstance(token, str)
            else token
            for token in run["argv"]
        ]

        run["env"] = [
            [
                key,
                "${PATH}"
                if key == "PATH"
                else value,
            ]
            for key, value in run["env"]
        ]

    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def plan_sha256(
    plan: ExecutionPlan,
) -> str:

    return hashlib.sha256(
        canonical_plan_bytes(plan)
    ).hexdigest()
