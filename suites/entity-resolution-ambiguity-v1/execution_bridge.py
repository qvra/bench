#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "qvra-family-2-execution-bridge/v1"

BRIDGE_EFFECTUATION_AUTHORIZED = False
PROCESS_LAUNCH_CAPABILITY_PRESENT = False

DESIGN_PATH = Path(
    "protocols/"
    "entity-resolution-ambiguity-execution-bridge-design-v1.json"
)

ACTIVATION_PATH = Path(
    "protocols/"
    "entity-resolution-ambiguity-execution-activation-v1.json"
)

PERMIT_PATH = Path(
    "protocols/"
    "entity-resolution-ambiguity-one-shot-execution-permit-v1.json"
)

CONTROLLER_PATH = Path(
    "suites/"
    "entity-resolution-ambiguity-v1/"
    "execution_controller.py"
)

LAUNCHER_PATH = Path(
    "suites/"
    "entity-resolution-ambiguity-v1/"
    "process_launcher.py"
)

DESCRIPTOR_PATH = Path(
    "protocols/"
    "entity-resolution-ambiguity-command-descriptors-v1.json"
)

EXPECTED_DESIGN_SHA256 = (
    "2d4875b94cf7467f591201436c6fbd9e"
    "ab19e879282c4d03d7500720699c5afe"
)

EXPECTED_ACTIVATION_SHA256 = (
    "d418c4d21865f50c7a1d949777d22dca"
    "793eb51a79965bfa941017f892f2f2ea"
)

EXPECTED_PERMIT_SHA256 = (
    "7cef4548b571940a2fe34e3a4025afe8"
    "fe632a90c4af38b9fbd00b1b5794a8d3"
)

EXPECTED_CONTROLLER_SHA256 = (
    "2b9e0026ed756468432c8d07edca9ebc"
    "49ef3b727defbc39f3b55cb9319d9661"
)

EXPECTED_PORTABLE_PLAN_SHA256 = (
    "df1fbeab0a2c89c16fb9530aaf4f5545"
    "d62a4dab3f44f160dacdc231a3463ac7"
)

EXPECTED_LAUNCHER_SHA256 = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_DESCRIPTOR_SHA256 = (
    "817d3e1eae8babb26eb49792b5778898"
    "793235042020c9f904cad0057e8549ac"
)

SYSTEMS = (
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
)

RUN_NUMBERS = (1, 2, 3)


class BridgeRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class BridgeRun:
    ordinal: int
    system_id: str
    run_number: int
    argv: tuple[str, ...]
    cwd: str
    env: tuple[tuple[str, str], ...]
    output_path: str
    stdout_path: str
    stderr_path: str


@dataclass(frozen=True)
class BridgeTransaction:
    schema: str
    bridge_design_sha256: str
    activation_sha256: str
    permit_sha256: str
    controller_sha256: str
    launcher_sha256: str
    portable_plan_sha256: str
    total_required_raw_runs: int
    network_disabled_required: bool
    runtime_mutation_allowed: bool
    retuning_allowed: bool
    raw_outputs_hash_before_truth_required: bool
    all_raw_before_scoring_required: bool
    bridge_effectuation_authorized: bool
    process_launch_capability_present: bool
    runs: tuple[BridgeRun, ...]


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


def require_hash(
    repo_root: Path,
    relative: Path,
    expected: str,
) -> None:
    observed = sha256_file(
        repo_root / relative
    )

    if observed != expected:
        raise BridgeRefused(
            f"identity mismatch: {relative}"
        )


def verify_launcher_hard_disabled(
    repo_root: Path,
) -> None:
    source = (
        repo_root
        / LAUNCHER_PATH
    ).read_text(
        encoding="utf-8"
    )

    tree = ast.parse(source)

    authorized: Any = None

    for node in tree.body:
        if not isinstance(
            node,
            ast.Assign,
        ):
            continue

        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id
                == "EXECUTION_AUTHORIZED"
            ):
                authorized = ast.literal_eval(
                    node.value
                )

    if authorized is not False:
        raise BridgeRefused(
            "launcher is not hard disabled"
        )


def verify_governed_chain(
    repo_root: Path,
) -> None:
    bindings = (
        (DESIGN_PATH, EXPECTED_DESIGN_SHA256),
        (ACTIVATION_PATH, EXPECTED_ACTIVATION_SHA256),
        (PERMIT_PATH, EXPECTED_PERMIT_SHA256),
        (CONTROLLER_PATH, EXPECTED_CONTROLLER_SHA256),
        (LAUNCHER_PATH, EXPECTED_LAUNCHER_SHA256),
        (DESCRIPTOR_PATH, EXPECTED_DESCRIPTOR_SHA256),
    )

    for relative, expected in bindings:
        require_hash(
            repo_root,
            relative,
            expected,
        )

    design = load_json(
        repo_root / DESIGN_PATH
    )

    if design["schema"] != (
        "qvra-family-2-execution-bridge-design/v1"
    ):
        raise BridgeRefused(
            "bridge design schema mismatch"
        )

    if design[
        "future_implementation_contract"
    ]["module_path"] != (
        "suites/"
        "entity-resolution-ambiguity-v1/"
        "execution_bridge.py"
    ):
        raise BridgeRefused(
            "bridge module-path contract mismatch"
        )

    if design["bindings"][
        "portable_plan_sha256"
    ] != EXPECTED_PORTABLE_PLAN_SHA256:
        raise BridgeRefused(
            "portable-plan binding mismatch"
        )

    scope = design["scope"]

    if scope["systems"] != list(SYSTEMS):
        raise BridgeRefused(
            "system topology mismatch"
        )

    if scope["run_numbers"] != list(RUN_NUMBERS):
        raise BridgeRefused(
            "run topology mismatch"
        )

    if scope["runs_per_system"] != 3:
        raise BridgeRefused(
            "runs-per-system mismatch"
        )

    if scope["total_required_raw_runs"] != 9:
        raise BridgeRefused(
            "nine-run contract mismatch"
        )

    if scope["all_nine_runs_required"] is not True:
        raise BridgeRefused(
            "partial execution permitted"
        )

    implementation = design[
        "future_implementation_contract"
    ]

    required_true = (
        "must_verify_activation_identity",
        "must_verify_permit_identity",
        "must_verify_controller_identity",
        "must_verify_portable_plan_identity",
        "must_verify_launcher_identity",
        "must_require_exact_nine_run_topology",
        "must_refuse_partial_execution",
        "must_refuse_second_execution",
        "must_forbid_truth_input",
        "must_forbid_retuning",
        "must_forbid_runtime_mutation",
        "must_require_network_disabled",
        "must_retain_failed_runs",
        "must_retain_raw_outputs",
        "must_capture_stdout",
        "must_capture_stderr",
        "must_hash_raw_outputs_before_truth_reveal",
        "must_complete_all_raw_runs_before_scoring",
    )

    for key in required_true:
        if implementation[key] is not True:
            raise BridgeRefused(
                f"implementation contract missing: {key}"
            )

    activation = load_json(
        repo_root / ACTIVATION_PATH
    )

    effect = activation[
        "activation_effect"
    ]

    if effect[
        "execution_authorized"
    ] is not True:
        raise BridgeRefused(
            "activation effect absent"
        )

    if effect[
        "one_shot"
    ] is not True:
        raise BridgeRefused(
            "activation is not one-shot"
        )

    if effect[
        "maximum_execution_batches"
    ] != 1:
        raise BridgeRefused(
            "execution-batch contract mismatch"
        )

    verify_launcher_hard_disabled(
        repo_root
    )


def load_controller(
    repo_root: Path,
):
    path = (
        repo_root
        / CONTROLLER_PATH
    )

    spec = importlib.util.spec_from_file_location(
        "qvra_family2_bridge_controller",
        path,
    )

    if spec is None or spec.loader is None:
        raise BridgeRefused(
            "controller import unavailable"
        )

    module = importlib.util.module_from_spec(
        spec
    )

    sys.modules[
        spec.name
    ] = module

    try:
        spec.loader.exec_module(
            module
        )
    except Exception:
        sys.modules.pop(
            spec.name,
            None,
        )
        raise

    return module


def assert_raw_root_empty(
    raw_root: Path,
) -> None:
    if not raw_root.exists():
        return

    if any(
        path.is_file()
        for path in raw_root.rglob("*")
    ):
        raise BridgeRefused(
            "raw root is not empty; "
            "partial or repeated execution refused"
        )


def assert_under_root(
    path: Path,
    root: Path,
) -> None:
    try:
        path.resolve().relative_to(
            root.resolve()
        )
    except ValueError as exc:
        raise BridgeRefused(
            f"path escapes raw root: {path}"
        ) from exc


def prepare_transaction(
    *,
    repo_root: Path,
    corpus_root: Path,
    raw_root: Path,
) -> BridgeTransaction:
    verify_governed_chain(
        repo_root
    )

    assert_raw_root_empty(
        raw_root
    )

    controller = load_controller(
        repo_root
    )

    plan = controller.build_plan(
        repo_root=repo_root,
        corpus_root=corpus_root,
        raw_root=raw_root,
    )

    observed_plan_sha = (
        controller.plan_sha256(
            plan
        )
    )

    if (
        observed_plan_sha
        != EXPECTED_PORTABLE_PLAN_SHA256
    ):
        raise BridgeRefused(
            "portable plan identity mismatch"
        )

    if plan.execution_authorized is not False:
        raise BridgeRefused(
            "controller plan unexpectedly executable"
        )

    if plan.authorization_consumable is not False:
        raise BridgeRefused(
            "controller plan unexpectedly consumable"
        )

    expected_pairs = [
        (system_id, run_number)
        for system_id in SYSTEMS
        for run_number in RUN_NUMBERS
    ]

    observed_pairs = [
        (
            run.system_id,
            run.run_number,
        )
        for run in plan.runs
    ]

    if observed_pairs != expected_pairs:
        raise BridgeRefused(
            "execution order mismatch"
        )

    if len(plan.runs) != 9:
        raise BridgeRefused(
            "nine-run topology violated"
        )

    bridge_runs: list[BridgeRun] = []
    artifact_paths: set[str] = set()

    for run in plan.runs:
        output = Path(
            run.output_path
        )

        assert_under_root(
            output,
            raw_root,
        )

        stdout = (
            output.parent
            / "stdout.txt"
        )

        stderr = (
            output.parent
            / "stderr.txt"
        )

        for path in (
            output,
            stdout,
            stderr,
        ):
            assert_under_root(
                path,
                raw_root,
            )

            normalized = str(
                path.resolve()
            )

            if normalized in artifact_paths:
                raise BridgeRefused(
                    "duplicate raw artifact path"
                )

            artifact_paths.add(
                normalized
            )

        for token in run.argv:
            if (
                isinstance(token, str)
                and Path(token).name
                == "truth.json"
            ):
                raise BridgeRefused(
                    "truth input entered argv"
                )

        bridge_runs.append(
            BridgeRun(
                ordinal=run.ordinal,
                system_id=run.system_id,
                run_number=run.run_number,
                argv=run.argv,
                cwd=run.cwd,
                env=run.env,
                output_path=str(
                    output.resolve()
                ),
                stdout_path=str(
                    stdout.resolve()
                ),
                stderr_path=str(
                    stderr.resolve()
                ),
            )
        )

    if len(artifact_paths) != 27:
        raise BridgeRefused(
            "raw artifact topology mismatch"
        )

    return BridgeTransaction(
        schema=SCHEMA,
        bridge_design_sha256=(
            EXPECTED_DESIGN_SHA256
        ),
        activation_sha256=(
            EXPECTED_ACTIVATION_SHA256
        ),
        permit_sha256=(
            EXPECTED_PERMIT_SHA256
        ),
        controller_sha256=(
            EXPECTED_CONTROLLER_SHA256
        ),
        launcher_sha256=(
            EXPECTED_LAUNCHER_SHA256
        ),
        portable_plan_sha256=(
            EXPECTED_PORTABLE_PLAN_SHA256
        ),
        total_required_raw_runs=9,
        network_disabled_required=True,
        runtime_mutation_allowed=False,
        retuning_allowed=False,
        raw_outputs_hash_before_truth_required=True,
        all_raw_before_scoring_required=True,
        bridge_effectuation_authorized=False,
        process_launch_capability_present=False,
        runs=tuple(
            bridge_runs
        ),
    )


def effectuate(
    transaction: BridgeTransaction,
) -> None:
    if (
        BRIDGE_EFFECTUATION_AUTHORIZED
        is not True
    ):
        raise BridgeRefused(
            "Family-2 execution bridge "
            "effectuation is hard disabled"
        )

    raise BridgeRefused(
        "No process-launch implementation "
        "exists in the governed bridge"
    )
