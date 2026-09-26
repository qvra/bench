#!/usr/bin/env python3

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]

BRIDGE = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_bridge.py"
)

DESIGN = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-bridge-design-v1.json"
)

ACTIVATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-activation-v1.json"
)

PERMIT = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-one-shot-execution-permit-v1.json"
)

BINDING = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-controller-binding-v1.json"
)

AUTHORIZATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-authorization-v1.json"
)

CONTROLLER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_controller.py"
)

LAUNCHER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "process_launcher.py"
)

DESCRIPTOR = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-command-descriptors-v1.json"
)

EXPECTED_BRIDGE_SHA = (
    "f0aaa7706f92d99ee80f152a199b2e8f"
    "31dd12cf0c6494c8733e51a962b807be"
)

EXPECTED_DESIGN_SHA = (
    "2d4875b94cf7467f591201436c6fbd9e"
    "ab19e879282c4d03d7500720699c5afe"
)

EXPECTED_ACTIVATION_SHA = (
    "d418c4d21865f50c7a1d949777d22dca"
    "793eb51a79965bfa941017f892f2f2ea"
)

EXPECTED_PERMIT_SHA = (
    "7cef4548b571940a2fe34e3a4025afe8"
    "fe632a90c4af38b9fbd00b1b5794a8d3"
)

EXPECTED_BINDING_SHA = (
    "f11beabbbd55b9f36ab924fcd767e985"
    "eee3e218d70a5520047997b4e3cb6f57"
)

EXPECTED_AUTH_SHA = (
    "30890b1ac027caf4c3175e6c602581ad"
    "3c9e544d932435bff045884b795e5728"
)

EXPECTED_CONTROLLER_SHA = (
    "2b9e0026ed756468432c8d07edca9ebc"
    "49ef3b727defbc39f3b55cb9319d9661"
)

EXPECTED_PLAN_SHA = (
    "df1fbeab0a2c89c16fb9530aaf4f5545"
    "d62a4dab3f44f160dacdc231a3463ac7"
)

EXPECTED_LAUNCHER_SHA = (
    "d8d028d95adb463f27b5df6a5ec44ae"
    "9049b6799aae46c4b0176ca2adfd07f90"
)

EXPECTED_DESCRIPTOR_SHA = (
    "817d3e1eae8babb26eb49792b5778898"
    "793235042020c9f904cad0057e8549ac"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}

    for path in root.rglob("*"):
        if path.is_file():
            result[
                path.relative_to(root).as_posix()
            ] = sha256_file(path)

    return result


assert sha256_file(BRIDGE) == EXPECTED_BRIDGE_SHA
assert sha256_file(DESIGN) == EXPECTED_DESIGN_SHA
assert sha256_file(ACTIVATION) == EXPECTED_ACTIVATION_SHA
assert sha256_file(PERMIT) == EXPECTED_PERMIT_SHA
assert sha256_file(BINDING) == EXPECTED_BINDING_SHA
assert sha256_file(AUTHORIZATION) == EXPECTED_AUTH_SHA
assert sha256_file(CONTROLLER) == EXPECTED_CONTROLLER_SHA
assert sha256_file(LAUNCHER) == EXPECTED_LAUNCHER_SHA
assert sha256_file(DESCRIPTOR) == EXPECTED_DESCRIPTOR_SHA

design = json.loads(
    DESIGN.read_text(
        encoding="utf-8"
    )
)

assert design[
    "future_implementation_contract"
]["module_path"] == (
    "suites/"
    "entity-resolution-ambiguity-v1/"
    "execution_bridge.py"
)

assert design[
    "bindings"
]["portable_plan_sha256"] == EXPECTED_PLAN_SHA

# The design's false implementation-state fields are an
# immutable preimplementation snapshot. They are not treated
# here as the current repository state.
assert design[
    "implementation_boundary"
]["bridge_implementation_created"] is False

source = BRIDGE.read_text(
    encoding="utf-8"
)

tree = ast.parse(source)

assignments: dict[str, Any] = {}

for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                try:
                    assignments[
                        target.id
                    ] = ast.literal_eval(
                        node.value
                    )
                except Exception:
                    pass

assert assignments[
    "BRIDGE_EFFECTUATION_AUTHORIZED"
] is False

assert assignments[
    "PROCESS_LAUNCH_CAPABILITY_PRESENT"
] is False

# The bridge itself may not import any process-execution
# mechanism.
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            assert alias.name not in {
                "subprocess",
                "multiprocessing",
            }

    if isinstance(node, ast.ImportFrom):
        assert node.module not in {
            "subprocess",
            "multiprocessing",
        }

# The bridge may not contain a process-launch call or a direct
# persistent-write primitive.
for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue

    fn = node.func

    if isinstance(fn, ast.Attribute):
        assert fn.attr not in {
            "launch",
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "system",
            "write_text",
            "write_bytes",
            "touch",
            "unlink",
        }

    if isinstance(fn, ast.Name):
        assert fn.id not in {
            "exec",
            "eval",
            "compile",
        }

# The effectuation entry point itself is allowed only to refuse.
effectuate_nodes = [
    node
    for node in tree.body
    if (
        isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        )
        and node.name == "effectuate"
    )
]

assert len(effectuate_nodes) == 1

effectuate_calls = []

for node in ast.walk(
    effectuate_nodes[0]
):
    if isinstance(node, ast.Call):
        fn = node.func

        if isinstance(fn, ast.Name):
            effectuate_calls.append(
                fn.id
            )
        elif isinstance(fn, ast.Attribute):
            effectuate_calls.append(
                fn.attr
            )

assert set(effectuate_calls) <= {
    "BridgeRefused",
}

process_reached: list[str] = []

original_run = subprocess.run
original_popen = subprocess.Popen
original_call = subprocess.call
original_check_call = subprocess.check_call
original_check_output = subprocess.check_output
original_os_system = os.system


def tripwire(name: str):
    def refuse(*args: Any, **kwargs: Any) -> Any:
        process_reached.append(name)
        raise AssertionError(
            f"process execution reached: {name}"
        )

    return refuse


subprocess.run = tripwire(
    "subprocess.run"
)
subprocess.Popen = tripwire(
    "subprocess.Popen"
)
subprocess.call = tripwire(
    "subprocess.call"
)
subprocess.check_call = tripwire(
    "subprocess.check_call"
)
subprocess.check_output = tripwire(
    "subprocess.check_output"
)
os.system = tripwire(
    "os.system"
)

try:
    spec = importlib.util.spec_from_file_location(
        "qvra_family2_bridge_semantic_verifier",
        BRIDGE,
    )

    assert spec is not None
    assert spec.loader is not None

    bridge = importlib.util.module_from_spec(
        spec
    )

    sys.modules[
        spec.name
    ] = bridge

    spec.loader.exec_module(
        bridge
    )

    assert bridge.SCHEMA == (
        "qvra-family-2-execution-bridge/v1"
    )

    assert (
        bridge.BRIDGE_EFFECTUATION_AUTHORIZED
        is False
    )

    assert (
        bridge.PROCESS_LAUNCH_CAPABILITY_PRESENT
        is False
    )

    with tempfile.TemporaryDirectory(
        prefix="qvra-bridge-verifier-"
    ) as temporary:
        temp = Path(temporary)

        corpus = temp / "corpus"
        raw = temp / "raw"

        corpus.mkdir()
        raw.mkdir()

        (corpus / "train.csv").write_text(
            "record_id,entity_id\n",
            encoding="utf-8",
        )

        (corpus / "test.csv").write_text(
            "record_id\n",
            encoding="utf-8",
        )

        before = snapshot(temp)

        transaction = bridge.prepare_transaction(
            repo_root=ROOT,
            corpus_root=corpus,
            raw_root=raw,
        )

        after_prepare = snapshot(temp)

        assert after_prepare == before

        assert transaction.schema == (
            "qvra-family-2-execution-bridge/v1"
        )

        assert transaction.bridge_design_sha256 == (
            EXPECTED_DESIGN_SHA
        )

        assert transaction.activation_sha256 == (
            EXPECTED_ACTIVATION_SHA
        )

        assert transaction.permit_sha256 == (
            EXPECTED_PERMIT_SHA
        )

        assert transaction.controller_sha256 == (
            EXPECTED_CONTROLLER_SHA
        )

        assert transaction.launcher_sha256 == (
            EXPECTED_LAUNCHER_SHA
        )

        assert transaction.portable_plan_sha256 == (
            EXPECTED_PLAN_SHA
        )

        assert (
            transaction.total_required_raw_runs
            == 9
        )

        assert (
            transaction.network_disabled_required
            is True
        )

        assert (
            transaction.runtime_mutation_allowed
            is False
        )

        assert (
            transaction.retuning_allowed
            is False
        )

        assert (
            transaction.raw_outputs_hash_before_truth_required
            is True
        )

        assert (
            transaction.all_raw_before_scoring_required
            is True
        )

        assert (
            transaction.bridge_effectuation_authorized
            is False
        )

        assert (
            transaction.process_launch_capability_present
            is False
        )

        assert len(transaction.runs) == 9

        expected_pairs = [
            (system_id, run_number)
            for system_id in (
                "qvra-native-er-v1",
                "splink-4.0.17",
                "dedupe-3.0.3",
            )
            for run_number in (
                1,
                2,
                3,
            )
        ]

        observed_pairs = [
            (
                run.system_id,
                run.run_number,
            )
            for run in transaction.runs
        ]

        assert observed_pairs == expected_pairs

        raw_artifacts: set[str] = set()

        for ordinal, run in enumerate(
            transaction.runs,
            start=1,
        ):
            assert run.ordinal == ordinal

            assert Path(
                run.cwd
            ).resolve() == ROOT.resolve()

            env = dict(
                run.env
            )

            assert set(env) == {
                "PATH",
                "PYTHONHASHSEED",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONNOUSERSITE",
            }

            assert env[
                "PYTHONHASHSEED"
            ] == "0"

            assert env[
                "PYTHONDONTWRITEBYTECODE"
            ] == "1"

            assert env[
                "PYTHONNOUSERSITE"
            ] == "1"

            for token in run.argv:
                if isinstance(token, str):
                    assert (
                        Path(token).name
                        != "truth.json"
                    )

            output = Path(
                run.output_path
            )

            stdout = Path(
                run.stdout_path
            )

            stderr = Path(
                run.stderr_path
            )

            assert output.name == "output.json"
            assert stdout.name == "stdout.txt"
            assert stderr.name == "stderr.txt"

            assert (
                output.parent
                == stdout.parent
                == stderr.parent
            )

            for artifact in (
                output,
                stdout,
                stderr,
            ):
                artifact.resolve().relative_to(
                    raw.resolve()
                )

                raw_artifacts.add(
                    str(
                        artifact.resolve()
                    )
                )

        assert len(raw_artifacts) == 27

        try:
            bridge.effectuate(
                transaction
            )
        except bridge.BridgeRefused as exc:
            assert "hard disabled" in str(exc)
        else:
            raise AssertionError(
                "effectuation unexpectedly succeeded"
            )

        after_effectuate = snapshot(temp)

        assert after_effectuate == before

        # Prove partial/repeated execution state is rejected.
        dirty_raw = temp / "dirty-raw"

        sentinel = (
            dirty_raw
            / "qvra-native-er-v1"
            / "run-1"
            / "output.json"
        )

        sentinel.parent.mkdir(
            parents=True
        )

        sentinel.write_text(
            "{}\n",
            encoding="utf-8",
        )

        dirty_before = snapshot(
            dirty_raw
        )

        try:
            bridge.prepare_transaction(
                repo_root=ROOT,
                corpus_root=corpus,
                raw_root=dirty_raw,
            )
        except bridge.BridgeRefused as exc:
            assert "raw root is not empty" in str(exc)
        else:
            raise AssertionError(
                "dirty raw root unexpectedly accepted"
            )

        dirty_after = snapshot(
            dirty_raw
        )

        assert dirty_after == dirty_before

finally:
    subprocess.run = original_run
    subprocess.Popen = original_popen
    subprocess.call = original_call
    subprocess.check_call = original_check_call
    subprocess.check_output = original_check_output
    os.system = original_os_system


assert process_reached == []

print("FAMILY_2_EXECUTION_BRIDGE_IMPLEMENTATION=PASS")
print("BRIDGE_IDENTITY=PASS")
print("UPSTREAM_BINDINGS=PASS")
print("PORTABLE_PLAN_IDENTITY=PASS")
print("EXACT_NINE_RUN_TRANSACTION=PASS")
print("RAW_ARTIFACT_TOPOLOGY=27")
print("TRUTH_INPUT=false")
print("RETUNING_ALLOWED=false")
print("RUNTIME_MUTATION_ALLOWED=false")
print("NETWORK_DISABLED_REQUIRED=true")
print("PARTIAL_EXECUTION_REFUSAL=PASS")
print("BRIDGE_IMPLEMENTATION_PRESENT=true")
print("BRIDGE_EFFECTUATION_AUTHORIZED=false")
print("PROCESS_LAUNCH_CAPABILITY_PRESENT=false")
print("LAUNCHER_EXECUTION_AUTHORIZED=false")
print("EFFECTUATION_REFUSED=PASS")
print("SUBPROCESS_REACHED=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
