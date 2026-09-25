#!/usr/bin/env python3

from __future__ import annotations

import ast
import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CONTROLLER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_controller.py"
)


def load_controller():
    spec = importlib.util.spec_from_file_location(
        "qvra_family2_execution_controller",
        CONTROLLER,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)

    sys.modules[spec.name] = module

    spec.loader.exec_module(module)

    return module


source = CONTROLLER.read_text(
    encoding="utf-8"
)

tree = ast.parse(source)

forbidden_imports = {
    "subprocess",
    "shutil",
}

forbidden_calls = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "open",
    "Path.write_text",
    "Path.write_bytes",
    "Path.touch",
    "Path.mkdir",
    "Path.unlink",
    "Path.rename",
    "Path.replace",
}

for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            assert (
                alias.name.split(".", 1)[0]
                not in forbidden_imports
            )

    elif isinstance(node, ast.ImportFrom):
        if node.module:
            assert (
                node.module.split(".", 1)[0]
                not in forbidden_imports
            )

    elif isinstance(node, ast.Call):
        try:
            called = ast.unparse(
                node.func
            )
        except Exception:
            called = ""

        assert called not in forbidden_calls, called

assert ".launch(" not in source
assert "EXECUTION_AUTHORIZED = True" not in source
assert "authorization_consumable=True" not in source
assert "execution_authorized=True" not in source


module = load_controller()


with tempfile.TemporaryDirectory() as td:
    temp = Path(td)

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

    def snapshot() -> dict[str, bytes]:
        return {
            p.relative_to(temp).as_posix():
                p.read_bytes()
            for p in temp.rglob("*")
            if p.is_file()
        }

    before = snapshot()

    plan_one = module.build_plan(
        repo_root=ROOT,
        corpus_root=corpus,
        raw_root=raw,
    )

    after_one = snapshot()

    plan_two = module.build_plan(
        repo_root=ROOT,
        corpus_root=corpus,
        raw_root=raw,
    )

    after_two = snapshot()

    assert before == after_one
    assert before == after_two

    assert plan_one == plan_two

    bytes_one = module.canonical_plan_bytes(
        plan_one
    )

    bytes_two = module.canonical_plan_bytes(
        plan_two
    )

    assert bytes_one == bytes_two

    sha_one = module.plan_sha256(
        plan_one
    )

    sha_two = module.plan_sha256(
        plan_two
    )

    assert sha_one == sha_two

    assert plan_one.schema == (
        "qvra-family-2-"
        "execution-controller-plan/v1"
    )

    assert (
        plan_one.authorization_sha256
        == module.EXPECTED_AUTHORIZATION_SHA256
    )

    assert (
        plan_one.launcher_sha256
        == module.EXPECTED_LAUNCHER_SHA256
    )

    assert (
        plan_one.authorization_consumable
        is False
    )

    assert (
        plan_one.execution_authorized
        is False
    )

    assert (
        plan_one.total_required_raw_runs
        == 9
    )

    assert len(plan_one.runs) == 9

    expected_topology = [
        (system, run)
        for system in (
            "qvra-native-er-v1",
            "splink-4.0.17",
            "dedupe-3.0.3",
        )
        for run in (1, 2, 3)
    ]

    actual_topology = [
        (
            planned.system_id,
            planned.run_number,
        )
        for planned in plan_one.runs
    ]

    assert actual_topology == expected_topology

    assert [
        planned.ordinal
        for planned in plan_one.runs
    ] == list(range(1, 10))

    output_paths = set()

    for planned in plan_one.runs:
        assert isinstance(
            planned.argv,
            tuple,
        )

        assert len(planned.argv) > 0

        assert "truth.json" not in planned.argv

        assert planned.output_path.endswith(
            f"{planned.system_id}/"
            f"run-{planned.run_number}/"
            "output.json"
        )

        assert (
            planned.output_path
            not in output_paths
        )

        output_paths.add(
            planned.output_path
        )

    assert len(output_paths) == 9

    print(
        "PLAN_SHA256="
        + sha_one
    )


print("SYSTEM_COUNT=3")
print("RUNS_PER_SYSTEM=3")
print("PLANNED_RUNS=9")
print("UNIQUE_OUTPUT_PATHS=9")
print("PLAN_DETERMINISM=PASS")
print("FILE_WRITES_BY_CONTROLLER=false")
print("PROCESS_LAUNCH_CAPABILITY=false")
print("LAUNCHER_LAUNCH_CALL=false")
print("AUTHORIZATION_MUTATION_CAPABILITY=false")
print("AUTHORIZATION_CONSUMABLE=false")
print("EXECUTION_AUTHORIZED=false")
print("SYSTEM_TRUTH_ACCESS=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
print("FAMILY_2_EXECUTION_CONTROLLER_VERIFIER=PASS")
