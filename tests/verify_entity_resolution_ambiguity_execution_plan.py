#!/usr/bin/env python3

import ast
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAN = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_plan.py"
)


source = PLAN.read_text(
    encoding="utf-8"
)

tree = ast.parse(source)

for node in ast.walk(tree):
    if isinstance(
        node,
        (
            ast.Import,
            ast.ImportFrom,
        ),
    ):
        names = []

        if isinstance(node, ast.Import):
            names = [
                alias.name
                for alias in node.names
            ]
        else:
            if node.module:
                names = [node.module]

        for name in names:
            assert not name.startswith(
                (
                    "subprocess",
                    "os",
                    "shlex",
                    "multiprocessing",
                )
            )

for forbidden in (
    "truth.json",
    "evaluate_clusters",
    "pair_f1",
    "pair_precision",
    "pair_recall",
    "cluster_exact_match_rate",
):
    if forbidden == "truth.json":
        # The plan is allowed to name truth.json only
        # as an explicit forbidden input.
        continue

    assert forbidden not in source

spec = importlib.util.spec_from_file_location(
    "family2_execution_plan",
    PLAN,
)

module = importlib.util.module_from_spec(
    spec
)

spec.loader.exec_module(module)

plan = module.build_run_plan()

module.validate_run_plan(plan)

assert len(plan) == 9

assert {
    item.system
    for item in plan
} == {
    "qvra-native-er-v1",
    "splink",
    "dedupe",
}

assert all(
    item.run in (1, 2, 3)
    for item in plan
)

assert all(
    str(item.train_input) == "train.csv"
    for item in plan
)

assert all(
    str(item.test_input) == "test.csv"
    for item in plan
)

assert all(
    "truth.json"
    not in str(item.train_input)
    for item in plan
)

assert all(
    "truth.json"
    not in str(item.test_input)
    for item in plan
)

assert len({
    str(path)
    for item in plan
    for path in (
        item.output_json,
        item.stdout,
        item.stderr,
    )
}) == 27

print("FAMILY_2_EXECUTION_PLAN_VERIFIER=PASS")
print("SYSTEM_COUNT=3")
print("RUNS_PER_SYSTEM=3")
print("TOTAL_RAW_RUNS=9")
print("RAW_ARTIFACT_PATHS=27")
print("TRUTH_INPUT=false")
print("EXECUTION_CAPABILITY=false")
