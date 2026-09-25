#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

LAUNCHER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "process_launcher.py"
)

spec = importlib.util.spec_from_file_location(
    "family2_process_launcher",
    LAUNCHER,
)

assert spec is not None
assert spec.loader is not None

module = importlib.util.module_from_spec(spec)

sys.modules[spec.name] = module
spec.loader.exec_module(module)

assert module.EXECUTION_AUTHORIZED is False


subprocess_reached = False


def forbidden_subprocess_run(*args, **kwargs):
    global subprocess_reached
    subprocess_reached = True

    raise AssertionError(
        "subprocess.run was reached"
    )


# Replace the actual process primitive with a tripwire.
module.subprocess.run = forbidden_subprocess_run


with tempfile.TemporaryDirectory() as td:
    root = Path(td)

    corpus = root / "corpus"
    raw = root / "raw"

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

    systems = (
        "qvra-native-er-v1",
        "splink-4.0.17",
        "dedupe-3.0.3",
    )

    for system in systems:
        for run_number in (1, 2, 3):
            prepared = module.prepare_launch(
                repo_root=ROOT,
                corpus_root=corpus,
                raw_root=raw,
                system_id=system,
                run_number=run_number,
            )

            assert prepared.system_id == system
            assert prepared.run_number == run_number

            assert (
                "truth.json"
                not in prepared.argv
            )

            expected_suffix = (
                f"{system}/"
                f"run-{run_number}/"
                "output.json"
            )

            assert prepared.output_path.endswith(
                expected_suffix
            )

            try:
                module.launch(prepared)
            except module.LaunchRefused as exc:
                assert "hard disabled" in str(exc)
            else:
                raise AssertionError(
                    "launch unexpectedly returned"
                )

assert subprocess_reached is False


# Unknown systems must be rejected.
try:
    module.prepare_launch(
        repo_root=ROOT,
        corpus_root=Path("/tmp"),
        raw_root=Path("/tmp"),
        system_id="unknown-system",
        run_number=1,
    )
except module.LaunchRefused:
    pass
else:
    raise AssertionError(
        "unknown system accepted"
    )


# Out-of-contract run numbers must be rejected.
for invalid_run in (0, 4, -1, 999):
    try:
        module.prepare_launch(
            repo_root=ROOT,
            corpus_root=Path("/tmp"),
            raw_root=Path("/tmp"),
            system_id="qvra-native-er-v1",
            run_number=invalid_run,
        )
    except module.LaunchRefused:
        pass
    else:
        raise AssertionError(
            f"invalid run accepted: {invalid_run}"
        )


print("SYSTEM_COUNT=3")
print("RUNS_PER_SYSTEM=3")
print("PREPARED_RUNS=9")
print("PROCESS_LAUNCH_PRIMITIVE_PRESENT=true")
print("EXECUTION_CAPABILITY_PRESENT=true")
print("EXECUTION_AUTHORIZED=false")
print("SUBPROCESS_REACHED=false")
print("SYSTEM_TRUTH_ACCESS=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("FAMILY_2_PROCESS_LAUNCHER_VERIFIER=PASS")
