#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


SCHEMA = "qvra-family-2-process-launcher/v1"
EXECUTION_AUTHORIZED = False

DESCRIPTOR_PATH = Path(
    "protocols/entity-resolution-ambiguity-command-descriptors-v1.json"
)

EXPECTED_DESCRIPTOR_SHA256 = (
    "817d3e1eae8babb26eb49792b5778898"
    "793235042020c9f904cad0057e8549ac"
)

ALLOWED_SYSTEMS = frozenset({
    "qvra-native-er-v1",
    "splink-4.0.17",
    "dedupe-3.0.3",
})

FORBIDDEN_INPUT_BASENAMES = frozenset({
    "truth.json",
})


class LaunchRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedLaunch:
    system_id: str
    run_number: int
    argv: tuple[str, ...]
    cwd: str
    env: tuple[tuple[str, str], ...]
    output_path: str


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_descriptor(repo_root: Path) -> dict:
    path = repo_root / DESCRIPTOR_PATH

    if sha256_file(path) != EXPECTED_DESCRIPTOR_SHA256:
        raise LaunchRefused("descriptor identity mismatch")

    return json.loads(path.read_text(encoding="utf-8"))


def assert_under_root(path: Path, root: Path) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise LaunchRefused(
            f"path escapes governed root: {path}"
        ) from exc


def render_argv(
    template: Sequence[str],
    *,
    train_csv: Path | None,
    test_csv: Path,
    output_json: Path,
) -> tuple[str, ...]:

    replacements = {
        "{test_csv}": str(test_csv.resolve()),
        "{output_json}": str(output_json.resolve()),
    }

    if train_csv is not None:
        replacements["{train_csv}"] = str(train_csv.resolve())

    rendered = tuple(
        replacements.get(item, item)
        for item in template
    )

    unresolved = tuple(
        item for item in rendered
        if item.startswith("{") and item.endswith("}")
    )

    if unresolved:
        raise LaunchRefused(
            "unresolved argv placeholders: "
            + ",".join(unresolved)
        )

    return rendered


def prepare_launch(
    *,
    repo_root: Path,
    corpus_root: Path,
    raw_root: Path,
    system_id: str,
    run_number: int,
) -> PreparedLaunch:

    if system_id not in ALLOWED_SYSTEMS:
        raise LaunchRefused(f"unknown system: {system_id}")

    if run_number not in (1, 2, 3):
        raise LaunchRefused(
            f"invalid run number: {run_number}"
        )

    descriptor = load_descriptor(repo_root)
    system = descriptor["systems"][system_id]

    train_csv = corpus_root / "train.csv"
    test_csv = corpus_root / "test.csv"

    output_json = (
        raw_root
        / system_id
        / f"run-{run_number}"
        / "output.json"
    )

    assert_under_root(train_csv, corpus_root)
    assert_under_root(test_csv, corpus_root)
    assert_under_root(output_json, raw_root)

    required = set(system["required_inputs"])
    forbidden = set(system["forbidden_inputs"])

    if "truth.json" not in forbidden:
        raise LaunchRefused("truth firewall absent")

    if "test.csv" not in required:
        raise LaunchRefused("test input contract absent")

    if system_id == "splink-4.0.17":
        if "train.csv" in required:
            raise LaunchRefused(
                "Splink train contract changed"
            )
        train_arg = None
    else:
        if "train.csv" not in required:
            raise LaunchRefused(
                "train input contract absent"
            )
        train_arg = train_csv

    argv = render_argv(
        system["argv_template"],
        train_csv=train_arg,
        test_csv=test_csv,
        output_json=output_json,
    )

    if any(
        Path(item).name in FORBIDDEN_INPUT_BASENAMES
        for item in argv
    ):
        raise LaunchRefused("truth input entered argv")

    child_env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }

    return PreparedLaunch(
        system_id=system_id,
        run_number=run_number,
        argv=argv,
        cwd=str(repo_root.resolve()),
        env=tuple(sorted(child_env.items())),
        output_path=str(output_json.resolve()),
    )


def launch(
    prepared: PreparedLaunch,
) -> subprocess.CompletedProcess[str]:

    if EXECUTION_AUTHORIZED is not True:
        raise LaunchRefused(
            "Family-2 execution is hard disabled"
        )

    return subprocess.run(
        list(prepared.argv),
        cwd=prepared.cwd,
        env=dict(prepared.env),
        text=True,
        capture_output=True,
        check=False,
    )
