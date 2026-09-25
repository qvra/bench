#!/usr/bin/env python3

import csv
import hashlib
import importlib.util
import json
from pathlib import Path


SELECTED_SEED = 20260926

GENERATOR_PATH = (
    Path(__file__).with_name(
        "generate_corpus.py"
    )
)


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "family2_frozen_generator",
        GENERATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            "unable to load frozen generator"
        )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(module)

    return module


def public_projection(
    record: dict[str, object],
) -> dict[str, str]:
    return {
        "record_id": str(
            record["record_id"]
        ),
        "first_name": str(
            record["first_name"]
        ),
        "last_name": str(
            record["last_name"]
        ),
        "city": str(
            record["city"]
        ),
        "email": str(
            record["email"]
        ),
    }


def training_projection(
    record: dict[str, object],
) -> dict[str, str]:
    row = public_projection(record)

    row["entity_id"] = str(
        record["entity_id"]
    )

    return row


def truth_projection(
    records: list[dict[str, object]],
) -> dict[str, str]:
    truth = {}

    for record in records:
        record_id = str(
            record["record_id"]
        )

        entity_id = str(
            record["entity_id"]
        )

        assert record_id not in truth

        truth[record_id] = entity_id

    return truth


def build_projected_corpus() -> dict[str, object]:
    generator = load_generator()

    selected_seed, candidate = (
        generator.select_first_passing_seed(
            generator.SEED_SCHEDULE
        )
    )

    assert selected_seed == SELECTED_SEED

    assert all(
        candidate["invariants"].values()
    )

    train_internal = candidate[
        "train_records"
    ]

    test_internal = candidate[
        "test_records"
    ]

    train_public = [
        training_projection(record)
        for record in train_internal
    ]

    test_public = [
        public_projection(record)
        for record in test_internal
    ]

    records_public = [
        public_projection(record)
        for record in (
            train_internal
            + test_internal
        )
    ]

    truth_private = truth_projection(
        test_internal
    )

    return {
        "seed": selected_seed,
        "records": records_public,
        "train": train_public,
        "test": test_public,
        "truth": truth_private,
    }


def validate_projection(
    corpus: dict[str, object],
) -> None:
    assert corpus["seed"] == SELECTED_SEED

    records = corpus["records"]
    train = corpus["train"]
    test = corpus["test"]
    truth = corpus["truth"]

    assert records
    assert train
    assert test
    assert truth

    public_fields = {
        "record_id",
        "first_name",
        "last_name",
        "city",
        "email",
    }

    train_fields = (
        public_fields
        | {"entity_id"}
    )

    assert all(
        set(row) == public_fields
        for row in records
    )

    assert all(
        set(row) == train_fields
        for row in train
    )

    assert all(
        set(row) == public_fields
        for row in test
    )

    assert all(
        "entity_id" not in row
        for row in test
    )

    test_ids = {
        row["record_id"]
        for row in test
    }

    assert set(truth) == test_ids

    all_ids = [
        row["record_id"]
        for row in records
    ]

    assert len(all_ids) == len(
        set(all_ids)
    )



PUBLIC_FIELDS = [
    "record_id",
    "first_name",
    "last_name",
    "city",
    "email",
]

TRAIN_FIELDS = (
    PUBLIC_FIELDS + ["entity_id"]
)


def file_sha256(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def write_csv(
    path: Path,
    rows: list[dict[str, str]],
    fields: list[str],
) -> None:
    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="raise",
            lineterminator="\n",
        )

        writer.writeheader()
        writer.writerows(rows)


def write_projected_corpus(
    output: Path,
    corpus: dict[str, object],
) -> dict[str, object]:
    validate_projection(corpus)

    output.mkdir(
        parents=True,
        exist_ok=False,
    )

    records_path = (
        output / "records.csv"
    )

    train_path = (
        output / "train.csv"
    )

    test_path = (
        output / "test.csv"
    )

    truth_path = (
        output / "truth.json"
    )

    split_path = (
        output / "split.json"
    )

    manifest_path = (
        output / "manifest.json"
    )

    write_csv(
        records_path,
        corpus["records"],
        PUBLIC_FIELDS,
    )

    write_csv(
        train_path,
        corpus["train"],
        TRAIN_FIELDS,
    )

    write_csv(
        test_path,
        corpus["test"],
        PUBLIC_FIELDS,
    )

    truth_path.write_text(
        json.dumps(
            corpus["truth"],
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    train_entity_ids = sorted({
        row["entity_id"]
        for row in corpus["train"]
    })

    truth_entity_ids = sorted(
        set(corpus["truth"].values())
    )

    split = {
        "schema":
            "qvra-entity-resolution-ambiguity-split/v1",
        "seed": corpus["seed"],
        "train_entities": train_entity_ids,
        "test_entities": truth_entity_ids,
        "train_entity_count":
            len(train_entity_ids),
        "test_entity_count":
            len(truth_entity_ids),
    }

    split_path.write_text(
        json.dumps(
            split,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema":
            "qvra-entity-resolution-ambiguity-corpus/v1",
        "seed": corpus["seed"],
        "records":
            len(corpus["records"]),
        "train_records":
            len(corpus["train"]),
        "test_records":
            len(corpus["test"]),
        "truth_records":
            len(corpus["truth"]),
        "label_boundary": {
            "records.csv":
                "PUBLIC_NO_ENTITY_ID",
            "train.csv":
                "TRAINING_LABELS_PRESENT",
            "test.csv":
                "PUBLIC_NO_ENTITY_ID",
            "truth.json":
                "EVALUATOR_ONLY_TEST_TRUTH",
        },
        "files": {
            "records.csv":
                file_sha256(records_path),
            "train.csv":
                file_sha256(train_path),
            "test.csv":
                file_sha256(test_path),
            "truth.json":
                file_sha256(truth_path),
            "split.json":
                file_sha256(split_path),
        },
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    return manifest

def main() -> int:
    corpus = build_projected_corpus()

    validate_projection(corpus)

    # Block 1 deliberately performs no writes.
    raise SystemExit(
        "materialization writing disabled: "
        "projection validated only"
    )


if __name__ == "__main__":
    raise SystemExit(main())
