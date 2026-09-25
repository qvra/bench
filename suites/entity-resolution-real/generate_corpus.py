from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from pathlib import Path


FIRST = [
    "Anna", "Marco", "Sara", "Luca", "Elena",
    "David", "Marta", "Omar", "Nina", "Jonas",
]

LAST = [
    "Rossi", "Bianchi", "Smith", "Meyer", "Costa",
    "Khan", "Novak", "Silva", "Brown", "Fischer",
]

CITIES = [
    "Milan", "Rome", "Berlin", "Paris", "Madrid",
    "Vienna", "Prague", "Lisbon", "Warsaw", "Athens",
]

PUBLIC_FIELDS = [
    "record_id",
    "first_name",
    "last_name",
    "city",
    "email",
]

TRAIN_FIELDS = [
    "record_id",
    "entity_id",
    "first_name",
    "last_name",
    "city",
    "email",
]


def typo(rng: random.Random, value: str) -> str:
    if len(value) < 3:
        return value

    index = rng.randrange(len(value))
    return value[:index] + value[index + 1:]


def mutate(
    rng: random.Random,
    value: str,
) -> str:
    mode = rng.randrange(5)

    if mode == 0:
        return value

    if mode == 1:
        return value.lower()

    if mode == 2:
        return value.upper()

    if mode == 3:
        return typo(rng, value)

    return value + " "


def stable_token(
    seed: int,
    entity: int,
) -> str:
    import hashlib

    raw = (
        str(seed)
        + ":"
        + str(entity)
        + ":qvra-er-v3"
    ).encode("utf-8")

    return hashlib.sha256(
        raw
    ).hexdigest()[:12]


def make_email(
    first: str,
    last: str,
    seed: int,
    entity: int,
) -> str:
    return (
        first.lower()
        + "."
        + last.lower()
        + "."
        + stable_token(seed, entity)
        + "@example.test"
    )


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
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)


def digest(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--seed",
        type=int,
        default=20260925,
    )

    parser.add_argument(
        "--entities",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--min-records",
        type=int,
        default=2,
    )

    parser.add_argument(
        "--max-records",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    if args.entities < 10:
        raise SystemExit(
            "entities must be >= 10"
        )

    if args.min_records < 2:
        raise SystemExit(
            "min-records must be >= 2"
        )

    if args.max_records < args.min_records:
        raise SystemExit(
            "max-records must be >= min-records"
        )

    rng = random.Random(args.seed)

    all_rows: list[dict[str, str]] = []

    for entity in range(args.entities):
        first = rng.choice(FIRST)
        last = rng.choice(LAST)
        city = rng.choice(CITIES)

        email = make_email(
            first,
            last,
            args.seed,
            entity,
        )

        count = rng.randint(
            args.min_records,
            args.max_records,
        )

        for version in range(count):
            all_rows.append(
                {
                    "record_id": (
                        f"r{entity:06d}_{version:02d}"
                    ),
                    "entity_id": (
                        f"e{entity:06d}"
                    ),
                    "first_name": mutate(
                        rng,
                        first,
                    ),
                    "last_name": mutate(
                        rng,
                        last,
                    ),
                    "city": mutate(
                        rng,
                        city,
                    ),
                    "email": mutate(
                        rng,
                        email,
                    ),
                }
            )

    rng.shuffle(all_rows)

    entity_ids = [
        f"e{entity:06d}"
        for entity in range(args.entities)
    ]

    split_rng = random.Random(
        args.seed + 1
    )

    split_rng.shuffle(entity_ids)

    cut = int(
        len(entity_ids) * 0.3
    )

    train_entities = set(
        entity_ids[:cut]
    )

    test_entities = set(
        entity_ids[cut:]
    )

    train_rows = [
        row
        for row in all_rows
        if row["entity_id"]
        in train_entities
    ]

    test_rows_private = [
        row
        for row in all_rows
        if row["entity_id"]
        in test_entities
    ]

    test_rows_public = [
        {
            key: row[key]
            for key in PUBLIC_FIELDS
        }
        for row in test_rows_private
    ]

    all_public = [
        {
            key: row[key]
            for key in PUBLIC_FIELDS
        }
        for row in all_rows
    ]

    truth = {
        row["record_id"]:
        row["entity_id"]
        for row in test_rows_private
    }

    args.output.mkdir(
        parents=True,
        exist_ok=True,
    )

    records_path = (
        args.output / "records.csv"
    )

    train_path = (
        args.output / "train.csv"
    )

    test_path = (
        args.output / "test.csv"
    )

    truth_path = (
        args.output / "truth.json"
    )

    split_path = (
        args.output / "split.json"
    )

    manifest_path = (
        args.output / "manifest.json"
    )

    write_csv(
        records_path,
        all_public,
        PUBLIC_FIELDS,
    )

    write_csv(
        train_path,
        train_rows,
        TRAIN_FIELDS,
    )

    write_csv(
        test_path,
        test_rows_public,
        PUBLIC_FIELDS,
    )

    truth_path.write_text(
        json.dumps(
            truth,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    split_path.write_text(
        json.dumps(
            {
                "train_entities": sorted(
                    train_entities
                ),
                "test_entities": sorted(
                    test_entities
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "schema": (
            "qvra-entity-resolution-corpus/v3"
        ),
        "seed": args.seed,
        "entities": args.entities,
        "records": len(all_rows),
        "train_entities": len(
            train_entities
        ),
        "test_entities": len(
            test_entities
        ),
        "train_records": len(
            train_rows
        ),
        "test_records": len(
            test_rows_public
        ),
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
                digest(records_path),
            "train.csv":
                digest(train_path),
            "test.csv":
                digest(test_path),
            "truth.json":
                digest(truth_path),
            "split.json":
                digest(split_path),
        },
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
