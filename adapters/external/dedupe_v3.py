from __future__ import annotations

import argparse
import csv
import importlib.metadata
import itertools
import json
import random
import time
from collections import defaultdict
from pathlib import Path

import dedupe


FIELDS = (
    "first_name",
    "last_name",
    "city",
    "email",
)


def load_csv(path: Path):
    with path.open(
        encoding="utf-8"
    ) as handle:
        return list(
            csv.DictReader(handle)
        )


def public_record(row):
    return {
        field: row[field]
        for field in FIELDS
    }


def build_training_pairs(
    rows,
    seed: int,
    max_match: int = 300,
    max_distinct: int = 300,
):
    by_entity = defaultdict(list)

    for row in rows:
        by_entity[
            row["entity_id"]
        ].append(row)

    match_candidates = []

    for members in by_entity.values():
        for left, right in itertools.combinations(
            members,
            2,
        ):
            match_candidates.append(
                (
                    public_record(left),
                    public_record(right),
                )
            )

    rng = random.Random(seed)
    rng.shuffle(match_candidates)

    match_pairs = match_candidates[
        :max_match
    ]

    entity_ids = sorted(
        by_entity
    )

    distinct_candidates = []

    # Deterministically sample across
    # different known training entities.
    attempts = 0
    target = max_distinct * 20

    while (
        len(distinct_candidates)
        < max_distinct
        and attempts < target
    ):
        attempts += 1

        left_entity, right_entity = (
            rng.sample(
                entity_ids,
                2,
            )
        )

        left = rng.choice(
            by_entity[left_entity]
        )

        right = rng.choice(
            by_entity[right_entity]
        )

        pair = (
            public_record(left),
            public_record(right),
        )

        distinct_candidates.append(
            pair
        )

    if not match_pairs:
        raise RuntimeError(
            "no training match pairs"
        )

    if not distinct_candidates:
        raise RuntimeError(
            "no training distinct pairs"
        )

    return {
        "match": match_pairs,
        "distinct": distinct_candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--train",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--test",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=20260925,
    )

    args = parser.parse_args()

    version = importlib.metadata.version(
        "dedupe"
    )

    if version != "3.0.3":
        raise RuntimeError(
            "expected dedupe 3.0.3, got "
            + version
        )

    train_rows = load_csv(
        args.train
    )

    test_rows = load_csv(
        args.test
    )

    if not train_rows:
        raise RuntimeError(
            "empty training set"
        )

    if not test_rows:
        raise RuntimeError(
            "empty test set"
        )

    if "entity_id" not in train_rows[0]:
        raise RuntimeError(
            "training labels missing"
        )

    if "entity_id" in test_rows[0]:
        raise RuntimeError(
            "test label leakage detected"
        )

    training_pairs = (
        build_training_pairs(
            train_rows,
            args.seed,
        )
    )

    variables = [
        dedupe.variables.String(
            "first_name"
        ),
        dedupe.variables.String(
            "last_name"
        ),
        dedupe.variables.String(
            "city"
        ),
        dedupe.variables.String(
            "email"
        ),
    ]

    train_data = {
        row["record_id"]:
        public_record(row)
        for row in train_rows
    }

    test_data = {
        row["record_id"]:
        public_record(row)
        for row in test_rows
    }

    if set(train_data) & set(test_data):
        raise RuntimeError(
            "train/test record overlap detected"
        )

    started = time.perf_counter()

    model = dedupe.Dedupe(
        variables,
        num_cores=1,
        in_memory=True,
    )

    # Dedupe active-learning preparation is
    # performed exclusively on training records.
    # Test records and test truth are unavailable
    # to model preparation and supervised labels.
    model.prepare_training(
        train_data,
        sample_size=min(
            1500,
            len(train_data),
        ),
    )

    model.mark_pairs(
        training_pairs
    )

    model.train(
        recall=1.0,
        index_predicates=True,
    )

    trained_at = time.perf_counter()

    partitioned = model.partition(
        test_data,
        threshold=args.threshold,
    )

    finished = time.perf_counter()

    clusters = {}

    for cluster_number, item in enumerate(
        partitioned
    ):
        record_ids = item[0]

        cluster_id = (
            "dedupe:"
            + str(cluster_number)
        )

        for record_id in record_ids:
            clusters[
                str(record_id)
            ] = cluster_id

    missing = (
        set(test_data)
        - set(clusters)
    )

    for record_id in sorted(
        missing
    ):
        clusters[
            record_id
        ] = (
            "singleton:"
            + record_id
        )

    result = {
        "schema":
            "qvra-er-adapter-output/v1",
        "system_id":
            "dedupe-3.0.3",
        "version":
            version,
        "threshold":
            args.threshold,
        "training_seed":
            args.seed,
        "training_match_pairs":
            len(
                training_pairs[
                    "match"
                ]
            ),
        "training_distinct_pairs":
            len(
                training_pairs[
                    "distinct"
                ]
            ),
        "training_ms":
            (
                trained_at - started
            ) * 1000,
        "inference_and_clustering_ms":
            (
                finished - trained_at
            ) * 1000,
        "total_ms":
            (
                finished - started
            ) * 1000,
        "records":
            len(test_data),
        "clusters":
            clusters,
        "provenance": {
            "source":
                "dedupe==3.0.3",
            "training_source":
                "train.csv only",
            "prepare_training_source":
                "train.csv only",
            "test_records_consumed_during_training":
                False,
            "test_truth_consumed":
                False,
            "observed_at":
                "runtime",
        },
        "mutation_performed":
            False,
    }

    args.output.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "system_id":
                    result[
                        "system_id"
                    ],
                "version":
                    version,
                "records":
                    len(test_data),
                "clusters":
                    len(
                        set(
                            clusters.values()
                        )
                    ),
                "training_match_pairs":
                    result[
                        "training_match_pairs"
                    ],
                "training_distinct_pairs":
                    result[
                        "training_distinct_pairs"
                    ],
                "training_ms":
                    result[
                        "training_ms"
                    ],
                "inference_and_clustering_ms":
                    result[
                        "inference_and_clustering_ms"
                    ],
            },
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
