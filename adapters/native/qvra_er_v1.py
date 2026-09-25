#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import time
import unicodedata
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression


SYSTEM_ID = "qvra-native-er-v1"
SEED = 20260925

PREREGISTRATION_SHA256 = (
    "6952231739c4bb6dcc722af8eb59577cb59d08b39b762fdbd461aff9da233e9f"
)

FIELDS = (
    "first_name",
    "last_name",
    "city",
    "email",
)


def normalize(value: str) -> str:
    value = unicodedata.normalize(
        "NFKC",
        value or "",
    )
    return " ".join(
        value.strip().split()
    ).casefold()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(
        newline="",
        encoding="utf-8",
    ) as handle:
        return list(csv.DictReader(handle))


def normalized_row(
    row: dict[str, str],
) -> dict[str, str]:
    return {
        field: normalize(row.get(field, ""))
        for field in FIELDS
    }


def levenshtein_distance(
    left: str,
    right: str,
) -> int:
    if left == right:
        return 0

    if not left:
        return len(right)

    if not right:
        return len(left)

    previous = list(range(len(right) + 1))

    for i, left_char in enumerate(left, start=1):
        current = [i]

        for j, right_char in enumerate(right, start=1):
            insertion = current[-1] + 1
            deletion = previous[j] + 1
            substitution = (
                previous[j - 1]
                + (0 if left_char == right_char else 1)
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution,
                )
            )

        previous = current

    return previous[-1]


def similarity(
    left: str,
    right: str,
) -> float:
    left = normalize(left)
    right = normalize(right)

    width = max(len(left), len(right))

    if width == 0:
        return 1.0

    return (
        1.0
        - levenshtein_distance(left, right) / width
    )


def block_keys(
    row: dict[str, str],
) -> tuple[tuple[str, str], ...]:
    row = normalized_row(row)

    first_name = row["first_name"]
    last_name = row["last_name"]
    city = row["city"]
    email = row["email"]

    keys: list[tuple[str, str]] = []

    # 1. normalized_email_exact
    if email:
        keys.append(
            ("email", email)
        )

    # 2. normalized_last_name_exact
    if last_name:
        keys.append(
            ("last-name", last_name)
        )

    # 3. normalized_city_exact_and_first_name_initial
    if city and first_name:
        keys.append(
            (
                "city-first-initial",
                city + "\x1f" + first_name[:1],
            )
        )

    # 4. normalized_first_name_exact_and_normalized_last_name_prefix_3
    if first_name and last_name:
        keys.append(
            (
                "first-last-prefix3",
                first_name + "\x1f" + last_name[:3],
            )
        )

    return tuple(keys)


def candidate_pairs(
    rows: list[dict[str, str]],
) -> list[tuple[int, int]]:
    blocks: dict[
        tuple[str, str],
        list[int],
    ] = defaultdict(list)

    for index, row in enumerate(rows):
        for key in block_keys(row):
            blocks[key].append(index)

    pairs: set[tuple[int, int]] = set()

    for members in blocks.values():
        members = sorted(set(members))

        for position, left in enumerate(members):
            for right in members[position + 1:]:
                pairs.add((left, right))

    return sorted(pairs)


def feature_vector(
    left: dict[str, str],
    right: dict[str, str],
) -> list[float]:
    return [
        similarity(
            left.get("first_name", ""),
            right.get("first_name", ""),
        ),
        similarity(
            left.get("last_name", ""),
            right.get("last_name", ""),
        ),
        similarity(
            left.get("city", ""),
            right.get("city", ""),
        ),
        similarity(
            left.get("email", ""),
            right.get("email", ""),
        ),
        float(
            normalize(left.get("email", ""))
            == normalize(right.get("email", ""))
        ),
    ]


def training_matrix(
    rows: list[dict[str, str]],
) -> tuple[np.ndarray, np.ndarray]:
    if not rows:
        raise ValueError(
            "training data is empty"
        )

    if "entity_id" not in rows[0]:
        raise ValueError(
            "training entity labels required"
        )

    pairs = candidate_pairs(rows)

    features: list[list[float]] = []
    labels: list[int] = []

    for left_index, right_index in pairs:
        left = rows[left_index]
        right = rows[right_index]

        features.append(
            feature_vector(
                left,
                right,
            )
        )

        labels.append(
            int(
                left["entity_id"]
                == right["entity_id"]
            )
        )

    if not features:
        raise ValueError(
            "no training candidate pairs"
        )

    if len(set(labels)) != 2:
        raise ValueError(
            "training candidates require both classes"
        )

    return (
        np.asarray(
            features,
            dtype=float,
        ),
        np.asarray(
            labels,
            dtype=int,
        ),
    )


def pair_f1_precision(
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> tuple[float, float]:
    predicted = probabilities >= threshold
    positive = labels == 1

    true_positive = int(
        np.sum(predicted & positive)
    )

    false_positive = int(
        np.sum(predicted & ~positive)
    )

    false_negative = int(
        np.sum(~predicted & positive)
    )

    precision = (
        true_positive
        / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )

    recall = (
        true_positive
        / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )

    f1 = (
        2.0
        * precision
        * recall
        / (precision + recall)
        if precision + recall
        else 0.0
    )

    return f1, precision


def threshold_candidates() -> tuple[float, ...]:
    return tuple(
        value / 100.0
        for value in range(5, 96)
    )


def select_threshold(
    labels: np.ndarray,
    probabilities: np.ndarray,
) -> float:
    ranked: list[
        tuple[float, float, float]
    ] = []

    for threshold in threshold_candidates():
        f1, precision = pair_f1_precision(
            labels,
            probabilities,
            threshold,
        )

        ranked.append(
            (
                f1,
                precision,
                threshold,
            )
        )

    # Required tie-break:
    # highest F1,
    # then highest precision,
    # then highest threshold.
    return max(ranked)[2]


def fit_model(
    training_rows: list[dict[str, str]],
) -> tuple[LogisticRegression, float]:
    features, labels = training_matrix(
        training_rows
    )

    model = LogisticRegression(
        penalty="l2",
        class_weight="balanced",
        solver="liblinear",
        random_state=SEED,
    )

    model.fit(
        features,
        labels,
    )

    probabilities = model.predict_proba(
        features
    )[:, 1]

    threshold = select_threshold(
        labels,
        probabilities,
    )

    return model, threshold


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        if self.parent[item] != item:
            self.parent[item] = self.find(
                self.parent[item]
            )

        return self.parent[item]

    def union(
        self,
        left: int,
        right: int,
    ) -> None:
        left_root = self.find(left)
        right_root = self.find(right)

        if left_root == right_root:
            return

        if left_root < right_root:
            self.parent[right_root] = left_root
        else:
            self.parent[left_root] = right_root


def infer_clusters(
    model: LogisticRegression,
    threshold: float,
    rows: list[dict[str, str]],
) -> list[list[str]]:
    if rows and "entity_id" in rows[0]:
        raise ValueError(
            "test entity_id is forbidden"
        )

    pairs = candidate_pairs(rows)

    union_find = UnionFind(
        len(rows)
    )

    if pairs:
        features = np.asarray(
            [
                feature_vector(
                    rows[left],
                    rows[right],
                )
                for left, right in pairs
            ],
            dtype=float,
        )

        probabilities = model.predict_proba(
            features
        )[:, 1]

        for (
            left,
            right,
        ), probability in zip(
            pairs,
            probabilities,
            strict=True,
        ):
            if float(probability) >= threshold:
                union_find.union(
                    left,
                    right,
                )

    clusters: dict[
        int,
        list[str],
    ] = defaultdict(list)

    for index, row in enumerate(rows):
        record_id = row.get(
            "record_id",
            "",
        )

        if not record_id:
            raise ValueError(
                "record_id required"
            )

        clusters[
            union_find.find(index)
        ].append(record_id)

    result = [
        sorted(records)
        for records in clusters.values()
    ]

    return sorted(
        result,
        key=lambda cluster: (
            cluster[0],
            len(cluster),
            cluster,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--train",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--test",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    training_rows = read_csv(
        args.train
    )

    test_rows = read_csv(
        args.test
    )

    training_started = time.perf_counter()

    model, threshold = fit_model(
        training_rows
    )

    training_ms = (
        time.perf_counter()
        - training_started
    ) * 1000.0

    inference_started = time.perf_counter()

    clusters = infer_clusters(
        model,
        threshold,
        test_rows,
    )

    inference_ms = (
        time.perf_counter()
        - inference_started
    ) * 1000.0

    payload = {
        "system_id": SYSTEM_ID,
        "version": "1",
        "records": len(test_rows),
        "clusters": clusters,
        "selected_threshold": threshold,
        "training_ms": training_ms,
        "inference_and_clustering_ms": inference_ms,
        "mutation_performed": False,
        "provenance": {
            "preregistration_sha256":
                PREREGISTRATION_SHA256,
            "truth_consumed": False,
        },
    }

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.output.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "system_id": SYSTEM_ID,
                "records": len(test_rows),
                "cluster_count": len(clusters),
                "selected_threshold": threshold,
                "training_ms": training_ms,
                "inference_and_clustering_ms":
                    inference_ms,
            },
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
