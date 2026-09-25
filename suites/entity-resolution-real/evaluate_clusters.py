from __future__ import annotations

import argparse
import itertools
import json
from collections import defaultdict
from pathlib import Path


def pairs(groups):
    result = set()

    for members in groups.values():
        ordered = sorted(set(members))

        for left, right in itertools.combinations(
            ordered,
            2,
        ):
            result.add((left, right))

    return result


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--truth",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--predictions",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    truth = json.loads(
        args.truth.read_text(
            encoding="utf-8"
        )
    )

    prediction = json.loads(
        args.predictions.read_text(
            encoding="utf-8"
        )
    )

    predicted_mapping = prediction[
        "clusters"
    ]

    assert set(predicted_mapping) == set(truth)

    truth_groups = defaultdict(list)
    predicted_groups = defaultdict(list)

    for record_id, entity_id in truth.items():
        truth_groups[
            entity_id
        ].append(record_id)

    for record_id, cluster_id in predicted_mapping.items():
        predicted_groups[
            str(cluster_id)
        ].append(record_id)

    truth_pairs = pairs(truth_groups)
    predicted_pairs = pairs(predicted_groups)

    tp = len(
        truth_pairs & predicted_pairs
    )

    fp = len(
        predicted_pairs - truth_pairs
    )

    fn = len(
        truth_pairs - predicted_pairs
    )

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 1.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 1.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if precision + recall
        else 0.0
    )

    truth_sets = {
        frozenset(members)
        for members in truth_groups.values()
    }

    predicted_sets = {
        frozenset(members)
        for members in predicted_groups.values()
    }

    exact_clusters = len(
        truth_sets & predicted_sets
    )

    cluster_exact_match_rate = (
        exact_clusters
        / len(truth_sets)
        if truth_sets
        else 1.0
    )

    result = {
        "pair_true_positive": tp,
        "pair_false_positive": fp,
        "pair_false_negative": fn,
        "pair_precision": precision,
        "pair_recall": recall,
        "pair_f1": f1,
        "truth_clusters": len(
            truth_sets
        ),
        "predicted_clusters": len(
            predicted_sets
        ),
        "exact_truth_clusters_recovered":
            exact_clusters,
        "cluster_exact_match_rate":
            cluster_exact_match_rate,
    }

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
