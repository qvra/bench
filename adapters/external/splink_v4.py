from __future__ import annotations

import argparse
import importlib.metadata
import json
import time
from pathlib import Path

import pandas as pd

from splink import (
    DuckDBAPI,
    Linker,
    SettingsCreator,
    block_on,
)

from splink.comparison_library import (
    ExactMatch,
    LevenshteinAtThresholds,
)


def frame_to_records(frame):
    if hasattr(
        frame,
        "as_pandas_dataframe",
    ):
        return (
            frame
            .as_pandas_dataframe()
            .to_dict(
                orient="records"
            )
        )

    raise RuntimeError(
        "unsupported Splink dataframe surface"
    )


def main() -> int:
    parser = argparse.ArgumentParser()

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

    args = parser.parse_args()

    version = importlib.metadata.version(
        "splink"
    )

    if version != "4.0.17":
        raise RuntimeError(
            "expected splink 4.0.17, got "
            + version
        )

    data = pd.read_csv(
        args.test,
        dtype=str,
        keep_default_na=False,
    )

    expected_columns = {
        "record_id",
        "first_name",
        "last_name",
        "city",
        "email",
    }

    if set(data.columns) != expected_columns:
        raise RuntimeError(
            "unexpected test schema"
        )

    started = time.perf_counter()

    settings = SettingsCreator(
        link_type="dedupe_only",
        unique_id_column_name=(
            "record_id"
        ),
        comparisons=[
            LevenshteinAtThresholds(
                "first_name",
                [1, 2],
            ),
            LevenshteinAtThresholds(
                "last_name",
                [1, 2],
            ),
            ExactMatch("city"),
            ExactMatch("email"),
        ],
        blocking_rules_to_generate_predictions=[
            block_on("email"),
            block_on("last_name"),
            block_on("first_name"),
        ],
        retain_matching_columns=True,
    )

    linker = Linker(
        data,
        settings,
        DuckDBAPI(),
    )

    linker.training.estimate_u_using_random_sampling(
        max_pairs=100000,
        seed=20260925,
    )

    for blocking_rule in (
        block_on("email"),
        block_on("last_name"),
    ):
        try:
            linker.training.estimate_parameters_using_expectation_maximisation(
                blocking_rule,
            )
        except Exception:
            # Retain execution viability if one EM
            # condition is insufficiently informative.
            pass

    trained_at = time.perf_counter()

    predictions = (
        linker.inference.predict(
            threshold_match_probability=(
                args.threshold
            )
        )
    )

    clustered = (
        linker.clustering
        .cluster_pairwise_predictions_at_threshold(
            predictions,
            threshold_match_probability=(
                args.threshold
            ),
        )
    )

    finished = time.perf_counter()

    rows = frame_to_records(
        clustered
    )

    clusters = {}

    for row in rows:
        record_id = str(
            row["record_id"]
        )

        cluster_id = str(
            row["cluster_id"]
        )

        clusters[
            record_id
        ] = cluster_id

    missing = set(
        data["record_id"].astype(str)
    ) - set(clusters)

    # Any record omitted by the clustered output
    # becomes its own singleton rather than
    # disappearing from scoring.
    for record_id in sorted(missing):
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
            "splink-4.0.17",
        "version":
            version,
        "threshold":
            args.threshold,
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
            len(data),
        "clusters":
            clusters,
        "provenance": {
            "source":
                "splink==4.0.17",
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
                    result["system_id"],
                "version":
                    result["version"],
                "records":
                    result["records"],
                "clusters":
                    len(
                        set(
                            clusters.values()
                        )
                    ),
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
