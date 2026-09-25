from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path


def normal(value: str) -> str:
    return value.strip().lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
    )
    args = parser.parse_args()

    test_path = (
        args.corpus / "test.csv"
    )

    truth_path = (
        args.corpus / "truth.json"
    )

    with test_path.open(
        encoding="utf-8"
    ) as handle:
        rows = list(
            csv.DictReader(handle)
        )

    truth = json.loads(
        truth_path.read_text(
            encoding="utf-8"
        )
    )

    by_entity = defaultdict(list)

    for row in rows:
        by_entity[
            truth[row["record_id"]]
        ].append(row)

    fields = [
        "first_name",
        "last_name",
        "city",
        "email",
    ]

    entity_stats = {}

    for entity_id, group in by_entity.items():
        exact_shared = 0
        corrupted_fields = 0

        for field in fields:
            values = {
                normal(row[field])
                for row in group
            }

            if len(values) == 1:
                exact_shared += 1
            else:
                corrupted_fields += 1

        if exact_shared >= 3:
            difficulty = "easy"
        elif exact_shared >= 1:
            difficulty = "medium"
        else:
            difficulty = "hard"

        entity_stats[entity_id] = {
            "records": len(group),
            "exact_shared_fields": exact_shared,
            "varying_fields": corrupted_fields,
            "difficulty": difficulty,
        }

    counts = {
        "easy": 0,
        "medium": 0,
        "hard": 0,
    }

    for stat in entity_stats.values():
        counts[
            stat["difficulty"]
        ] += 1

    numeric_signal = 0

    for row in rows:
        if re.search(
            r"\\.\\d+@example\\.test$",
            normal(row["email"]),
        ):
            numeric_signal += 1

    exact_email_groups = defaultdict(
        list
    )

    for row in rows:
        value = normal(row["email"])

        if value:
            exact_email_groups[
                value
            ].append(
                row["record_id"]
            )

    duplicate_email_records = sum(
        len(group)
        for group in exact_email_groups.values()
        if len(group) > 1
    )

    result = {
        "schema":
            "qvra-er-difficulty-analysis/v1",
        "test_records": len(rows),
        "test_entities": len(by_entity),
        "difficulty_entities": counts,
        "numeric_email_signal_records":
            numeric_signal,
        "numeric_email_signal_ratio":
            numeric_signal / len(rows),
        "records_in_duplicated_exact_email_groups":
            duplicate_email_records,
        "duplicated_exact_email_ratio":
            duplicate_email_records
            / len(rows),
        "entities": entity_stats,
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
