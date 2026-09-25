#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import random
import unicodedata
from pathlib import Path


SUITE_ID = "entity-resolution-ambiguity-v1"

SEED_SCHEDULE = [
    20260926,
    20260927,
    20260928,
    20260929,
    20260930,
]

RECORD_SUPPORT = [2, 3, 4, 5, 6]
RECORD_PROBABILITIES = [0.15, 0.25, 0.30, 0.20, 0.10]

CORRUPTION_SUPPORT = [0, 1, 2, 3, 4]
CORRUPTION_PROBABILITIES = [0.05, 0.20, 0.35, 0.25, 0.15]

PUBLIC_FIELDS = [
    "record_id",
    "first_name",
    "last_name",
    "city",
    "email",
]

TRAIN_FIELDS = PUBLIC_FIELDS + ["entity_id"]


FIRST_NAMES = [
    "Maria", "Mohamed", "Anna", "Ali", "Sara",
    "David", "Elena", "Daniel", "Sofia", "Omar",
    "Marta", "Lucas", "Nina", "Adam", "Maya",
    "José", "Zoë", "Łukasz", "Renée", "Søren",
]

LAST_NAMES = [
    "Smith", "Garcia", "Rossi", "Kim", "Khan",
    "Martin", "Silva", "Brown", "Müller", "Ivanov",
    "Lee", "Jones", "Santos", "Nowak", "Ahmed",
    "García", "Núñez", "Dvořák", "Sørensen", "Łuczak",
]

CITIES = [
    "Milan", "Rome", "Paris", "Berlin", "Madrid",
    "Lisbon", "Warsaw", "Vienna", "Prague", "Athens",
    "London", "Dublin", "Brussels", "Zurich", "Oslo",
]


def stable_token(*parts: object) -> str:
    payload = "|".join(
        str(part)
        for part in parts
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def weighted_choice(
    rng: random.Random,
    values: list[int],
    probabilities: list[float],
) -> int:
    return rng.choices(
        values,
        weights=probabilities,
        k=1,
    )[0]


def normalize_ascii(value: str) -> str:
    return "".join(
        ch
        for ch in unicodedata.normalize(
            "NFKD",
            value,
        )
        if not unicodedata.combining(ch)
    )


def make_record_id(
    seed: int,
    entity_index: int,
    record_index: int,
) -> str:
    # Nonsemantic: derived through a cryptographic digest rather
    # than exposing latent entity identity in the identifier.
    token = stable_token(
        "record",
        seed,
        entity_index,
        record_index,
    )

    return f"r-{token[:20]}"



def build_latent_population(
    seed: int,
    entity_count: int = 600,
) -> list[dict[str, object]]:
    rng = random.Random(seed)

    entities: list[dict[str, object]] = []

    for entity_index in range(entity_count):
        first_name = rng.choice(FIRST_NAMES)
        last_name = rng.choice(LAST_NAMES)
        city = rng.choice(CITIES)

        email_token = stable_token(
            "email",
            seed,
            entity_index,
        )[:12]

        entity = {
            "entity_index": entity_index,
            "entity_id": (
                "e-"
                + stable_token(
                    "entity",
                    seed,
                    entity_index,
                )[:20]
            ),
            "first_name": first_name,
            "last_name": last_name,
            "city": city,
            "email": (
                f"{email_token}"
                "@example.test"
            ),
            "collision_tags": [],
        }

        entities.append(entity)

    return entities


def apply_collision_groups(
    seed: int,
    entities: list[dict[str, object]],
) -> list[dict[str, object]]:
    rng = random.Random(
        int(
            stable_token(
                "collisions",
                seed,
            )[:16],
            16,
        )
    )

    count = len(entities)

    assert count >= 20

    order = list(range(count))
    rng.shuffle(order)

    # Five deterministic, disjoint collision families.
    # Each family receives a fixed slice of shuffled entities.
    slices = {
        "same_full_name": order[0:60],
        "same_last_name_and_city": order[60:120],
        "shared_email": order[120:180],
        "near_name_same_city": order[180:240],
        "multi_field_hard_negative": order[240:300],
    }

    def pairs(indices: list[int]):
        assert len(indices) % 2 == 0
        for i in range(0, len(indices), 2):
            yield indices[i], indices[i + 1]

    for left, right in pairs(
        slices["same_full_name"]
    ):
        entities[right]["first_name"] = (
            entities[left]["first_name"]
        )
        entities[right]["last_name"] = (
            entities[left]["last_name"]
        )

        entities[left]["collision_tags"].append(
            "same_full_name"
        )
        entities[right]["collision_tags"].append(
            "same_full_name"
        )

    for left, right in pairs(
        slices["same_last_name_and_city"]
    ):
        entities[right]["last_name"] = (
            entities[left]["last_name"]
        )
        entities[right]["city"] = (
            entities[left]["city"]
        )

        entities[left]["collision_tags"].append(
            "same_last_name_and_city"
        )
        entities[right]["collision_tags"].append(
            "same_last_name_and_city"
        )

    for left, right in pairs(
        slices["shared_email"]
    ):
        shared = (
            "shared-"
            + stable_token(
                "shared-email",
                seed,
                left,
                right,
            )[:10]
            + "@example.test"
        )

        entities[left]["email"] = shared
        entities[right]["email"] = shared

        entities[left]["collision_tags"].append(
            "shared_email"
        )
        entities[right]["collision_tags"].append(
            "shared_email"
        )

    for left, right in pairs(
        slices["near_name_same_city"]
    ):
        left_first = str(
            entities[left]["first_name"]
        )

        entities[right]["first_name"] = (
            left_first[:-1]
            + (
                "a"
                if not left_first.endswith("a")
                else "e"
            )
        )

        entities[right]["city"] = (
            entities[left]["city"]
        )

        entities[left]["collision_tags"].append(
            "near_name_same_city"
        )
        entities[right]["collision_tags"].append(
            "near_name_same_city"
        )

    for left, right in pairs(
        slices["multi_field_hard_negative"]
    ):
        entities[right]["first_name"] = (
            entities[left]["first_name"]
        )
        entities[right]["last_name"] = (
            entities[left]["last_name"]
        )
        entities[right]["city"] = (
            entities[left]["city"]
        )

        entities[left]["collision_tags"].append(
            "multi_field_hard_negative"
        )
        entities[right]["collision_tags"].append(
            "multi_field_hard_negative"
        )

    return entities


def validate_latent_population(
    entities: list[dict[str, object]],
) -> None:
    assert len(entities) == 600

    entity_ids = [
        str(entity["entity_id"])
        for entity in entities
    ]

    assert len(set(entity_ids)) == 600

    required = {
        "same_full_name",
        "same_last_name_and_city",
        "shared_email",
        "near_name_same_city",
        "multi_field_hard_negative",
    }

    observed = {
        str(tag)
        for entity in entities
        for tag in entity["collision_tags"]
    }

    assert required <= observed

    # Explicitly prove multiple latent entities share
    # observed identity-like values.
    full_names: dict[tuple[str, str], int] = {}
    emails: dict[str, int] = {}

    for entity in entities:
        name = (
            str(entity["first_name"]),
            str(entity["last_name"]),
        )

        full_names[name] = (
            full_names.get(name, 0) + 1
        )

        email = str(entity["email"])
        emails[email] = emails.get(email, 0) + 1

    assert any(
        count >= 2
        for count in full_names.values()
    )

    assert any(
        count >= 2
        for count in emails.values()
    )


def split_latent_entities(
    seed: int,
    entities: list[dict[str, object]],
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
]:
    assert len(entities) == 600

    order = list(range(len(entities)))

    rng = random.Random(
        int(
            stable_token(
                "entity-split",
                seed,
            )[:16],
            16,
        )
    )

    rng.shuffle(order)

    train_indices = set(order[:180])
    test_indices = set(order[180:])

    assert len(train_indices) == 180
    assert len(test_indices) == 420
    assert train_indices.isdisjoint(
        test_indices
    )

    train = [
        entity
        for index, entity in enumerate(entities)
        if index in train_indices
    ]

    test = [
        entity
        for index, entity in enumerate(entities)
        if index in test_indices
    ]

    return train, test


def generate_clean_records(
    seed: int,
    entities: list[dict[str, object]],
    split_name: str,
) -> list[dict[str, object]]:
    assert split_name in {
        "train",
        "test",
    }

    records: list[dict[str, object]] = []

    for entity in entities:
        entity_index = int(
            entity["entity_index"]
        )

        count_rng = random.Random(
            int(
                stable_token(
                    "record-count",
                    seed,
                    entity_index,
                )[:16],
                16,
            )
        )

        record_count = weighted_choice(
            count_rng,
            RECORD_SUPPORT,
            RECORD_PROBABILITIES,
        )

        assert 2 <= record_count <= 6

        for record_index in range(
            record_count
        ):
            record = {
                "record_id": make_record_id(
                    seed,
                    entity_index,
                    record_index,
                ),
                "first_name": str(
                    entity["first_name"]
                ),
                "last_name": str(
                    entity["last_name"]
                ),
                "city": str(
                    entity["city"]
                ),
                "email": str(
                    entity["email"]
                ),
                "entity_id": str(
                    entity["entity_id"]
                ),
                "_entity_index": entity_index,
                "_record_index": record_index,
                "_split": split_name,
                "_collision_tags": list(
                    entity["collision_tags"]
                ),
                "_corruptions": [],
            }

            records.append(record)

    return records


def validate_entity_split(
    train_entities: list[dict[str, object]],
    test_entities: list[dict[str, object]],
) -> None:
    assert len(train_entities) == 180
    assert len(test_entities) == 420

    train_ids = {
        str(entity["entity_id"])
        for entity in train_entities
    }

    test_ids = {
        str(entity["entity_id"])
        for entity in test_entities
    }

    assert len(train_ids) == 180
    assert len(test_ids) == 420
    assert train_ids.isdisjoint(test_ids)


def validate_clean_records(
    records: list[dict[str, object]],
    expected_entities: int,
    split_name: str,
) -> None:
    assert records

    entity_counts: dict[str, int] = {}

    record_ids: list[str] = []

    for record in records:
        assert record["_split"] == split_name
        assert record["_corruptions"] == []

        entity_id = str(
            record["entity_id"]
        )

        entity_counts[entity_id] = (
            entity_counts.get(
                entity_id,
                0,
            )
            + 1
        )

        record_ids.append(
            str(record["record_id"])
        )

    assert len(entity_counts) == expected_entities

    assert all(
        2 <= count <= 6
        for count in entity_counts.values()
    )

    assert len(record_ids) == len(
        set(record_ids)
    )


CORRUPTION_OPERATORS = [
    "character_edit",
    "whitespace_variation",
    "case_variation",
    "unicode_diacritic_variation",
    "transliteration",
    "name_order_swap",
    "nickname_or_short_form",
    "field_missingness",
    "city_change",
    "email_change",
    "contradictory_field_from_collision_peer",
]

NICKNAMES = {
    "Maria": "Mia",
    "Mohamed": "Mo",
    "Anna": "Ann",
    "Ali": "Al",
    "Sara": "Sar",
    "David": "Dave",
    "Elena": "Lena",
    "Daniel": "Dan",
    "Sofia": "Sofi",
    "Omar": "Om",
    "Marta": "Mart",
    "Lucas": "Luc",
    "Nina": "Nin",
    "Adam": "Ad",
    "Maya": "May",
    "José": "Jose",
    "Zoë": "Zoe",
    "Łukasz": "Lukasz",
    "Renée": "Renee",
    "Søren": "Soren",
}


def _text_fields(
    record: dict[str, object],
) -> list[str]:
    return [
        field
        for field in [
            "first_name",
            "last_name",
            "city",
            "email",
        ]
        if str(record[field])
    ]


def apply_corruption_operator(
    record: dict[str, object],
    operator: str,
    rng: random.Random,
    collision_peers: list[dict[str, object]],
) -> dict[str, object]:
    out = dict(record)
    out["_collision_tags"] = list(record["_collision_tags"])
    out["_corruptions"] = list(record["_corruptions"])

    assert operator in CORRUPTION_OPERATORS

    if operator == "character_edit":
        field = rng.choice(_text_fields(out))
        value = str(out[field])

        if len(value) >= 2:
            pos = rng.randrange(len(value))
            replacement = (
                "x"
                if value[pos].lower() != "x"
                else "z"
            )
            out[field] = (
                value[:pos]
                + replacement
                + value[pos + 1:]
            )

    elif operator == "whitespace_variation":
        field = rng.choice([
            "first_name",
            "last_name",
        ])
        out[field] = " " + str(out[field]) + " "

    elif operator == "case_variation":
        field = rng.choice(_text_fields(out))
        value = str(out[field])
        out[field] = (
            value.upper()
            if value != value.upper()
            else value.lower()
        )

    elif operator == "unicode_diacritic_variation":
        field = rng.choice([
            "first_name",
            "last_name",
        ])
        value = str(out[field])
        ascii_value = normalize_ascii(value)

        if ascii_value != value:
            out[field] = ascii_value
        else:
            replacements = {
                "a": "á",
                "e": "é",
                "i": "í",
                "o": "ó",
                "u": "ú",
            }

            for i, char in enumerate(value):
                lower = char.lower()

                if lower in replacements:
                    replacement = replacements[lower]

                    if char.isupper():
                        replacement = replacement.upper()

                    out[field] = (
                        value[:i]
                        + replacement
                        + value[i + 1:]
                    )
                    break

    elif operator == "transliteration":
        field = rng.choice([
            "first_name",
            "last_name",
        ])
        out[field] = normalize_ascii(
            str(out[field])
        )

    elif operator == "name_order_swap":
        first = str(out["first_name"])
        last = str(out["last_name"])
        out["first_name"] = last
        out["last_name"] = first

    elif operator == "nickname_or_short_form":
        value = str(out["first_name"])
        out["first_name"] = NICKNAMES.get(
            value,
            value[:max(1, min(3, len(value)))],
        )

    elif operator == "field_missingness":
        field = rng.choice([
            "first_name",
            "last_name",
            "city",
            "email",
        ])
        out[field] = ""

    elif operator == "city_change":
        current = str(out["city"])
        choices = [
            city
            for city in CITIES
            if city != current
        ]
        out["city"] = rng.choice(choices)

    elif operator == "email_change":
        token = stable_token(
            "changed-email",
            out["record_id"],
            out["email"],
        )[:12]
        out["email"] = (
            token + "@example.test"
        )

    elif operator == "contradictory_field_from_collision_peer":
        assert collision_peers

        peer = rng.choice(collision_peers)

        fields = [
            field
            for field in [
                "first_name",
                "last_name",
                "city",
                "email",
            ]
            if str(peer[field]) != str(out[field])
        ]

        if fields:
            field = rng.choice(fields)
            out[field] = str(peer[field])

    out["_corruptions"].append(operator)

    return out


def corrupt_records(
    seed: int,
    records: list[dict[str, object]],
) -> list[dict[str, object]]:
    by_entity: dict[
        str,
        list[dict[str, object]],
    ] = {}

    for record in records:
        entity_id = str(record["entity_id"])
        by_entity.setdefault(
            entity_id,
            [],
        ).append(record)

    all_records = list(records)
    corrupted: list[dict[str, object]] = []

    for record in records:
        record_id = str(record["record_id"])
        entity_id = str(record["entity_id"])

        count_rng = random.Random(
            int(
                stable_token(
                    "corruption-count",
                    seed,
                    record_id,
                )[:16],
                16,
            )
        )

        corruption_count = weighted_choice(
            count_rng,
            CORRUPTION_SUPPORT,
            CORRUPTION_PROBABILITIES,
        )

        assert 0 <= corruption_count <= 4

        operator_rng = random.Random(
            int(
                stable_token(
                    "corruption-operators",
                    seed,
                    record_id,
                )[:16],
                16,
            )
        )

        selected = operator_rng.sample(
            CORRUPTION_OPERATORS,
            k=corruption_count,
        )

        peers = [
            candidate
            for candidate in all_records
            if (
                str(candidate["entity_id"])
                != entity_id
            )
        ]

        assert peers

        out = dict(record)
        out["_collision_tags"] = list(
            record["_collision_tags"]
        )
        out["_corruptions"] = list(
            record["_corruptions"]
        )

        for position, operator in enumerate(
            selected
        ):
            operation_rng = random.Random(
                int(
                    stable_token(
                        "corruption-operation",
                        seed,
                        record_id,
                        position,
                        operator,
                    )[:16],
                    16,
                )
            )

            out = apply_corruption_operator(
                out,
                operator,
                operation_rng,
                peers,
            )

        assert len(
            out["_corruptions"]
        ) == corruption_count

        corrupted.append(out)

    return corrupted


def validate_corrupted_records(
    clean: list[dict[str, object]],
    corrupted: list[dict[str, object]],
) -> None:
    assert len(clean) == len(corrupted)

    for before, after in zip(
        clean,
        corrupted,
    ):
        assert (
            before["record_id"]
            == after["record_id"]
        )

        assert (
            before["entity_id"]
            == after["entity_id"]
        )

        assert (
            before["_entity_index"]
            == after["_entity_index"]
        )

        assert (
            before["_record_index"]
            == after["_record_index"]
        )

        assert (
            before["_split"]
            == after["_split"]
        )

        assert 0 <= len(
            after["_corruptions"]
        ) <= 4

        assert len(
            after["_corruptions"]
        ) == len(
            set(after["_corruptions"])
        )


def evaluate_corpus_invariants(
    train_entities: list[dict[str, object]],
    test_entities: list[dict[str, object]],
    train_records: list[dict[str, object]],
    test_records: list[dict[str, object]],
) -> dict[str, bool]:
    train_ids = {
        str(entity["entity_id"])
        for entity in train_entities
    }

    test_ids = {
        str(entity["entity_id"])
        for entity in test_entities
    }

    test_full_names: dict[
        tuple[str, str],
        set[str],
    ] = {}

    test_emails: dict[
        str,
        set[str],
    ] = {}

    test_tags = set()

    for entity in test_entities:
        entity_id = str(
            entity["entity_id"]
        )

        name = (
            str(entity["first_name"]),
            str(entity["last_name"]),
        )

        test_full_names.setdefault(
            name,
            set(),
        ).add(entity_id)

        test_emails.setdefault(
            str(entity["email"]),
            set(),
        ).add(entity_id)

        test_tags.update(
            str(tag)
            for tag in entity[
                "collision_tags"
            ]
        )

    all_records = (
        list(train_records)
        + list(test_records)
    )

    public_test_label_absence = all(
        "entity_id"
        not in {
            key
            for key in row
            if not key.startswith("_")
        }
        - {"entity_id"}
        for row in []
    )

    # Internal in-memory records retain entity_id for
    # generation validation. Public projection is
    # separately constrained to PUBLIC_FIELDS.
    public_projection_has_no_label = (
        "entity_id"
        not in PUBLIC_FIELDS
    )

    identical_full_name_negative = any(
        len(entity_ids) >= 2
        for entity_ids
        in test_full_names.values()
    )

    shared_email_negative = any(
        email
        and len(entity_ids) >= 2
        for email, entity_ids
        in test_emails.items()
    )

    missingness_present = any(
        any(
            str(row[field]) == ""
            for field in [
                "first_name",
                "last_name",
                "city",
                "email",
            ]
        )
        for row in test_records
    )

    unicode_or_transliteration = any(
        (
            "unicode_diacritic_variation"
            in row["_corruptions"]
            or
            "transliteration"
            in row["_corruptions"]
        )
        for row in test_records
    )

    contradictory_evidence = any(
        "contradictory_field_from_collision_peer"
        in row["_corruptions"]
        for row in test_records
    )

    multi_field_hard_negative = (
        "multi_field_hard_negative"
        in test_tags
    )

    nonsemantic_record_id = all(
        str(row["record_id"]).startswith(
            "r-"
        )
        and len(str(row["record_id"])) == 22
        for row in all_records
    )

    entity_ids = [
        str(row["entity_id"])
        for row in all_records
    ]

    record_ids = [
        str(row["record_id"])
        for row in all_records
    ]

    no_numeric_identity_shortcut = (
        len(set(record_ids))
        == len(record_ids)
        and all(
            entity_id.startswith("e-")
            and len(entity_id) == 22
            for entity_id in entity_ids
        )
    )

    return {
        "train_test_entity_disjointness":
            train_ids.isdisjoint(test_ids),

        "public_test_label_absence":
            public_projection_has_no_label,

        "identical_full_name_negative_presence":
            identical_full_name_negative,

        "shared_email_negative_presence":
            shared_email_negative,

        "multi_field_hard_negative_presence":
            multi_field_hard_negative,

        "missingness_presence":
            missingness_present,

        "unicode_or_transliteration_presence":
            unicode_or_transliteration,

        "contradictory_evidence_presence":
            contradictory_evidence,

        "nonsemantic_record_id":
            nonsemantic_record_id,

        "no_numeric_identity_shortcut":
            no_numeric_identity_shortcut,
    }


def build_candidate_in_memory(
    seed: int,
) -> dict[str, object]:
    entities = build_latent_population(
        seed
    )

    entities = apply_collision_groups(
        seed,
        entities,
    )

    train_entities, test_entities = (
        split_latent_entities(
            seed,
            entities,
        )
    )

    clean_train = generate_clean_records(
        seed,
        train_entities,
        "train",
    )

    clean_test = generate_clean_records(
        seed,
        test_entities,
        "test",
    )

    train_records = corrupt_records(
        seed,
        clean_train,
    )

    test_records = corrupt_records(
        seed,
        clean_test,
    )

    invariants = evaluate_corpus_invariants(
        train_entities,
        test_entities,
        train_records,
        test_records,
    )

    return {
        "seed": seed,
        "train_entities": train_entities,
        "test_entities": test_entities,
        "train_records": train_records,
        "test_records": test_records,
        "invariants": invariants,
    }


def select_first_passing_seed(
    seed_schedule: list[int],
) -> tuple[
    int,
    dict[str, object],
]:
    assert seed_schedule == SEED_SCHEDULE

    for seed in seed_schedule:
        candidate = build_candidate_in_memory(
            seed
        )

        invariants = candidate[
            "invariants"
        ]

        if all(invariants.values()):
            return seed, candidate

    raise RuntimeError(
        "no preregistered seed satisfies "
        "all frozen corpus invariants"
    )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--seed",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.seed not in SEED_SCHEDULE:
        raise SystemExit(
            "seed is outside frozen preregistered schedule"
        )

    # Block 1 intentionally stops before corpus generation.
    # Subsequent implementation blocks add:
    #
    # 1. latent identity population
    # 2. collision groups
    # 3. train/test entity split
    # 4. clean records
    # 5. corruption operators
    # 6. invariant verifier
    # 7. deterministic first-passing-seed selection
    #
    # No system adapter or evaluator may be called here.

    raise SystemExit(
        "generator implementation incomplete: "
        "no corpus generated"
    )


if __name__ == "__main__":
    raise SystemExit(main())
