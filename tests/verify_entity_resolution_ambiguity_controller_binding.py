#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

ATTEST = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-controller-binding-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-controller-binding.schema.json"
)

AUTHORIZATION = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-execution-authorization-v1.json"
)

CONTROLLER = (
    ROOT
    / "suites"
    / "entity-resolution-ambiguity-v1"
    / "execution_controller.py"
)

EXPECTED_AUTHORIZATION_SHA256 = (
    "30890b1ac027caf4c3175e6c602581ad"
    "3c9e544d932435bff045884b795e5728"
)

EXPECTED_CONTROLLER_SHA256 = (
    "2b9e0026ed756468432c8d07edca9ebc"
    "49ef3b727defbc39f3b55cb9319d9661"
)

EXPECTED_PLAN_SHA256 = (
    "df1fbeab0a2c89c16fb9530aaf4f5545"
    "d62a4dab3f44f160dacdc231a3463ac7"
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def validate_schema_subset(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
) -> None:
    if "const" in schema:
        assert value == schema["const"], (
            path,
            value,
            schema["const"],
        )

    expected_type = schema.get("type")

    if expected_type == "object":
        assert isinstance(value, dict), (
            path,
            type(value),
        )

        required = schema.get(
            "required",
            [],
        )

        for key in required:
            assert key in value, (
                path,
                key,
            )

        properties = schema.get(
            "properties",
            {},
        )

        if (
            schema.get(
                "additionalProperties"
            )
            is False
        ):
            assert set(value) <= set(
                properties
            ), (
                path,
                sorted(
                    set(value)
                    - set(properties)
                ),
            )

        for key, child in value.items():
            if key in properties:
                validate_schema_subset(
                    child,
                    properties[key],
                    f"{path}.{key}",
                )


attestation = load_json(ATTEST)
schema = load_json(SCHEMA)

validate_schema_subset(
    attestation,
    schema,
)

assert (
    sha256_file(AUTHORIZATION)
    == EXPECTED_AUTHORIZATION_SHA256
)

assert (
    sha256_file(CONTROLLER)
    == EXPECTED_CONTROLLER_SHA256
)

authorization_binding = attestation[
    "authorization"
]

assert (
    authorization_binding["sha256"]
    == EXPECTED_AUTHORIZATION_SHA256
)

assert (
    authorization_binding[
        "immutable_input"
    ]
    is True
)

controller_binding = attestation[
    "controller"
]

assert (
    controller_binding["sha256"]
    == EXPECTED_CONTROLLER_SHA256
)

assert (
    controller_binding["reviewed"]
    is True
)

plan_binding = attestation["plan"]

assert (
    plan_binding["sha256"]
    == EXPECTED_PLAN_SHA256
)

assert (
    plan_binding[
        "portable_identity"
    ]
    is True
)

binding_semantics = attestation[
    "binding_semantics"
]

assert (
    binding_semantics["direction"]
    == "authorization_and_controller_to_attestation"
)

assert (
    binding_semantics[
        "authorization_mutated"
    ]
    is False
)

assert (
    binding_semantics[
        "controller_mutated"
    ]
    is False
)

assert (
    binding_semantics[
        "controller_binding_recorded"
    ]
    is True
)

firewall = attestation[
    "execution_firewall"
]

assert (
    firewall[
        "authorization_consumable"
    ]
    is False
)

assert (
    firewall[
        "execution_authorized"
    ]
    is False
)

assert (
    firewall[
        "authorization_consumed"
    ]
    is False
)

assert firewall[
    "raw_runs_produced"
] == 0

assert (
    firewall[
        "system_execution"
    ]
    is False
)

assert (
    firewall[
        "truth_scoring"
    ]
    is False
)

assert (
    firewall[
        "quality_result_available"
    ]
    is False
)

# The source authorization is immutable input,
# not a mutable downstream binding record.
source_authorization = load_json(
    AUTHORIZATION
)

source_binding = source_authorization[
    "controller_binding"
]

assert (
    source_binding[
        "execution_controller_created"
    ]
    is False
)

assert (
    source_binding[
        "execution_controller_sha256"
    ]
    is None
)

assert (
    source_binding[
        "authorization_consumable"
    ]
    is False
)

source_state = source_authorization[
    "state"
]

assert (
    source_state[
        "execution_authorized"
    ]
    is False
)

assert (
    source_state[
        "authorization_consumed"
    ]
    is False
)

assert source_state[
    "raw_runs_produced"
] == 0

assert (
    source_state[
        "system_execution"
    ]
    is False
)

assert (
    source_state[
        "truth_scoring"
    ]
    is False
)

assert (
    source_state[
        "quality_result_available"
    ]
    is False
)

# Independently reproduce the reviewed plan.
spec = importlib.util.spec_from_file_location(
    "qvra_binding_attestation_controller",
    CONTROLLER,
)

assert spec is not None
assert spec.loader is not None

module = importlib.util.module_from_spec(
    spec
)

sys.modules[
    spec.name
] = module

spec.loader.exec_module(
    module
)

with tempfile.TemporaryDirectory(
    prefix="qvra-binding-attestation-"
) as temporary:
    temp = Path(temporary)

    corpus = temp / "corpus"
    raw = temp / "raw"

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

    before = sorted(
        p.relative_to(temp).as_posix()
        for p in temp.rglob("*")
        if p.is_file()
    )

    plan = module.build_plan(
        repo_root=ROOT,
        corpus_root=corpus,
        raw_root=raw,
    )

    observed_plan_sha = (
        module.plan_sha256(
            plan
        )
    )

    after = sorted(
        p.relative_to(temp).as_posix()
        for p in temp.rglob("*")
        if p.is_file()
    )

assert before == after

assert (
    observed_plan_sha
    == EXPECTED_PLAN_SHA256
)

assert len(plan.runs) == 9

assert (
    plan.authorization_consumable
    is False
)

assert (
    plan.execution_authorized
    is False
)

for run in plan.runs:
    assert "truth.json" not in run.argv

print(
    "FAMILY_2_CONTROLLER_BINDING_ATTESTATION=PASS"
)
print(
    "STRICT_SCHEMA_VALIDATION=PASS"
)
print(
    "AUTHORIZATION_IDENTITY=PASS"
)
print(
    "CONTROLLER_IDENTITY=PASS"
)
print(
    "PORTABLE_PLAN_IDENTITY=PASS"
)
print(
    "DOWNSTREAM_BINDING_DIRECTION=PASS"
)
print(
    "AUTHORIZATION_MUTATION=false"
)
print(
    "CONTROLLER_MUTATION=false"
)
print(
    "AUTHORIZATION_CONSUMABLE=false"
)
print(
    "EXECUTION_AUTHORIZED=false"
)
print(
    "AUTHORIZATION_CONSUMED=false"
)
print(
    "SYSTEM_TRUTH_ACCESS=false"
)
print(
    "RAW_RUNS_PRODUCED=0"
)
print(
    "SYSTEM_EXECUTION=false"
)
print(
    "TRUTH_SCORING=false"
)
