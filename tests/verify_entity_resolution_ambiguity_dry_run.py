#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

MANIFEST = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-dry-run-v1.json"
)

SCHEMA = (
    ROOT
    / "schemas"
    / "entity-resolution-ambiguity-dry-run.schema.json"
)

RUNTIME = (
    ROOT
    / "protocols"
    / "runtime-v1.json"
)

PREREG = (
    ROOT
    / "protocols"
    / "entity-resolution-ambiguity-v1.json"
)

REGISTRY = (
    ROOT
    / "challengers"
    / "registry.json"
)


def digest(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


d = json.loads(
    MANIFEST.read_text(
        encoding="utf-8"
    )
)

runtime = json.loads(
    RUNTIME.read_text(
        encoding="utf-8"
    )
)

prereg = json.loads(
    PREREG.read_text(
        encoding="utf-8"
    )
)

registry = json.loads(
    REGISTRY.read_text(
        encoding="utf-8"
    )
)


# --------------------------------------------------
# Core identity
# --------------------------------------------------

assert d["schema"] == \
    "qvra-family-2-dry-run/v1"

assert d["benchmark_family"] == \
    "entity-resolution-ambiguity-v1"

assert d["benchmark_main"] == \
    "f55da9d228619b8a61f3c3ea1e3a689cfe72e80d"


# --------------------------------------------------
# Governed source bindings
# --------------------------------------------------

for name, binding in d["bindings"].items():
    path = ROOT / binding["path"]

    assert path.is_file(), (
        name,
        binding["path"],
    )

    assert digest(path) == \
        binding["sha256"], name


# --------------------------------------------------
# Real adapter bindings
# --------------------------------------------------

expected_adapters = {
    "qvra-native-er-v1": (
        "adapters/native/qvra_er_v1.py",
        "cd51eff4b0ffddbac5e96b360b305183dcf365e7eaf7a117df8bf01cff489a42",
    ),

    "splink-4.0.17": (
        "adapters/external/splink_v4.py",
        "8d08f2cc92dd3404c89c3e9de6e010003705b4e988905916bb05ddf39fcedf77",
    ),

    "dedupe-3.0.3": (
        "adapters/external/dedupe_v3.py",
        "798dce2e5ca90a9f4cf8fbe309d4c6c7aeddb415e098267975ab2c41b3da80d4",
    ),
}

assert set(d["systems"]) == \
    set(expected_adapters)

for system_id, (
    path,
    expected_sha,
) in expected_adapters.items():

    system = d["systems"][system_id]

    assert system["adapter"] == path
    assert system["adapter_sha256"] == \
        expected_sha

    assert digest(ROOT / path) == \
        expected_sha


# --------------------------------------------------
# Runtime cross-binding
# --------------------------------------------------

rp = d["runtime_policy"]

assert rp["implementation"] == \
    runtime["python"]["implementation"]

assert rp["python_major_minor"] == \
    runtime["python"]["major_minor"]

assert rp["observed_version"] == \
    runtime["python"]["observed_version"]

assert rp["package_versions_exact"] == \
    runtime["policy"]["package_versions_exact"]

assert rp["same_python_major_minor"] == \
    runtime["policy"]["same_python_major_minor"]

assert rp["isolated_virtual_environments"] == \
    runtime["policy"]["isolated_virtual_environments"]

assert rp["dependency_freeze_retained"] == \
    runtime["policy"]["dependency_freeze_retained"]


splink_runtime = runtime[
    "challengers"
]["splink-4.0.17"]

manifest_splink = d[
    "systems"
]["splink-4.0.17"]["runtime"]

assert manifest_splink["package"] == \
    splink_runtime["package"]

assert manifest_splink["package_version"] == \
    splink_runtime["version"]


dedupe_runtime = runtime[
    "challengers"
]["dedupe-3.0.3"]

manifest_dedupe = d[
    "systems"
]["dedupe-3.0.3"]["runtime"]

assert manifest_dedupe["package"] == \
    dedupe_runtime["package"]

assert manifest_dedupe["package_version"] == \
    dedupe_runtime["version"]

assert (
    manifest_dedupe[
        "compatibility_dependencies"
    ]["BTrees"]
    ==
    dedupe_runtime[
        "compatibility_dependencies"
    ]["BTrees"]["version"]
)


# --------------------------------------------------
# Preregistration cross-binding
# --------------------------------------------------

systems = prereg["systems"]

assert systems["qvra"]["system_id"] == \
    "qvra-native-er-v1"

assert systems["qvra"][
    "implementation_sha256"
] == expected_adapters[
    "qvra-native-er-v1"
][1]

assert systems["qvra"][
    "retuning_allowed"
] is False

assert systems["splink"]["system_id"] == \
    "splink-4.0.17"

assert systems["splink"]["version"] == \
    "4.0.17"

assert systems["splink"][
    "retuning_allowed"
] is False

assert systems["dedupe"]["system_id"] == \
    "dedupe-3.0.3"

assert systems["dedupe"]["version"] == \
    "3.0.3"

assert systems["dedupe"][
    "compatibility_binding"
] == "BTrees==6.4"

assert systems["dedupe"][
    "retuning_allowed"
] is False


# --------------------------------------------------
# Registry cross-binding
# --------------------------------------------------

registry_items = {
    item["system_id"]: item
    for item in registry["challengers"]
}

for system_id in (
    "splink-4.0.17",
    "dedupe-3.0.3",
):
    item = registry_items[system_id]

    assert item["adapter"]["sha256"] == \
        expected_adapters[system_id][1]

    execution = item["execution"]

    assert execution[
        "mutation_allowed"
    ] is False

    assert execution[
        "network_required"
    ] is False

    assert execution[
        "credentials_required"
    ] is False


# --------------------------------------------------
# Exact nine-run matrix
# --------------------------------------------------

runs = d["runs"]

assert len(runs) == 9

expected_pairs = {
    (system, run)
    for system in (
        "qvra-native-er-v1",
        "splink-4.0.17",
        "dedupe-3.0.3",
    )
    for run in (1, 2, 3)
}

actual_pairs = {
    (
        item["system_id"],
        item["run"],
    )
    for item in runs
}

assert actual_pairs == expected_pairs


# --------------------------------------------------
# Input + artifact firewall
# --------------------------------------------------

artifacts = []

for item in runs:
    assert item["inputs"] == {
        "train": "train.csv",
        "test": "test.csv",
    }

    assert "truth.json" not in \
        item["inputs"].values()

    artifacts.extend(
        item["artifacts"].values()
    )

assert len(artifacts) == 27
assert len(set(artifacts)) == 27

assert all(
    "truth.json" not in path
    for path in artifacts
)


# --------------------------------------------------
# Execution firewall
# --------------------------------------------------

firewall = d["firewall"]

assert firewall[
    "truth_input_allowed"
] is False

assert firewall[
    "retuning_allowed"
] is False

assert firewall[
    "network_required"
] is False

assert firewall[
    "credentials_required"
] is False

assert firewall[
    "raw_runs_required_before_scoring"
] == 9

assert firewall[
    "raw_outputs_hash_bound_before_truth_reveal"
] is True


# --------------------------------------------------
# State must remain pre-execution
# --------------------------------------------------

assert d["state"] == {
    "comparison_performed": False,
    "dry_run_only": True,
    "execution_capability": False,
    "quality_result_available": False,
    "raw_runs_produced": 0,
    "system_execution": False,
    "truth_scoring": False,
}


print("FAMILY_2_DRY_RUN_MANIFEST=PASS")
print("GOVERNED_BINDINGS=PASS")
print("REAL_ADAPTER_BINDING=PASS")
print("RUNTIME_CROSS_BINDING=PASS")
print("PREREGISTRATION_CROSS_BINDING=PASS")
print("REGISTRY_CROSS_BINDING=PASS")
print("NINE_RUN_MATRIX=PASS")
print("RAW_ARTIFACT_PATHS=27")
print("SYSTEM_TRUTH_ACCESS=false")
print("RETUNING=false")
print("EXECUTION_CAPABILITY=false")
print("RAW_RUNS_PRODUCED=0")
print("SYSTEM_EXECUTION=false")
print("TRUTH_SCORING=false")
