import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REPORT = (
    ROOT
    / "reports"
    / "entity-resolution-benchmark-v1.md"
)

MANIFEST = (
    ROOT
    / "reports"
    / "entity-resolution-benchmark-v1.manifest.json"
)

CAPSULE = (
    ROOT
    / "evidence"
    / "three-system-comparison"
    / "capsule-v1.json"
)

manifest = json.loads(
    MANIFEST.read_text(
        encoding="utf-8"
    )
)

capsule = json.loads(
    CAPSULE.read_text(
        encoding="utf-8"
    )
)

actual_report_sha = hashlib.sha256(
    REPORT.read_bytes()
).hexdigest()

assert manifest["schema"] == (
    "qvra-publication-report-manifest/v1"
)

assert manifest["report_sha256"] == actual_report_sha

assert manifest["comparison_sha256"] == (
    capsule["comparison_sha256"]
)

assert manifest["publication_status"] == "UNPUBLISHED"

assert manifest["global_superiority_claim"] is False
assert manifest["cross_suite_generalization"] is False

text = REPORT.read_text(
    encoding="utf-8"
)

required_phrases = [
    "Status: UNPUBLISHED",
    "entity-resolution-real-v3",
    "QVRA native ER v1",
    "Splink 4.0.17",
    "Dedupe 3.0.3",
    "0.991664",
    "0.249732",
    "0.123896",
    "0.971429",
    "0.062857",
    "0.091429",
    "same corpus",
    "sealed truth",
    "lossless representation bridge",
    "does not establish",
    "global superiority",
    "Publication status:",
    "UNPUBLISHED",
]

for phrase in required_phrases:
    assert phrase in text, phrase

print("PUBLICATION_REPORT_V1=PASS")
print("REPORT_HASH_BINDING=PASS")
print("COMPARISON_BINDING=PASS")
print("CLAIM_BOUNDARY=PASS")
print("PUBLICATION_STATUS=UNPUBLISHED")
