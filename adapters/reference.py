from __future__ import annotations

import json
import sys
from pathlib import Path

fixture_path = Path(sys.argv[-1])
fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

print(json.dumps({
    "items": fixture["expected_items"],
    "provenance": {
        "source": fixture["fixture_id"],
        "observed_at": "controlled-fixture",
    },
    "mutation_performed": False,
}, sort_keys=True))
