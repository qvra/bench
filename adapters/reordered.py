import json
import sys
from pathlib import Path
fixture=json.loads(Path(sys.argv[-1]).read_text())
items=list(reversed(fixture["expected_items"]))
print(json.dumps({"items":items,"provenance":{"source":fixture["fixture_id"],"observed_at":"reordered-hostile"},"mutation_performed":False}))
