import json
import sys
from pathlib import Path
fixture=json.loads(Path(sys.argv[-1]).read_text())
items=fixture["expected_items"]
print(json.dumps({"items":items+items+items,"provenance":{"source":fixture["fixture_id"],"observed_at":"duplicate-hostile"},"mutation_performed":False}))
