from __future__ import annotations

import json
import sys
from pathlib import Path

from qvra_bench.kernel import verify_result_capsule


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "usage: python3 -m qvra_bench.verify CAPSULE.json",
            file=sys.stderr,
        )
        return 2

    path = Path(sys.argv[1])

    try:
        capsule = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "reason": "CAPSULE_UNREADABLE",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1

    result = verify_result_capsule(capsule)

    print(
        json.dumps(
            result,
            sort_keys=True,
        )
    )

    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
