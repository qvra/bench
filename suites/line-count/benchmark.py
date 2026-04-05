import argparse
import json
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

def build_dataset(path: Path, rows: int) -> int:
    with path.open("w", encoding="utf-8", newline="") as f:
        for i in range(rows):
            f.write(f"{i:08d}|qvra|bench|line-count\n")
    return rows

def wc_count(path: Path) -> int:
    out = subprocess.run(
        ["wc", "-l", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return int(out.split()[0])

def py_count(path: Path) -> int:
    with path.open("rb") as f:
        return sum(1 for _ in f)

def timed(fn, path: Path, runs: int):
    times = []
    value = None
    for _ in range(runs):
        t0 = time.perf_counter()
        value = fn(path)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)
    return value, times

def summarize(label: str, times, value: int):
    return {
        "method": label,
        "count": value,
        "avg_ms": round(statistics.mean(times), 3),
        "stdev_ms": round(statistics.pstdev(times), 3),
        "min_ms": round(min(times), 3),
        "max_ms": round(max(times), 3),
        "runs": len(times),
    }

def table(rows):
    headers = ["method", "count", "avg_ms", "stdev_ms", "min_ms", "max_ms", "runs"]
    widths = {h: max(len(h), *(len(str(r[h])) for r in rows)) for h in headers}
    line = " | ".join(h.ljust(widths[h]) for h in headers)
    sep = "-+-".join("-" * widths[h] for h in headers)
    body = [" | ".join(str(r[h]).ljust(widths[h]) for h in headers) for r in rows]
    return "\n".join([line, sep, *body])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=200000)
    ap.add_argument("--runs", type=int, default=7)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="qvra-bench-") as td:
        path = Path(td) / "dataset.txt"
        expected = build_dataset(path, args.rows)

        wc_value, wc_times = timed(wc_count, path, args.runs)
        py_value, py_times = timed(py_count, path, args.runs)

        if wc_value != expected or py_value != expected or wc_value != py_value:
            raise SystemExit("count mismatch")

        rows = [
            summarize("wc -l", wc_times, wc_value),
            summarize("python-iter", py_times, py_value),
        ]

        payload = {
            "dataset_rows": expected,
            "dataset_path_kind": "temporary-generated",
            "results": rows,
        }

        print(f"dataset_rows: {expected}")
        print(table(rows))
        print()
        print(json.dumps(payload, indent=2))

main()
