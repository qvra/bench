# line-count

First live benchmark suite for `bench`.

This suite compares two ways to count lines in a generated text file:

- `wc -l`
- pure Python iteration

## Why this exists

It is a real, reproducible benchmark surface for `bench`.
It proves that `bench` is no longer only declared and now contains a measurable comparison with explicit scope, explicit method, and visible output.

## Method

The benchmark script:
1. generates a deterministic input file
2. counts lines with `wc -l`
3. counts lines with pure Python iteration
4. repeats both methods across multiple runs
5. prints a result table and a JSON summary
6. writes the latest result to `latest.txt`

## Run

    python3 benchmark.py --rows 200000 --runs 7

## Output

- identical correctness check across both methods
- average timing in milliseconds
- standard deviation
- fastest run
- slowest run

## Notes

This suite is intentionally narrow.
It is not trying to claim universal file-processing superiority.
It establishes the exact benchmark discipline required for future `bench` artifacts:
- deterministic input
- explicit method
- explicit comparison target
- reproducible output
