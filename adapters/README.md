# Cross-system adapter contract

Every implementation is a challenger, including qvra-owned systems.

The harness supplies one fixture path as the final command argument.

The challenger MUST emit exactly one JSON object to stdout:

```json
{"items":["stable-id"],"provenance":{"source":"source-id","observed_at":"observation-id"},"mutation_performed":false}
```

Required semantics:

- `items` contains stable result identifiers.
- `provenance.source` identifies the evidence source or controlled fixture.
- `provenance.observed_at` identifies the observation boundary.
- `mutation_performed` truthfully declares whether the run changed external state.
- diagnostic output belongs on stderr.
- credentials and secrets MUST NOT appear in stdout or benchmark capsules.
- the harness does not repair malformed challenger output.
- the harness does not grant qvra implementations privileged scoring.
- timeout, invalid JSON, missing provenance and mutations remain measurable failures.
