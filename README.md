# bench

Argument engine for `qvra`.

`bench` exists to create constrained comparison, reproducible measurement, and technical pressure.
It is where claims get tested in public.

## What belongs here

Artifacts in `bench` should provide one or more of:
- benchmark harnesses
- reproducible comparisons
- methodology notes
- challenger slots
- before/after evaluation
- reference measurements worth citing

## What does not belong here

`bench` is not:
- marketing theater
- vague faster-than claims without method
- screenshots of results with no way to reproduce them
- prestige signaling through numbers alone

## Anchor standard

Anything promoted into `bench` should satisfy these:
- explicit scope
- explicit comparison target or baseline
- explicit method
- outputs that can be checked
- a reason the result matters

## Current role in qvra

`bench` is one of the gravitational anchors.
It creates discussion, links, credibility, retesting, and technical argument under pressure.

Related routes:
- [`run`](https://github.com/qvra/run) for utility surfaces users can touch directly
- [`lab`](https://github.com/qvra/lab) for experiments that may later deserve measurement
- [`show`](https://github.com/qvra/show) for visible demos of what is being measured
- [`pulse`](https://github.com/qvra/pulse) for the public rhythm of what changed

## Publication rule

No benchmark belongs here unless the method is strong enough that disagreement can become productive instead of theatrical.

## First live suite

- [`suites/line-count`](./suites/line-count) — reproducible comparison between `wc -l` and pure Python line counting on generated input

## Status

Active anchor surface.
