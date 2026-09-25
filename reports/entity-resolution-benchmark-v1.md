# QVRA Entity Resolution Benchmark Report v1

**Status: UNPUBLISHED — governed review candidate**

## Executive result

This report records a suite-specific comparative result for `entity-resolution-real-v3`. It does not establish global superiority across entity-resolution workloads.

| Metric (three-run mean) | QVRA native ER v1 | Splink 4.0.17 | Dedupe 3.0.3 |
|---|---:|---:|---:|
| Pair precision | 1.000000 | 1.000000 | 0.069706 |
| Pair recall | 0.983466 | 0.142682 | 0.556848 |
| Pair F1 | 0.991664 | 0.249732 | 0.123896 |
| Exact-cluster rate | 0.971429 | 0.062857 | 0.091429 |

## Secondary median view

| Metric (three-run median) | QVRA native ER v1 | Splink 4.0.17 | Dedupe 3.0.3 |
|---|---:|---:|---:|
| Pair precision | 1.000000 | 1.000000 | 0.069542 |
| Pair recall | 0.983466 | 0.142682 | 0.557869 |
| Pair F1 | 0.991664 | 0.249732 | 0.123906 |
| Exact-cluster rate | 0.971429 | 0.062857 | 0.091429 |

## Methodology

- Benchmark suite: `entity-resolution-real-v3`.
- Three runs were used for each system.
- All systems were evaluated against the same corpus and sealed truth.
- The comparison uses the same metric semantics across systems.
- Mean is the primary aggregation; median is retained as a secondary view.
- QVRA's three sealed runs produced identical quality outputs.
- External baseline observations were fixed before the QVRA native implementation.
- QVRA was preregistered before implementation and sealed evaluation.
- QVRA's result was fixed before the three-system comparison was constructed.
- No system was executed during construction of the comparative result.

## Evaluation boundary

QVRA emitted cluster membership in a list-of-clusters representation. Before independent scoring, that output was converted losslessly to the evaluator's `record_id -> cluster_id` representation. The conversion preserved every cluster membership and consumed no test truth.

The evaluator then scored the fixed predictions against the sealed truth. The representation bridge changed format, not clustering semantics.

## Interpretation

On this benchmark, QVRA native ER v1 recorded mean pair precision 1.000000, recall 0.983466, F1 0.991664, and exact-cluster rate 0.971429.

Splink recorded mean pair precision 1.000000, recall 0.142682, F1 0.249732, and exact-cluster rate 0.062857.

Dedupe recorded mean pair precision 0.069706, recall 0.556848, F1 0.123896, and exact-cluster rate 0.091429.

These are descriptive results for this benchmark suite. They should not be interpreted as evidence that any system is globally superior across different datasets, corruption processes, domains, operating constraints, or entity-resolution tasks.

## Reproducibility and provenance

- Governed main commit: `160452dfee7a133e78f63cf15a581672adda4e84`
- Comparison SHA-256: `1713cdb70be7a1948a6e70f0ba169f7791a598fe06e575df9f3d5f9445a604e5`
- External observation SHA-256: `749fc76db8648a3d7ba2fd9afd0a0993e01b1776e67b3c930be0560650b3b3e3`
- QVRA observation SHA-256: `892c67737b3e1df81d972c56474ab53ab61765056b03f1a7b4c67b9430ff9f3c`
- Evaluator SHA-256: `11354bcdafab27ebc0173bd0ba32f234ad2f418ed2e384e2dc43f15d5d7c1f58`
- QVRA implementation SHA-256: `cd51eff4b0ffddbac5e96b360b305183dcf365e7eaf7a117df8bf01cff489a42`
- QVRA preregistration SHA-256: `6952231739c4bb6dcc722af8eb59577cb59d08b39b762fdbd461aff9da233e9f`
- Sealed truth SHA-256: `218763de852e4b9bb27ccf052eb188e832de579ac392c36bcf51f771862ff15b`

## Governance chronology

1. External benchmark protocol was frozen.
2. Splink and Dedupe were executed under the frozen protocol.
3. The external result was independently governed and replicated.
4. QVRA native ER v1 was preregistered before implementation.
5. The QVRA implementation and environment were frozen and independently reviewed.
6. Three sealed QVRA runs were executed without test-truth access.
7. Raw QVRA predictions were hash-bound before scoring.
8. A lossless representation bridge was verified.
9. The frozen independent evaluator revealed QVRA quality.
10. The fixed QVRA observation was compared with the pre-existing external observations.
11. The three-system comparative capsule was independently reviewed and merged to main.

## Limitations

- This report covers one deterministic synthetic benchmark family and therefore does not establish cross-distribution or real-world generalization.
- The external systems and QVRA have different implementation families and may respond differently to other field schemas, noise processes, class distributions, and scale regimes.
- Only metrics retained in the governed external aggregate observation are used for the cross-system comparison.
- Runtime measurements are not used as quality claims here.

## Claim boundary

**Supported:** suite-specific comparative reporting for `entity-resolution-real-v3`.

**Not supported:** global superiority, cross-suite generalization, or universal entity-resolution performance claims.

**Publication status:** UNPUBLISHED.
