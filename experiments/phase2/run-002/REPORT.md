# Phase 2 extraction and leakage report

Shared extraction and temporal dataset construction completed on the audited two-file UNSW excerpt. No model was trained. The dataset remains provisional; independent evaluation and complete family support are not established.

The fixed Phase 1 chronological ranges were saved before extraction. Both original files and both endpoint views retain the same source group. This is explicitly within-group evaluation; it does not meet an independent-session split.

| Partition | Endpoint-seconds | Benign samples | Reconnaissance samples | DoS samples |
| --- | ---: | ---: | ---: | ---: |
| train | 32,967 | 6,433 | 19 | 5 |
| validation | 10,982 | 2,173 | 5 | 0 |
| internal_test | 11,016 | 2,501 | 11 | 1 |

Raw packet records: 3,415,660. Retained observations: 1,708,290. Identified forwarded copies removed: 1,707,370. All receive observations and genuine retransmissions are retained.

Emitted endpoint-seconds: 55,033; retained eight-row samples: 11,148. Preprocessing uses 11,357 unique windows appearing in training samples, once each, with log1p and population standard deviation. Held-out rows never enter the fit.

Exclusions are counted by primary reason below; coverage reasons and label certainty remain separate columns in windows.parquet. A final label never propagates through the earlier seven seconds.

| Primary exclusion | Endpoint-seconds |
| --- | ---: |
| crossing_connection | 1,667 |
| history_warmup | 19,174 |
| invalid_capture | 17,808 |
| out_of_scope_family | 3,228 |
| unassigned_capture_edge | 68 |
| unknown_final_label | 1,940 |

Every pair of sample partitions has zero shared window IDs and zero shared conservative connection IDs after purging complete affected windows. Connection IDs group bidirectional tuples conservatively, including reuse. All annotated boundary-crossing connections are also purged. The first seven final seconds in each new partition cannot form a sample. Source-group overlap remains disclosed because all data came from one source group.

Capture validity is independent of label availability. Supported ICMP contributes to v1 features; it can still have an unknown label. Silent rows in these files are not certified healthy without capture-health evidence. In a declared healthy adapter interval, silent seconds produce valid zero rows. Partial edges, observed gaps, BRO missed-byte reports, unsupported packets and malformed packets reset histories. Inactive devices stop emitting full rows after 60 seconds and require eight fresh rows on reactivation.

Remaining limitations:

- Only one connected original capture group; evaluation is within-group, not independent.
- Original provider session and device IDs are unavailable and remain null.
- Physical sensor drop counters are unavailable; coverage is observational.
- validation has no retained dos samples.

The original PCAPs were read in place; temporary sorted runs were removed automatically. Additional provider captures could not be fetched without Microsoft sign-in. External datasets and threshold calibration remain untouched. No performance claim or training readiness is inferred from this run.

Reproduce with `python -m ids.datasets.build_temporal --output NEW_DIRECTORY`. See `docs/phase2.md` for setup, shared gateway APIs, fixture calculations and tests.
