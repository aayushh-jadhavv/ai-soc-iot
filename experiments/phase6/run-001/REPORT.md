# Phase 6 export and validation

The Phase 5 selection **ga_3** carries forward as **float32**. Its INT8 decision records calibration_coverage. The program and checksum are in [the handoff](handoff.json).

All 7 frozen checkpoints used the fixed batch-one input and their original weights. The 965 development histories contain 1 attack example(s) across 1 source group(s). Independent held-out development groups total 0. The comparisons use the Phase 5 score rule, float64 sigmoid of the float32 logit with a positive decision at 0.5 or above.

## Export sizes, warm runtime and development agreement

| Checkpoint | Precision | PTE bytes | p50 µs | p95 µs | Max score error vs eager | Crossings / rows | Recall | Macro-F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| unpruned | float32 | 42,756 | 10.559 | 12.792 | 1.801418e-07 | 0 / 965 | 1.0000 | 0.641557 |
| unpruned | int8 | 18,564 | 9.707 | 16.207 | 0.03546796 | 0 / 965 | 1.0000 | 0.641557 |
| direct_small_seed_1729 | float32 | 18,052 | 7.635 | 13.484 | 8.084596e-08 | 0 / 965 | 1.0000 | 0.563272 |
| direct_small_seed_1729 | int8 | 12,036 | 7.594 | 10.499 | 0.03907138 | 1 / 965 | 1.0000 | 0.558843 |
| direct_small_seed_2718 | float32 | 18,052 | 7.684 | 13.349 | 4.667752e-08 | 0 / 965 | 1.0000 | 0.532159 |
| direct_small_seed_2718 | int8 | 12,036 | 7.802 | 9.004 | 0.00531847 | 0 / 965 | 1.0000 | 0.532159 |
| direct_small_seed_31415 | float32 | 18,052 | 7.710 | 11.881 | 1.232062e-07 | 0 / 965 | 1.0000 | 0.580726 |
| direct_small_seed_31415 | int8 | 12,036 | 7.695 | 8.905 | 0.04257032 | 0 / 965 | 1.0000 | 0.580726 |
| ga_1 | float32 | 15,236 | 7.682 | 13.262 | 4.845274e-08 | 0 / 965 | 1.0000 | 0.749481 |
| ga_1 | int8 | 11,396 | 7.540 | 8.597 | 0.02085415 | 0 / 965 | 1.0000 | 0.749481 |
| ga_2 | float32 | 15,876 | 7.534 | 8.341 | 5.252515e-08 | 0 / 965 | 1.0000 | 0.749481 |
| ga_2 | int8 | 11,652 | 7.637 | 8.577 | 0.01712106 | 0 / 965 | 1.0000 | 0.749481 |
| ga_3 | float32 | 15,236 | 7.734 | 13.479 | 5.582708e-08 | 0 / 965 | 1.0000 | 0.699221 |
| ga_3 | int8 | 11,396 | 7.756 | 9.246 | 0.01197309 | 0 / 965 | 1.0000 | 0.699221 |

Python timed the loaded ExecuTorch forward method on prebuilt input tuples in the x86-64 Linux VM. Each of three repeats per artifact used 100 warmups and 1,000 timed calls, cycling through the development inputs. The table gives the median of the three repeat p50s and p95s. Program/method load times, repeat order and raw nanoseconds are in [the benchmark](benchmark_summary.json) and [timing samples](timing_samples.csv). Process resource samples cover export and numerical evaluation. The monitor stopped before timing. These costs exclude preprocessing and service overhead.

## PTQ calibration and acceptance

The seed-1729 observer sample contains 88 unique training IDs from 6,457 eligible histories. At most 32 were sampled per stratum. The benign burst cutoff was 289.0 packets in the final second. The shuffled observer order and original tensor indices are in [the calibration manifest](calibration.json).

| Training stratum | Available | Used by observers |
| --- | ---: | ---: |
| attack/dos | 5 | 5 |
| attack/reconnaissance | 19 | 19 |
| benign_burst | 644 | 32 |
| benign_other | 5789 | 32 |
| idle | 0 | 0 |

The training data contains 0 benign histories with any zero-packet second. Representative idle calibration is unavailable. INT8 results are diagnostic. The synthetic healthy-idle contract fixture used the frozen training transform and ran only in the reference checks.

The registered score tolerance for each INT8 program uses the earlier third of distinct development end times. The observed maximum absolute eager/runtime score difference is rounded up on a 0.001 grid, with a 0.001 floor and 0.05 ceiling. Each tolerance was saved before running the remaining INT8 development rows. Later checks exclude histories sharing a window with the prefix. All rows, including the boundary rows and the separate idle fixture, also face the registered bound. The float32 limit is 0.0001.

| Checkpoint | INT8 tolerance | Later check max | All references max | Recall loss vs float | Macro-F1 loss vs float | INT8 decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| unpruned | 0.024 | 0.035468 | 0.035468 | 0.0000 | 0.000000 | calibration_coverage, numerical, measured_value |
| direct_small_seed_1729 | 0.040 | 0.0169318 | 0.0390714 | 0.0000 | 0.004430 | phase5_quality_eligible, calibration_coverage, unpruned_quality |
| direct_small_seed_2718 | 0.005 | 0.00531847 | 0.00531847 | 0.0000 | 0.000000 | phase5_quality_eligible, calibration_coverage, numerical, unpruned_quality |
| direct_small_seed_31415 | 0.043 | 0.0212947 | 0.0425703 | 0.0000 | 0.000000 | phase5_quality_eligible, calibration_coverage, unpruned_quality |
| ga_1 | 0.013 | 0.0208542 | 0.0208542 | 0.0000 | 0.000000 | calibration_coverage, numerical |
| ga_2 | 0.018 | 0.0146627 | 0.0171211 | 0.0000 | 0.000000 | calibration_coverage |
| ga_3 | 0.012 | 0.0119731 | 0.0119731 | 0.0000 | 0.000000 | calibration_coverage |

Acceptance requires both recall and macro-F1 losses to be at most 0.01 against the matching float32 runner and 0.02 against the unpruned float32 runner. Phase 5 quality eligibility carries forward. Measured value requires a smaller program with p50 and p95 each within 5% of float32, or an equal-size program with both at least 5% faster. Ratios and each gate outcome appear in [the summary](summary.json).

## Operator precision and fallback

- **float32**. XNNConv2d (fp32 input, fp32 weights, fp32 bias, fp32 output). XNNFullyConnected (fp32 input, fp32 weights, fp32 bias, fp32 output). Portable fallback kernels observed were aten::mean.out (FLOAT, FLOAT, FLOAT).
- **int8**. XNNConv2d (qint8 input, qcint8 weights, qcint32 bias, qint8 output). XNNFullyConnected (qint8 input, qcint8 weights, qcint32 bias, qint8 output). Portable fallback kernels observed were aten::mean.out (FLOAT, FLOAT, FLOAT).

The exported ATen graph retains the two Conv1d layers. The pinned backend represents their convolutions internally as XNNConv2d. Each delegation record decodes the actual serialized XNNPACK operator operands and lists the portable execution-plan calls and tensor dtypes.

## Per-family development decisions

| Checkpoint | Precision | Family | Rows | Positive decisions | Positive rate |
| --- | --- | --- | ---: | ---: | ---: |
| unpruned | float32 | benign | 964 | 5 | 0.00519 |
| unpruned | float32 | dos | 0 | — | — |
| unpruned | float32 | reconnaissance | 1 | 1 | 1.00000 |
| unpruned | int8 | benign | 964 | 5 | 0.00519 |
| unpruned | int8 | dos | 0 | — | — |
| unpruned | int8 | reconnaissance | 1 | 1 | 1.00000 |
| direct_small_seed_1729 | float32 | benign | 964 | 13 | 0.01349 |
| direct_small_seed_1729 | float32 | dos | 0 | — | — |
| direct_small_seed_1729 | float32 | reconnaissance | 1 | 1 | 1.00000 |
| direct_small_seed_1729 | int8 | benign | 964 | 14 | 0.01452 |
| direct_small_seed_1729 | int8 | dos | 0 | — | — |
| direct_small_seed_1729 | int8 | reconnaissance | 1 | 1 | 1.00000 |
| direct_small_seed_2718 | float32 | benign | 964 | 24 | 0.02490 |
| direct_small_seed_2718 | float32 | dos | 0 | — | — |
| direct_small_seed_2718 | float32 | reconnaissance | 1 | 1 | 1.00000 |
| direct_small_seed_2718 | int8 | benign | 964 | 24 | 0.02490 |
| direct_small_seed_2718 | int8 | dos | 0 | — | — |
| direct_small_seed_2718 | int8 | reconnaissance | 1 | 1 | 1.00000 |
| direct_small_seed_31415 | float32 | benign | 964 | 10 | 0.01037 |
| direct_small_seed_31415 | float32 | dos | 0 | — | — |
| direct_small_seed_31415 | float32 | reconnaissance | 1 | 1 | 1.00000 |
| direct_small_seed_31415 | int8 | benign | 964 | 10 | 0.01037 |
| direct_small_seed_31415 | int8 | dos | 0 | — | — |
| direct_small_seed_31415 | int8 | reconnaissance | 1 | 1 | 1.00000 |
| ga_1 | float32 | benign | 964 | 2 | 0.00207 |
| ga_1 | float32 | dos | 0 | — | — |
| ga_1 | float32 | reconnaissance | 1 | 1 | 1.00000 |
| ga_1 | int8 | benign | 964 | 2 | 0.00207 |
| ga_1 | int8 | dos | 0 | — | — |
| ga_1 | int8 | reconnaissance | 1 | 1 | 1.00000 |
| ga_2 | float32 | benign | 964 | 2 | 0.00207 |
| ga_2 | float32 | dos | 0 | — | — |
| ga_2 | float32 | reconnaissance | 1 | 1 | 1.00000 |
| ga_2 | int8 | benign | 964 | 2 | 0.00207 |
| ga_2 | int8 | dos | 0 | — | — |
| ga_2 | int8 | reconnaissance | 1 | 1 | 1.00000 |
| ga_3 | float32 | benign | 964 | 3 | 0.00311 |
| ga_3 | float32 | dos | 0 | — | — |
| ga_3 | float32 | reconnaissance | 1 | 1 | 1.00000 |
| ga_3 | int8 | benign | 964 | 3 | 0.00311 |
| ga_3 | int8 | dos | 0 | — | — |
| ga_3 | int8 | reconnaissance | 1 | 1 | 1.00000 |

The positive rate is the false-positive rate for benign rows and detection recall for attack-family rows. An em dash indicates zero support. Overall confusion counts, precision, recall, macro-F1, tied-score average precision and each supported family versus benign are in each program's comparison.json.

## Threshold disagreement review

Across the exports, 1 program/input pairs had a decision change between any recorded stages. For each pair, threshold_crossings.json records the sample ID, binary label when available, signed margins and decisions from a second batch-one execution. It identifies whether conversion or subsequent backend execution changed the side of the threshold. Each program's references.parquet joins logits and scores to shared/reference_tensors.npy by reference_index.

Only training and model-selection development outcomes were accessed. The threshold reserve, internal test and external tests stayed sealed. The single development attack and shared source group limit recall and generalization claims. The handoff carries the comparison threshold and leaves the deployment threshold unset.
