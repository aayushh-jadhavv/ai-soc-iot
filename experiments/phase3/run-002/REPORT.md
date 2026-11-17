# Phase 3 development training results

Completed 15 registered runs: five variants, seeds 1729, 2718, 31415. No smaller run budget was used. Internal-test, external and reserved-subset outcomes remain unopened.

**This is a provisional within-group experiment, not independent detector validation.** There is one original source group and zero independently held-out development groups. Development has 964 benign samples, one reconnaissance sample and no DoS samples. One positive cannot establish recall, temporal superiority or family generalization.

## Comparison at the fixed selection threshold 0.5

Values summarize each seed's selected checkpoint. Standard deviations are across training seeds, not group-level confidence intervals. All variants use the same 6,457 training and 965 development samples.

| Variant | Parameters | Macro-F1 mean ± sample SD | Attack recall mean | FPR mean | Average precision mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| cnn64_weighted | 9,345 | 0.609346 ± 0.028285 | 1.000000 | 0.007607 | 0.136508 |
| cnn32_weighted | 3,137 | 0.558719 ± 0.024602 | 1.000000 | 0.016252 | 0.086111 |
| logistic128_weighted | 129 | 0.484406 ± 0.001574 | 1.000000 | 0.098548 | 0.305556 |
| last_window_weighted | 9,345 | 0.553643 ± 0.049791 | 0.666667 | 0.007261 | 0.280322 |
| cnn64_unweighted | 9,345 | 0.499741 ± 0.000000 | 0.000000 | 0.000000 | 0.001286 |

All runs use BCEWithLogitsLoss, Adam 0.001, batch 128, maximum 30 epochs and patience five. The earliest strictly best development macro-F1 checkpoint is retained. The logistic comparator uses 128 channel-major flattened normalized inputs; the temporal ablation uses only the final window with the same 64/32 CNN parameterization. No architecture was chosen using test outcomes.

## Training-only balancing

Training has 6,433 benign, 19 reconnaissance and five DoS samples (24 positives, 0.3717% prevalence). The preregistered imbalance rule gives BCE positive weight 6433/24 = 268.0416667. All original training samples are visited once per epoch; development is never resampled or weighted.

| Seed | Weighted minus unweighted macro-F1 | Recall delta | False-positive rate delta |
| ---: | ---: | ---: | ---: |
| 1729 | +0.088823 | +1.000000 | +0.009336 |
| 2718 | +0.098176 | +1.000000 | +0.008299 |
| 31415 | +0.141816 | +1.000000 | +0.005187 |

Every unweighted selected CNN64 predicts all development samples benign. Weighting detects the lone reconnaissance sample at the cost of additional false positives. Its effect on unseen groups or DoS cannot be inferred. Weighted sigmoid scores are uncalibrated.

## Selected baseline and family support

The required 64/32 pruning baseline is **cnn64_weighted, seed 31415, epoch 23** (28 epochs completed). Selection follows the registered development-only seed/balancing rule.

Macro-F1: **0.641557**. Confusion counts: TN=959, FP=5, FN=0, TP=1. Attack precision is 0.166667, attack F1 0.285714, FPR 0.005187, and average precision 0.166667.

| Development family | Support | Predicted attack | Interpretation |
| --- | ---: | ---: | --- |
| Benign | 964 | 5 | False positives |
| Reconnaissance | 1 | 1 | One observed detection; insufficient recall evidence |
| DoS | 0 | null | No measurable development performance |

Full family-versus-benign binary metrics are saved per epoch and per selected checkpoint. The binary model never predicts an attack family. Selecting the best seed adds optimism beyond the three-seed means.

## Audit and split provenance

The missing Phase 2 reserve was registered before development labels were loaded: the fixed validation midpoint 1421928508000000000 ns divides development and the future threshold-only block. The build rechecks padded annotation spans, tuple reuse and physical histories. Train is unchanged; 93 development candidates are purged. The reserve has 81 boundary-history and 124 connection-history exclusions. Its 915 retained index rows have no decoded labels or scores.

Preprocessing fits 11,357 unique training windows once, with the registered log1p population standardization and epsilon 1e-6. The original fit set is unchanged. Exact normalization replay, feature units/order, final-window labels, label packet evidence, continuous valid histories and the independent Wireshark offline/live/saved-feature ledger all pass. Train/development/reserve share zero physical windows or connections; they still share the one original source group.

Development precision is poor and DoS support is absent. The audit found no label-mapping, unit or extraction-parity defect that justifies a scope/schema change. The experiment retains the registered architectures and features. New independent sessions and adequate family support require a new data registration; there was no test-driven architecture selection. Optional calibration and final thresholds are deferred to the registered reserve, whose suitability remains unestablished.

## Measured CPU budget

The two-epoch CPU pilot measured 0.4834s and 0.2610s per full CNN64 train/development epoch. Before the large run, it estimated 217.5s for all 450 maximum epochs, or 326.3s with 50% allowance.

The suite actually completed 294 epochs: 46.09s summed epoch wall time and 44.94s process CPU. First-run start to last-run completion was 55.89s, including checkpoint/log persistence. Preparation and interpreter startup are separate. CPU intraop and interop threads were one. This is Windows CPU evidence, not edge-device evidence. The pilot saves raw resource samples and labels sampled RSS as an estimate, not exact peak memory.

## Handoff

Use the complete [baseline package](baseline_package/handoff.json), which includes architecture, feature schema, preprocessing, fit IDs, split/source provenance, independent-group counts, development predictions, exact hashes and resume state. A bare checkpoint is rejected by the package validator. It is suitable as a provenance-complete experimental pruning input; it is not a validated deployed detector.

Exact checkpoint SHA-256:

`5276653f95f5d6eb38b1a92d194f60e95eeac4d69ca7e014dc55de2a1103425b`

Deterministic tensor-state SHA-256:

`0b2f9fb0dc7256476608f771e5b2a3dc0d521d9ff72dd43a9f86ec71cdc25f81`

Preprocessing SHA-256:

`59e7b2667228141d96095f1a878675659c2c302a2a2dc428c94e0b15603c5a9c`

The independent evidence check verifies every run's predictions, unchanged prevalence, early stopping, checkpoint selection, resumable state and exact selected checkpoint replay. All 965 development logits and scores reproduce bit for bit. See [verification.json](verification.json) and [the implementation guide](../../../docs/phase3.md).

```powershell
.\.venv-phase2\Scripts\python.exe -m ids.training.train replay --bundle experiments/phase3/run-002/baseline_package --experiment experiments/phase3/run-002
```

## Individual seed checkpoints

| Variant | Seed | Selected epoch | Completed epochs | Macro-F1 | TP | FP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cnn64_weighted | 1729 | 16 | 21 | 0.588564 | 1 | 9 |
| cnn64_weighted | 2718 | 17 | 22 | 0.597917 | 1 | 8 |
| cnn64_weighted | 31415 | 23 | 28 | 0.641557 | 1 | 5 |
| cnn32_weighted | 1729 | 15 | 20 | 0.563272 | 1 | 13 |
| cnn32_weighted | 2718 | 1 | 6 | 0.532159 | 1 | 24 |
| cnn32_weighted | 31415 | 23 | 28 | 0.580726 | 1 | 10 |
| logistic128_weighted | 1729 | 30 | 30 | 0.485984 | 1 | 91 |
| logistic128_weighted | 2718 | 30 | 30 | 0.482837 | 1 | 99 |
| logistic128_weighted | 31415 | 30 | 30 | 0.484395 | 1 | 95 |
| last_window_weighted | 1729 | 1 | 6 | 0.499741 | 0 | 0 |
| last_window_weighted | 2718 | 23 | 28 | 0.563272 | 1 | 13 |
| last_window_weighted | 31415 | 22 | 27 | 0.597917 | 1 | 8 |
| cnn64_unweighted | 1729 | 1 | 6 | 0.499741 | 0 | 0 |
| cnn64_unweighted | 2718 | 1 | 6 | 0.499741 | 0 | 0 |
| cnn64_unweighted | 31415 | 1 | 6 | 0.499741 | 0 | 0 |
