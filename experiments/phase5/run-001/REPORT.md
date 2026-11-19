# Phase 5 compact networks and fine-tuning

Selected **ga_3** using the registered development quality gate and actual parameter count.
The unpruned baseline and all three direct-small seed artifacts are preserved for the final compression comparison.

| Candidate | Channels | Parameters | Float tensor bytes | Saved weight bytes | MACs/sample | Pre recall / macro-F1 | Post recall / macro-F1 | Gate | Selected epoch | Warm median / p95 (us) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| unpruned | 64/32 | 9345 | 37380 | 40085 | 73760 | 1.000000 / 0.641557 | 1.000000 / 0.641557 | pass | - | 179.850 / 335.150 |
| direct_small_seed_1729 | 32/16 | 3137 | 12548 | 15253 | 24592 | 1.000000 / 0.563272 | 1.000000 / 0.563272 | reject | - | 221.300 / 272.315 |
| direct_small_seed_2718 | 32/16 | 3137 | 12548 | 15253 | 24592 | 1.000000 / 0.532159 | 1.000000 / 0.532159 | reject | - | 221.700 / 340.155 |
| direct_small_seed_31415 | 32/16 | 3137 | 12548 | 15253 | 24592 | 1.000000 / 0.580726 | 1.000000 / 0.580726 | reject | - | 154.550 / 280.620 |
| ga_1 | 26/14 | 2395 | 9580 | 12373 | 18734 | 1.000000 / 1.000000 | 1.000000 / 0.749481 | pass | 1 | 222.000 / 311.635 |
| ga_2 | 27/15 | 2569 | 10276 | 13013 | 20103 | 1.000000 / 1.000000 | 1.000000 / 0.749481 | pass | 1 | 141.250 / 274.410 |
| ga_3 | 25/15 | 2381 | 9524 | 12309 | 18615 | 1.000000 / 0.833074 | 1.000000 / 0.699221 | pass | 1 | 139.900 / 295.520 |

Direct-small comparison uses its best Phase 3 development seed, with lowest seed on exact ties: **direct_small_seed_31415**. Direct-small/unpruned pre and post are identical because they were replayed without additional training.

## Compaction and numerical correctness

Each GA artifact contains ordinary smaller Conv1d and Linear tensors. Conv1 output filters/biases, conv2 output filters/biases and matching conv1 input columns, and final Linear input columns are copied in ascending retained-index order. The final output bias is unchanged.
All candidates passed before any training: every fixed development input plus 291 fixed synthetic inputs, each at batch sizes 1 and 1,024, with atol=1e-6 and rtol=1e-5. Synthetic inputs cover zero/bias behavior, signs, random values and every channel/time impulse. Exact archived masked outputs were also replayed.

- ga_1 conv1: [2, 3, 4, 5, 6, 7, 9, 11, 13, 15, 16, 21, 22, 23, 33, 38, 40, 41, 42, 43, 45, 46, 48, 53, 55, 56]; conv2: [2, 3, 11, 13, 16, 17, 18, 20, 21, 23, 26, 28, 29, 31].
- ga_2 conv1: [2, 3, 5, 6, 7, 9, 11, 13, 15, 16, 21, 22, 23, 33, 38, 40, 41, 42, 43, 44, 45, 46, 48, 52, 53, 55, 56]; conv2: [2, 3, 11, 13, 16, 17, 18, 20, 22, 23, 24, 25, 26, 29, 30].
- ga_3 conv1: [3, 4, 5, 6, 7, 9, 11, 13, 15, 16, 17, 21, 22, 23, 33, 38, 40, 41, 43, 45, 47, 48, 53, 56, 59]; conv2: [1, 2, 3, 9, 13, 16, 17, 18, 20, 21, 24, 26, 28, 29, 31].

## Registered comparison

The designated reference is the original trained 64/32 Phase 3 baseline preserved by Phase 4. The exact development rows, preprocessing, class prevalence, fixed-label metrics and float64 sigmoid(float32 logit) >= 0.5 rule are unchanged. Recall or macro-F1 loss greater than 0.02 rejects a candidate; the tolerance was never widened.
Each GA candidate received 5 epochs of training-only fine-tuning using fresh Adam at 0.0001, batch 128 and the original training-only positive weight. The highest macro-F1 among trained epochs is selected; exact ties keep the earliest epoch. Epoch zero is preserved but is not a fallback for a failed fine-tuned result. All epoch metrics and the terminal checkpoint are retained.
The architecture selection first applies both quality gates, then minimizes actual parameter count; ties prefer macro-F1, recall and ID. It considers the unpruned fallback, the best direct-small comparator and all GA candidates. Latency is measured and reported separately. No required percentage reduction was imposed.

## Measured costs

Warm costs are host CPU eager float32 batch-one model calls: one intraop/interop thread, 100 warmups and 1,000 timed calls per model per repeat, three repeats, rotated model order. Table values are medians across repeat medians/p95s. Raw nanosecond measurements are in timing_samples.csv. They exclude preprocessing, service overhead, export and RISC-V/Arm execution; they do not predict target-device latency.
Tensor bytes and serialized weights are measured on the physical modules. MACs are analytical convolution/linear counts excluding activations, biases and pooling. No savings are attributed to zero-filled dense tensors. Process RSS samples include the interpreter and other resident models; no per-model RAM reduction is inferred.

- ga_1: 255 optimizer steps; training 1.577672s wall / 1.546875s CPU; training plus epoch evaluation 1.650709s wall; sampled process RSS maximum 360718336 bytes.
- ga_2: 255 optimizer steps; training 1.496718s wall / 1.453125s CPU; training plus epoch evaluation 1.565264s wall; sampled process RSS maximum 362049536 bytes.
- ga_3: 255 optimizer steps; training 1.529820s wall / 1.453125s CPU; training plus epoch evaluation 1.589740s wall; sampled process RSS maximum 362762240 bytes.

Run cost through measurement: 24.150297s wall / 18.843750s CPU. Setup, equivalence and benchmark costs are recorded separately in summary.json; startup and final report/checksum persistence are excluded. Verification cost is separate.

## Scope and frozen handoff

Development support: 965 samples; classes {'0': 964, '1': 1}; families {'benign': 964, 'reconnaissance': 1}; independent held-out groups 0.
There is only one attack sample and one original source group. Repeated development selection is optimistic; this experiment cannot establish attack recall or generalization. Absent-family metrics remain null. Threshold-reserve, internal-test and external-test files were not opened. No thresholds, calibration, quantization, runtime export or deployment were performed.
frozen/ contains architecture-bound weights and checksums for every comparison artifact, including rejected ones with explicit gate status. handoff.json fixes the selected architecture and parent identities; shared/ preserves preprocessing, schema and split metadata. These are Phase 5 research artifacts for later export and compression comparisons, not deployment approval.
