# Phase 5 physical compaction and fine-tuning

Phase 5 consumes the completed Phase 4 archive and its preserved 64/32 parent,
plus the provenance-matched Phase 3 training and development data. It rebuilds
up to three leading masks as ordinary smaller `Conv1d` and `Linear` modules,
fine-tunes them, compares the original direct 32/16 CNN, and freezes architectures
and weights for later export. Export, quantization, calibration, threshold fitting
and final evaluation are outside this phase.

## Reproduction

Use the existing Python 3.12 CPU environment pinned by `requirements-phase3.txt`:

```powershell
.\.venv-phase2\Scripts\python.exe -m ids.compaction.run run --output experiments/phase5/run-001
.\.venv-phase2\Scripts\python.exe -m ids.compaction.run verify --output experiments/phase5/run-001
```

The output must be new. The run never overwrites an existing experiment or
automatically extends a failed experiment. Reproduction uses a new directory.
Defaults are `--search experiments/phase4/run-001`,
`--experiment experiments/phase3/run-002`, `--seed 1729`, `--top-k 3`, and
`--max-epochs 5`. Budgets may be reduced to 1–3 candidates and 1–5 epochs.
Learning rate, parity tolerances and quality limits are fixed in code.

## Reconstruction and mandatory entry gate

For ascending original indices `I` and `J` of enabled conv1/conv2 channels:

```text
compact.conv1.weight = parent.conv1.weight[I, :, :]
compact.conv1.bias   = parent.conv1.bias[I]
compact.conv2.weight = parent.conv2.weight[J, :, :][:, I, :]
compact.conv2.bias   = parent.conv2.bias[J]
compact.output.weight = parent.output.weight[:, J]
compact.output.bias   = parent.output.bias
```

The input has 16 channels and eight time steps; the output remains one logit.
ReLU and global temporal mean are unchanged. Copies own their storage. There
are no masks, pruning hooks, sparse wrappers or zero-filled parent-sized tensors
in compact artifacts. Both hidden biases and the output bias are accounted for.

Before any optimizer step, **all** candidates must match the masked parent at
`atol=1e-6`, `rtol=1e-5`. The reference operand is the masked logit. Tests cover
every fixed development sample and 291 seeded synthetic inputs (zero, positive
and negative ones, 32 normal random inputs, and positive/negative basis impulses
for all 128 input positions). Both batch-one and batch-1,024 evaluation are
checked under inference mode, disabled autocast and deterministic CPU float32.
The real sample IDs and all input/output hashes are saved. Threshold crossings
are counted even when numerical tolerance passes. Archived masked predictions
and baseline predictions must also replay exactly.

A wiring failure writes the failed parity evidence and stops the whole run,
with zero training steps. It does not relax the numerical tolerance, retrain to
hide a wiring error or proceed with the remaining candidates.

## Registered development comparison

`registration.json` is written before new evaluations or training. It binds the
input hashes, source implementation, runtime, candidate order, designated parent,
exact validation manifest and the following rules:

- Use the original unpruned Phase 3 baseline preserved by Phase 4 as the quality
  reference. Do not compare only against the masked parent.
- Use all frozen development rows in their original order without resampling or
  refitting preprocessing. Scores are float64 sigmoid of float32 logits, with
  `score >= 0.5`. Fixed-label binary metrics reuse the Phase 3/4 implementation.
- Fine-tune each physical model with fresh Adam at 0.0001, batch 128, and the
  original training-only positive weight. The same seeded permutation stream
  is used for each candidate. There are initially five epochs and one recorded
  fine-tuning seed per candidate; no automatic budget extension occurs.
- Select the highest development macro-F1 among **trained epochs 1–5**, keeping
  the earliest exact tie. Preserve epoch zero and the terminal epoch separately.
  Epoch zero is not substituted for a failed trained checkpoint.
- Reject the selected checkpoint if either attack recall or macro-F1 loses
  **more than 0.02 absolute** against the designated unpruned baseline. Equality
  at 0.02 is allowed. Undefined or nonfinite metrics fail the gate.
- Replay and preserve all three existing direct-small seeds unchanged. Its
  comparator is the highest development macro-F1, then lowest seed on a tie.
- Among feasible GA candidates, the best direct-small comparator and the
  unpruned fallback, choose the fewest actual parameters, then highest macro-F1,
  recall and stable ID. Measured host latency is reported separately and does
  not introduce a noisy tie-break. No percentage reduction is required.

A failed GA experiment is a complete result. The unpruned fallback always stays
available. Rejected compact and direct-small artifacts retain explicit rejection
status for the later research comparison. Freezing an artifact is not deployment
approval.

## Outcome access and provenance

`ids.compaction.data` uses explicit filename allowlists. It extends the Phase 4
development loader with only Phase 3 `train/tensor.npy` and
`train/samples.parquet`, and the checkpoint/config/result/development predictions
of the three registered direct-small seeds. It does not use the general training
loader, traverse input manifests as filenames, or open raw data, threshold-reserve
indices, internal tests or external data. The manifest may contain hashes for
those artifacts; their paths are not followed. The exact opened-file list is in
`outcome_access.json`.

Training/development tensors, sample alignment, role labels, disjoint sample and
window IDs, training balance, preprocessing and split bindings are checked.
The Phase 4 checkpoint digest, completed status, top-three ranking, masks,
context and original implementation hashes must match. New Phase 5 files do
not invalidate the already-completed Phase 4 archive; changing a file used by
Phase 4 does. No new GA search is run.

## Physical and measured costs

Actual parameter count is the sum of the compact module tensor sizes. Float
tensor bytes are their actual element counts times element size. Saved weight
bytes measure a common bare-state-dict serialization named `weights.pt` for
every model. Analytical convolution/linear MAC counts exclude activation,
pooling and bias work. No latency or RAM savings are inferred from mask sparsity.

Warm inference measures host CPU eager float32 at batch one, one intraop and one
interop thread, with 100 warmups and 1,000 timed calls per model, repeated three
times. Models rotate order across repeats; inputs cycle through fixed validation
order. Raw nanosecond samples, repeat medians, p95s and means are preserved.
This excludes preprocessing, service overhead, serialization and target-device
runtime. It is not a RISC-V, Arm64, ExecuTorch or energy measurement.

Each epoch records training loss, full development metrics, optimizer steps,
training wall/CPU time, training-plus-evaluation time and sampled process RSS.
Setup, parity, benchmark and verification costs are separate. Process RSS includes
the interpreter and all resident models, is not an exact peak and cannot support
a per-model RAM saving claim. Original Phase 3 and Phase 4 search costs remain in
their original artifacts rather than being counted as Phase 5 training.

## Frozen handoff and verification

- `candidates/ga_*/`: ascending channel maps, architecture, equivalence results,
  `pre.pt`, selected `post.pt`, terminal `last.pt`, per-epoch metrics, pre/post
  predictions and quality-gate results.
- `originals/`: byte-preserved unpruned and all three direct-small input artifacts.
- `frozen/<id>/`: ordinary `weights.pt`, frozen architecture/state shapes, handoff,
  checksums and GA channel map where applicable. No optimizer or masks are needed
  to load these modules with `load_frozen`.
- `shared/`: unchanged preprocessing, feature schema and split metadata.
- `handoff.json`: selected ID, architecture/state hash and all retained comparison
  directories. Threshold and calibration remain unset.
- `summary.json`, `REPORT.md`, `benchmark.json`, `timing_samples.csv`: quality,
  cost and selection evidence. `artifact_checksums.json` binds the complete run.

`verify` checks all saved hashes and source/runtime bindings, rebuilds every
pre-fine-tuning model, reruns parity, reloads every frozen comparison model, and
requires exact development metrics/predictions. It checks trained epoch selection,
terminal metrics and architecture selection without performing training. Its
additional cost is recorded separately in `verification.json`.

Regression tests use synthetic data, including a protected-file trap, deliberate
miswiring of every affine tensor, exact acceptance boundaries, deterministic
fine-tuning, failed-GA fallback and an end-to-end frozen-artifact replay:

```powershell
.\.venv-phase2\Scripts\python.exe -m pytest -q tests/test_compaction.py
.\.venv-phase2\Scripts\python.exe -m pytest -q
```

The available development excerpt has only one attack sample and one original
source group. Selection remains provisional and optimistic. No independent
recall or generalization claim follows from these development metrics; absent
families remain visibly undefined.
