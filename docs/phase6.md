# Phase 6 batch-one export and PTQ assessment

The Phase 5 handoff names seven frozen checkpoints. Phase 6 exports each
comparison artifact, including the direct-small seeds that failed the earlier
quality gate. The selected architecture comes from that handoff.
[Development results](../experiments/phase6/run-001/REPORT.md)

## Measured outcome

The handoff retains **`ga_3` float32**. Its 15,236-byte program agreed with
eager PyTorch on all 965 development decisions. The diagnostic INT8 export
used 11,396 bytes. Its maximum score error was 0.011973 against its registered
0.012 tolerance. Its warm median was 7.756 µs, compared with 7.734 µs for
float32. The training archive had no healthy idle example for observer calibration.
[Selected program](../experiments/phase6/run-001/ga_3/float32/model.pte)

The only threshold disagreement occurred on a benign development history for
`direct_small_seed_1729`. Eager scored it at 0.485313. In the converted graph,
the final quantizer mapped a logit of −0.050937 to integer code 54, its zero
point, at a step size of 0.165449. The resulting logit was exactly zero in both
PT2E and ExecuTorch. The inclusive 0.5 threshold turned the row into a false
positive. [Per-sample trace](../experiments/phase6/run-001/threshold_review.json)

## Reproduce in the Phase 0 Linux environment

Run from the repository root in Ubuntu WSL2 or native Linux. Use the existing
Phase 0 environment or install it with the frozen project lock. The `records`
extra supplies PyArrow. The default source paths are
`experiments/phase5/run-001` and `experiments/phase3/run-002/data`.
The latter needs the original train and development tensors and sample tables,
including the training raw array. Their digests are bound to the trained baseline.

```sh
venv_path="${IDS_VENV:-$HOME/.cache/ai-soc-phase0/venv}"
UV_PROJECT_ENVIRONMENT="$venv_path" .tools/uv-x86_64-unknown-linux-gnu/uv sync --frozen --extra records --extra test
export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
"$venv_path/bin/python" -m scripts.phase6.run run --output experiments/phase6/reproduction
"$venv_path/bin/python" -m scripts.phase6.run verify --output experiments/phase6/reproduction
"$venv_path/bin/python" -m scripts.review_phase6_crossings --output experiments/phase6/reproduction
"$venv_path/bin/python" -m pytest -q tests/test_phase6.py
```

The run command creates a fresh output directory. Use `--host-manifest PATH`
on a different host to supply its provenance. The runner checks the Phase 0
Python, Torch, ExecuTorch, torchao, NumPy, PyArrow and flatc pins and records
installed library versions, the wheel's native runtime binary hash, host/guest
details, thread settings, source hashes and input checksums.

## Inputs and calibration

Only the allowlisted train/development arrays and tables are read. The loader
checks Phase 5 weights, architecture and shared preprocessing, validates sample
and tensor alignment, replays the training transform and checks train/development
sample and window disjointness. All seven models run under disabled gradients
and CPU autocast, using frozen eval-mode weights and `float32[1,16,8]` input.
The score is the Phase 5 float64 sigmoid. Equality at 0.5 counts as positive.

Static PT2E uses the XNNPACK quantizer and observes up to 32 distinct training
histories per stratum. Idle means zero observed packets in the labeled benign
final second. A burst reaches the 90th percentile of active benign training
packet counts in the final second. Other active benign histories and each
observed attack family are sampled separately. The seed, population counts,
ordered observer IDs and tensor indices are in `calibration.json`. This excerpt
has no observed idle training second. The PTQ comparison therefore records an
incomplete calibration stratum. The contract's healthy-idle sequence is a
separate synthetic numerical reference and carries no family label.
[Pinned ExecuTorch PT2E guidance](https://docs.pytorch.org/executorch/1.0/quantization-overview.html)

## Registration and evidence

The run writes its comparison protocol before any model evaluation. Float32
uses a maximum absolute score error of 0.0001 across all 965 development
histories and the idle reference. Each INT8 model derives its own numerical
tolerance from the earlier third of unique development end times. The rule
rounds its maximum eager/runner probability difference upward to a 0.001 grid,
with a 0.001 floor and 0.05 ceiling. Each numerical value is written before
the remaining INT8 inputs are evaluated. The later check shares no physical
window with the prefix. The full development metrics retain boundary rows.

Each program directory contains the executable `model.pte`, `exported.pt2`,
ATen and lowered graphs, serialized XNNPACK operand types and portable fallback
kernel dtypes. Its `references.parquet` contains sample IDs, float32 logits and
float64 scores for eager, exported ATen and deployed inference. INT8 tables
also include the float32 runner. Use `reference_index` to retrieve the input
from `shared/reference_tensors.npy`, with a one-row slice to preserve the batch
dimension. The shared directory contains the frozen transform, split and feature
schema. Every threshold-changing program/input pair has a second execution,
stage attribution, scores, signed margins and decisions in
`threshold_crossings.json`. The crossing review command traces each affected
saved graph to its output and records the logit before final quantization,
quantization scale, zero point and integer output when present.
[Threshold review](../experiments/phase6/run-001/threshold_review.json)

The quality gate allows at most 0.01 absolute recall and macro-F1 loss relative
to each float32 parent and 0.02 relative to the unpruned float32 baseline.
The INT8 handoff also requires all three affine layers to run quantized, all
calibration strata, the numerical gate and a measured benefit. The size and
runtime rule, three-repeat measurements and per-family validation results are
recorded in the run report. The command times `Method.execute` using a
one-thread ExecuTorch pool. It records load time separately. The sampling
monitor covers export and numerical assessment and stops before the warm
benchmark.

Verification reloads every saved program, replays all references through eager
PyTorch, exported ATen and ExecuTorch, and checks the stored values, calibration
selection, tolerance, threshold-crossing accounting, per-family metrics and
artifact checksums. The deployment threshold remains unset.
