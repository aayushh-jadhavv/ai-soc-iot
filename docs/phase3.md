# Phase 3 training and pruning handoff

Phase 3 trains the registered temporal baseline and comparisons on the accepted
Phase 2 `run-002` data. This is a provisional within-group experiment: the two
original captures belong to **one** connected source group. There are zero
independently held-out development groups. Device counts and overlapping windows
are not independent replicates. No internal-test or external outcomes are read.
Pruning, quantization, deployment, final threshold fitting and calibration are
outside this implementation.

The completed experiment is `experiments/phase3/run-002`. Its `REPORT.md` contains
the measured results; `comparison.json` contains all individual runs, three-seed
summaries and the paired balancing comparison. `baseline_package/handoff.json`
identifies the exact selected 64/32 checkpoint and its provenance.

## Registered data amendment

Phase 2 did not contain a threshold-only reserve. Before loading development
labels or training, Phase 3 registered the integer-second midpoint of the
original validation interval: `1421928508000000000` ns. The earlier block is
development and the later block is reserved for future threshold/calibration
work. This was a fixed chronological rule, with no search over boundaries.
The original train and internal-test boundaries are retained.

The new boundary is a split amendment, not a feature or label-scope change.
`registration.json` records it before the affected dataset is rebuilt. Original
Phase 2 files are unchanged. Tuple/time projections of the original full CSV,
GT and BRO sources supply conservative annotation crossings, including spans
with no observed packet on one side. Label/category columns in those CSVs are
excluded from projection. Physical-window metadata supply observed crossings
and tuple reuse. Every sample touching a crossing connection is removed on both
sides; every eight-window history must fit entirely within its new block.
Both endpoint views retain their original group and connection membership.

The derivation removes 93 original development candidates. It removes 81
boundary-crossing histories and 124 connection-touching histories from the
reserved candidates. Training is unchanged. Train/development/reserve have zero
shared raw-window IDs or connection IDs, while their common source group remains
explicit. Original Phase 2 purges against the locked internal-test boundary are
inherited by taking subsets; that test partition is never reopened.

The retained training set contains 6,433 benign, 19 reconnaissance and five DoS
samples. Development contains 964 benign and **one reconnaissance** sample,
with **no DoS**. Its attack prevalence is 1/965. These counts make family quality
and generalization conclusions unsupported, even if a checkpoint scores well.
All comparisons use exactly these same samples and unchanged development
prevalence. There is no stratified resampling of evaluation data.

The reserve is stored only as a label-free `reserved_index.parquet`, referring to
the hash-bound Phase 2 validation rows. Its labels, family support and scores
remain uninspected. A future phase must establish whether it supports threshold
selection/calibration; chronological separation does not make it an independent
session. If support is inadequate, omit calibration or collect independently
grouped data under a new registration. Do not move the boundary using outcomes.

`run-001` is a retained failed preparation attempt: the GT source contains quoted
multiline cells. The CSV projection was corrected before any development labels
were loaded. The successful build uses the identical boundary and scope.

## Preprocessing and audits

The feature contract remains `device_window_v1`. All 16 features keep their
registered order and units: IPv4 byte counts, population length/IAT statistics,
and within-second IATs in milliseconds. No identifier, family or label enters a
model input.

The shared `Preprocessor` computes `(log1p(x) - mean) / max(std, 1e-6)`, then
transposes raw `[N,8,16]` arrays to contiguous float32 `[N,16,8]`. The means and
population deviations are fitted once per unique retained training window,
never per overlapping occurrence or from a held-out block. The derivation
refits using its retained training IDs and verifies that the original fit set
is unchanged. Saved `preprocess.json`, `fit_window_ids.json` and split hashes
bind that fit to the exact data. There is no clipping or imputation.

Before training, the build verifies the Phase 2 artifact and extractor hashes,
the final-window sample labels against window metadata and packet evidence,
binary/family mapping, valid continuous histories, and exact saved normalization.
It reruns the independent real training-window Wireshark ledger against both
offline and live adapters and the original saved features. Results are in
`data/audit.json` and `data/extraction_parity.json`. Poor development results do
not trigger an architecture search or a look at the test set. Any later scope
or semantic/schema correction requires a registration and affected-data rebuild.

## Models and selection

All runs use BCEWithLogitsLoss, Adam with learning rate 0.001, betas `(0.9,0.999)`,
epsilon `1e-8`, no weight decay, batch size 128, at most 30 epochs and patience
five. A seeded permutation visits each training sample once per epoch, including
the final partial batch. There is no learning-rate schedule. The development
loss is always unweighted BCE.

| Registered variant | Architecture | Parameters |
| --- | --- | ---: |
| CNN64 weighted | Conv1d 16→64, ReLU, Conv1d 64→32, ReLU, temporal mean, Linear 32→1 | 9,345 |
| CNN32 weighted | Directly initialized Conv1d 16→32→16, otherwise identical | 3,137 |
| Logistic128 weighted | Channel-major flatten of `[16,8]`, Linear 128→1 | 129 |
| Last-window weighted | CNN64 on only the final normalized second, length one | 9,345 |
| CNN64 unweighted | CNN64 with ordinary unweighted BCE | 9,345 |

Convolutions use kernel three, padding one, stride one and biases. There is no
batch normalization or dropout. The last-window ablation retains the same
CNN64 parameterization; off-center padded kernel positions cannot add historical
information. All models are trained from scratch on identical groups and sample
IDs. Logistic regression uses the same Adam/early-stopping budget, with no
separate regularization or solver search.

The training-only imbalance rule is registered: if negative/positive support
exceeds ten, use `pos_weight = N_negative / N_positive`. Here it is
`6433/24 = 268.0416667`. Weighted BCE changes the training objective without
duplicating samples. The unweighted CNN64 provides a paired three-seed control.
`comparison.json` reports its effect on macro-F1, attack recall and false-positive
rate. Weighted sigmoid outputs remain uncalibrated scores.

Checkpoint selection uses binary macro-F1 over the two fixed labels at sigmoid
threshold **0.5**. Only strict improvement resets patience; an exact tie keeps
the earliest epoch. Both development classes are required for selection. Metrics
with undefined denominators are null. Average precision groups tied scores and
uses the noninterpolated precision-recall sum. Per-family records include
support, binary detection rate and family-versus-benign binary metrics; the
models do not predict an attack family. An absent family has null metrics.

The pruning baseline remains a 64/32 CNN. Its seed and balancing choice are
selected by the best development macro-F1, then lowest seed and lexical variant
name on an exact tie. The other architectures are comparisons. This selection
across seeds adds development optimism, especially with only one attack sample;
three-seed means and sample standard deviations are retained for comparison and
are not independent-group confidence intervals.

## CPU budget, deterministic execution and resume

Seeds are `1729`, `2718`, and `31415`. All five variants are scheduled for all
three seeds (15 runs). A smaller explicit `--seeds` list is accepted only from
the registered list and is disclosed in `comparison.json`.

The CPU pilot measures two complete CNN64 training/development epochs, discards
its weights and saves timing/resource samples before the large run. The runner
requires a pilot matching the data and implementation hashes. The conservative
estimate applies the slower measured epoch to all 450 possible remaining epochs
and adds a 50% overhead allowance. This measures the current Windows CPU host,
not an edge board. RSS is sampled, not an exact native-memory peak.

Python, NumPy, PyTorch and the shuffle generator are seeded. CPU intraop and
interop threads are fixed to one and deterministic algorithms are required.
The current environment is Python 3.12.14, PyTorch 2.9.0+cpu, NumPy 2.2.6 and
PyArrow 22.0.0. Full installed versions and the host environment are saved per
run. Determinism is verified in this environment; other hardware or library
versions can change floating-point results.

Every completed epoch atomically saves `resume.pt`: current model and Adam
states, all RNG states, shuffle-generator state, selected weights/epoch, patience
counter, metric history and configuration/data/source hashes. Resuming starts
at the next complete epoch. A partial epoch is replayed from the last complete
state. Epoch tables are rebuilt from that state, preventing duplicate rows after
a crash. Configuration, data or implementation drift is rejected. The automated
interruption test compares resumed/uninterrupted model weights, Adam state,
shuffle state and development metrics exactly.

From the repository in PowerShell, using the existing verified environment:

```powershell
.\.venv-phase2\Scripts\python.exe -m ids.training.data --parent experiments/phase2/run-002 --output experiments/phase3/reproduction
.\.venv-phase2\Scripts\python.exe -m ids.training.train pilot --experiment experiments/phase3/reproduction
.\.venv-phase2\Scripts\python.exe -m ids.training.train run --experiment experiments/phase3/reproduction
```

The preparation and pilot directories must be new. To continue an interrupted
run, repeat the final command with `--resume`. Training consumes only the
derived train/development shards. `requirements-phase3.txt` pins the CPU
dependencies for a new Python 3.12 environment; the Phase 0 export lock is
unchanged. Fresh experiment metadata include new timestamps/paths and therefore
have new artifact hashes, while seeded tensor weights and predictions should
reproduce within the same pinned environment.

To verify the completed selected checkpoint and replay its development outputs:

```powershell
.\.venv-phase2\Scripts\python.exe -m ids.training.train replay --bundle experiments/phase3/run-002/baseline_package --experiment experiments/phase3/run-002
.\.venv-phase2\Scripts\python.exe -m scripts.check_phase3_evidence experiments/phase3/run-002
.\.venv-phase2\Scripts\python.exe -m pytest -q
```

## Required pruning input

Use the entire `baseline_package` directory, not a bare `.pt` file.
`verify_bundle` rejects missing or mismatched required artifacts and cross-checks
the checkpoint, architecture, preprocessing and split bindings. The package has:

- Exact checkpoint-file SHA-256 and deterministic tensor-state SHA-256.
- Architecture and training configuration, seed, selected epoch, library versions
  and implementation hashes.
- The shared feature schema, preprocessing artifact and unique fit-window IDs.
- Registered and parent split/source provenance, outcome-access policy, group
  counts, label/unit/extraction audits and the untouched reserved index.
- Development logits, scores, labels, families, sample/group IDs and selected
  per-family metrics, plus full resume state and deterministic replay command.

`checksums.json` hashes each package member. Each individual run also preserves
its checkpoint, predictions, per-epoch/per-family records and resume state.
The package is a structurally complete input for a later pruning experiment.
Its provenance-completeness flag is not a deployment or generalization approval.
Final thresholds remain null and no calibration parameters are fitted.
