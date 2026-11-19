# Phase 4 bounded channel-mask search

Phase 4 evaluates masks on the frozen Phase 3 64/32 temporal CNN. It does not
train, compact, fine-tune, quantize or export a model. The input is the selected
`experiments/phase3/run-002/baseline_package`, with its checkpoint, preprocessing,
architecture and split provenance. A bare checkpoint is rejected.

## Fixed validation and access boundary

The validation selection is **all 965 Phase 3 development rows in their original
order**, without sampling or changing prevalence: 964 benign and one
reconnaissance sample, with no DoS. `validation_manifest.json` freezes the sample
IDs, tensor indices, metadata digest and source artifact hashes before search.
The same subset is used for every candidate and all-ones parity.

`ids.ga.data.load_inputs` uses explicit filename allowlists. It reads only
development tensors/metadata, the baseline's development predictions, weights
and inference/provenance metadata. It checks the Phase 3 data manifest's digest
without following the manifest's other filenames. It neither calls the general
training loader nor reads training tensors, threshold-reserve indices/outcomes,
test data, raw captures or external sources. Original training and held-out split
boundaries appear only in the saved provenance metadata. Source paths in those
metadata are never followed. `outcome_access.json` records opened input files.

The single source group and already-used development subset make this an
exploratory model-selection experiment. Repeated mask selection adds optimism;
one positive cannot establish recall or generalization. Null absent-family
metrics remain null. Phase 4 does not fit a final threshold or calibration.

## Registered search

| Setting | Value |
| --- | --- |
| Mask lengths | 64 and 32 |
| Mask application | After each convolution and ReLU, before the next layer |
| Population | 20, including the all-ones baseline |
| Other initial bits | Independent Bernoulli 0.5, followed by repair |
| Replacement generations | At most 15, after generation zero |
| Elites | Best two valid individuals, copied unchanged |
| Parent selection | Roulette proportional to nonnegative finite fitness, with replacement |
| Zero-weight fallback | Uniform among valid parents when all valid weights are zero |
| Crossover | Probability 0.6 per pair; one uniformly chosen layer and one interior cut |
| Mutation | Independent probability 0.05 for each of the 96 bits in each child |
| Repair | Sample disabled bits without replacement to retain at least four per layer |
| Fitness | `0.1 * (1 - (kept_conv1 + kept_conv2) / 96) + 0.9 * validation_macro_f1` |
| Decision threshold | Float64 sigmoid of float32 logits, `score >= 0.5` |
| Stopping | Five replacement generations without best-fitness improvement of at least `1e-6` |
| Seed | 1729 by default; explicitly recorded and configurable |
| Archive | All unique candidates, baseline, best three distinct pruned masks, Pareto frontier |

Output masking removes bias contributions as well as weighted inputs. Input and
output units stay unchanged. Inference uses a frozen model copy, CPU float32,
`eval()`, `torch.inference_mode()`, disabled autocast, deterministic algorithms,
one intraop/interop thread and batches of at most 1,024. There is no optimizer,
gradient computation or per-candidate training.

Nonfinite logits, scores or fitness invalidate a candidate. Invalid candidates
are cached for accounting but cannot be parents, elites or selected artifacts.
An invalid all-ones baseline stops the run. If only one valid parent remains,
it supplies both elite slots. Duplicate individuals are permitted and hit cache.

Fitness ties use lexical mask order. At each completed generation, the actual
best-so-far fitness is retained even for a gain below `1e-6`. Patience compares
that generation's best-so-far value with the previous generation's best-so-far
value; a gain **at least** `1e-6` resets patience. Generation zero initializes
the reference and does not consume patience. This avoids an ambiguous extra
generation or counting the initial population as a replacement generation.

## Cache and resume

Each cache key includes both masks and the digest of the fitness context:

- Original checkpoint-file hash and evaluated tensor-state hash, architecture,
  preprocessing, feature schema, split and package provenance hashes.
- Exact normalized validation tensor bytes, shape and dtype; ordered row
  metadata, labels, families, groups and fixed selection manifest.
- Fitness formula, fixed-label metric convention, score conversion, threshold,
  output-mask semantics, batching, precision and inference configuration.
- Project implementation hashes, Python/NumPy/PyTorch/PyArrow versions, PyTorch
  build, CPU capability, platform, deterministic/backend/thread settings and
  numerical-library environment variables.

The run configuration additionally binds the seed and all genetic parameters.
This intentionally invalidates reuse conservatively when inputs, source or
numeric runtime change. Records include metrics, output hashes, retained counts,
evaluation wall/CPU time and validity; no cache entry triggers training.

`resume.json` is an atomic, checksum-protected checkpoint after every candidate
request and generation transition. It contains the current population/cursor,
cache, complete request log, generation history, best candidate, patience and
the dedicated Python RNG state used by **all** genetic operations. Python,
NumPy and PyTorch are also seeded; inference consumes no randomness. A crash
replays at most the uncommitted request. Completed requests and cache hits are
not duplicated. Tables and reports are regenerated from this authoritative
state. Configuration, input, implementation and runtime drift reject resume.

## Execution

Use the existing Python 3.12 environment pinned by `requirements-phase3.txt`:

```powershell
.\.venv-phase2\Scripts\python.exe -m ids.ga.search run --output experiments/phase4/run-001
.\.venv-phase2\Scripts\python.exe -m ids.ga.search verify --output experiments/phase4/run-001
```

The output directory must be new. To continue an interrupted run, repeat the
same `run` command with `--resume` and the same seed/generation limit. Repeating
resume on a completed run leaves the search counts unchanged. Use a fresh
output directory for reproduction. Optional `--max-generations` can reduce the
budget to 0–15; default is 15. All other search constants remain registered.
`--bundle` and `--experiment` select a provenance-matched Phase 3 input pair;
neither accepts a partition name or arbitrary validation array.

Verification reevaluates **every unique cached mask** independently and requires
exact metrics and logit/score hashes. It repeats all-ones parity against both
the original model and Phase 3's saved development predictions, checks candidate
accounting and preserved baseline hashes, and records its additional cost
separately in `verification.json`. It does not update the search population or
cache counts.

## Counts, costs and handoff

The request bound is `20 * (1 + 15) = 320`. Since two elite requests in each
replacement generation must hit cache, at most `20 + 18 * 15 = 290` unique
candidate inferences are possible. Other duplicates and early stopping can
reduce this further. The first all-ones evaluation supplies a measured estimate
for the remaining inference budget, with a 50% allowance, in `budget.json`.

`candidate_requests.csv` records every population slot, including hits, its
fitness, retained counts, evaluation/request timings and sampled process RSS.
`cache.json` records each distinct evaluation. `generations.json` records full
populations, best-so-far fitness, stopping counters and generation costs.
`summary.json`, `quality_retention.csv` and `REPORT.md` compare quality with
retention, including the macro-F1/retention Pareto frontier. Costs distinguish
candidate inference, committed search overhead, setup/parity and verification.
RSS samples are not an exact peak; interpreter startup, final write/export and
work lost during an abrupt interruption are outside committed search timing.

All candidates still execute the same 9,345-parameter dense network, with
73,760 convolution/linear MACs per eight-window sample, plus masking overhead.
For retained counts `c1,c2`, future compact counts are calculated as
`49*c1 + 3*c1*c2 + 2*c2 + 1` parameters and
`8*16*c1*3 + 8*c1*c2*3 + c2` MACs. These are theoretical architecture counts,
not measured memory or latency savings. Compaction and any fine-tuning belong
to Phase 5.

`baseline/` preserves the unmodified checkpoint and allowlisted inference
provenance; it omits Phase 3 training resume state and reserved indices.
`top_candidates.json` contains the baseline and up to three distinct leading
pruned masks from the entire search, even if they left the final population.
Masks include explicit binary arrays for both layers, exact hashes, metrics and
retention counts. No candidate receives deployment or generalization approval.

Regression checks use synthetic fixtures:

```powershell
.\.venv-phase2\Scripts\python.exe -m pytest -q tests/test_ga.py
.\.venv-phase2\Scripts\python.exe -m pytest -q
```
