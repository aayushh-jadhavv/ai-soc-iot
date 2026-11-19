# Phase 4 validation-only genetic search

Status: complete; stopping reason: patience_5. Completed 9 replacement generations.

Population 20; two elites; crossover 0.6 in one selected layer; per-bit mutation 0.05; minimum four channels per layer. Fitness is 0.1 × channel sparsity + 0.9 × binary macro-F1 at threshold 0.5. Five generations without a gain of at least 1e-6 stop the search.

Candidate requests: **200**; unique candidates/inferences: **182**; cache hits: **18**; invalid candidates: 0. The request bound is 320; the inference bound with cached elites is 290.

Candidate evaluation wall time: 3.783738s; process CPU: 3.500000s. Committed search wall time: 13.163799s; CPU: 12.265625s. Sampled process RSS maximum: 267485184 bytes (not exact peak). Setup/parity and verification are recorded separately. Final persistence/export and lost in-flight work during a crash are outside the committed search timing.

## Quality and retention

Top candidates are the best three distinct pruned masks across the entire cache. The all-ones baseline is always preserved separately. Exact fitness ties use lexical mask order.

| Candidate | Kept conv1/conv2 | Retention | Macro-F1 | Recall | FPR | Fitness | Potential parameters | Potential MACs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 64/32 | 100.000% | 0.641557 | 1.000000 | 0.005187 | 0.577401 | 9345 | 73760 |
| Top 1 | 26/14 | 41.667% | 1.000000 | 1.000000 | 0.000000 | 0.958333 | 2395 | 18734 |
| Top 2 | 27/15 | 43.750% | 1.000000 | 1.000000 | 0.000000 | 0.956250 | 2569 | 20103 |
| Top 3 | 25/15 | 41.667% | 0.833074 | 1.000000 | 0.001037 | 0.808100 | 2381 | 18615 |

Every evaluation still uses the dense 9,345-parameter network (73,760 convolution/linear MACs per sample, excluding masks, activations and pooling). Potential counts describe a future compact architecture; they are not measured compression or latency savings. No compact model or per-candidate training was performed.

`quality_retention.csv` records every valid unique mask. `summary.json` also preserves the full macro-F1/retention Pareto frontier, including recall and per-family metrics.

## Validation scope

The same 965 development samples are used for every candidate in their frozen order. Class counts: {'0': 964, '1': 1}; family counts: {'benign': 964, 'reconnaissance': 1}; source groups: 1; independently held-out groups: 0.

This is a model-selection experiment on the already-used development subset. Repeated mask selection adds validation optimism; the available one-positive, single-group excerpt cannot establish attack recall or generalization, and absent families have no measured quality. Test, external, training and threshold-reserve data are not opened by this search. No final threshold or calibration is fitted.

## Artifacts

`resume.json` atomically binds the population, cursor, sole search RNG state, cache, request log, best-so-far history and patience counter. `config.json` binds all fitness inputs, source hashes and numeric runtime settings. `validation_manifest.json` fixes the development subset. `candidate_requests.csv` includes evaluation times and cache status. `baseline/` preserves the original weights and inference provenance; `top_candidates.json` preserves selected masks. `parity.json`, `budget.json`, and `verification.json` record the entry check, measured budget and independent cache replay when the corresponding commands complete.
