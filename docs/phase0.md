# Phase 0 implementation contract

Scope: design v1.1 Sections 4–5 and the implementation plan's Phase 0 and Section 14. The supplied documents are reference specifications; their prompts for later phases are not execution instructions. No training, dataset download, packet extractor, HTTP service, policy, enforcement, pruning or quantization experiment is part of this implementation. Stub packages mark future ownership boundaries without pretending these capabilities exist.

## Inputs and ownership

`device_window_v1` is fixed: ordered features and units are in `contracts/v1/feature_schema.json`. Gateway owns raw extraction, quality diagnostics, window finalization and history lifecycle. The future shared extractor belongs in `ids.features`, imported by offline and live adapters. IDS owns validation and preprocessing exactly once. Neither identity fields nor dataset labels enter the tensor.

Complete nonfragmented supported IPv4 observations count retransmissions and IPv4 total_length bytes. Outgoing/incoming refer to the monitored endpoint. Update both endpoints only when both are monitored; do not invent broadcast recipients. Unique IP/port sets are per device/window. Length and within-window interarrival statistics use population variance; never carry a gap across windows. Zero outgoing packets imply zero outgoing statistics; one packet implies zero length deviation and zero IAT statistics; one gap implies zero IAT deviation. The Phase 0 schema validates numbers and message structure, not whether packet-derived statistics were calculated correctly; extractor parity belongs to Phase 2.

Windows are integer-second aligned half-open `[start,end)` intervals of 1,000 ms. Healthy capture can produce valid zero rows. Fragments, truncation, malformed/unsupported traffic, capture loss, timestamp discontinuity, late finalized packets and capped uniqueness overflow must remain visible as coverage diagnostics and invalidate affected histories. ARP registry observation alone does not invalidate IPv4 coverage. A gap, restart, identity binding, capture session or enforcement revision change resets history; collect eight fresh valid rows. Proposed ordering allowance is 100 ms; proposed inactivity timeout is 60 s, followed by fresh warm-up on reactivation. Those lifecycle rules are specified here, not implemented as gateway policy.

Preprocessing: validate raw `[8,16]`; compute `(log1p(x) - mean) / max(std, 1e-6)` feature-wise, transpose and convert to contiguous float32 `[1,16,8]`. Means/stds are population statistics of log1p values fitted on unique training windows only. Preserve their feature order, units, transform version and provenance with the bundle. Do not impute, clip, normalize at the gateway, or refit on validation/test. This smoke run uses explicitly synthetic zero means/unit standard deviations, never a trained preprocessing artifact.

## Wire version and semantic validation

JSON Schema draft 2020-12 files and `ids.contracts.validate` together are normative. Use `validate_for_inference` at the inference boundary. Python wire types are in `contracts/types.py`. Positive/negative fixture names denote valid/invalid contract cases, not benign/attack examples. The index declares expected status/error. Invalid JSON NaN/Infinity tokens are rejected; tests also cover in-memory nonfinite values.

Proposed Phase 0 refinements:

- Require `schema_version: "1.0"` on FeatureSequence as well as windows/results. Reject all other versions until an explicit compatibility implementation exists. Semantic/order/coverage changes require a new feature major version and retraining; optional minor additions still require an explicit supported-version update.
- Bounded IDs are 1–128 ASCII letters/digits or `._:-`, starting alphanumeric. Deployment device IDs remain gateway-issued UUIDs; compact synthetic IDs are permitted by the schema. Integers/revisions/counts/bytes are nonnegative signed-int64 bounded; timestamps are signed int64. JSON integers can be represented with `.0` if mathematically integral; booleans are never numbers.
- Exactly eight oldest-first windows share gateway, boot, session, device, binding, enforcement, feature schema, wire schema and observed mode. Window IDs are unique; both event time and sequence numbers are consecutive. Wire mode is `live` or `offline`.
- Unknown fields are rejected. Valid quality has no reasons; invalid quality requires at least one bounded reason. Reasons are extensible strings so new diagnostics do not silently disappear. A valid degraded FeatureWindow is a valid observation message; a sequence containing it abstains at the inference boundary.
- Status `ok` requires finite score in `[0,1]` and null error; `abstain`/`error` require null score and a matching code. `score_type` is `uncalibrated_sigmoid`; calibrated output requires a future explicit contract. Binary output never supplies an attack family.

The final window defines the scored second, earlier windows provide context. Attack-associated traffic is not proof of compromise or of an attacker role. The untrained smoke output must never be consumed as a detector score.

## Status and errors

The Phase 7 service will bind loopback and require a provisioned service credential. Phase 0 publishes its boundary in `contracts/openapi.json` but starts no service. Structural validation precedes model/coverage checks. Invalid requests with untrustworthy/missing identity receive a Problem envelope instead of fabricated InferenceResult identity. An accepted correlated request can receive an InferenceResult. Inference time is nonnegative milliseconds measured around the forward call; zero means no forward call. It does not mean total request latency.

| Code | Status | Proposed HTTP | Meaning |
| --- | --- | --- | --- |
| INVALID_INPUT | error | 422 | Malformed JSON, missing/extra field, wrong type/length, nonfinite value, bad interval |
| SCHEMA_MISMATCH | error | 422 | Unsupported wire/feature version |
| HISTORY_DISCONTINUITY | error | 422 | Mixed identity/revision or noncontiguous rows |
| MODEL_MISMATCH | error | 409 | Requested immutable model version is not loaded |
| INVALID_COVERAGE | abstain | 200 | Well-formed rows include degraded coverage |
| INSUFFICIENT_HISTORY | abstain | 200 | Reserved for future worker/history state; short wire arrays are INVALID_INPUT |
| MODEL_NOT_READY | error | 503 | Bundle not loaded/warmed/reference checked |
| OVERLOADED | error | 503 | Bounded queue full; never silently drop |
| DEADLINE_EXCEEDED | error | 504 | One-second request deadline expired |
| REQUEST_ID_CONFLICT | error | 409 | Same ID reused with changed canonical content/model |
| PREPROCESS_ERROR | error | 500 | Valid request cannot be transformed safely |
| RUNTIME_ERROR | error | 500 | Backend failed or produced nonfinite output |

401 uses an authentication Problem envelope. `error` and `abstain` are degraded monitoring, never benign classifications. Future cache: 256 entries, 60 s TTL; only identical canonical JSON content plus model version may be reused. One identical retry retains ID; changed windows require a new ID. Deadline/queue/cache are documented contracts, not implemented in Phase 0. Gateway will match expected request/current binding/current enforcement and exclude results older than five seconds from escalation. No gateway decision rule is implemented here.

## Proposed refinements recorded for later phases

The following are frozen as initial experiment settings, not evaluated findings: start with benign/reconnaissance/DoS only where annotations support them; verified positive plus unknown traffic stays positive unless conflicts/identity/coverage invalidate it, recording mixed coverage; earlier unknown labels alone do not invalidate valid features. Idle labels need reliable normal coverage. Reserve validation groups for calibration/threshold selection where feasible; otherwise disclose reuse or omit calibration. Keep tests untouched and fit transforms on unique training windows.

Checkpoint selection and GA fitness use fixed 0.5 macro-F1 before deployment threshold selection. Seed all RNGs; initialize GA nonbaseline bits with p=0.5, repair to four channels per layer, use uniform parents if selection weights vanish, cache complete provenance keys, reject nonfinite candidates and checkpoint state. Stop after five generations with improvement below 1e-6. Compaction parity tolerance: atol 1e-6, rtol 1e-5. Float exported score tolerance: absolute 1e-4 (this probe additionally checks logits atol/rtol 1e-5). Optional INT8 quality budget: at most 0.01 absolute recall/macro-F1 loss from float parent and the overall 0.02 loss from baseline. These budgets are proposals, not achieved accuracy.

Future benchmark proposal: 100 warmups, at least 1,000 varied calls, three repeats, then 30-minute sustained VM load. Register operational recall/false incident/onset objectives before release evaluation. The short Phase 0 timing sample is only an execution smoke test and does not establish a service capacity, detection quality, or board performance result.

## Native VM and toolchain

The user approved installed WSL2 for this gate. The probe executes natively in the Ubuntu x86-64 guest and records Windows host CPU/OS/RAM and WSL version in `experiments/phase0/host.json`; per-run manifests capture guest kernel, distribution, CPU affinity, vCPU count, RAM, libraries, threads, source/document hashes and background workload. WSL2 resources are not fixed-size board equivalents. This is not Arm64, physical-board, throughput or energy evidence.

Python 3.12.12, torch 2.9.0 CPU and ExecuTorch 1.0.0 are exact project choices. `uv.lock` contains transitive versions and wheel hashes. ExecuTorch pulls torchao 0.14.0 and Core ML tools 9.0b1 (declared upstream dependencies); the dependency resolver therefore needs prereleases enabled when regenerating the lock. All resolved prereleases are recorded in the lock/environment, not implicitly upgraded during reproduction. Torchao 0.14.0 disables its C++ extensions with this torch version; this is an observed optional-tooling limitation, not a claim of quantization compatibility. Its Python import is exercised by ExecuTorch, but PT2E/INT8/QAT compatibility remains a separate Phase 6 gate. No quantization is performed. See the [upstream compatibility issue](https://github.com/pytorch/ao/issues/2919). The reproduction script uses the frozen lock, exposes its bundled flatc on PATH, and keeps dependencies on the guest Linux filesystem. The standalone probe also resolves the venv's flatc explicitly. Avoid mixing a Windows interpreter with this Linux virtual environment.

Conv1d is the primary implementation. The probe asserts actual XNNPACK delegates, saves delegate subgraph operators and the serialized execution-plan fallback list, reloads `model.pte` through the ExecuTorch runtime, and compares eager/exported/runtime logits and sigmoid scores for five fixed inputs. Conv2d is permitted only after a demonstrated incompatibility and copied-weight parity check; no substitute is enabled by default. Synthetic seeded weights are saved along with inputs, raw fixtures, transformed tensors, outputs and tolerances. No threshold is selected for deployment.

Official API references used for setup: [ExecuTorch 1.0 getting started](https://docs.pytorch.org/executorch/1.0/getting-started.html), [XNNPACK partitioner](https://docs.pytorch.org/executorch/1.0/backends/xnnpack/xnnpack-partitioner.html), and the installed pinned package source. Actual execution evidence takes precedence over a documentation claim about operator support.

## Shared Section 14 run logger

`ids.run_logging.RunLogger` is a single-writer, immutable-run-directory contract. It emits run_manifest.json, events.jsonl, epoch_metrics.csv, ga_candidates.parquet, predictions.parquet, raw timing_samples.csv, resource_samples.csv, resource_summary.json and benchmark_summary.json. Empty epoch/GA/prediction tables in Phase 0 mean no training/search/detection evaluation was performed. Null metrics mean undefined, not zero. Later phases supply per-group predictions and GA mask/cache/provenance fields; never manufacture labels from telemetry.

Use perf_counter_ns and save raw durations, load time, preprocessing and forward timing separately; future services add roundtrip/alert timing separately. Eager benchmark/profiler runs stay separate from deployed runtime measurements and are not delegation evidence. ResourceMonitor spawns a separate sampler at 200 ms, primes CPU sampling, records worker and children independently, and excludes its own process. CPU 100% means one logical core. Sampled maximum RSS is not exact peak and child RSS is not summed. Its sampling collection cost and an observed monitored/unmonitored median ratio are saved; neither isolates all observer overhead. No CUDA synchronization is needed for this CPU proof. tracemalloc is not used as a proxy for native tensor memory. The JSON logger rejects nonfinite records.

Every run includes code/data/model hashes, seed, environment and provenance. There is no Git repository in the supplied workspace; per-file SHA-256 values identify this source state instead of inventing a commit. Failed probes retain a failed manifest and traceback. Use a new output directory to reproduce; never overwrite evidence in place.

## Data and handoff

Phase 0 needs no dataset. Local CSV filenames were inventoried only and do not supply contiguous packet windows. For Phase 1 the team must supply one intact raw PCAP/session with benign and relevant attacks, matching ground truth/event files, monitored-address mapping, timezone/offset and capture-continuity metadata, source/license/hash provenance. Later phases need independent sessions and agreed attack scope. A gateway-generated fixture is optional for an additional contract check. Gateway/CNN/app owner names remain a team coordination item and do not block this isolated package.
