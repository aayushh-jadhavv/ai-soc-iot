# Phase 0 compatibility evidence

Phase 0's float32 contract/model/export gate passed on the user-approved Ubuntu WSL2 guest. No training, dataset download, packet extraction, inference service, gateway policy or quantization was performed. The model is untrained and unsuitable for security decisions.

## Verified result

| Check | Observed result |
| --- | --- |
| Contract, model and logger tests | 54 passed in 6.63 s |
| CNN | Conv1D 16→64→32, kernels 3, padding 1, ReLU, temporal mean, Linear 32→1 |
| Parameters | 9,345: 3,136 + 6,176 + 33 |
| Parameter tensor bytes | 37,380 float32 bytes |
| Export/runtime path | strict torch.export → ExecuTorch lowering → serialized model.pte → ExecuTorch Python Runtime |
| Input/output | float32 [1,16,8] → logit [1,1] |
| Native execution | Ubuntu 26.04 LTS, x86_64, WSL2; host x86_64 |
| XNNPACK delegates | Two: both convolutions/ReLUs in one; linear output in the other |
| Runtime fallback operators | aten::mean.out only |
| Manual Conv2D substitution | None; Conv1D passed |
| Reference inputs | Raw synthetic sequence, healthy idle, seeded normal, alternating signs, large finite tensor |
| Maximum absolute logit difference | 2.3096799850463867e-07 |
| Maximum absolute sigmoid-score difference | 5.960464477539063e-08 |
| Tolerances | Logits atol 1e-5/rtol 1e-5; scores absolute 1e-4 |
| Diagnostic 0.5 crossings | Zero across the five inputs; this is not a selected deployment threshold |
| Exported PTE size | 42,756 bytes |
| Artifact/source integrity | 84 recorded hashes checked; zero mismatches |

## Evidence files

The successful run is `run-004/`:

- `run_manifest.json`: run identity, exact source/document hashes, environment, seed, model hash, reproduction command and compatibility outcome.
- `environment_manifest.json`: measured host/guest configuration, Python executable, all library versions and environment thread settings.
- `model.pte`, `untrained_state_dict.pt`, `exported.pt2`, `preprocess.json`, `bundle_manifest.json`: untrained artifacts, synthetic transform and checksums/provenance.
- `reference_outputs.json`: raw request, five full transformed input tensors, eager/exported/runtime outputs and parity deltas.
- `delegation.json`, `exported_graph.txt`, `lowered_graph.txt`: original operators, delegate subgraphs and serialized runtime fallback inventory.
- `timing_samples.csv`, `benchmark_summary.json`, `resource_samples.csv`, `resource_summary.json`: raw Python timing/resource observations and limitations.
- `epoch_metrics.csv`, `ga_candidates.parquet`, `predictions.parquet`: intentionally empty record schemas for later phases, not fabricated experiments.
- `events.jsonl`: delegate events.

The test and runtime transcript is `run-004-console.log`. `host.json` records the Windows/WSL provenance used for the run. Earlier failure transcripts/manifests remain available: run-001 caught an incorrect test exception expectation; run-002 caught missing flatc discovery; run-003 caught a logger field-name collision. These issues were corrected before run-004; none required changing the CNN architecture.

## Environment and limitations

Python 3.12.12; PyTorch 2.9.0+cpu; ExecuTorch 1.0.0; bundled flatc 24.3.25; NumPy 2.2.6; jsonschema 4.25.1; psutil 7.1.3; PyArrow 22.0.0. `uv.lock` pins the full resolved environment with wheel hashes. Installer uv 0.9.10 was used. The Linux venv is `/home/aayus/.cache/ai-soc-phase0/venv`.

Host: Intel Core i3-1305U, Windows 11 Home Single Language 10.0.26200, 8,259,321,856 host-visible RAM bytes, WSL 2.7.13.0 / Microsoft Hyper-V. Guest: Ubuntu 26.04, Linux 6.18.33.2-microsoft-standard-WSL2, six visible logical CPUs, 3,942,772,736 guest-visible RAM bytes. Background desktop workload was not controlled. The user explicitly accepted installed WSL2 for this gate.

The eager intra-op/inter-op thread counts were one; XNNPACK used its runtime-default threadpool, whose exact size was not exposed by this probe. Raw CPU usage is reported with 100% equal to one logical core. The sampler observed two 200 ms intervals; this is neither a memory-peak measurement nor a sustained benchmark. The observed monitored/unmonitored timing ratio is strongly confounded by order, threadpool activity and host load. No service capacity or latency acceptance claim is made.

Two upstream warnings are retained in the transcript. Torchao 0.14.0, pulled by ExecuTorch, disables its optional C++ extensions with this torch version; quantization is disabled and unvalidated. ExecuTorch reports that its optional InternalConsistency verification is unavailable in this runtime build; that is not silently treated as a security verification. Actual program loading, execution, graph inventory and numerical parity did pass. These results establish only this float32 native x86-64 WSL2 path, not INT8, Arm64, physical-board performance, trained quality or production readiness.

## Reproduce

From the repository root inside the Ubuntu guest, use a new output directory:

```sh
bash scripts/reproduce_phase0.sh experiments/phase0/reproduction
```

From PowerShell:

```powershell
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/Users/aayus/dev/AI-SoC && bash scripts/reproduce_phase0.sh experiments/phase0/reproduction'
```

The script installs from the frozen lock, sets CPU thread environment variables, runs the tests and executes the export probe. It refuses to overwrite an existing run. For another host/VM, supply updated host provenance as the second script argument. `IDS_VENV` overrides the guest-local environment location. Use uv 0.9.10 on PATH if the locally downloaded `.tools/uv-x86_64-unknown-linux-gnu/uv` is absent.

No data is needed to reproduce Phase 0. Phase 1 will require an intact raw PCAP/session, matching labels/events, endpoint/time/continuity metadata and provenance; existing prepared CSV rows alone do not establish this temporal input contract.
