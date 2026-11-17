# AI SoC IDS

Untrained 9,345-parameter temporal CNN, versioned raw-window contracts, semantic validators, synthetic positive/negative fixtures, shared run logger and a native Linux ExecuTorch/XNNPACK export probe.

Start with [the Phase 0 contract](docs/phase0.md). Run from Ubuntu WSL2 (approved for this task) or a native Linux VM:

```sh
bash scripts/reproduce_phase0.sh experiments/phase0/reproduction
```

The output directory must not already exist. Python 3.12.12 and the complete CPU toolchain are locked in `.python-version` and `uv.lock`. Use uv 0.9.10; the script also recognizes the locally downloaded `.tools/uv-x86_64-unknown-linux-gnu/uv`. Dependencies default to the guest's `$HOME/.cache/ai-soc-phase0/venv` for fast native Linux filesystem access; override `IDS_VENV` if needed. Supply current host provenance at `experiments/phase0/host.json` before running on a different VM. No dataset is needed.

The proof saves model.pte, eager/exported/reference outputs, delegate/fallback inventories, source/environment/bundle manifests, raw Python timing/resource logs and explicit untrained provenance. These weights are not a detector and must not be deployed for decisions.

Phase 1 inventories the supplied data, audits the two January captures and verifies benign, reconnaissance and DoS final-window labels on a conservative subset. Both captures belong to one group, so independent evaluation partitions remain pending. [Dataset audit](docs/phase1.md) · [UNSW label verification](experiments/phase1/raw-label-verification-002/REPORT.md)

Phase 2 provides the shared packet/window extractor, offline and live adapters,
partitioned temporal datasets, preprocessing and exclusion/leakage checks. The
supplied excerpt supports a provisional chronological within-group build; it is
not an independent evaluation dataset. No training has started.
[Phase 2 implementation and gateway handoff](docs/phase2.md)
· [Phase 2 counts and verification](experiments/phase2/REPORT.md)
