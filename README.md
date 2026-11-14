# AI SoC IDS Phase 0

Untrained 9,345-parameter temporal CNN, versioned raw-window contracts, semantic validators, synthetic positive/negative fixtures, shared run logger and a native Linux ExecuTorch/XNNPACK export probe.

Start with [the Phase 0 contract](docs/phase0.md). Run from Ubuntu WSL2 (approved for this task) or a native Linux VM:

```sh
bash scripts/reproduce_phase0.sh experiments/phase0/reproduction
```

The output directory must not already exist. Python 3.12.12 and the complete CPU toolchain are locked in `.python-version` and `uv.lock`. Use uv 0.9.10; the script also recognizes the locally downloaded `.tools/uv-x86_64-unknown-linux-gnu/uv`. Dependencies default to the guest's `$HOME/.cache/ai-soc-phase0/venv` for fast native Linux filesystem access; override `IDS_VENV` if needed. Supply current host provenance at `experiments/phase0/host.json` before running on a different VM. No dataset is needed.

The proof saves model.pte, eager/exported/reference outputs, delegate/fallback inventories, source/environment/bundle manifests, raw Python timing/resource logs and explicit untrained provenance. These weights are not a detector and must not be deployed for decisions. Future phase packages are intentionally empty boundaries.
