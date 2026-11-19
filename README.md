# AI SoC IDS

Temporal IDS with versioned raw-window contracts, shared packet extraction,
reproducible CPU training and a native Linux ExecuTorch/XNNPACK export probe.
Phase 3 includes a trained 9,345-parameter baseline and comparisons; the available
single-group excerpt supports only a provisional development experiment.

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
not an independent evaluation dataset.
[Phase 2 implementation and gateway handoff](docs/phase2.md)
· [Phase 2 counts and verification](experiments/phase2/REPORT.md)

Phase 3 trains the 64/32 CNN, direct 32/16 CNN, flattened logistic regression and
final-window ablation with three seeds and a training-only balancing control.
The registered threshold reserve and internal/external test outcomes stay locked.
[Phase 3 training and handoff](docs/phase3.md)
· [Development results](experiments/phase3/run-002/REPORT.md)
· [Selected baseline package](experiments/phase3/run-002/baseline_package/handoff.json)

Phase 4 runs a bounded genetic search over 64/32 hidden-output masks using only
the frozen development subset. It preserves the baseline, candidate cache,
generation history and exact resume state; compaction and fine-tuning are deferred.
[Phase 4 implementation and reproduction](docs/phase4.md)
· [Search results and retention trade-offs](experiments/phase4/run-001/REPORT.md)

Phase 5 rebuilds the three leading masks as physical smaller networks, checks
masked-parent logit equivalence before training, fine-tunes for up to five epochs
and applies the fixed development recall/macro-F1 loss gates. It preserves the
unpruned and direct-small comparisons and freezes architectures for later export.
[Phase 5 implementation and reproduction](docs/phase5.md)
· [Compaction and fine-tuning results](experiments/phase5/run-001/REPORT.md)

Phase 6 exports the seven frozen checkpoints at batch one in the pinned Linux
ExecuTorch/XNNPACK runtime. It measures numerical agreement, threshold changes,
operator precision and VM latency. The selected `ga_3` handoff uses float32.
[Phase 6 reproduction](docs/phase6.md)
· [Export and PTQ results](experiments/phase6/run-001/REPORT.md)
· [Selected program and checksum](experiments/phase6/run-001/handoff.json)
