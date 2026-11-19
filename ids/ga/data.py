"""Phase 4's explicit development-only input boundary. No training data loader."""

from collections import Counter
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch

from ids.datasets.temporal import digest
from ids.model import TemporalCNN
from ids.run_logging import sha256
from ids.training.data import read_json, require
from ids.training.train import architecture, weight_hash

# Never iterate the checksum manifest as a list of files to open. In particular,
# neither resume.pt (training state) nor reserved_index.parquet is read/copied.
BUNDLE_FILES = (
    "architecture.json", "audit.json", "best.pt", "config.json",
    "development_predictions.parquet", "environment.json", "extraction_parity.json",
    "feature_schema.json", "fit_window_ids.json", "handoff.json", "outcome_access.json",
    "parent_provenance.json", "preprocess.json", "registration.json", "result.json",
    "split_manifest.json",
)
DATA_FILES = ("development/tensor.npy", "development/samples.parquet",
              "preprocess.json", "split_manifest.json", "feature_schema.json")


def allowed_path(root, name, names):
    require(name in names, "File is outside the Phase 4 allowlist")
    target = Path(root).resolve() / name
    require(target.resolve() == target, "Symlink or redirected input is not allowed")
    return target


def load_inputs(bundle, experiment):
    bundle, data = Path(bundle).resolve(), Path(experiment).resolve() / "data"
    opened = []

    def path(root, name, names):
        result = allowed_path(root, name, names)
        opened.append(str(result))
        return result

    checksums = read_json(path(bundle, "checksums.json", ("checksums.json",)))
    require(set(BUNDLE_FILES) <= checksums.keys(), "Incomplete Phase 4 baseline package")
    for name in BUNDLE_FILES:
        require(sha256(path(bundle, name, BUNDLE_FILES)) == checksums[name], f"Bundle checksum mismatch: {name}")
    handoff = read_json(bundle / "handoff.json")
    config = read_json(bundle / "config.json")
    arch = read_json(bundle / "architecture.json")
    require(handoff["trained"] and handoff["pruning_input_valid"], "A trained pruning handoff is required")
    require(config["variant"] in ("cnn64_weighted", "cnn64_unweighted") and
            arch == architecture(config["variant"]) == config["architecture"] == handoff["architecture"],
            "Phase 4 requires the eight-window 64/32 temporal CNN")
    for field, name in (("checkpoint_sha256", "best.pt"), ("preprocess_sha256", "preprocess.json"),
                        ("split_manifest_sha256", "split_manifest.json"),
                        ("development_predictions_sha256", "development_predictions.parquet")):
        require(handoff[field] == checksums[name], f"Handoff binding mismatch: {field}")
    require(config["preprocess_sha256"] == handoff["preprocess_sha256"] and
            config["split_manifest_sha256"] == handoff["split_manifest_sha256"], "Configuration binding mismatch")
    require(read_json(bundle / "preprocess.json")["split_manifest_sha256"] ==
            digest(read_json(bundle / "split_manifest.json")), "Preprocessor split binding failed")
    checkpoint = torch.load(bundle / "best.pt", map_location="cpu", weights_only=True)
    require(checkpoint["config"] == config and
            weight_hash(checkpoint["model_state"]) == handoff["state_dict_sha256"], "Checkpoint provenance mismatch")
    model = TemporalCNN()
    model.load_state_dict(checkpoint["model_state"], strict=True)
    require(all(bool(torch.isfinite(p).all()) for p in model.parameters()), "Nonfinite baseline parameters")
    model.eval().requires_grad_(False)

    manifest = read_json(path(data, "artifact_checksums.json", ("artifact_checksums.json",)))
    require(digest(manifest) == handoff["data_sha256"] == config["data_sha256"], "Development manifest binding mismatch")
    require(set(DATA_FILES) <= manifest.keys(), "Missing development input hashes")
    for name in DATA_FILES:
        require(sha256(path(data, name, DATA_FILES)) == manifest[name], f"Development checksum mismatch: {name}")
    for name in ("preprocess.json", "split_manifest.json", "feature_schema.json"):
        require(manifest[name] == checksums[name], f"Baseline/development mismatch: {name}")
    x = np.load(data / "development/tensor.npy", allow_pickle=False)
    rows = pq.read_table(data / "development/samples.parquet").to_pylist()
    require(x.dtype == np.float32 and x.shape == (len(rows), 16, 8) and np.isfinite(x).all(), "Invalid development tensor")
    require([r["tensor_index"] for r in rows] == list(range(len(rows))), "Development tensor/metadata misalignment")
    require(len({r["sample_id"] for r in rows}) == len(rows), "Duplicate development sample IDs")
    require(all(type(r["label"]) is int and r["label"] in (0, 1) for r in rows) and
            {r["label"] for r in rows} == {0, 1}, "Fixed validation needs both binary classes")
    saved = pq.read_table(bundle / "development_predictions.parquet").to_pylist()
    fields = ("sample_id", "group_id", "label", "family")
    require([[r[f] for f in fields] for r in saved] == [[r[f] for f in fields] for r in rows],
            "Baseline/development prediction alignment mismatch")
    selection = dict(version="phase4_validation_v1", role="development",
        policy="all frozen Phase 3 development rows, original order; no resampling",
        sample_ids=[r["sample_id"] for r in rows], tensor_indices=list(range(len(rows))),
        sample_count=len(rows), rows_sha256=digest(rows),
        files={name: manifest[name] for name in DATA_FILES},
        class_counts=dict(Counter(str(r["label"]) for r in rows)),
        family_counts=dict(Counter(r["family"] for r in rows)),
        source_groups=len({r["group_id"] for r in rows}),
        independent_heldout_groups=handoff["independent_heldout_development_groups"])
    provenance = dict(bundle=str(bundle), experiment=str(Path(experiment).resolve()),
        checkpoint_sha256=handoff["checkpoint_sha256"], state_dict_sha256=handoff["state_dict_sha256"],
        architecture=arch, bundle_checksums={name: checksums[name] for name in BUNDLE_FILES},
        preprocess_sha256=handoff["preprocess_sha256"], split_manifest_sha256=handoff["split_manifest_sha256"],
        data_manifest_sha256=digest(manifest), validation=selection,
        access=dict(files=sorted(set(opened)), decoded_outcome_roles=["development"],
                    train_files_opened=[], reserved_files_opened=[], test_files_opened=[], external_files_opened=[]))
    return model, x, rows, saved, provenance
