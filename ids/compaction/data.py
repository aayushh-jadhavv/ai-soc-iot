"""Allowlisted Phase 3 train/development inputs and the completed Phase 4 archive."""

from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch

from ids.datasets.temporal import digest
from ids.ga.data import BUNDLE_FILES, allowed_path, load_inputs as load_baseline
from ids.ga.masks import ALL_ONES, Mask
from ids.ga.search import FITNESS, array_hash, cache_key, ranking
from ids.model import TemporalCNN
from ids.run_logging import sha256
from ids.training.data import ROOT, SEEDS, read_json, require
from ids.training.train import architecture, positive_weight, weight_hash

SEARCH_FILES = ("config.json", "resume.json", "top_candidates.json", "validation_manifest.json")
TRAIN_FILES = ("train/tensor.npy", "train/samples.parquet")
DIRECT_FILES = ("best.pt", "config.json", "result.json", "development_predictions.parquet", "environment.json")


def load_inputs(search, experiment):
    search, experiment = Path(search).resolve(), Path(experiment).resolve()
    parent, dev, rows, saved, provenance = load_baseline(search / "baseline", experiment)
    opened = list(provenance["access"]["files"])

    def path(root, name, allowed):
        p = allowed_path(root, name, allowed)
        opened.append(str(p))
        return p

    archive = {n: read_json(path(search, n, SEARCH_FILES)) for n in SEARCH_FILES}
    config, top, checkpoint = archive["config.json"], archive["top_candidates.json"], archive["resume.json"]
    state, context = checkpoint["state"], config["context"]
    require(digest(state) == checkpoint["sha256"], "Phase 4 state checksum mismatch")
    require(state["status"] == "complete" and state["config"] == config["search"], "Incomplete Phase 4 search")
    require(digest(context) == state["context_sha256"] == top["context_sha256"], "Phase 4 context mismatch")
    require(context["fitness"] == FITNESS, "Phase 4 comparison procedure changed")
    # Match the files actually used by Phase 4, allowing new Phase 5 source files.
    for name, expected in context["implementation"].items():
        require(name in {p.relative_to(ROOT).as_posix() for p in (ROOT / "ids").rglob("*.py")},
                "Unexpected Phase 4 source path")
        require(sha256(ROOT / name) == expected, f"Phase 4 implementation changed: {name}")
    for key in ("checkpoint_sha256", "state_dict_sha256", "bundle_checksums", "preprocess_sha256",
                "split_manifest_sha256", "data_manifest_sha256", "architecture", "validation"):
        require(context["inputs"][key] == provenance[key], f"Phase 4 input drift: {key}")
    require(top["checkpoint_sha256"] == provenance["checkpoint_sha256"], "Wrong pruning parent")
    require(context["tensor_sha256"] == array_hash(dev) and context["rows_sha256"] == digest(rows),
            "Phase 4 validation data drift")
    require(archive["validation_manifest.json"] == provenance["validation"], "Validation selection drift")
    expected = sorted((r for r in state["cache"].values() if r["valid"] and r["mask"] != ALL_ONES.code),
                      key=ranking)[:3]
    require(top["candidates"] == expected, "Leading candidates differ from completed search")
    require(top["baseline"] == state["cache"][cache_key(top["context_sha256"], ALL_ONES)], "Baseline archive mismatch")
    for candidate in expected:
        mask = Mask.decode(candidate["mask"])
        require(candidate["layers"] == [list(b) for b in mask.layers] and
                mask.retained == (candidate["retained_conv1"], candidate["retained_conv2"]), "Invalid mask metadata")

    data = experiment / "data"
    manifest = read_json(data / "artifact_checksums.json")  # Already opened and bound by load_baseline.
    for name in TRAIN_FILES:
        require(sha256(path(data, name, TRAIN_FILES)) == manifest[name], f"Training checksum mismatch: {name}")
    train = np.load(data / TRAIN_FILES[0], allow_pickle=False)
    train_rows = pq.read_table(data / TRAIN_FILES[1]).to_pylist()
    require(train.dtype == np.float32 and train.shape == (len(train_rows), 16, 8) and np.isfinite(train).all(),
            "Invalid training tensors")
    require([r["tensor_index"] for r in train_rows] == list(range(len(train_rows))) and
            len({r["sample_id"] for r in train_rows}) == len(train_rows), "Training metadata misalignment")
    require(all(type(r["label"]) is int and r["label"] in (0, 1) for r in train_rows) and
            {r["label"] for r in train_rows} == {0, 1}, "Training needs both binary classes")
    require(all(r["partition_id"] == "train" and r["role"] == "train" for r in train_rows), "Wrong training role")
    require(all(r["partition_id"] == "development" and r["role"] == "validation" for r in rows), "Wrong validation role")
    for field in ("sample_id", "window_ids"):
        a = {r[field] for r in train_rows} if field == "sample_id" else {v for r in train_rows for v in r[field]}
        b = {r[field] for r in rows} if field == "sample_id" else {v for r in rows for v in r[field]}
        require(not a & b, f"Train/development overlap: {field}")
    y = np.array([r["label"] for r in train_rows], dtype=np.float32)
    parent_config = read_json(search / "baseline/config.json")
    require(positive_weight(y, parent_config["variant"]) == parent_config["positive_weight"], "Training balance drift")

    directs = []
    for seed in SEEDS:
        root = experiment / f"runs/cnn32_weighted/seed-{seed}"
        hashes = read_json(path(root, "artifact_checksums.json", ("artifact_checksums.json",)))
        for name in DIRECT_FILES:
            require(sha256(path(root, name, DIRECT_FILES)) == hashes[name], f"Direct-small checksum mismatch: {name}")
        cfg, result = read_json(root / "config.json"), read_json(root / "result.json")
        require(cfg["variant"] == "cnn32_weighted" and cfg["seed"] == seed and
                cfg["architecture"] == architecture("cnn32_weighted"), "Wrong direct-small architecture")
        require(cfg["data_sha256"] == provenance["data_manifest_sha256"] and
                cfg["preprocess_sha256"] == provenance["preprocess_sha256"] and
                cfg["split_manifest_sha256"] == provenance["split_manifest_sha256"], "Direct-small data mismatch")
        cp = torch.load(root / "best.pt", map_location="cpu", weights_only=True)
        require(cp["config"] == cfg and cp["state_dict_sha256"] == result["state_dict_sha256"] ==
                weight_hash(cp["model_state"]) and result["checkpoint_sha256"] == hashes["best.pt"],
                "Direct-small checkpoint binding mismatch")
        model = TemporalCNN((32, 16))
        model.load_state_dict(cp["model_state"], strict=True)
        model.eval().requires_grad_(False)
        predictions = pq.read_table(root / "development_predictions.parquet").to_pylist()
        fields = ("sample_id", "group_id", "label", "family")
        require([[r[k] for k in fields] for r in predictions] == [[r[k] for k in fields] for r in rows],
                "Direct-small validation alignment mismatch")
        directs.append(dict(id=f"direct_small_seed_{seed}", seed=seed, model=model, result=result,
                            predictions=predictions, root=root, hashes={n: hashes[n] for n in DIRECT_FILES}))
    access = dict(files=sorted(set(opened)), decoded_outcome_roles=["train", "development"],
                  reserved_files_opened=[], test_files_opened=[], external_files_opened=[])
    return dict(parent=parent, dev=dev, rows=rows, saved=saved, provenance=provenance, top=top,
                train=train, train_y=y, train_rows=train_rows, parent_config=parent_config, directs=directs,
                access=access, input_hashes={p: sha256(p) for p in sorted(set(opened))})
