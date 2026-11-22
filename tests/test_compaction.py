"""Phase 5 wiring, quality, outcome boundaries and artifact replay on synthetic data."""

import copy
from dataclasses import replace
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import torch

from ids.compaction import data as compact_data
from ids.compaction import run as phase5
from ids.compaction.model import (WiringError, channel_map, check_equivalence, describe,
                                  physical_cost, rebuild, synthetic_samples)
from ids.datasets.temporal import digest
from ids.ga import data as ga_data
from ids.ga import search as ga
from ids.ga.masks import ALL_ONES, Mask
from ids.model import TemporalCNN
from ids.run_logging import sha256, write_json
from ids.training.data import SEEDS, read_json
from ids.training.train import architecture, determinism, weight_hash


def sparse_mask():
    return Mask(tuple(int(i in (1, 6, 35, 63)) for i in range(64)),
                tuple(int(i in (0, 3, 18, 31)) for i in range(32)))


@pytest.mark.parametrize("mask", [ALL_ONES, sparse_mask(), Mask(tuple(i % 2 for i in range(64)),
                                                               tuple(int(i % 3 == 0) for i in range(32)))])
def test_physical_slices_biases_equivalence_and_parent_independence(mask):
    determinism(15)
    parent = TemporalCNN().eval()
    with torch.no_grad():
        parent.conv1.bias.copy_(torch.linspace(-.2, .2, 64))
        parent.conv2.bias.copy_(torch.linspace(-.1, .3, 32))
        parent.output.bias.fill_(.123)
    original = weight_hash(parent.state_dict())
    model = rebuild(parent, mask)
    mapping = channel_map(mask)
    i, j = mapping["conv1"], mapping["conv2"]
    expected = {"conv1.weight": parent.conv1.weight[i], "conv1.bias": parent.conv1.bias[i],
                "conv2.weight": parent.conv2.weight[j][:, i], "conv2.bias": parent.conv2.bias[j],
                "output.weight": parent.output.weight[:, j], "output.bias": parent.output.bias}
    for name, value in model.state_dict().items():
        torch.testing.assert_close(value, expected[name], atol=0, rtol=0)
        assert value.data_ptr() != parent.state_dict()[name].data_ptr()
    cost = physical_cost(model)
    c1, c2 = mask.retained
    assert cost["parameters"] == 49*c1 + 3*c1*c2 + 2*c2 + 1
    assert cost["tensor_bytes"] == cost["parameters"] * 4
    assert describe(model)["channels"] == [c1, c2]
    assert not list(model.buffers())
    report = check_equivalence(parent, model, mask, {"synthetic": synthetic_samples()})
    assert report["passed"] and report["atol"] == 1e-6 and report["rtol"] == 1e-5
    with torch.no_grad():
        model.conv1.bias.add_(1)
    assert weight_hash(parent.state_dict()) == original


@pytest.mark.parametrize("parameter", ["conv1.weight", "conv1.bias", "conv2.weight", "conv2.bias", "output.weight", "output.bias"])
def test_every_affine_slice_has_a_fail_closed_numerical_gate(parameter):
    determinism(3)
    parent = TemporalCNN()
    with torch.no_grad():
        for p in parent.parameters():
            p.uniform_(.05, .15)
    model = rebuild(parent, sparse_mask())
    with torch.no_grad():
        model.state_dict()[parameter].add_(.01)
    with pytest.raises(WiringError) as error:
        check_equivalence(parent, model, sparse_mask(), {"fixture": np.ones((2, 16, 8), dtype=np.float32)})
    assert not error.value.report["passed"]


def test_gate_keeps_exact_boundary_and_rejects_either_metric_or_undefined():
    baseline = {"recall": .9, "macro_f1": .8}
    assert phase5.quality_gate({"recall": .88, "macro_f1": .78}, baseline)["accepted"]
    assert not phase5.quality_gate({"recall": np.nextafter(.88, 0), "macro_f1": .9}, baseline)["accepted"]
    assert not phase5.quality_gate({"recall": .9, "macro_f1": .779999}, baseline)["accepted"]
    for value in (None, float("nan"), float("inf")):
        assert not phase5.quality_gate({"recall": value, "macro_f1": .9}, baseline)["accepted"]
    for changes in ({"max_epochs": 6}, {"top_k": 4}, {"learning_rate": .001}, {"recall_loss_limit": .03}):
        with pytest.raises(ValueError):
            replace(phase5.Config(), **changes)


def test_selection_allows_failed_ga_and_direct_small_or_unpruned_fallback():
    baseline = {"recall": .9, "macro_f1": .8}
    def record(name, kind, params, metrics):
        return dict(id=name, kind=kind, cost={"parameters": params}, post=metrics,
                    gate=phase5.quality_gate(metrics, baseline))
    original = record("unpruned", "unpruned", 9345, baseline)
    direct = record("direct", "direct_small", 3137, {"recall": .9, "macro_f1": .79})
    failed = record("ga_1", "ga", 1000, {"recall": .87, "macro_f1": .99})
    assert phase5.select_candidate([original, direct, failed], "direct") == "direct"
    direct["gate"]["accepted"] = False
    assert phase5.select_candidate([original, direct, failed], "direct") == "unpruned"
    compact = record("ga_2", "ga", 2569, {"recall": .9, "macro_f1": .79})
    assert phase5.select_candidate([original, failed, compact], "direct") == "ga_2"


def fixture_experiment(root):
    """Real Phase 3/4 formats with poisoned manifest entries for protected data."""
    determinism(22)
    bundle, experiment, search = root / "bundle", root / "phase3", root / "phase4"
    bundle.mkdir()
    data = experiment / "data"
    rows_by_role, xs = {}, {}
    for role in ("train", "development"):
        (data / role).mkdir(parents=True)
        x = np.random.default_rng(15 if role == "train" else 16).normal(size=(12, 16, 8)).astype(np.float32)
        rows = [dict(sample_id=f"{role}-{i}", tensor_index=i, group_id="fixture", label=i % 2,
                     family="reconnaissance" if i % 2 else "benign", window_ids=[f"{role}-window-{i}"],
                     partition_id=role, role="train" if role == "train" else "validation") for i in range(len(x))]
        np.save(data / role / "tensor.npy", x, allow_pickle=False)
        pq.write_table(pa.Table.from_pylist(rows), data / role / "samples.parquet")
        rows_by_role[role], xs[role] = rows, x
    for name in ga_data.BUNDLE_FILES:
        if name.endswith(".json"):
            write_json(bundle / name, {"synthetic_fixture": True})
    split = {"synthetic_fixture": True}
    for name, content in (("split_manifest.json", split), ("preprocess.json", {"split_manifest_sha256": digest(split)}),
                          ("feature_schema.json", {})):
        write_json(data / name, content)
        write_json(bundle / name, content)
    manifest = {n: sha256(data / n) for n in ga_data.DATA_FILES + compact_data.TRAIN_FILES}
    manifest.update({n: "must_not_open" for n in ("reserved_index.parquet", "../internal_test/labels.npy", "external.csv")})
    write_json(data / "artifact_checksums.json", manifest)
    common = dict(data_sha256=digest(manifest), preprocess_sha256=sha256(bundle / "preprocess.json"),
                  split_manifest_sha256=sha256(bundle / "split_manifest.json"), positive_weight=1.)
    model = TemporalCNN()
    arch = architecture("cnn64_weighted")
    cfg = dict(**common, variant="cnn64_weighted", seed=31415, architecture=arch)
    write_json(bundle / "config.json", cfg)
    write_json(bundle / "architecture.json", arch)
    torch.save(dict(model_state=model.state_dict(), config=cfg), bundle / "best.pt")
    _, logits, scores = phase5.assess(model, xs["development"], rows_by_role["development"])
    phase5.save_predictions(bundle / "development_predictions.parquet", rows_by_role["development"], logits, scores)
    write_json(bundle / "handoff.json", dict(trained=True, pruning_input_valid=True, architecture=arch,
        data_sha256=digest(manifest), checkpoint_sha256=sha256(bundle / "best.pt"), state_dict_sha256=weight_hash(model.state_dict()),
        preprocess_sha256=common["preprocess_sha256"], split_manifest_sha256=common["split_manifest_sha256"],
        development_predictions_sha256=sha256(bundle / "development_predictions.parquet"), independent_heldout_development_groups=0))
    write_json(bundle / "checksums.json", {n: sha256(bundle / n) for n in ga_data.BUNDLE_FILES})
    for seed in SEEDS:
        path = experiment / f"runs/cnn32_weighted/seed-{seed}"
        path.mkdir(parents=True)
        model = TemporalCNN((32, 16))
        cfg = dict(**common, variant="cnn32_weighted", seed=seed, architecture=architecture("cnn32_weighted"))
        state_hash = weight_hash(model.state_dict())
        torch.save(dict(model_state=model.state_dict(), config=cfg, state_dict_sha256=state_hash), path / "best.pt")
        metrics, logits, scores = phase5.assess(model, xs["development"], rows_by_role["development"])
        phase5.save_predictions(path / "development_predictions.parquet", rows_by_role["development"], logits, scores)
        write_json(path / "config.json", cfg)
        write_json(path / "result.json", dict(state_dict_sha256=state_hash, checkpoint_sha256=sha256(path / "best.pt"), development=metrics))
        write_json(path / "environment.json", {})
        write_json(path / "artifact_checksums.json", {n: sha256(path / n) for n in compact_data.DIRECT_FILES})
    ga.run(bundle, experiment, search, config=ga.SearchConfig(max_generations=0))
    return search, experiment


def test_training_selects_earliest_best_trained_epoch_and_never_epoch_zero(tmp_path, monkeypatch):
    model = TemporalCNN((4, 4))
    folder = tmp_path / "ga"
    folder.mkdir()
    data = dict(train=np.zeros((2, 16, 8), dtype=np.float32), train_y=np.array([0, 1], dtype=np.float32),
                dev=None, rows=None, parent_config=dict(variant="cnn64_weighted", positive_weight=1.))
    epoch = [0]
    def train(model, optimizer, *args):
        assert optimizer.param_groups[0]["lr"] == .0001
        epoch[0] += 1
        with torch.no_grad():
            model.output.bias.fill_(epoch[0])
        return .1
    def assess(*args):
        return {"macro_f1": [.5, .7, .7, .6, .4][epoch[0]-1], "recall": .9}, None, None
    monkeypatch.setattr(phase5, "train_epoch", train)
    monkeypatch.setattr(phase5, "assess", assess)
    history, selected = phase5.fine_tune(model, data, phase5.Config(), folder)
    assert len(history) == 5 and selected == 2 and model.output.bias.item() == 2
    assert torch.load(folder / "last.pt", weights_only=True)["output.bias"].item() == 5


def test_input_allowlist_and_checksum_failures(tmp_path, monkeypatch):
    search, experiment = fixture_experiment(tmp_path)
    opened = []
    original_open = Path.open
    def guard(path, *args, **kwargs):
        if args and "r" in args[0]:
            assert "reserved_index" not in str(path) and "internal_test" not in str(path) and "external.csv" not in str(path)
        opened.append(str(path))
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guard)
    inputs = compact_data.load_inputs(search, experiment)
    assert inputs["access"]["decoded_outcome_roles"] == ["train", "development"]
    assert len(inputs["train"]) == 12 and len(inputs["directs"]) == 3
    assert opened
    (experiment / "data/train/tensor.npy").write_bytes(b"corruption")
    with pytest.raises(ValueError, match="Training checksum"):
        compact_data.load_inputs(search, experiment)


def test_run_stops_all_training_on_a_wiring_error(tmp_path, monkeypatch):
    search, experiment = fixture_experiment(tmp_path)
    calls = []
    original = phase5.rebuild
    def faulty(parent, mask):
        model = original(parent, mask)
        if calls:
            with torch.no_grad():
                model.output.bias.add_(1)
        calls.append(mask)
        return model
    monkeypatch.setattr(phase5, "rebuild", faulty)
    def forbidden(*args):
        pytest.fail("Optimizer must not run before every candidate passes")
    monkeypatch.setattr(phase5, "fine_tune", forbidden)
    output = tmp_path / "failed"
    with pytest.raises(WiringError):
        phase5.run(search, experiment, output)
    assert read_json(output / "status.json")["status"] == "wiring_error"
    assert read_json(output / "candidates/preflight.json")["training_steps"] == 0
    assert not list(output.rglob("post.pt"))


def test_end_to_end_freezes_real_modules_and_replays_every_comparison(tmp_path):
    search, experiment = fixture_experiment(tmp_path)
    output = tmp_path / "phase5"
    original_hash = sha256(search / "baseline/best.pt")
    result = phase5.run(search, experiment, output, phase5.Config(max_epochs=2))
    assert len(result["models"]) == 7 and len(result["equivalence"]) == 3
    assert sha256(search / "baseline/best.pt") == original_hash == sha256(output / "originals/unpruned/best.pt")
    assert all(r["epochs_completed"] == 2 for r in result["models"] if r["kind"] == "ga")
    assert phase5.verify(output, search, experiment)["passed"]
    for name in ("unpruned", *(f"direct_small_seed_{seed}" for seed in SEEDS)):
        assert (output / "frozen" / name / "weights.pt").is_file()
    data = compact_data.load_inputs(search, experiment)
    replay_model = rebuild(data["parent"], Mask.decode(result["models"][-1]["mask"]))
    replay_path = tmp_path / "training_replay"
    replay_path.mkdir()
    phase5.fine_tune(replay_model, data, phase5.Config(max_epochs=2), replay_path)
    frozen, _ = phase5.load_frozen(output / "frozen/ga_3")
    assert weight_hash(frozen.state_dict()) == weight_hash(replay_model.state_dict())
    with pytest.raises(ValueError, match="must be new"):
        phase5.run(search, experiment, output)
    (output / "frozen/ga_1/weights.pt").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="Frozen artifact changed"):
        phase5.load_frozen(output / "frozen/ga_1")
