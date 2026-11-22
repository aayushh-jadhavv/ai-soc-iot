import json
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import torch

from ids.run_logging import sha256, write_json
from ids.training.data import load_training_data, projected_csv, sample_partition
from ids.training.metrics import binary_metrics, development_metrics
from ids.training.train import (VARIANTS, architecture, inputs, make_model, positive_weight,
                                run_one, verify_bundle, weight_hash)


def test_threshold_fixed_labels_ties_and_missing_support():
    result = binary_metrics([0, 1, 1, 0], [.8, .8, .2, .1])
    assert result["macro_f1"] == .5
    assert result["pr_auc"] == pytest.approx(7 / 12)
    assert binary_metrics([0, 1], [.49, .5])["macro_f1"] == 1
    missing = binary_metrics([0, 0], [.1, .2])
    assert missing["macro_f1"] is missing["recall"] is missing["pr_auc"] is None
    none_detected = binary_metrics([0, 1], [.1, .2])
    assert none_detected["attack_f1"] == 0
    assert none_detected["macro_f1"] == pytest.approx(1 / 3)
    with pytest.raises(ValueError):
        binary_metrics([0, 1], [.1, np.nan])
    families = development_metrics([dict(label=0, family="benign", group_id="g"),
                                    dict(label=1, family="reconnaissance", group_id="g")], [.1, .9])
    assert families["per_family"]["dos"]["support"] == 0
    assert families["per_family"]["dos"]["binary_vs_benign"] is None
    assert families["per_family"]["reconnaissance"]["binary_vs_benign"]["macro_f1"] == 1


def test_architectures_and_temporal_ablation():
    x = torch.randn(3, 16, 8)
    expected = {"cnn64_weighted": 9345, "cnn64_unweighted": 9345,
                "last_window_weighted": 9345, "cnn32_weighted": 3137, "logistic128_weighted": 129}
    for variant in VARIANTS:
        model = make_model(variant)
        assert sum(p.numel() for p in model.parameters()) == expected[variant]
        assert model(inputs(x, variant)).shape == (3, 1)
    changed = x.clone()
    changed[:, :, :-1] += 100
    model = make_model("last_window_weighted")
    torch.testing.assert_close(model(inputs(x, "last_window_weighted")),
                               model(inputs(changed, "last_window_weighted")), atol=0, rtol=0)
    assert architecture("logistic128_weighted")["input_features"] == 128
    y = np.r_[np.zeros(24), np.ones(2)]
    assert positive_weight(y, "cnn64_weighted") == 12
    assert positive_weight(y, "cnn64_unweighted") == 1


def test_boundary_and_connection_purge_is_outcome_blind():
    windows = {str(i): dict(start_ns=i, end_ns=i+1, connection_ids=["cross"] if i == 9 else [])
               for i in range(24)}
    rows = [dict(sample_id="across", window_ids=[str(i) for i in range(7, 15)]),
            dict(sample_id="touch", window_ids=[str(i) for i in range(8, 16)]),
            dict(sample_id="keep", window_ids=[str(i) for i in range(16, 24)])]
    kept, excluded = sample_partition(rows, windows, {"cross"}, 8, 24)
    assert [r["sample_id"] for r in kept] == ["keep"]
    assert excluded == {"history_crosses_boundary": 1, "crossing_connection_history": 1}
    # No label/family fields exist; adding arbitrary outcomes cannot affect selection.
    again, _ = sample_partition([{**r, "label": 1, "family": "dos"} for r in rows], windows, {"cross"}, 8, 24)
    assert [r["sample_id"] for r in again] == ["keep"]


def test_csv_projection_excludes_outcome_and_supports_quoted_newlines(tmp_path):
    path = tmp_path / "source.csv"
    path.write_text('a,b,label\n1,2,"attack\ncategory"\n3,4,benign\n')
    assert list(projected_csv(path, [0, 1], skip_rows=1)) == [{"f0": "1", "f1": "2"}, {"f0": "3", "f1": "4"}]


def synthetic_data(seed=18):
    rng = np.random.default_rng(seed)
    result = {}
    for role, n in (("train", 40), ("development", 16)):
        x = rng.normal(size=(n, 16, 8)).astype(np.float32)
        y = (np.arange(n) % 2).astype(np.float32)
        x[:, 0, :] += y[:, None] * 2
        result[role] = dict(x=x, y=y, rows=[dict(sample_id=f"{role}-{i}", source_sample_id=f"original-{role}-{i}",
            tensor_index=i, group_id="g", original_group_id=None, device_id="d", final_time_ns=i,
            label=int(label), family="reconnaissance" if label else "benign") for i, label in enumerate(y)])
    return result


def setup_experiment(path):
    (path / "data").mkdir(parents=True)
    write_json(path / "registration.json", {"test_fixture": True})
    write_json(path / "data/preprocess.json", {"test_fixture": True})
    write_json(path / "data/split_manifest.json", {"test_fixture": True})


def test_exact_interruption_resume_and_provenance_guard(tmp_path):
    data = synthetic_data()
    full, resumed = tmp_path / "full", tmp_path / "resumed"
    setup_experiment(full)
    setup_experiment(resumed)
    complete = run_one(full, data, "fixture", "cnn64_weighted", 1729)
    assert run_one(resumed, data, "fixture", "cnn64_weighted", 1729, stop_after_epoch=2) is None
    continued = run_one(resumed, data, "fixture", "cnn64_weighted", 1729, resume=True)
    assert complete["best_epoch"] == continued["best_epoch"]
    assert complete["development"] == continued["development"]
    assert complete["state_dict_sha256"] == continued["state_dict_sha256"]
    full_state = torch.load(full / complete["run_directory"] / "resume.pt", weights_only=True)
    resumed_state = torch.load(resumed / continued["run_directory"] / "resume.pt", weights_only=True)
    assert weight_hash(full_state["model_state"]) == weight_hash(resumed_state["model_state"])
    assert full_state["bad_epochs"] == resumed_state["bad_epochs"]
    assert torch.equal(full_state["rng"]["permutation"], resumed_state["rng"]["permutation"])
    for key in full_state["optimizer_state"]["state"]:
        for field, value in full_state["optimizer_state"]["state"][key].items():
            assert torch.equal(value, resumed_state["optimizer_state"]["state"][key][field])
    histories = [read_json_file(p / complete["run_directory"] / "epochs.json") for p in (full, resumed)]
    assert [r["development"] for r in histories[0]] == [r["development"] for r in histories[1]]
    assert len(histories[0]) <= 30
    if complete["stopping_reason"] == "patience_5":
        assert histories[0][-1]["bad_epochs"] == 5
    with pytest.raises(ValueError, match="drift"):
        run_one(resumed, data, "changed-data", "cnn64_weighted", 1729, resume=True)


def read_json_file(path):
    return json.loads(path.read_text())


def test_loader_never_reads_protected_outcomes(tmp_path, monkeypatch):
    data = synthetic_data()
    target = tmp_path / "data"
    for role, value in data.items():
        p = target / role
        p.mkdir(parents=True)
        np.save(p / "tensor.npy", value["x"], allow_pickle=False)
        pq.write_table(pa.Table.from_pylist(value["rows"]), p / "samples.parquet")
    write_json(target / "artifact_checksums.json", {p.relative_to(target).as_posix(): sha256(p)
               for p in target.rglob("*") if p.is_file()})
    real_read, reads = pq.read_table, []
    def guarded(path, *args, **kwargs):
        assert Path(path).parent.name in {"train", "development"}
        reads.append(str(path))
        return real_read(path, *args, **kwargs)
    monkeypatch.setattr(pq, "read_table", guarded)
    loaded, _ = load_training_data(tmp_path)
    assert len(reads) == 2
    assert len(loaded["development"]["y"]) == len(data["development"]["y"])
    assert np.mean(loaded["development"]["y"]) == np.mean(data["development"]["y"])


def test_bare_checkpoint_is_not_pruning_input(tmp_path):
    torch.save(make_model("cnn64_weighted").state_dict(), tmp_path / "best.pt")
    write_json(tmp_path / "checksums.json", {"best.pt": sha256(tmp_path / "best.pt")})
    with pytest.raises(ValueError, match="Incomplete pruning package"):
        verify_bundle(tmp_path)
