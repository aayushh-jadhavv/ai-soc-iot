"""Independently reopen and verify a saved Phase 2 dataset without training."""

import argparse
from itertools import combinations
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from ids.datasets.audit import sha256
from ids.datasets.temporal import write_json
from ids.features import FEATURE_NAMES


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(output):
    output = Path(output)
    checksums = json.loads((output / "artifact_checksums.json").read_text())
    for name, expected in checksums.items():
        require(sha256(output / name) == expected, "Artifact checksum mismatch: " + name)
    split = json.loads((output / "split_manifest.json").read_text())
    pre = json.loads((output / "preprocess.json").read_text())
    report = json.loads((output / "counts_and_leakage.json").read_text())
    windows = pq.read_table(output / "windows.parquet").to_pylist()
    by_id = {w["window_id"]: w for w in windows}
    require(len(by_id) == len(windows), "Duplicate saved window IDs")
    require(pre["feature_names"] == list(FEATURE_NAMES), "Feature order changed")
    for window in windows:
        values = np.asarray(window["values"], dtype=np.float64)
        require(values.shape == (16,) and np.isfinite(values).all() and (values >= 0).all(), "Invalid raw window")
        require((values[:12] == np.floor(values[:12])).all(), "Counts and IP bytes must be integral")
        require(window["start_ns"] % 1_000_000_000 == 0 and window["end_ns"] - window["start_ns"] == 1_000_000_000,
                "Invalid window boundary")
        require(window["capture_valid"] == (not window["coverage_reasons"]), "Coverage reason disagreement")
    used_windows, used_connections, sample_ids, training_ids = {}, {}, set(), set()
    counts = {}
    same = ("group_id", "device_id", "lifecycle", "binding_revision", "boot_id", "capture_session_id", "enforcement_revision")
    for partition in split["partitions"]:
        folder = output / partition["partition_id"]
        raw = np.load(folder / "raw.npy", allow_pickle=False)
        tensor = np.load(folder / "tensor.npy", allow_pickle=False)
        samples = pq.read_table(folder / "samples.parquet").to_pylist()
        n = len(samples)
        require(raw.shape == (n, 8, 16), "Raw array layout changed")
        require(tensor.shape == (n, 16, 8) and tensor.dtype == np.float32, "Tensor layout/dtype changed")
        expected = ((np.log1p(raw) - pre["mean"]) / np.maximum(pre["std"], 1e-6)).transpose(0, 2, 1).astype(np.float32)
        np.testing.assert_array_equal(tensor, expected)
        ids, connections = set(), set()
        for index, sample in enumerate(samples):
            require(sample["tensor_index"] == index, "Metadata row points to another tensor")
            require(sample["sample_id"] not in sample_ids, "Repeated sample ID")
            sample_ids.add(sample["sample_id"])
            history = [by_id[wid] for wid in sample["window_ids"]]
            require(len(history) == 8 and len({w["window_id"] for w in history}) == 8, "Invalid history size")
            for i, w in enumerate(history):
                require(w["capture_valid"] and not w["exclusion_reason"] in {"crossing_connection", "invalid_capture"},
                        "Excluded window entered sample")
                require(w["partition_id"] == partition["partition_id"], "Sample crossed partition")
                require(all(w[k] == history[0][k] for k in same), "History crossed identity/lifecycle")
                require(partition["start_ns"] <= w["start_ns"] < w["end_ns"] <= partition["end_ns"],
                        "History outside declared split")
                if i:
                    require(history[i-1]["end_ns"] == w["start_ns"] and history[i-1]["sequence_number"] + 1 == w["sequence_number"],
                            "Discontinuous sample")
                ids.add(w["window_id"])
                connections.update(w["connection_ids"])
            final = history[-1]
            require(final["label"] is not None and sample["label"] == final["label"] and sample["family"] == final["family"],
                    "Label is not the final-second label")
            require(sample["final_time_ns"] == final["end_ns"] and sample["final_window_start_ns"] == final["start_ns"],
                    "Final time metadata mismatch")
            require(sample["original_group_id"] == final["original_group_id"] and sample["original_device_id"] == final["original_device_id"],
                    "Original identities changed")
            np.testing.assert_array_equal(raw[index], [w["values"] for w in history])
        counts[partition["partition_id"]] = n
        used_windows[partition["partition_id"]] = ids
        used_connections[partition["partition_id"]] = connections
        if partition["role"] == "train":
            training_ids.update(ids)
    for a, b in combinations(used_windows, 2):
        require(not used_windows[a] & used_windows[b], "Shared windows across partitions")
        require(not used_connections[a] & used_connections[b], "Shared connections across partitions")
    saved_fit = json.loads((output / "fit_window_ids.json").read_text())
    require(len(saved_fit) == len(set(saved_fit)) and set(saved_fit) == training_ids, "Training fit set is not unique sample windows")
    logvalues = np.log1p(np.asarray([by_id[wid]["values"] for wid in sorted(training_ids)], dtype=np.float64))
    np.testing.assert_allclose(pre["mean"], logvalues.mean(axis=0), atol=1e-12, rtol=1e-12)
    np.testing.assert_allclose(pre["std"], logvalues.std(axis=0, ddof=0), atol=1e-12, rtol=1e-12)
    require(len(sample_ids) == report["sample_count"], "Report sample total disagrees")
    require(report["training_performed"] is False, "Unexpected training artifact status")
    result = dict(passed=True, checked_artifacts=len(checksums), checked_windows=len(windows),
        checked_samples=len(sample_ids), samples_by_partition=counts, unique_fit_windows=len(training_ids),
        raw_tensor_metadata_roundtrip=True, exact_normalization_roundtrip=True,
        final_second_labels_only=True, shared_windows=0, shared_connections=0,
        source_group_overlap=report["shared_source_groups"],
        independent_evaluation=report["independent_group_evaluation"], training_performed=False)
    write_json(output / "verification.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(check(parser.parse_args().output), indent=2))
