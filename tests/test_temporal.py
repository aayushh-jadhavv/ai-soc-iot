from dataclasses import replace
import json

import numpy as np
import pytest

from ids.datasets.temporal import LabeledWindow, Partition, SplitPlan, form_samples, save_dataset
from ids.features import Binding, Registry, WindowExtractor
from ids.features.packets import SECOND
from ids.preprocessing import fit_unique_training_windows


def rows(group="g", count=24):
    result = []
    engine = WindowExtractor(Registry([Binding("d", "192.0.2.1", 0, 100 * SECOND)]),
        start_ns=0, capture_session_id=group, on_window=result.append)
    engine.finish(count * SECOND)
    return [LabeledWindow(w, group, "original-" + group, "original-d", None, None,
        "unknown_final_label", {"mixed_unknown": False}) for w in result]


def plan():
    return SplitPlan([Partition("train", "g", "train", 0, 12 * SECOND),
        Partition("validation", "g", "validation", 12 * SECOND, 24 * SECOND)],
        mode="within_group_chronological")


def test_final_label_only_and_partition_before_history():
    source = rows()
    source[0] = replace(source[0], label=1, family="dos", label_reason="observed_attack_involvement")
    source[7] = replace(source[7], label=0, family="benign", label_reason="verified_normal_coverage")
    source[19] = replace(source[19], label=1, family="dos", label_reason="observed_attack_involvement")
    raw, samples, metadata, report = form_samples(source, plan())
    assert raw.shape == (2, 8, 16)
    assert [s["label"] for s in samples] == [0, 1]  # earlier attack does not label final
    assert samples[0]["final_time_ns"] == 8 * SECOND
    assert samples[1]["window_ids"][0] == source[12].window.wire["window_id"]
    assert report["overlap_checks"][0]["shared_window_count"] == 0
    assert metadata[0]["label"] == 1 and metadata[0]["capture_valid"]
    with pytest.raises(ValueError, match="Establish partitions"):
        form_samples(source, None)


def test_unknown_labels_and_invalid_coverage_remain_separate():
    source = rows(count=12)
    source[7] = replace(source[7], label=1, family="dos", label_reason="observed_attack_involvement")
    _, samples, meta, _ = form_samples(source, plan())
    assert len(samples) == 1  # seven unknown contexts still form a valid sample
    bad = {**source[3].window.wire, "quality": {"valid": False, "reasons": ["capture_drop"]}}
    source[3] = replace(source[3], window=replace(source[3].window, wire=bad))
    _, samples, meta, report = form_samples(source, plan())
    assert not samples
    assert not meta[3]["capture_valid"] and meta[3]["label_reason"] == "unknown_final_label"
    assert report["exclusions"]["invalid_capture"] == 1


def test_crossing_connections_purge_whole_windows_both_endpoints():
    source = [replace(r, label=0, family="benign") for r in rows()]
    for index in (8, 14):
        source[index] = replace(source[index], connection_ids=("same-connection",))
    _, samples, meta, report = form_samples(source, plan())
    assert meta[8]["exclusion_reason"] == meta[14]["exclusion_reason"] == "crossing_connection"
    assert report["crossing_connection_count"] == 1
    assert not any(source[8].window.wire["window_id"] in s["window_ids"] for s in samples)
    assert all(x["shared_connection_count"] == 0 for x in report["overlap_checks"])
    _, _, meta, _ = form_samples(source, plan(), annotated_crossing_connections={"same-connection"})
    assert meta[8]["exclusion_reason"] == "crossing_connection"


def test_independent_group_guard_external_guard_and_overlap():
    with pytest.raises(ValueError, match="group leaks"):
        SplitPlan(plan().partitions)
    with pytest.raises(ValueError, match="Overlapping"):
        SplitPlan([Partition("a", "g", "train", 0, 10 * SECOND),
                   Partition("b", "g", "train", SECOND, 20 * SECOND)])
    with pytest.raises(ValueError, match="evaluation-only"):
        SplitPlan([Partition("a", "g", "train", 0, SECOND, dataset="BoT-IoT")])
    p = SplitPlan([Partition("a", "one", "train", 0, 8 * SECOND),
                   Partition("b", "two", "validation", 0, 8 * SECOND)])
    data = [replace(r, label=0, family="benign") for r in rows("one", 8) + rows("two", 8)]
    _, samples, _, report = form_samples(data, p)
    assert len(samples) == 2 and report["independent_group_evaluation"]
    assert not report["shared_source_groups"]


def test_fit_counts_unique_training_windows_and_rejects_leakage():
    a = dict(window_id="a", values=[0] * 16, role="train", valid=True)
    b = dict(window_id="b", values=[8] * 16, role="train", valid=True)
    fit, metadata = fit_unique_training_windows([a, b, a, a, b])
    assert metadata["unique_training_window_count"] == 2
    np.testing.assert_allclose(fit.mean, np.log(9) / 2)
    np.testing.assert_allclose(fit.std, np.log(9) / 2)
    for bad in [{**b, "role": "validation"}, {**b, "valid": False}, {**b, "values": [-1] * 16},
                {**a, "values": [4] * 16}]:
        with pytest.raises(ValueError):
            fit_unique_training_windows([a, bad])
    assert fit.transform_array(np.zeros((1, 8, 16))).shape == (1, 16, 8)


def test_saved_metadata_separate_from_tensor_and_no_validation_fit(tmp_path):
    import pyarrow.parquet as pq

    source = [replace(r, label=0, family="benign", label_reason="verified_normal_coverage") for r in rows()]
    for i, row in enumerate(source):
        # Nonzero held-out data must not alter the zero-valued training fit.
        if i >= 12:
            source[i] = replace(row, window=replace(row.window, wire={**row.window.wire, "values": [999] * 16}))
    raw, samples, meta, report = form_samples(source, plan())
    pre = save_dataset(tmp_path, raw, samples, meta, report)
    assert pre["mean"] == [0] * 16 and pre["unique_training_window_count"] == 12
    tensor = np.load(tmp_path / "train" / "tensor.npy", allow_pickle=False)
    assert tensor.dtype == np.float32 and tensor.shape == (5, 16, 8) and not tensor.any()
    saved = pq.read_table(tmp_path / "validation" / "samples.parquet").to_pylist()
    assert saved[0]["original_group_id"] == "original-g" and saved[0]["original_device_id"] == "original-d"
    assert set(saved[0]) >= {"sample_id", "label", "family", "final_time_ns", "coverage_json", "window_ids"}
    assert json.loads((tmp_path / "counts_and_leakage.json").read_text())["training_performed"] is False


def test_independent_saved_artifact_checker_and_corruption_detection(tmp_path):
    from ids.datasets.audit import sha256
    from ids.datasets.check_temporal import check
    from ids.datasets.temporal import write_json

    source = [replace(r, label=0, family="benign", label_reason="verified_normal_coverage") for r in rows()]
    raw, samples, meta, report = form_samples(source, plan())
    save_dataset(tmp_path, raw, samples, meta, report)
    write_json(tmp_path / "split_manifest.json", plan().to_dict())
    write_json(tmp_path / "artifact_checksums.json", {str(p.relative_to(tmp_path)): sha256(p)
               for p in tmp_path.rglob("*") if p.is_file()})
    assert check(tmp_path)["checked_samples"] == 10
    (tmp_path / "train" / "raw.npy").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checksum mismatch"):
        check(tmp_path)


def test_duplicate_physical_window_cannot_hide_behind_new_id():
    source = rows(count=8)
    duplicate = replace(source[-1], window=replace(source[-1].window,
                         wire={**source[-1].window.wire, "window_id": "another-id"}))
    with pytest.raises(ValueError, match="original endpoint-second"):
        form_samples([*source, duplicate], plan())
