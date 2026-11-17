"""Register Phase 3 and derive development data without opening held-out labels.

The original Phase 2 files remain immutable. Only train/development outcomes
are decoded; reserved data are represented by a label-free index for later work.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import numpy as np
import pyarrow as pa
import pyarrow.csv as pc
import pyarrow.parquet as pq

from ids.datasets.audit import tuple_key
from ids.datasets.packet_audit import microseconds
from ids.datasets.temporal import digest
from ids.features import (FEATURE_NAMES, FEATURE_UNITS, Binding, LiveAdapter,
                          OfflineAdapter, Registry, WindowExtractor, read_pcap)
from ids.features.packets import SECOND, canonical_tuple
from ids.preprocessing import Preprocessor, fit_unique_training_windows
from ids.run_logging import sha256, write_json

ROOT = Path(__file__).resolve().parents[2]
SEEDS = [1729, 2718, 31415]
VARIANTS = ["cnn64_weighted", "cnn32_weighted", "logistic128_weighted",
            "last_window_weighted", "cnn64_unweighted"]
INDEX_COLUMNS = ["sample_id", "tensor_index", "group_id", "original_group_id",
                 "device_id", "original_device_id", "final_time_ns",
                 "final_window_start_ns", "window_ids"]


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def require(value, message):
    if not value:
        raise ValueError(message)


def projected_csv(path, indices, *, skip_rows=0):
    """Project tuple/time columns; label and attack-category columns are excluded."""
    names = [f"f{i}" for i in indices]
    reader = pc.open_csv(path, read_options=pc.ReadOptions(
        autogenerate_column_names=True, skip_rows=skip_rows, block_size=4 * 1024**2, encoding="latin1"),
        parse_options=pc.ParseOptions(newlines_in_values=True),
        convert_options=pc.ConvertOptions(include_columns=names,
                                         column_types={n: pa.string() for n in names}))
    for batch in reader:
        yield from batch.to_pylist()


def annotation_crossings(parent_manifest, boundary, group):
    """Reapply Phase 2's conservative ±0.5s annotation bound policy at new B.

    Read only tuple/time metadata, including annotations with no packet on one
    side. Label values are neither projected nor used. Hash all scanned sources.
    """
    crossing, provenance = set(), {}
    def observe(key, start, end):
        if (start - 500_000) * 1000 < boundary < (end + 500_000) * 1000 + 1:
            crossing.add(digest([group, canonical_tuple(key)]))
    for name, expected in parent_manifest["source_hashes"].items():
        path = Path(name)
        flow = path.name in {f"UNSW-NB15_{i}.csv" for i in range(1, 5)}
        gt, bro = path.name == "NUSW-NB15_GT.csv", path.name == "conn.log"
        if not (flow or gt or bro):
            continue
        require(sha256(path) == expected, f"Annotation source changed: {path}")
        provenance[name] = expected
        if flow:
            for r in projected_csv(path, [0, 1, 2, 3, 4, 28, 29]):
                a, b = int(r["f28"]) * 1_000_000, int(r["f29"]) * 1_000_000
                if (a - 500_000) * 1000 < boundary < (b + 500_000) * 1000 + 1:
                    observe(tuple_key(r["f4"], *(r[f"f{i}"] for i in range(4))), a, b)
        elif gt:
            for r in projected_csv(path, [0, 1, 4, 5, 6, 7, 8], skip_rows=1):
                a, b = microseconds(r["f0"]), microseconds(r["f1"])
                if (a - 500_000) * 1000 < boundary < (b + 500_000) * 1000 + 1:
                    observe(tuple_key(r["f4"], *(r[f"f{i}"] for i in range(5, 9))), a, b)
        else:
            with path.open(encoding="utf-8") as stream:
                fields = None
                for line in stream:
                    if line.startswith("#fields\t"):
                        fields = line.rstrip().split("\t")[1:]
                    if line.startswith("#"):
                        continue
                    require(fields is not None, "BRO header absent")
                    r = dict(zip(fields, line.rstrip("\r\n").split("\t")))
                    a = microseconds(r["ts"])
                    b = a + (0 if r["duration"] == "-" else microseconds(r["duration"]))
                    if (a - 500_000) * 1000 < boundary < (b + 500_000) * 1000 + 1:
                        observe(tuple_key(r["proto"], r["id.orig_h"], r["id.orig_p"],
                                          r["id.resp_h"], r["id.resp_p"]), a, b)
    require(provenance, "Missing annotation provenance")
    return crossing, provenance


def sample_partition(rows, windows, crossing, start, end):
    """Outcome-blind sample selection; a whole touched history is removed."""
    kept, excluded = [], Counter()
    for r in rows:
        history = [windows[w] for w in r["window_ids"]]
        if history[0]["start_ns"] < start or history[-1]["end_ns"] > end:
            excluded["history_crosses_boundary"] += 1
        elif any(c in crossing for w in history for c in w["connection_ids"]):
            excluded["crossing_connection_history"] += 1
        else:
            kept.append(r)
    return kept, dict(excluded)


def parity_audit(parent, destination):
    """Rerun the independent real training-window ledger without reading test data."""
    validation = ROOT / "experiments/phase2/validation"
    evidence = read_json(validation / "real_window_handcheck.json")
    fixture = validation / "hand_checked_unsw_window.pcap"
    require(sha256(fixture) == evidence["raw_fixture_sha256"], "Parity fixture changed")
    a, b = evidence["epoch_interval_ns"]
    def extractor(result):
        return WindowExtractor(Registry([Binding("endpoint", evidence["endpoint"], a, b)]),
                               start_ns=a, on_window=result.append)
    offline, live = [], []
    OfflineAdapter(extractor(offline)).run([fixture], end_ns=b)
    adapter = LiveAdapter(extractor(live), event_anchor_ns=a, monotonic_anchor_ns=100,
                          interface="fixture")
    for raw in read_pcap(fixture, interface="fixture"):
        adapter.receive(raw, monotonic_ns=raw.time_ns - a + 100)
    adapter.tick(b - a + 100_000_000 + 100)
    require(len(offline) == len(live) == 1, "Fixture emission changed")
    require(offline[0].wire["values"] == live[0].wire["values"], "Offline/live mismatch")
    np.testing.assert_allclose(offline[0].wire["values"], evidence["expected_values"], atol=1e-12, rtol=1e-12)
    saved = pq.read_table(parent / "windows.parquet", columns=["values", "role"],
        filters=[("role", "=", "train"), ("device_id", "=", "jan22-ip-" + evidence["endpoint"]),
                 ("start_ns", "=", a)]).to_pylist()
    require(len(saved) == 1, "Real training fixture absent")
    np.testing.assert_allclose(saved[0]["values"], evidence["expected_values"], atol=1e-12, rtol=1e-12)
    write_json(destination / "extraction_parity.json", dict(passed=True,
        evidence_sha256=sha256(validation / "real_window_handcheck.json"),
        fixture_sha256=sha256(fixture), independent_decoder="Wireshark ledger from Phase 2",
        offline_live_and_saved_training_equal=True, units="IPv4 bytes; within-second IAT milliseconds",
        population_moments=True))


def prepare(parent, output):
    parent, output = Path(parent).resolve(), Path(output).resolve()
    split, manifest = read_json(parent / "split_manifest.json"), read_json(parent / "data_manifest.json")
    train = next(p for p in split["partitions"] if p["role"] == "train")
    validation = next(p for p in split["partitions"] if p["role"] == "validation")
    require(sum(p["role"] == "train" for p in split["partitions"]) == 1 and
            sum(p["role"] == "validation" for p in split["partitions"]) == 1,
            "This derivation supports the audited one-group excerpt; register a new build for new groups")
    require(split["mode"] == "within_group_chronological", "Unexpected Phase 2 split")
    boundary = ((validation["start_ns"] // SECOND + validation["end_ns"] // SECOND) // 2) * SECOND
    plan = {**split, "partitions": [train,
        {**validation, "partition_id": "development", "role": "validation", "end_ns": boundary},
        {**validation, "partition_id": "reserved_threshold", "role": "threshold", "start_ns": boundary},
        *(p for p in split["partitions"] if p["role"] not in {"train", "validation"})],
        "parent_split_sha256": sha256(parent / "split_manifest.json"),
        "derivation": "fixed integer-second midpoint of validation; no outcome-based boundary search"}
    output.mkdir(parents=True, exist_ok=False)
    # Registration is durable BEFORE decoding any development/reserved outcome.
    write_json(output / "registration.json", dict(version="phase3_protocol_v1",
        created_utc=datetime.now(timezone.utc).isoformat(), parent=str(parent),
        parent_data_manifest_sha256=sha256(parent / "data_manifest.json"), split=plan,
        feature_schema="device_window_v1", preprocessing_version="log1p_population_zscore_v1",
        scope=["benign", "reconnaissance", "dos"], scope_or_feature_schema_changed=False,
        amendment="Missing reserved subset supplied by a registered chronological split; affected samples rebuilt",
        seeds=SEEDS, variants=VARIANTS, batch_size=128, optimizer="Adam", learning_rate=.001,
        max_epochs=30, patience=5, min_delta=0.0, loss="BCEWithLogitsLoss",
        selection="development binary macro-F1 at 0.5; strict improvement; earliest tied epoch",
        baseline_selection="best development macro-F1 across cnn64 weighted/unweighted seeds; lowest seed then variant on tie",
        balancing="If training negative/positive ratio > 10, compare pos_weight=Nnegative/Npositive with unweighted CNN64",
        comparison="same retained train/development samples and preprocessing for every model",
        reserved_outcomes="unread; support and suitability unestablished until later threshold work",
        final_threshold=None, optional_calibration="deferred to reserved subset after model selection",
        protected_roles=["threshold", "internal_test", "external_test"],
        limitations=["one original source group; no independently held-out development group",
                     "same-group reserved block is not independent calibration evidence"],
        poor_performance_policy="audit labels, units and extraction parity before any change; register/rebuild changes; never consult tests"))
    data = output / "data"
    data.mkdir()
    write_json(data / "split_manifest.json", plan)
    checksums = {n.replace("\\", "/"): v for n, v in read_json(parent / "artifact_checksums.json").items()}
    names = ["data_manifest.json", "split_manifest.json", "preprocess.json", "fit_window_ids.json", "windows.parquet"]
    names += [f"{role}/{n}" for role in ("train", "validation") for n in ("raw.npy", "tensor.npy", "samples.parquet")]
    parent_hashes = {}
    for name in names:
        actual = sha256(parent / name)
        require(actual == checksums[name], f"Phase 2 artifact changed: {name}")
        parent_hashes[name] = actual
    for name, expected in manifest["code_hashes"].items():
        require(sha256(ROOT / name) == expected, f"Phase 2 implementation changed: {name}; rebuild affected data")
    pre = read_json(parent / "preprocess.json")
    require(pre["feature_names"] == list(FEATURE_NAMES) and pre["feature_units"] == list(FEATURE_UNITS), "Feature units/order changed")
    require(pre["split_manifest_sha256"] == digest(split), "Preprocessor split provenance mismatch")
    print("Registered midpoint reserve; scanning tuple/time metadata for connection purges", flush=True)
    crossing, annotations = annotation_crossings(manifest, boundary, validation["group_id"])
    metadata = pq.read_table(parent / "windows.parquet",
        columns=["window_id", "start_ns", "end_ns", "connection_ids", "role"],
        filters=[("role", "in", ["train", "validation"])]).to_pylist()
    windows = {w["window_id"]: w for w in metadata}
    memberships = defaultdict(set)
    for w in metadata:
        role = "train" if w["role"] == "train" else "development" if w["start_ns"] < boundary else "reserved_threshold"
        for c in w["connection_ids"]:
            memberships[c].add(role)
    crossing.update(c for c, roles in memberships.items() if len(roles) > 1)
    write_json(data / "crossing_connections.json", sorted(crossing))
    train_rows = pq.read_table(parent / "train/samples.parquet").to_pylist()
    dev_rows = pq.read_table(parent / "validation/samples.parquet",
                             filters=[("final_time_ns", "<=", boundary)]).to_pylist()
    reserved_rows = pq.read_table(parent / "validation/samples.parquet", columns=INDEX_COLUMNS,
                                  filters=[("final_time_ns", ">", boundary)]).to_pylist()
    retained, exclusions = {}, {}
    bounds = {p["partition_id"]: p for p in plan["partitions"]}
    for role, rows in (("train", train_rows), ("development", dev_rows), ("reserved_threshold", reserved_rows)):
        p = bounds[role]
        retained[role], exclusions[role] = sample_partition(rows, windows, crossing, p["start_ns"], p["end_ns"])
    require(retained["train"] and retained["development"], "No train/development support after registered purges")
    used_windows, used_connections = {}, {}
    for role, rows in retained.items():
        used_windows[role] = {w for r in rows for w in r["window_ids"]}
        used_connections[role] = {c for w in used_windows[role] for c in windows[w]["connection_ids"]}
    for left, right in (("train", "development"), ("train", "reserved_threshold"), ("development", "reserved_threshold")):
        require(not used_windows[left] & used_windows[right], "Shared physical windows")
        require(not used_connections[left] & used_connections[right], "Shared connections")
    # Only now read label/value-bearing windows, restricted to train/development.
    audited = pq.read_table(parent / "windows.parquet", filters=[
        [("role", "=", "train")], [("role", "=", "validation"), ("end_ns", "<=", boundary)]]).to_pylist()
    audit_windows = {w["window_id"]: w for w in audited}
    fit_rows = [dict(window_id=w, role="train", valid=audit_windows[w]["capture_valid"],
                     values=audit_windows[w]["values"]) for w in sorted(used_windows["train"])]
    processor, fitting = fit_unique_training_windows(fit_rows)
    fit_ids = fitting.pop("fit_window_ids")
    write_json(data / "fit_window_ids.json", fit_ids)
    fitted = {**pre, "mean": list(processor.mean), "std": list(processor.std), **fitting,
              "split_manifest_sha256": digest(plan), "parent_preprocess_sha256": sha256(parent / "preprocess.json")}
    write_json(data / "preprocess.json", fitted)
    label_counts, group_counts = {}, {}
    for role in ("train", "development"):
        source_role = "train" if role == "train" else "validation"
        raw_source = np.load(parent / source_role / "raw.npy", mmap_mode="r", allow_pickle=False)
        tensor_source = np.load(parent / source_role / "tensor.npy", mmap_mode="r", allow_pickle=False)
        rows = retained[role]
        indices = [r["tensor_index"] for r in rows]
        raw = np.array(raw_source[indices])
        original_processor = Preprocessor(tuple(pre["mean"]), tuple(pre["std"]), fitted_on=pre["fitted_on"])
        np.testing.assert_array_equal(original_processor.transform_array(raw), tensor_source[indices])
        for index, r in enumerate(rows):
            history = [audit_windows[w] for w in r["window_ids"]]
            final = history[-1]
            require(r["label"] in (0, 1) and r["label"] == final["label"] and r["family"] == final["family"], "Final label mismatch")
            require((r["label"] == 0) == (r["family"] == "benign"), "Binary/family mapping mismatch")
            quality = json.loads(final["label_quality_json"])
            evidence = quality["packet_evidence"]
            require(quality["label"] == r["label"], "Label-quality mismatch")
            require(set(evidence) == {"benign"} if r["label"] == 0 else
                    evidence.get("attack", 0) > 0 and not (set(evidence) & {"conflict", "excluded"}),
                    "Packet label evidence mismatch")
            require(all(w["capture_valid"] for w in history), "Invalid context")
            require(all(a["end_ns"] == b["start_ns"] for a, b in zip(history, history[1:])), "Discontinuous context")
            np.testing.assert_array_equal(raw[index], [w["values"] for w in history])
        target = data / role
        target.mkdir()
        np.save(target / "raw.npy", raw, allow_pickle=False)
        np.save(target / "tensor.npy", processor.transform_array(raw), allow_pickle=False)
        new_rows = [{**r, "source_sample_id": r["sample_id"], "source_tensor_index": r["tensor_index"],
                     "sample_id": digest([digest(plan), r["window_ids"]]), "tensor_index": i,
                     "partition_id": role, "role": "train" if role == "train" else "validation"}
                    for i, r in enumerate(rows)]
        pq.write_table(pa.Table.from_pylist(new_rows), target / "samples.parquet", compression="zstd")
        label_counts[role] = dict(Counter(r["family"] for r in rows))
        group_counts[role] = dict(sample_count=len(rows), source_groups=len({r["group_id"] for r in rows}),
                                  devices=len({r["device_id"] for r in rows}), independent_heldout_groups=0)
    # No labels, scores, family counts or transformed arrays for the reserved set.
    pq.write_table(pa.Table.from_pylist(retained["reserved_threshold"],
        schema=pa.schema([pq.read_schema(parent / "validation/samples.parquet").field(n) for n in INDEX_COLUMNS])),
        data / "reserved_index.parquet", compression="zstd")
    parity_audit(parent, data)
    constants = [FEATURE_NAMES[i] for i, v in enumerate(processor.std) if v == 0]
    write_json(data / "audit.json", dict(passed=True, final_second_labels=True,
        label_evidence_checked_samples={r: len(retained[r]) for r in ("train", "development")},
        feature_names=list(FEATURE_NAMES), feature_units=list(FEATURE_UNITS),
        exact_phase2_normalization_parity=True, unique_training_fit_count=len(fit_ids),
        training_constant_features=constants, constant_feature_policy="retain registered epsilon=1e-6; no clipping/imputation",
        parent_fit_unchanged=fit_ids == read_json(parent / "fit_window_ids.json"),
        annotation_metadata_sources=annotations, crossing_connection_count=len(crossing),
        exclusions=exclusions, counts=label_counts, group_counts=group_counts,
        total_independent_source_groups=len({r["group_id"] for rows in retained.values() for r in rows}),
        independent_evaluation=False, reserved_index_count=len(retained["reserved_threshold"]),
        reserved_label_support="uninspected", shared_windows=0, shared_connections=0,
        evaluation_resampled=False, protected_outcomes_decoded=False))
    write_json(data / "parent_provenance.json", dict(parent=str(parent), artifacts=parent_hashes,
        data_manifest=manifest, split_manifest=split, registration_sha256=sha256(output / "registration.json")))
    shutil.copyfile(ROOT / "contracts/v1/feature_schema.json", data / "feature_schema.json")
    write_json(data / "outcome_access.json", dict(decoded_outcome_roles=["train", "development"],
        reserved_projection=INDEX_COLUMNS, internal_test_files_opened=[], external_files_opened=[],
        annotation_csv_projection="tuple/time only; no label/category columns", reserved_predictions_created=False))
    write_json(data / "artifact_checksums.json", {p.relative_to(data).as_posix(): sha256(p)
        for p in sorted(data.rglob("*")) if p.is_file()})
    print(json.dumps({"registered": str(output), "counts": label_counts, "exclusions": exclusions,
                      "independent_source_groups": 1, "reserved_outcomes": "unopened"}, indent=2), flush=True)


def load_training_data(experiment):
    """Hard allowlist: this API has no test/reserved partition argument."""
    data = Path(experiment) / "data"
    checksums = read_json(data / "artifact_checksums.json")
    for name, expected in checksums.items():
        require(sha256(data / name) == expected, f"Derived data changed: {name}")
    result = {}
    for role in ("train", "development"):
        x = np.load(data / role / "tensor.npy", allow_pickle=False)
        rows = pq.read_table(data / role / "samples.parquet").to_pylist()
        require(x.shape == (len(rows), 16, 8) and x.dtype == np.float32 and np.isfinite(x).all(), "Invalid training tensor")
        require([r["tensor_index"] for r in rows] == list(range(len(rows))), "Tensor/metadata misalignment")
        require(len({r["sample_id"] for r in rows}) == len(rows), "Duplicate samples")
        result[role] = dict(x=x, y=np.array([r["label"] for r in rows], dtype=np.float32), rows=rows)
    require(set(result["train"]["y"]) == {0, 1}, "Training needs both classes")
    require(set(result["development"]["y"]) == {0, 1},
            "Registered development split has one class: checkpoint selection is infeasible; do not move the boundary after inspecting labels")
    return result, digest(checksums)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, default=Path("experiments/phase2/run-002"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.parent, args.output)
