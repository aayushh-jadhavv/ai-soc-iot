"""Partition-first temporal samples, leakage purges and separate tensor metadata."""

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

import numpy as np

from ids.features import FEATURE_NAMES, FEATURE_UNITS, FeatureHistory
from ids.features.packets import SECOND
from ids.preprocessing import fit_unique_training_windows


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class Partition:
    partition_id: str
    group_id: str
    role: str
    start_ns: int
    end_ns: int
    dataset: str = "UNSW-NB15"
    original_session_id: str | None = None


class SplitPlan:
    def __init__(self, partitions, *, mode="independent_groups"):
        self.partitions = tuple(partitions)
        self.mode = mode
        if mode not in {"independent_groups", "within_group_chronological"}:
            raise ValueError("Unknown split method")
        if len({p.partition_id for p in self.partitions}) != len(self.partitions):
            raise ValueError("Duplicate partition IDs")
        grouped = defaultdict(list)
        for p in self.partitions:
            if p.role not in {"train", "validation", "threshold", "internal_test", "external_test"}:
                raise ValueError("Invalid partition role")
            if not p.group_id or not p.partition_id or p.start_ns >= p.end_ns or p.start_ns % SECOND or p.end_ns % SECOND:
                raise ValueError("Partition needs explicit group and aligned half-open bounds")
            if p.dataset != "UNSW-NB15" and p.role != "external_test":
                raise ValueError("External datasets are evaluation-only")
            grouped[p.group_id].append(p)
        for group in grouped.values():
            ordered = sorted(group, key=lambda p: p.start_ns)
            if any(a.end_ns > b.start_ns for a, b in zip(ordered, ordered[1:])):
                raise ValueError("Overlapping group partitions")
            if mode == "independent_groups" and len({p.role for p in group}) > 1:
                raise ValueError("Original group leaks across independent roles")
        self.fingerprint = digest(self.to_dict())

    def locate(self, group_id, start_ns):
        return next((p for p in self.partitions if p.group_id == group_id
                     and p.start_ns <= start_ns and start_ns + SECOND <= p.end_ns), None)

    def to_dict(self):
        return dict(mode=self.mode, partitions=[asdict(p) for p in self.partitions],
                    history_rows=8, history_purge_seconds=7, assignment_before_samples=True,
                    connection_policy="purge whole windows touched by any crossing connection or reused tuple")


@dataclass
class LabeledWindow:
    window: object
    group_id: str
    original_group_id: str | None
    original_device_id: str | None
    label: int | None
    family: str | None
    label_reason: str
    label_quality: dict
    connection_ids: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()


def form_samples(rows, plan, *, annotated_crossing_connections=()):
    """Labels are consumed only AFTER eight valid contiguous rows are assembled."""
    if not isinstance(plan, SplitPlan):
        raise ValueError("Establish partitions before forming any samples")
    rows = sorted(rows, key=lambda row: (row.group_id, row.window.wire["device_id"],
                                        row.window.wire["window_start_ms"]))
    ids = [row.window.wire["window_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Repeated physical windows in extraction input")
    physical = {(r.group_id, r.window.wire["device_id"], r.window.wire["window_start_ms"]) for r in rows}
    if len(physical) != len(rows):
        raise ValueError("Repeated original endpoint-second under different window IDs")
    memberships = defaultdict(set)
    assignments = {}
    for row in rows:
        p = plan.locate(row.group_id, row.window.wire["window_start_ms"] * 1_000_000)
        assignments[row.window.wire["window_id"]] = p
        if p:
            for connection in row.connection_ids:
                memberships[connection].add(p.partition_id)
    crossing = set(annotated_crossing_connections) | {c for c, parts in memberships.items() if len(parts) > 1}
    histories, samples, raw, window_metadata = {}, [], [], []
    exclusions = Counter()
    partition_counts = defaultdict(Counter)
    used_windows, used_connections = defaultdict(set), defaultdict(set)
    for row in rows:
        w = row.window.wire
        p = assignments[w["window_id"]]
        partition_id = p.partition_id if p else "unassigned"
        counts = partition_counts[partition_id]
        counts["windows"] += 1
        counts["valid_capture" if w["quality"]["valid"] else "invalid_capture"] += 1
        counts["label:" + (str(row.label) if row.label is not None else row.label_reason)] += 1
        if not any(w["values"]):
            counts["zero_rows"] += 1
        key = (row.group_id, w["device_id"], partition_id)
        history = histories.setdefault(key, FeatureHistory())
        if not p:
            reason, sequence = "unassigned_capture_edge", None
            history.reset()
        elif crossing.intersection(row.connection_ids):
            reason, sequence = "crossing_connection", None
            history.reset()
        elif not w["quality"]["valid"]:
            reason, sequence = "invalid_capture", None
            history.reset()
        else:
            sequence = history.append(row.window)
            reason = "history_warmup" if sequence is None else row.label_reason if row.label is None else None
        meta = dict(window_id=w["window_id"], group_id=row.group_id,
                    original_group_id=row.original_group_id, device_id=w["device_id"],
                    original_device_id=row.original_device_id, partition_id=partition_id,
                    role=p.role if p else None, start_ns=w["window_start_ms"] * 1_000_000,
                    end_ns=w["window_end_ms"] * 1_000_000, lifecycle=row.window.lifecycle,
                    sequence_number=w["sequence_number"], binding_revision=w["binding_revision"],
                    gateway_id=w["gateway_id"], boot_id=w["boot_id"],
                    capture_session_id=w["capture_session_id"], enforcement_revision=w["enforcement_revision"],
                    observed_mode=w["observed_mode"], feature_schema=w["feature_schema"], schema_version=w["schema_version"],
                    capture_valid=w["quality"]["valid"], coverage_reasons=w["quality"]["reasons"],
                    diagnostics_json=json.dumps(row.window.diagnostics, sort_keys=True),
                    label=row.label, family=row.family, label_reason=row.label_reason,
                    label_quality_json=json.dumps(row.label_quality, sort_keys=True),
                    connection_ids=list(row.connection_ids), source_refs=list(row.source_refs),
                    exclusion_reason=reason, values=w["values"])
        window_metadata.append(meta)
        if reason:
            exclusions[reason] += 1
            counts["excluded:" + reason] += 1
            continue
        sample_windows = [v.wire["window_id"] for v in sequence]
        sample_id = digest([plan.fingerprint, sample_windows])
        index = len(samples)
        samples.append(dict(sample_id=sample_id, tensor_index=index, group_id=row.group_id,
                            original_group_id=row.original_group_id, device_id=w["device_id"],
                            original_device_id=row.original_device_id, partition_id=p.partition_id,
                            capture_session_id=w["capture_session_id"], boot_id=w["boot_id"],
                            binding_revision=w["binding_revision"], enforcement_revision=w["enforcement_revision"],
                            role=p.role, final_time_ns=w["window_end_ms"] * 1_000_000,
                            final_window_start_ns=w["window_start_ms"] * 1_000_000,
                            label=row.label, family=row.family, label_quality_json=meta["label_quality_json"],
                            coverage_json=json.dumps({"valid": True, "rows": 8,
                                "diagnostics": [v.diagnostics for v in sequence]}, sort_keys=True),
                            window_ids=sample_windows, source_refs=list(row.source_refs)))
        raw.append([v.wire["values"] for v in sequence])
        used_windows[p.partition_id].update(sample_windows)
        counts["samples"] += 1
        counts["samples:" + row.family] += 1
    by_id = {row.window.wire["window_id"]: row for row in rows}
    for part, windows in used_windows.items():
        for window_id in windows:
            used_connections[part].update(by_id[window_id].connection_ids)
    overlaps = []
    parts = sorted(used_windows)
    for i, part in enumerate(parts):
        for other in parts[i + 1:]:
            overlaps.append(dict(left=part, right=other,
                shared_window_count=len(used_windows[part] & used_windows[other]),
                shared_connection_count=len(used_connections[part] & used_connections[other])))
    if any(v["shared_window_count"] or v["shared_connection_count"] for v in overlaps):
        raise ValueError("Leakage remains after purging")
    original_group_roles = defaultdict(set)
    for p in plan.partitions:
        original_group_roles[p.group_id].add(p.role)
    report = dict(mode=plan.mode, split_manifest_sha256=plan.fingerprint,
                  emitted_window_count=len(rows), sample_count=len(samples), exclusions=dict(exclusions),
                  counts_by_partition={p: dict(c) for p, c in partition_counts.items()},
                  crossing_connection_count=len(crossing), overlap_checks=overlaps,
                  shared_source_groups={g: sorted(v) for g, v in original_group_roles.items() if len(v) > 1},
                  independent_group_evaluation=plan.mode == "independent_groups",
                  denominators="windows are emitted endpoint-seconds; samples are retained labeled final seconds",
                  unique_used_windows_by_partition={p: len(v) for p, v in used_windows.items()},
                  device_hours_by_partition={p: c["windows"] / 3600 for p, c in partition_counts.items()},
                  undefined_metrics_are_null=True)
    array = np.asarray(raw, dtype=np.float64).reshape((-1, 8, 16))
    return array, samples, window_metadata, report


def save_dataset(output, raw, samples, windows, report):
    """Parquet metadata/shards and numeric-only arrays; never train a model."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    output = Path(output)
    fit_ids = {wid for sample in samples if sample["role"] == "train" for wid in sample["window_ids"]}
    fit_rows = [dict(window_id=w["window_id"], role=w["role"], valid=w["capture_valid"], values=w["values"])
                for w in windows if w["window_id"] in fit_ids]
    processor, fitting = fit_unique_training_windows(fit_rows)
    write_json(output / "fit_window_ids.json", fitting.pop("fit_window_ids"))
    preprocess = dict(mean=list(processor.mean), std=list(processor.std),
        feature_names=list(FEATURE_NAMES), feature_units=list(FEATURE_UNITS),
        feature_schema="device_window_v1", version=processor.version, fitted_on=processor.fitted_on,
        split_manifest_sha256=report["split_manifest_sha256"], **fitting)
    write_json(output / "preprocess.json", preprocess)
    # A row group is a bounded Parquet shard; IDs and labels never enter tensors.
    table = pa.Table.from_pylist(windows)
    pq.write_table(table, output / "windows.parquet", compression="zstd", row_group_size=4096)
    for p in sorted({w["partition_id"] for w in windows if w["role"] is not None}):
        target = output / p
        target.mkdir()
        selected = [i for i, s in enumerate(samples) if s["partition_id"] == p]
        subset = raw[selected]
        np.save(target / "raw.npy", subset, allow_pickle=False)
        np.save(target / "tensor.npy", processor.transform_array(subset), allow_pickle=False)
        metadata = [{**samples[i], "tensor_index": j} for j, i in enumerate(selected)]
        if metadata:
            pq.write_table(pa.Table.from_pylist(metadata), target / "samples.parquet", compression="zstd")
        else:
            # Preserve the same column types when a partition has zero samples.
            template = pa.Table.from_pylist(samples).slice(0, 0)
            pq.write_table(template, target / "samples.parquet", compression="zstd")
    report["preprocessing"] = fitting
    report["training_performed"] = False
    write_json(output / "counts_and_leakage.json", report)
    return preprocess
