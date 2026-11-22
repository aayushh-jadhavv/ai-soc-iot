"""Load the frozen shortlist and the two allowed Phase 6 data partitions."""

from collections import Counter
from pathlib import Path
import re

import numpy as np
import pyarrow.parquet as pq

from ids.compaction.run import load_frozen
from ids.datasets.temporal import digest
from ids.ga.data import allowed_path
from ids.preprocessing import Preprocessor
from ids.run_logging import sha256
from ids.training.data import read_json, require

DATA_FILES = ("train/raw.npy", "train/tensor.npy", "train/samples.parquet",
              "development/tensor.npy", "development/samples.parquet")
SHARED = ("feature_schema.json", "preprocess.json", "split_manifest.json")


def load_inputs(frozen, data):
    frozen, data = Path(frozen).resolve(), Path(data).resolve()
    access = {}

    def check(root, name, names, expected=None):
        path = allowed_path(root, name, names)
        actual = sha256(path)
        if expected is not None:
            require(expected == actual, f"Checksum mismatch for {name}")
        access[str(path)] = actual
        return path

    archive = read_json(check(frozen, "artifact_checksums.json", ("artifact_checksums.json",)))
    meta = ("handoff.json", "status.json", "registration.json", "validation_manifest.json",
            "originals/unpruned/handoff.json", "summary.json")
    checked = {name: read_json(check(frozen, name, meta, archive[name])) for name in meta}
    hand, validation = checked["handoff.json"], checked["validation_manifest.json"]
    require(checked["status.json"]["status"] == "complete" and hand["architectures_frozen"] and
            hand["registration_sha256"] == archive["registration.json"], "Incomplete Phase 5 handoff")
    base = checked["originals/unpruned/handoff.json"]
    manifest = read_json(check(data, "artifact_checksums.json", ("artifact_checksums.json",)))
    require(digest(manifest) == base["data_sha256"], "Phase 3 data differs from trained baseline")
    shared = {}
    for name in SHARED:
        expected = hand["shared_artifacts"][name]
        require(expected == archive["shared/" + name] == validation["files"][name] == manifest[name],
                f"Unbound shared {name}")
        shared[name] = check(frozen / "shared", name, SHARED, expected)
    pre = read_json(shared["preprocess.json"])
    require(pre["split_manifest_sha256"] == digest(read_json(shared["split_manifest.json"])),
            "Preprocessing/split mismatch")
    processor = Preprocessor(tuple(pre["mean"]), tuple(pre["std"]), tuple(pre["feature_names"]),
                             pre["version"], pre["fitted_on"])
    files = {n: check(data, n, DATA_FILES, manifest[n]) for n in DATA_FILES}
    tensors, rows = {}, {}
    for part, role in (("train", "train"), ("development", "validation")):
        x = np.load(files[f"{part}/tensor.npy"], allow_pickle=False)
        records = pq.read_table(files[f"{part}/samples.parquet"]).to_pylist()
        require(x.dtype == np.float32 and x.shape == (len(records), 16, 8) and np.isfinite(x).all(),
                f"Invalid {part} tensor")
        require(all(r["partition_id"] == part and r["role"] == role and r["tensor_index"] == i and
                    r["label"] in (0, 1) and len(r["window_ids"]) == 8 for i, r in enumerate(records)) and
                len({r["sample_id"] for r in records}) == len(records), f"Invalid {part} metadata")
        tensors[part], rows[part] = x, records
    train, dev = rows["train"], rows["development"]
    require(digest(dev) == validation["rows_sha256"] and
            [r["sample_id"] for r in dev] == validation["sample_ids"], "Development selection drift")
    for key in ("sample_id", "window_ids"):
        def identifiers(records):
            return {r[key] for r in records} if key == "sample_id" else {w for r in records for w in r[key]}
        require(identifiers(train).isdisjoint(identifiers(dev)), f"Train/development overlap in {key}")
    raw = np.load(files["train/raw.npy"], allow_pickle=False)
    require(np.array_equal(processor.transform_array(raw), tensors["train"]), "Raw/training tensor misalignment")

    models, bindings = {}, {}
    summary = checked["summary.json"]
    previous = {r["id"]: r for r in summary["models"]}
    for directory in hand["comparison_directories"]:
        require(re.fullmatch(r"frozen/[a-z][a-z0-9_]*", directory), "Invalid frozen model directory")
        name = directory.split("/")[1]
        require(name not in models and name in previous, "Unregistered or duplicate frozen model")
        folder = allowed_path(frozen, directory, (directory,))
        hashes = read_json(check(folder, "checksums.json", ("checksums.json",), archive[directory + "/checksums.json"]))
        for file, expected in hashes.items():
            require(expected == archive[f"{directory}/{file}"], "Unbound frozen artifact")
            check(folder, file, ("weights.pt", "architecture.json", "handoff.json", "channel_map.json"), expected)
        model, h = load_frozen(folder)
        require(h["id"] == name and h["registration_sha256"] == hand["registration_sha256"] and
                h["shared_artifacts"] == hand["shared_artifacts"] and h["architecture_frozen"] and
                h["selection_threshold"] == .5 and h["quality_gate"] == previous[name]["gate"],
                "Frozen candidate does not match handoff")
        models[name], bindings[name] = model, h
    require(set(models) == set(previous) and hand["selected"] == summary["selected"] and
            bindings[hand["selected"]]["state_dict_sha256"] == hand["selected_state_dict_sha256"] and
            bindings["unpruned"]["state_dict_sha256"] == base["state_dict_sha256"], "Shortlist/parent mismatch")
    return dict(models=models, bindings=bindings, selected=hand["selected"], previous=previous,
                shared=shared, processor=processor, train=tensors["train"], train_rows=train, raw=raw,
                dev=tensors["development"], rows=dev, validation=validation, access=access)


def calibration_sample(raw, rows, seed=1729, per_stratum=32):
    """Define strata on training packet counts before observing any model output."""
    require(len(raw) == len(rows) and all(r["role"] == r["partition_id"] == "train" and
            r["tensor_index"] == i for i, r in enumerate(rows)), "Calibration requires aligned training rows")
    packets = raw[:, :, :2].sum(axis=2)
    benign = np.array([r["label"] == 0 for r in rows])
    final = packets[:, -1]
    active = benign & (final > 0)
    burst = float(np.quantile(final[active], .9, method="higher")) if active.any() else None
    groups = {"idle": [], "benign_burst": [], "benign_other": []}
    for i, row in enumerate(rows):
        if not benign[i]:
            name = "attack/" + row["family"]
        elif final[i] == 0:
            name = "idle"
        elif final[i] >= burst:
            name = "benign_burst"
        else:
            name = "benign_other"
        groups.setdefault(name, []).append(i)
    rng = np.random.default_rng(seed)
    selected = []
    for name, group in sorted(groups.items()):
        for i in rng.choice(group, size=min(len(group), per_stratum), replace=False):
            r = rows[i]
            selected.append(dict(stratum=name, sample_id=r["sample_id"], tensor_index=int(i),
                label=r["label"], family=r["family"], final_packets=int(final[i]), role="train"))
    rng.shuffle(selected)
    counts = {name: len(group) for name, group in groups.items()}
    missing = [name for name in ("idle", "benign_burst") if not counts[name]]
    if not any(k.startswith("attack/") for k in groups):
        missing.append("attack")
    return dict(seed=seed, max_per_stratum=per_stratum, population=len(rows), available=counts,
                selected_counts=dict(Counter(r["stratum"] for r in selected)), samples=selected,
                absent_required_strata=missing, representative=not missing,
                idle_rule="eligible benign final second with zero incoming plus outgoing packets",
                fully_idle_benign_histories=int(np.sum(benign & (packets.max(axis=1) == 0))),
                benign_histories_with_any_idle_second=int(np.sum(benign & (packets.min(axis=1) == 0))),
                burst_rule="active benign final second at or above training benign p90 (higher)",
                burst_min_packets=burst)


def tolerance_partition(rows):
    """Earlier development times establish tolerance. Purge overlapping histories at the boundary."""
    times = sorted({r["final_time_ns"] for r in rows})
    cutoff = times[max(0, len(times) // 3 - 1)]
    fit = [i for i, r in enumerate(rows) if r["final_time_ns"] <= cutoff]
    used = {w for i in fit for w in rows[i]["window_ids"]}
    check, guard = [], []
    for i, row in enumerate(rows):
        if row["final_time_ns"] > cutoff:
            (guard if used.intersection(row["window_ids"]) else check).append(i)
    require(fit and check, "Need disjoint development windows for tolerance registration and checking")
    return dict(cutoff_final_ns=cutoff, fit=fit, check=check, guard=guard)
