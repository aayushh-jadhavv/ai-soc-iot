"""Reproduce the frozen comparison or verify the published per-history scores."""

import argparse
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile

import numpy as np

from ids.runtime.bundle import checked_bytes, digest, score_tensor
from ids.training.metrics import development_metrics as classification_metrics


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
KEYS = ["sample_id", "group_id", "family", "label"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_protocol():
    payload = (HERE / "freeze.json").read_bytes()
    plan = json.loads(payload)
    require(plan["comparison"]["threshold"] == 0.5 and plan["comparison"]["positive_at_equality"],
            "Metric implementation requires the registered inclusive 0.5 comparison")
    return plan, digest(payload)


def raw_scores(plan, data, exports):
    import pyarrow.parquet as pq
    import torch
    from executorch.extension.pybindings import _portable_lib
    from executorch.runtime import Runtime
    from importlib.metadata import version
    from ids.runtime.bundle import Bundle

    settings = plan["runtime"]
    require(version("executorch") == settings["executorch"]
            and torch.__version__.split("+")[0] == settings["torch"], "Runtime version mismatch")
    torch.set_num_threads(settings["comparison_threads"])
    torch.set_num_interop_threads(settings["comparison_threads"])
    _portable_lib._unsafe_reset_threadpool(settings["comparison_threads"])
    folder = ROOT / "models" / plan["release_model"]
    checked_bytes(folder / "manifest.json", plan["bundle_manifest_sha256"])
    bundle = Bundle(folder)

    dataset = plan["dataset"]
    files = dataset["phase2_files"]
    def input_file(name):
        key = dataset["role"] + "/" + name
        return io.BytesIO(checked_bytes(data / key, files[key]))

    columns = [*KEYS, "tensor_index", "role", "partition_id", "final_time_ns"]
    rows = pq.read_table(input_file("samples.parquet"), columns=columns).to_pylist()
    block, = [p for p in dataset["split"]["partitions"] if p["role"] == dataset["role"]]
    for i, row in enumerate(rows):
        require(row["tensor_index"] == i and row["role"] == row["partition_id"] == block["role"]
                and block["start_ns"] < row["final_time_ns"] <= block["end_ns"]
                and row["group_id"] == block["group_id"], "Row outside the frozen test block")
    raw = np.load(input_file("raw.npy"), allow_pickle=False)
    saved = np.load(input_file("tensor.npy"), allow_pickle=False)
    tensors = bundle.processor.transform_array(raw)
    require(len(rows) == len(tensors) and saved.dtype == tensors.dtype
            and np.array_equal(saved, tensors), "Raw/preprocessed tensor mismatch")
    scores = [{key: row[key] for key in KEYS} for row in rows]
    for name, expected in plan["program_sha256"].items():
        if name == plan["selected_program"]:
            require(bundle.metadata["model_hash"] == expected, "Selected program changed")
            method = bundle.method
        else:
            relative = f"{name}/model.pte"
            if exports is None:
                ref = f"{plan['source_commit']}:experiments/phase6/run-001/{relative}"
                program_bytes = subprocess.run(["git", "show", ref], cwd=ROOT, check=True,
                                               stdout=subprocess.PIPE).stdout
            else:
                program_bytes = (exports / relative).read_bytes()
            require(digest(program_bytes) == expected, f"Program checksum mismatch: {name}")
            program = Runtime.get().load_program(program_bytes)
            method = program.load_method("forward")
        for i, row in enumerate(scores):
            row[name], _ = score_tensor(method, torch.from_numpy(tensors[i:i + 1]))
        print(f"{name}: {len(scores)} batch-one inferences", flush=True)
    return scores


def score_csv(rows, programs):
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=KEYS + list(programs), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode("utf-8")


def summarize(plan, freeze_hash, payload):
    reader = csv.DictReader(io.StringIO(payload.decode("utf-8")))
    names = plan["program_sha256"]
    require(reader.fieldnames == KEYS + list(names), "Score ledger columns changed")
    rows = list(reader)
    dataset = plan["dataset"]
    for row in rows:
        row["label"] = int(row["label"])
        require(row["family"] in plan["analysis"]["scope"] and row["label"] == int(row["family"] != "benign")
                and row["group_id"] == dataset["group"], "Unexpected label, family or group")
    require(len({r["sample_id"] for r in rows}) == len(rows), "Duplicate test history")
    audit = json.loads(checked_bytes(HERE / "dataset-audit.json", dataset["phase2_files"]["counts_and_leakage.json"]))
    counts = audit["counts_by_partition"][dataset["role"]]
    require(len(rows) == counts["samples"], "Ledger does not cover the frozen test block")
    for family in plan["analysis"]["scope"]:
        require(sum(r["family"] == family for r in rows) == counts.get("samples:" + family, 0),
                "Per-family support differs from the data audit")
    models = {name: classification_metrics(rows, [float(r[name]) for r in rows]) for name in names}
    baseline, selected = models["unpruned/float32"], models[plan["selected_program"]]
    losses = {key: baseline[key] - selected[key] for key in ("recall", "macro_f1")}
    limit = plan["comparison"]["max_recall_and_macro_f1_loss_vs_unpruned"]
    return {
        "freeze_sha256": freeze_hash, "scores_csv_sha256": hashlib.sha256(payload).hexdigest(),
        "dataset": dataset["name"], "role": dataset["role"], "coverage": counts,
        "shared_window_and_connection_audit": audit["overlap_checks"],
        "independently_held_out_groups": 0, "group_confidence_interval": None,
        "selected_program": plan["selected_program"], "models": models,
        "compact_vs_unpruned": {"losses": losses, "absolute_loss_limit": limit,
                                "within_limit_on_this_block": all(v <= limit for v in losses.values())},
        "untested": plan["unavailable"]
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    score = commands.add_parser("score", help="Run locked programs on the original Phase 2 test material")
    score.add_argument("--data", type=Path, required=True, help="Parent of internal_test/")
    score.add_argument("--exports", type=Path, help="Original Phase 6 run directory; defaults to local Git history")
    score.add_argument("--output", type=Path, required=True, help="New directory for results and scores")
    verify = commands.add_parser("verify", help="Recompute the report from its score ledger")
    verify.add_argument("--results", type=Path, default=HERE, help="Directory with results.json and scores.csv.gz")
    args = parser.parse_args()
    plan, freeze_hash = read_protocol()
    if args.command == "verify":
        payload = gzip.decompress((args.results / "scores.csv.gz").read_bytes())
        report = summarize(plan, freeze_hash, payload)
        require(report == json.loads((args.results / "results.json").read_bytes()), "Published results differ")
        print(f"Verified {len(report['models'])} programs on {report['coverage']['samples']} histories.")
        return
    if args.output.exists():
        parser.error("--output must name a new directory")
    rows = raw_scores(plan, args.data, args.exports)
    payload = score_csv(rows, plan["program_sha256"])
    report = summarize(plan, freeze_hash, payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temp:
        stage = Path(temp) / "run"
        stage.mkdir()
        (stage / "scores.csv.gz").write_bytes(gzip.compress(payload, mtime=0))
        (stage / "results.json").write_bytes((json.dumps(report, indent=2, allow_nan=False) + "\n").encode())
        stage.rename(args.output)


if __name__ == "__main__":
    main()
