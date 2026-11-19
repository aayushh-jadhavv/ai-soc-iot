"""Phase 5 only: python -m ids.compaction.run {run,verify} --output PATH."""

import argparse
import copy
import csv
from dataclasses import asdict, dataclass
from decimal import Decimal
import json
from pathlib import Path
import shutil
import time

import numpy as np
import psutil
import pyarrow as pa
import pyarrow.parquet as pq
import torch

from ids.compaction.data import DIRECT_FILES, load_inputs
from ids.compaction.model import (ATOL, RTOL, SYNTHETIC_SEED, WiringError, channel_map,
                                  check_equivalence, describe, physical_cost, rebuild, synthetic_samples)
from ids.datasets.temporal import digest
from ids.ga.data import BUNDLE_FILES, allowed_path
from ids.ga.masks import Mask, masked_forward
from ids.ga.search import array_hash, implementation_hashes, runtime_fingerprint
from ids.model import TemporalCNN
from ids.run_logging import environment, sha256, write_json
from ids.training.data import read_json, require
from ids.training.metrics import development_metrics
from ids.training.train import atomic_torch_save, determinism, evaluate, train_epoch, weight_hash


@dataclass(frozen=True)
class Config:
    seed: int = 1729
    max_epochs: int = 5
    top_k: int = 3
    learning_rate: float = .0001
    recall_loss_limit: float = .02
    macro_f1_loss_limit: float = .02

    def __post_init__(self):
        require(type(self.seed) is int and 0 <= self.seed < 2**32 - 1, "Seed must allow a uint32 seed+1")
        require(type(self.max_epochs) is int and 1 <= self.max_epochs <= 5, "Phase 5 permits one to five epochs")
        require(type(self.top_k) is int and 1 <= self.top_k <= 3, "At most three leading candidates")
        require(self.learning_rate == .0001 and self.recall_loss_limit == .02 and
                self.macro_f1_loss_limit == .02, "Registered learning rate and quality limits cannot change")


def protocol(config, data):
    return dict(version="phase5_protocol_v1", created_unix_ns=time.time_ns(), config=asdict(config),
        candidate_order=[r["mask"] for r in data["top"]["candidates"][:config.top_k]],
        designated_baseline=dict(checkpoint_sha256=data["provenance"]["checkpoint_sha256"],
            state_dict_sha256=data["provenance"]["state_dict_sha256"],
            variant=data["parent_config"]["variant"], seed=data["parent_config"]["seed"]),
        comparison=dict(role="development", validation_manifest_sha256=digest(data["provenance"]["validation"]),
            threshold=.5, score="float64 sigmoid of CPU float32 logit; score >= 0.5",
            metrics="same fixed-label binary macro-F1, attack recall and tied-score AP as Phase 3/4",
            quality_gate="recall >= unpruned recall - 0.02 AND macro_f1 >= unpruned macro_f1 - 0.02",
            checkpoint_selection="highest development macro-F1 among trained epochs 1..max_epochs; earliest exact tie",
            epoch_zero="preserved and reported; never substituted for a failed fine-tuned result",
            direct_small="replay all three Phase 3 seeds unchanged; best macro-F1 then lowest seed is the comparator",
            architecture_selection="among quality-feasible GA, best direct-small and unpruned: fewest actual parameters, then highest macro-F1, then recall, then ID",
            latency_selection="descriptive measured host cost; no speedup requirement or noisy latency tie-break",
            final_threshold=None, calibration="not fitted", final_tests="unopened"),
        fine_tuning=dict(optimizer="fresh Adam", learning_rate=.0001, betas=[.9, .999], epsilon=1e-8,
            weight_decay=0, amsgrad=False, foreach=False, fused=False, batch_size=128,
            loss="BCEWithLogitsLoss", positive_weight=data["parent_config"]["positive_weight"],
            sampler="same seed+1 permutation stream per candidate; no replacement, no dropped tail",
            seed=config.seed, max_epochs=config.max_epochs, training_role="train", input_preprocessing="unchanged"),
        equivalence=dict(atol=ATOL, rtol=RTOL, batch_sizes=[1, 1024], real="all frozen development samples",
                         synthetic_seed=SYNTHETIC_SEED, synthetic_count=len(synthetic_samples()),
                         failure="stop the whole run before any optimizer step"),
        benchmark=dict(device="host CPU, eager float32", batch_size=1, threads=1, warmups_per_repeat=100,
            calls_per_repeat=1000, repeats=3, model_order="sorted IDs, rotated by repeat",
            input_order="development samples cycling in frozen order", clock="perf_counter_ns",
            scope="warm model call only; excludes preprocessing, serialization, service, export and target hardware",
            rss="sampled process RSS after epochs/repetitions; not per-model memory or exact peak"),
        runtime=runtime_fingerprint(), source_hashes=implementation_hashes(), input_hashes=data["input_hashes"],
        independent_evaluation=False, tolerance_may_widen=False, target_reduction=None)


def quality_gate(metrics, baseline):
    failures, losses = [], {}
    for key in ("recall", "macro_f1"):
        actual, reference = metrics.get(key), baseline.get(key)
        valid = actual is not None and reference is not None and np.isfinite(actual) and np.isfinite(reference)
        losses[key] = reference - actual if valid else None
        # Decimal comparison includes the exact 0.02 boundary without increasing the budget.
        if not valid or Decimal(str(reference)) - Decimal(str(actual)) > Decimal("0.02"):
            failures.append(key)
    return dict(accepted=not failures, absolute_losses=losses, failed_metrics=failures,
                recall_loss_limit=.02, macro_f1_loss_limit=.02)


def select_candidate(records, direct_id):
    feasible = [r for r in records if r["gate"]["accepted"] and
                (r["kind"] != "direct_small" or r["id"] == direct_id)]
    require(feasible, "No feasible candidate, including baseline")
    return min(feasible, key=lambda r: (r["cost"]["parameters"], -r["post"]["macro_f1"],
                                        -r["post"]["recall"], r["id"]))["id"]


def assess(model, x, rows):
    y = torch.tensor([r["label"] for r in rows], dtype=torch.float32).reshape(-1, 1)
    loss, logits, scores = evaluate(model, torch.from_numpy(x), y, "cnn64_weighted")
    return dict(**development_metrics(rows, scores), loss=loss), logits, scores


def save_predictions(path, rows, logits, scores):
    records = [dict(sample_id=r["sample_id"], group_id=r["group_id"], label=r["label"], family=r["family"],
                    logit=float(a), score=float(s), prediction=int(s >= .5)) for r, a, s in zip(rows, logits, scores)]
    pq.write_table(pa.Table.from_pylist(records), path, compression="zstd")


def replay_predictions(logits, scores, saved):
    np.testing.assert_array_equal(logits, [r["logit"] for r in saved])
    np.testing.assert_array_equal(scores, [r["score"] for r in saved])


def preflight(data, candidates, destination):
    """Build and check ALL candidates before returning control to training."""
    samples = dict(real_development=data["dev"], synthetic=synthetic_samples())
    np.save(destination / "synthetic_inputs.npy", samples["synthetic"], allow_pickle=False)
    write_json(destination / "equivalence_inputs.json", dict(
        real_sample_ids=[r["sample_id"] for r in data["rows"]],
        real_tensor_sha256=array_hash(data["dev"]), synthetic_sha256=array_hash(samples["synthetic"]),
        synthetic_seed=SYNTHETIC_SEED, synthetic_recipe="zeros, +ones, -ones, 32 standard normal, +/-128 basis impulses"))
    models, reports = {}, {}
    for index, record in enumerate(candidates, 1):
        name, mask = f"ga_{index}", Mask.decode(record["mask"])
        folder = destination / name
        folder.mkdir()
        compact = rebuild(data["parent"], mask)
        try:
            reports[name] = check_equivalence(data["parent"], compact, mask, samples)
        except WiringError as exc:
            write_json(folder / "equivalence.json", exc.report)
            write_json(destination / "preflight.json", dict(passed=False, failed_candidate=name, training_steps=0))
            raise
        # Reproduce the archived mask results, not just compact-vs-current-parent agreement.
        with torch.inference_mode():
            masked = torch.cat([masked_forward(data["parent"], b, mask)
                                for b in torch.from_numpy(data["dev"]).split(1024)]).numpy().reshape(-1)
        scores = torch.sigmoid(torch.from_numpy(masked).double()).numpy()
        require(array_hash(masked) == record["logits_sha256"] and array_hash(scores) == record["scores_sha256"] and
                development_metrics(data["rows"], scores) == record["metrics"], "Phase 4 masked result replay failed")
        write_json(folder / "equivalence.json", reports[name])
        write_json(folder / "channel_map.json", channel_map(mask))
        write_json(folder / "architecture.json", describe(compact))
        atomic_torch_save(compact.state_dict(), folder / "pre.pt")
        models[name] = compact
    write_json(destination / "preflight.json", dict(passed=True, candidates=list(models), training_steps=0,
                                                   all_checks_before_training=True))
    return models, reports


def fine_tune(model, data, config, folder):
    determinism(config.seed)
    model.requires_grad_(True)
    optimizer = torch.optim.Adam(model.parameters(), lr=.0001, betas=(.9, .999), eps=1e-8,
                                 weight_decay=0, amsgrad=False, foreach=False, fused=False)
    generator = torch.Generator().manual_seed(config.seed + 1)
    x, y = torch.from_numpy(data["train"]), torch.from_numpy(data["train_y"]).reshape(-1, 1)
    history, best_score, best_state, best_epoch = [], -1., None, None
    arch = describe(model)
    for epoch in range(1, config.max_epochs + 1):
        start, cpu = time.perf_counter(), time.process_time()
        train_loss = train_epoch(model, optimizer, x, y, data["parent_config"]["variant"],
                                 data["parent_config"]["positive_weight"], generator)
        train_seconds, train_cpu = time.perf_counter() - start, time.process_time() - cpu
        metrics, _, _ = assess(model, data["dev"], data["rows"])
        require(describe(model) == arch, "Architecture changed during fine-tuning")
        if metrics["macro_f1"] > best_score:
            best_score, best_epoch = metrics["macro_f1"], epoch
            best_state = copy.deepcopy(model.state_dict())
        history.append(dict(epoch=epoch, learning_rate=.0001, train_weighted_loss=train_loss, development=metrics,
            training_samples=len(x), optimizer_steps=(len(x) + 127) // 128,
            train_seconds=train_seconds, train_cpu_seconds=train_cpu,
            epoch_seconds=time.perf_counter() - start, epoch_cpu_seconds=time.process_time() - cpu,
            sampled_rss_bytes=psutil.Process().memory_info().rss, best_epoch=best_epoch))
        write_json(folder / "epochs.json", history)
        print(f"{folder.name} epoch={epoch} macro_f1={metrics['macro_f1']:.6f} recall={metrics['recall']:.6f} best={best_epoch}", flush=True)
    atomic_torch_save(model.state_dict(), folder / "last.pt")
    model.load_state_dict(best_state, strict=True)
    model.eval().requires_grad_(False)
    atomic_torch_save(model.state_dict(), folder / "post.pt")
    return history, best_epoch


@torch.inference_mode()
def benchmark(models, x, output):
    inputs = [torch.from_numpy(x[i % len(x):i % len(x) + 1]) for i in range(1000)]
    timings, costs = [], {key: [] for key in models}
    start, cpu = time.perf_counter(), time.process_time()
    names = sorted(models)
    with torch.autocast("cpu", enabled=False):
        for repeat in range(3):
            for name in names[repeat:] + names[:repeat]:
                model = models[name].eval()
                for sample in inputs[:100]:
                    model(sample)
                values = []
                for i, sample in enumerate(inputs):
                    tick = time.perf_counter_ns()
                    model(sample)
                    elapsed = time.perf_counter_ns() - tick
                    values.append(elapsed)
                    timings.append(dict(model=name, repeat=repeat + 1, iteration=i, elapsed_ns=elapsed))
                costs[name].append(dict(repeat=repeat + 1, calls=len(values),
                    median_ns=float(np.median(values)), p95_ns=float(np.percentile(values, 95)),
                    mean_ns=float(np.mean(values)), sampled_rss_bytes=psutil.Process().memory_info().rss))
    with (output / "timing_samples.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["model", "repeat", "iteration", "elapsed_ns"])
        writer.writeheader()
        writer.writerows(timings)
    result = dict(seconds=time.perf_counter() - start, cpu_seconds=time.process_time() - cpu,
        models={name: dict(repeats=values, median_of_repeat_medians_ns=float(np.median([v["median_ns"] for v in values])),
                           median_of_repeat_p95_ns=float(np.median([v["p95_ns"] for v in values])))
                for name, values in costs.items()})
    write_json(output / "benchmark.json", result)
    return result


def freeze(model, folder, *, record, registration_sha256, shared_hashes, mapping=None):
    folder.mkdir(parents=True)
    atomic_torch_save(model.state_dict(), folder / "weights.pt")
    write_json(folder / "architecture.json", describe(model))
    if mapping is not None:
        write_json(folder / "channel_map.json", mapping)
    handoff = dict(version="phase5_frozen_v1", id=record["id"], kind=record["kind"],
        architecture_frozen=True, checkpoint_file="weights.pt", architecture_file="architecture.json",
        state_dict_sha256=weight_hash(model.state_dict()), registration_sha256=registration_sha256,
        shared_artifacts=shared_hashes, quality_gate=record["gate"], selected=record["selected"],
        export_comparison_artifact=True, deployment_ready=False, independently_validated=False,
        selection_threshold=.5, final_threshold=None, calibration="not fitted")
    write_json(folder / "handoff.json", handoff)
    write_json(folder / "checksums.json", {p.name: sha256(p) for p in sorted(folder.iterdir()) if p.is_file()})
    return (folder / "weights.pt").stat().st_size


def load_frozen(folder):
    folder = Path(folder)
    hashes = read_json(folder / "checksums.json")
    allowed = {"weights.pt", "architecture.json", "handoff.json", "channel_map.json"}
    require({"weights.pt", "architecture.json", "handoff.json"} <= hashes.keys() <= allowed, "Invalid frozen bundle")
    for name, expected in hashes.items():
        require(sha256(allowed_path(folder, name, allowed)) == expected, f"Frozen artifact changed: {name}")
    arch, handoff = read_json(folder / "architecture.json"), read_json(folder / "handoff.json")
    model = TemporalCNN(tuple(arch["channels"]))
    model.load_state_dict(torch.load(folder / "weights.pt", map_location="cpu", weights_only=True), strict=True)
    require(describe(model) == arch and weight_hash(model.state_dict()) == handoff["state_dict_sha256"],
            "Frozen architecture/weights binding mismatch")
    return model.eval().requires_grad_(False), handoff


def write_report(output, summary):
    lines = ["# Phase 5 compact networks and fine-tuning", "",
        f"Selected **{summary['selected']}** using the registered development quality gate and actual parameter count.",
        "The unpruned baseline and all three direct-small seed artifacts are preserved for the final compression comparison.", "",
        "| Candidate | Channels | Parameters | Float tensor bytes | Saved weight bytes | MACs/sample | Pre recall / macro-F1 | Post recall / macro-F1 | Gate | Selected epoch | Warm median / p95 (us) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |"]
    for row in summary["models"]:
        cost, pre, post, bench = row["cost"], row["pre"], row["post"], row["benchmark"]
        lines.append(f"| {row['id']} | {'/'.join(map(str, cost['channels']))} | {cost['parameters']} | {cost['tensor_bytes']} | "
            f"{cost['serialized_weights_bytes']} | {cost['conv_linear_macs_per_sample']} | {pre['recall']:.6f} / {pre['macro_f1']:.6f} | "
            f"{post['recall']:.6f} / {post['macro_f1']:.6f} | {'pass' if row['gate']['accepted'] else 'reject'} | {row['best_epoch'] or '-'} | "
            f"{bench['median_of_repeat_medians_ns']/1000:.3f} / {bench['median_of_repeat_p95_ns']/1000:.3f} |")
    lines += ["", "Direct-small comparison uses its best Phase 3 development seed, with lowest seed on exact ties: "
              f"**{summary['direct_small_comparator']}**. Direct-small/unpruned pre and post are identical because they were replayed without additional training.",
        "", "## Compaction and numerical correctness", "",
        "Each GA artifact contains ordinary smaller Conv1d and Linear tensors. Conv1 output filters/biases, conv2 output filters/biases and matching conv1 input columns, and final Linear input columns are copied in ascending retained-index order. The final output bias is unchanged.",
        "All candidates passed before any training: every fixed development input plus 291 fixed synthetic inputs, each at batch sizes 1 and 1,024, with atol=1e-6 and rtol=1e-5. Synthetic inputs cover zero/bias behavior, signs, random values and every channel/time impulse. Exact archived masked outputs were also replayed.", ""]
    for row in summary["models"]:
        if row["kind"] == "ga":
            m = read_json(output / "candidates" / row["id"] / "channel_map.json")
            lines += [f"- {row['id']} conv1: {m['conv1']}; conv2: {m['conv2']}."]
    lines += ["", "## Registered comparison", "",
        "The designated reference is the original trained 64/32 Phase 3 baseline preserved by Phase 4. The exact development rows, preprocessing, class prevalence, fixed-label metrics and float64 sigmoid(float32 logit) >= 0.5 rule are unchanged. Recall or macro-F1 loss greater than 0.02 rejects a candidate; the tolerance was never widened.",
        f"Each GA candidate received {summary['config']['max_epochs']} epochs of training-only fine-tuning using fresh Adam at 0.0001, batch 128 and the original training-only positive weight. The highest macro-F1 among trained epochs is selected; exact ties keep the earliest epoch. Epoch zero is preserved but is not a fallback for a failed fine-tuned result. All epoch metrics and the terminal checkpoint are retained.",
        "The architecture selection first applies both quality gates, then minimizes actual parameter count; ties prefer macro-F1, recall and ID. It considers the unpruned fallback, the best direct-small comparator and all GA candidates. Latency is measured and reported separately. No required percentage reduction was imposed.",
        "", "## Measured costs", "",
        "Warm costs are host CPU eager float32 batch-one model calls: one intraop/interop thread, 100 warmups and 1,000 timed calls per model per repeat, three repeats, rotated model order. Table values are medians across repeat medians/p95s. Raw nanosecond measurements are in timing_samples.csv. They exclude preprocessing, service overhead, export and RISC-V/Arm execution; they do not predict target-device latency.",
        "Tensor bytes and serialized weights are measured on the physical modules. MACs are analytical convolution/linear counts excluding activations, biases and pooling. No savings are attributed to zero-filled dense tensors. Process RSS samples include the interpreter and other resident models; no per-model RAM reduction is inferred.", ""]
    for row in summary["models"]:
        if row["kind"] == "ga":
            c = row["training_cost"]
            lines.append(f"- {row['id']}: {c['optimizer_steps']} optimizer steps; training {c['train_seconds']:.6f}s wall / {c['train_cpu_seconds']:.6f}s CPU; training plus epoch evaluation {c['epoch_seconds']:.6f}s wall; sampled process RSS maximum {c['sampled_rss_max_bytes']} bytes.")
    lines += ["", f"Run cost through measurement: {summary['run_cost']['seconds']:.6f}s wall / {summary['run_cost']['cpu_seconds']:.6f}s CPU. Setup, equivalence and benchmark costs are recorded separately in summary.json; startup and final report/checksum persistence are excluded. Verification cost is separate.",
        "", "## Scope and frozen handoff", "",
        f"Development support: {summary['validation']['sample_count']} samples; classes {summary['validation']['class_counts']}; families {summary['validation']['family_counts']}; independent held-out groups {summary['validation']['independent_heldout_groups']}.",
        "There is only one attack sample and one original source group. Repeated development selection is optimistic; this experiment cannot establish attack recall or generalization. Absent-family metrics remain null. Threshold-reserve, internal-test and external-test files were not opened. No thresholds, calibration, quantization, runtime export or deployment were performed.",
        "frozen/ contains architecture-bound weights and checksums for every comparison artifact, including rejected ones with explicit gate status. handoff.json fixes the selected architecture and parent identities; shared/ preserves preprocessing, schema and split metadata. These are Phase 5 research artifacts for later export and compression comparisons, not deployment approval.", ""]
    (output / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def run(search, experiment, output, config=Config()):
    start, cpu = time.perf_counter(), time.process_time()
    output = Path(output).resolve()
    require(not output.exists(), "Output must be new; existing experiment artifacts are immutable")
    determinism(config.seed)
    data = load_inputs(search, experiment)
    output.mkdir(parents=True)
    write_json(output / "status.json", dict(status="preflight", training_steps=0))
    try:
        registration = protocol(config, data)
        write_json(output / "registration.json", registration)  # Before any new candidate outcomes/training.
        write_json(output / "environment.json", environment())
        write_json(output / "outcome_access.json", data["access"])
        write_json(output / "validation_manifest.json", data["provenance"]["validation"])
        originals = output / "originals"
        (originals / "unpruned").mkdir(parents=True)
        for name in BUNDLE_FILES:
            shutil.copyfile(Path(search) / "baseline" / name, originals / "unpruned" / name)
        for direct in data["directs"]:
            (originals / direct["id"]).mkdir()
            for name in DIRECT_FILES:
                shutil.copyfile(direct["root"] / name, originals / direct["id"] / name)
        shared = output / "shared"
        shared.mkdir()
        for name in ("preprocess.json", "feature_schema.json", "split_manifest.json"):
            shutil.copyfile(Path(search) / "baseline" / name, shared / name)
        shared_hashes = {p.name: sha256(p) for p in sorted(shared.iterdir())}
        setup_cost = dict(seconds=time.perf_counter() - start, cpu_seconds=time.process_time() - cpu)
        tick, tick_cpu = time.perf_counter(), time.process_time()
        candidate_folder = output / "candidates"
        candidate_folder.mkdir()
        candidates = data["top"]["candidates"][:config.top_k]
        models, parity = preflight(data, candidates, candidate_folder)
        parity_cost = dict(seconds=time.perf_counter() - tick, cpu_seconds=time.process_time() - tick_cpu)
        baseline, logits, scores = assess(data["parent"], data["dev"], data["rows"])
        replay_predictions(logits, scores, data["saved"])
        require({k: v for k, v in baseline.items() if k != "loss"} == data["top"]["baseline"]["metrics"], "Baseline metrics drift")
        records = [dict(id="unpruned", kind="unpruned", pre=baseline, post=baseline,
                        gate=quality_gate(baseline, baseline), cost=physical_cost(data["parent"]), best_epoch=None)]
        models["unpruned"] = data["parent"]
        for direct in data["directs"]:
            metrics, logits, scores = assess(direct["model"], data["dev"], data["rows"])
            replay_predictions(logits, scores, direct["predictions"])
            require(metrics == direct["result"]["development"], "Direct-small metric replay drift")
            records.append(dict(id=direct["id"], kind="direct_small", seed=direct["seed"], pre=metrics, post=metrics,
                                gate=quality_gate(metrics, baseline), cost=physical_cost(direct["model"]), best_epoch=None))
            models[direct["id"]] = direct["model"]
        direct_id = min((r for r in records if r["kind"] == "direct_small"),
                        key=lambda r: (-r["post"]["macro_f1"], r["seed"]))["id"]
        write_json(output / "status.json", dict(status="training", preflight_passed=True))
        parent_hash = weight_hash(data["parent"].state_dict())
        for i, source in enumerate(candidates, 1):
            name = f"ga_{i}"
            model, folder = models[name], candidate_folder / name
            pre, logits, scores = assess(model, data["dev"], data["rows"])
            save_predictions(folder / "pre_predictions.parquet", data["rows"], logits, scores)
            history, best_epoch = fine_tune(model, data, config, folder)
            post, logits, scores = assess(model, data["dev"], data["rows"])
            require(post == history[best_epoch - 1]["development"], "Selected trained checkpoint replay differs")
            save_predictions(folder / "post_predictions.parquet", data["rows"], logits, scores)
            record = dict(id=name, kind="ga", mask=source["mask"], pre=pre, post=post,
                pre_gate=quality_gate(pre, baseline), gate=quality_gate(post, baseline), best_epoch=best_epoch,
                terminal=history[-1]["development"], cost=physical_cost(model), epochs_completed=len(history),
                training_cost={**{k: sum(h[k] for h in history) for k in
                    ("optimizer_steps", "train_seconds", "train_cpu_seconds", "epoch_seconds", "epoch_cpu_seconds")},
                    "sampled_rss_max_bytes": max(h["sampled_rss_bytes"] for h in history)})
            write_json(folder / "result.json", record)
            records.append(record)
        require(weight_hash(data["parent"].state_dict()) == parent_hash, "Unpruned parent was modified")
        selected = select_candidate(records, direct_id)
        for record in records:
            record["selected"] = record["id"] == selected
            mapping = channel_map(Mask.decode(record["mask"])) if record["kind"] == "ga" else None
            record["cost"]["serialized_weights_bytes"] = freeze(models[record["id"]], output / "frozen" / record["id"],
                record=record, registration_sha256=sha256(output / "registration.json"), shared_hashes=shared_hashes,
                mapping=mapping)
        measured = benchmark(models, data["dev"], output)
        for record in records:
            record["benchmark"] = measured["models"][record["id"]]
        summary = dict(status="complete", selected=selected, direct_small_comparator=direct_id, models=records,
            config=asdict(config), validation=data["provenance"]["validation"], equivalence=parity,
            setup_cost=setup_cost, equivalence_cost=parity_cost,
            benchmark_cost={k: measured[k] for k in ("seconds", "cpu_seconds")},
            run_cost=dict(seconds=time.perf_counter() - start, cpu_seconds=time.process_time() - cpu),
            ga_experiment_succeeded=any(r["kind"] == "ga" and r["gate"]["accepted"] for r in records),
            protected_outcomes_accessed=False, exported=False, deployment_ready=False)
        write_json(output / "summary.json", summary)
        write_json(output / "handoff.json", dict(version="phase5_export_handoff_v1", selected=selected,
            selected_directory=f"frozen/{selected}", comparison_directories=[f"frozen/{r['id']}" for r in records],
            architectures_frozen=True, selected_architecture=describe(models[selected]),
            selected_state_dict_sha256=weight_hash(models[selected].state_dict()),
            registration_sha256=sha256(output / "registration.json"), shared_artifacts=shared_hashes,
            final_threshold=None, calibration="deferred", exported=False, deployment_ready=False))
        write_report(output, summary)
        write_json(output / "status.json", dict(status="complete", selected=selected))
        write_json(output / "artifact_checksums.json", {p.relative_to(output).as_posix(): sha256(p)
            for p in sorted(output.rglob("*")) if p.is_file() and p.name != "artifact_checksums.json"})
        print(json.dumps(dict(status="complete", selected=selected, output=str(output))), flush=True)
        return summary
    except BaseException as exc:
        write_json(output / "status.json", dict(status="wiring_error" if isinstance(exc, WiringError) else "failed",
                                                error_type=type(exc).__name__, error=str(exc)))
        raise


def verify(output, search, experiment):
    start, cpu = time.perf_counter(), time.process_time()
    output = Path(output).resolve()
    hashes = read_json(output / "artifact_checksums.json")
    for name, expected in hashes.items():
        p = (output / name).resolve()
        require(p.is_relative_to(output) and sha256(p) == expected, f"Phase 5 artifact changed: {name}")
    summary, registration = read_json(output / "summary.json"), read_json(output / "registration.json")
    config = Config(**registration["config"])
    determinism(config.seed)
    require(implementation_hashes() == registration["source_hashes"] and
            runtime_fingerprint() == registration["runtime"], "Verification source/runtime drift")
    data = load_inputs(search, experiment)
    require(data["input_hashes"] == registration["input_hashes"], "Verification input drift")
    baseline = next(r["post"] for r in summary["models"] if r["id"] == "unpruned")
    for record in summary["models"]:
        model, handoff = load_frozen(output / "frozen" / record["id"])
        require(handoff["registration_sha256"] == sha256(output / "registration.json"), "Registration binding drift")
        for name, expected in handoff["shared_artifacts"].items():
            require(name in {"preprocess.json", "feature_schema.json", "split_manifest.json"} and
                    sha256(output / "shared" / name) == expected, "Shared provenance drift")
        actual, logits, scores = assess(model, data["dev"], data["rows"])
        require(actual == record["post"] and quality_gate(actual, baseline) == record["gate"], "Frozen evaluation drift")
        require(all(record["cost"][k] == v for k, v in physical_cost(model).items()), "Physical cost drift")
        if record["kind"] == "ga":
            folder = output / "candidates" / record["id"]
            mask = Mask.decode(record["mask"])
            pre = rebuild(data["parent"], mask)
            state = torch.load(folder / "pre.pt", map_location="cpu", weights_only=True)
            require(weight_hash(state) == weight_hash(pre.state_dict()), "Reconstruction drift")
            report = check_equivalence(data["parent"], pre, mask, dict(real_development=data["dev"], synthetic=synthetic_samples()))
            require(report == summary["equivalence"][record["id"]], "Equivalence replay drift")
            before, a, b = assess(pre, data["dev"], data["rows"])
            require(before == record["pre"], "Pre-fine-tune evaluation drift")
            replay_predictions(a, b, pq.read_table(folder / "pre_predictions.parquet").to_pylist())
            replay_predictions(logits, scores, pq.read_table(folder / "post_predictions.parquet").to_pylist())
            history = read_json(folder / "epochs.json")
            best = max(history, key=lambda h: h["development"]["macro_f1"])
            require(best["epoch"] == record["best_epoch"] and best["development"] == actual and
                    len(history) == config.max_epochs, "Trained checkpoint selection drift")
            require(weight_hash(torch.load(folder / "post.pt", map_location="cpu", weights_only=True)) ==
                    weight_hash(model.state_dict()), "Frozen post checkpoint drift")
            model.load_state_dict(torch.load(folder / "last.pt", map_location="cpu", weights_only=True))
            require(assess(model, data["dev"], data["rows"])[0] == record["terminal"], "Terminal evaluation drift")
    selected = select_candidate(summary["models"], summary["direct_small_comparator"])
    handoff = read_json(output / "handoff.json")
    model, _ = load_frozen(output / "frozen" / selected)
    require(selected == summary["selected"] == handoff["selected"] and
            describe(model) == handoff["selected_architecture"] and
            weight_hash(model.state_dict()) == handoff["selected_state_dict_sha256"], "Architecture selection drift")
    result = dict(passed=True, frozen_models_replayed=len(summary["models"]),
        compact_preflight_replayed=len(summary["equivalence"]), selected=selected,
        exact_metrics_and_predictions=True, artifacts_and_input_hashes_verified=True,
        protected_outcomes_accessed=False, training_performed=False,
        seconds=time.perf_counter() - start, cpu_seconds=time.process_time() - cpu)
    write_json(output / "verification.json", result)
    print(json.dumps(result, indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "verify"])
    parser.add_argument("--search", type=Path, default=Path("experiments/phase4/run-001"))
    parser.add_argument("--experiment", type=Path, default=Path("experiments/phase3/run-002"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--max-epochs", type=int, default=5)
    parser.add_argument("--top-k", type=int, default=3)
    args = parser.parse_args()
    if args.action == "run":
        run(args.search, args.experiment, args.output, Config(seed=args.seed, max_epochs=args.max_epochs, top_k=args.top_k))
    else:
        verify(args.output, args.search, args.experiment)


if __name__ == "__main__":
    main()
