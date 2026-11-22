"""Deterministic CPU Phase 3 pilot, training, resumable checkpoints and handoff."""

import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
import random
import shutil
import time

import numpy as np
import psutil
import pyarrow as pa
import pyarrow.parquet as pq
import torch
from torch import nn

from ids.datasets.temporal import digest
from ids.model import TemporalCNN
from ids.run_logging import RunLogger, ResourceMonitor, environment, sha256, write_json
from ids.training.data import ROOT, SEEDS, VARIANTS, load_training_data, read_json, require
from ids.training.metrics import binary_metrics, development_metrics


class Logistic128(nn.Module):
    def __init__(self):
        super().__init__()
        self.output = nn.Linear(128, 1)

    def forward(self, x):
        return self.output(x.flatten(1))


def architecture(variant):
    require(variant in VARIANTS, "Unknown registered variant")
    if variant == "logistic128_weighted":
        return dict(kind="logistic_regression", input_features=128, flatten_order="channel-major [16,8]",
                    layers=["Flatten", "Linear(128,1)"], regularization="none", output="logit")
    channels = [32, 16] if variant == "cnn32_weighted" else [64, 32]
    return dict(kind="temporal_cnn", input_channels=16,
        history_rows=1 if variant == "last_window_weighted" else 8,
        history_selection="final window" if variant == "last_window_weighted" else "all eight oldest first",
        channels=channels, kernel_size=3, stride=1, padding=1, bias=True,
        activation="ReLU", pooling="global temporal mean", output="Linear(last_channels,1) logit",
        initialization="PyTorch default Kaiming-uniform; seeded", dropout=0.0, batch_norm=False)


def make_model(variant):
    config = architecture(variant)
    return Logistic128() if config["kind"] == "logistic_regression" else TemporalCNN(tuple(config["channels"]))


def inputs(x, variant):
    return x[:, :, -1:].contiguous() if variant == "last_window_weighted" else x


def determinism(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(1)
    if torch.get_num_interop_threads() != 1:
        torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True)
    torch.backends.mkldnn.deterministic = True


def implementation_hashes():
    paths = [*sorted((ROOT / "ids/training").glob("*.py")), ROOT / "ids/model.py",
             ROOT / "ids/preprocessing.py", ROOT / "ids/run_logging.py", ROOT / "pyproject.toml", ROOT / "uv.lock"]
    return {p.relative_to(ROOT).as_posix(): sha256(p) for p in paths}


def weight_hash(state):
    h = hashlib.sha256()
    for name, tensor in sorted(state.items()):
        h.update(name.encode())
        h.update(str(tensor.dtype).encode())
        h.update(str(tuple(tensor.shape)).encode())
        h.update(tensor.detach().cpu().contiguous().numpy().tobytes())
    return h.hexdigest()


def atomic_torch_save(value, path):
    path = Path(path)
    temp = path.with_suffix(".tmp")
    torch.save(value, temp)
    temp.replace(path)


def rng_state(generator):
    n = np.random.get_state()
    return dict(python=random.getstate(), numpy=[n[0], n[1].tolist(), n[2], n[3], n[4]],
                torch=torch.get_rng_state(), permutation=generator.get_state())


def restore_rng(state, generator):
    random.setstate(state["python"])
    n = state["numpy"]
    np.random.set_state((n[0], np.array(n[1], dtype=np.uint32), n[2], n[3], n[4]))
    torch.set_rng_state(state["torch"])
    generator.set_state(state["permutation"])


def tensors(data):
    return {role: (torch.from_numpy(v["x"]), torch.from_numpy(v["y"]).reshape(-1, 1))
            for role, v in data.items()}


def positive_weight(y, variant):
    ratio = float(np.sum(y == 0) / np.sum(y == 1))
    return ratio if variant != "cnn64_unweighted" and ratio > 10 else 1.0


def optimizer_for(model):
    return torch.optim.Adam(model.parameters(), lr=.001, betas=(.9, .999), eps=1e-8,
                            weight_decay=0, amsgrad=False, foreach=False, fused=False)


def train_epoch(model, optimizer, x, y, variant, weight, generator):
    model.train()
    criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([weight]))
    order = torch.randperm(len(x), generator=generator)
    losses = 0.0
    for indices in order.split(128):
        optimizer.zero_grad(set_to_none=True)
        logits = model(inputs(x[indices], variant))
        loss = criterion(logits, y[indices])
        require(bool(torch.isfinite(loss)), "Nonfinite training loss; audit data before continuing")
        loss.backward()
        require(all(p.grad is None or bool(torch.isfinite(p.grad).all()) for p in model.parameters()), "Nonfinite gradient")
        optimizer.step()
        losses += float(loss.detach()) * len(indices)
    return losses / len(x)


def evaluate(model, x, y, variant):
    model.eval()
    with torch.inference_mode():
        logits = torch.cat([model(inputs(batch, variant)) for batch in x.split(1024)])
        require(bool(torch.isfinite(logits).all()), "Nonfinite development output")
        loss = float(nn.functional.binary_cross_entropy_with_logits(logits, y))
        scores = torch.sigmoid(logits.double()).numpy().reshape(-1)
    return loss, logits.numpy().reshape(-1), scores


def configuration(experiment, variant, seed, data, data_hash):
    return dict(record_version="phase3_training_v1", variant=variant, seed=seed,
        architecture=architecture(variant), data_sha256=data_hash,
        registration_sha256=sha256(Path(experiment) / "registration.json"),
        source_hashes=implementation_hashes(), feature_schema="device_window_v1",
        preprocess_sha256=sha256(Path(experiment) / "data/preprocess.json"),
        split_manifest_sha256=sha256(Path(experiment) / "data/split_manifest.json"),
        loss="BCEWithLogitsLoss", positive_weight=positive_weight(data["train"]["y"], variant),
        optimizer=dict(name="Adam", learning_rate=.001, betas=[.9, .999], epsilon=1e-8,
                       weight_decay=0, foreach=False, fused=False, amsgrad=False),
        batch_size=128, max_epochs=30, patience=5, min_delta=0.0,
        selection_metric="binary macro-F1", selection_threshold=.5,
        tie_policy="strict improvement, earliest epoch", training_sampler="seeded permutation, no replacement, no dropped tail",
        device="cpu", intraop_threads=1, interop_threads=1, deterministic_algorithms=True,
        evaluation_loss="unweighted BCE", final_threshold=None, calibration="not fitted",
        versions={"torch": str(torch.__version__), "numpy": str(np.__version__), "python": environment()["python"]})


def save_epoch_tables(logger, history):
    """Rebuild from the atomic resume state; a crash cannot duplicate an epoch."""
    with (logger.output / "epoch_metrics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=RunLogger.EPOCH_FIELDS)
        writer.writeheader()
        for record in history:
            m = record["development"]
            writer.writerow(dict(epoch=record["epoch"], split="development", loss=m["loss"], learning_rate=.001,
                precision=m["precision"], recall=m["recall"], macro_f1=m["macro_f1"], pr_auc=m["pr_auc"],
                pr_auc_method=m["pr_auc_method"], sample_count=m["sample_count"], epoch_seconds=record["seconds"],
                examples_per_second=record["training_samples"] / record["seconds"]))
    write_json(logger.output / "epochs.json", history)


def run_one(experiment, data, data_hash, variant, seed, *, resume=False, stop_after_epoch=None):
    experiment = Path(experiment)
    path = experiment / "runs" / variant / f"seed-{seed}"
    determinism(seed)
    config = configuration(experiment, variant, seed, data, data_hash)
    model = make_model(variant)
    optimizer = optimizer_for(model)
    generator = torch.Generator().manual_seed(seed + 1)
    ts = tensors(data)
    history, best_score, bad_epochs, best_epoch, best_state, first = [], -1.0, 0, 0, None, 1
    if path.exists():
        require(resume, f"Existing run requires --resume: {path}")
        require(read_json(path / "config.json") == config, "Resume configuration/data/source/environment drift")
        logger = RunLogger.__new__(RunLogger)
        logger.output, logger.manifest = path, read_json(path / "run_manifest.json")
        if logger.manifest["status"] == "complete":
            for name, expected in read_json(path / "artifact_checksums.json").items():
                require(sha256(path / name) == expected, f"Completed run corrupted: {name}")
            return read_json(path / "result.json")
        state = torch.load(path / "resume.pt", map_location="cpu", weights_only=True)
        require(state["config"] == config, "Resume state provenance mismatch")
        model.load_state_dict(state["model_state"])
        optimizer.load_state_dict(state["optimizer_state"])
        restore_rng(state["rng"], generator)
        history, best_score = state["history"], state["best_score"]
        bad_epochs, best_epoch, best_state = state["bad_epochs"], state["best_epoch"], state["best_state"]
        first = state["epoch"] + 1
        logger.event("resumed", after_epoch=state["epoch"], resume_sha256=sha256(path / "resume.pt"))
    else:
        logger = RunLogger(path, dict(stage="phase3", config=config, trained=True,
            independent_evaluation=False, protected_outcomes_accessed=False))
        write_json(path / "config.json", config)
        write_json(path / "environment.json", environment())
    try:
        for epoch in range(first, 31):
            if bad_epochs >= 5:
                break
            start, cpu = time.perf_counter(), time.process_time()
            train_loss = train_epoch(model, optimizer, *ts["train"], variant, config["positive_weight"], generator)
            dev_loss, _, scores = evaluate(model, *ts["development"], variant)
            metrics = development_metrics(data["development"]["rows"], scores)
            metrics["loss"] = dev_loss
            require(metrics["macro_f1"] is not None, "Development needs both classes")
            score = metrics["macro_f1"]
            if score > best_score:
                best_score, best_epoch, bad_epochs = score, epoch, 0
                best_state = copy.deepcopy(model.state_dict())
            else:
                bad_epochs += 1
            record = dict(epoch=epoch, train_weighted_loss=train_loss, development=metrics,
                seconds=time.perf_counter() - start, cpu_seconds=time.process_time() - cpu,
                sampled_rss_bytes=psutil.Process().memory_info().rss, training_samples=len(ts["train"][0]),
                best_epoch=best_epoch, bad_epochs=bad_epochs)
            history.append(record)
            state = dict(config=config, epoch=epoch, model_state=model.state_dict(),
                optimizer_state=optimizer.state_dict(), rng=rng_state(generator), history=history,
                best_score=best_score, best_epoch=best_epoch, best_state=best_state, bad_epochs=bad_epochs)
            atomic_torch_save(state, path / "resume.pt")
            save_epoch_tables(logger, history)
            logger.event("epoch", epoch=epoch, macro_f1=score, best_epoch=best_epoch)
            print(f"{variant} seed={seed} epoch={epoch:02} dev_macro_f1={score:.6f} best={best_epoch} stale={bad_epochs}", flush=True)
            if stop_after_epoch is not None and epoch >= stop_after_epoch:
                logger.finish("interrupted", last_epoch=epoch)
                return None
        require(best_state is not None, "No selected checkpoint")
        best = dict(config=config, epoch=best_epoch, development_macro_f1=best_score,
                    model_state=best_state, state_dict_sha256=weight_hash(best_state))
        atomic_torch_save(best, path / "best.pt")
        model.load_state_dict(best_state)
        dev_loss, logits, scores = evaluate(model, *ts["development"], variant)
        metrics = development_metrics(data["development"]["rows"], scores)
        metrics["loss"] = dev_loss
        require(metrics["macro_f1"] == best_score, "Selected checkpoint replay differs")
        rows = data["development"]["rows"]
        predictions = [dict(sample_id=r["sample_id"], source_sample_id=r["source_sample_id"],
            group_id=r["group_id"], original_group_id=r["original_group_id"], device_id=r["device_id"],
            final_time_ns=r["final_time_ns"], label=r["label"], family=r["family"],
            logit=float(logit), score=float(score), prediction=int(score >= .5), selection_threshold=.5)
            for r, logit, score in zip(rows, logits, scores)]
        pq.write_table(pa.Table.from_pylist(predictions), path / "development_predictions.parquet", compression="zstd")
        # Shared Section 14 prediction schema alongside richer development records.
        shared = [dict(sample_id=r["sample_id"], group_id=r["group_id"], dataset="UNSW-NB15",
                       family=r["family"], label=r["label"], score=r["score"], status="ok", exclusion_reason=None)
                  for r in predictions]
        if (path / "predictions.parquet").exists():
            # Crash recovery may repeat finalization, but must reproduce identical scores.
            require(pq.read_table(path / "predictions.parquet").to_pylist() == shared, "Finalization prediction drift")
        else:
            logger.write_table("predictions", shared)
        result = dict(variant=variant, seed=seed, best_epoch=best_epoch, epochs_completed=len(history),
            stopping_reason="patience_5" if bad_epochs >= 5 else "maximum_30_epochs",
            parameter_count=sum(p.numel() for p in model.parameters()), positive_weight=config["positive_weight"],
            development=metrics, checkpoint_sha256=sha256(path / "best.pt"),
            state_dict_sha256=best["state_dict_sha256"], resume_sha256=sha256(path / "resume.pt"),
            training_seconds=sum(r["seconds"] for r in history), cpu_seconds=sum(r["cpu_seconds"] for r in history),
            run_directory=path.relative_to(experiment).as_posix())
        write_json(path / "result.json", result)
        logger.finish("complete", **result)
        write_json(path / "artifact_checksums.json", {p.name: sha256(p) for p in sorted(path.iterdir())
            if p.is_file() and p.name != "artifact_checksums.json"})
        return result
    except BaseException as exc:
        logger.finish("failed_resumable" if (path / "resume.pt").exists() else "failed",
                      error_type=type(exc).__name__, error=str(exc))
        raise


def pilot(experiment):
    experiment = Path(experiment)
    data, data_hash = load_training_data(experiment)
    path = experiment / "pilot"
    path.mkdir(exist_ok=False)
    determinism(SEEDS[0])
    variant = "cnn64_weighted"
    model, generator = make_model(variant), torch.Generator().manual_seed(SEEDS[0] + 1)
    optimizer, ts = optimizer_for(model), tensors(data)
    weight = positive_weight(data["train"]["y"], variant)
    durations = []
    with ResourceMonitor(path):
        for epoch in range(2):
            start, cpu = time.perf_counter(), time.process_time()
            train_epoch(model, optimizer, *ts["train"], variant, weight, generator)
            evaluate(model, *ts["development"], variant)  # Timing only; no metrics/checkpoints kept.
            durations.append(dict(epoch=epoch + 1, wall_seconds=time.perf_counter() - start,
                                  cpu_seconds=time.process_time() - cpu))
    per_epoch = max(r["wall_seconds"] for r in durations)
    count, maximum = len(VARIANTS) * len(SEEDS), len(VARIANTS) * len(SEEDS) * 30
    result = dict(kind="CPU timing pilot only; discarded weights", seed=SEEDS[0],
        data_sha256=data_hash, source_hashes=implementation_hashes(), environment=environment(),
        intraop_threads=1, interop_threads=1, epochs=durations, planned_runs=count,
        planned_seeds=SEEDS, max_remaining_epochs=maximum, upper_compute_seconds=per_epoch * maximum,
        conservative_wall_seconds_with_50pct_overhead=per_epoch * maximum * 1.5,
        estimate_basis="slowest full CNN64 train+development epoch; all 15 runs at 30 epochs; excludes setup; early stopping may reduce cost",
        any_candidate_kept=False, protected_outcomes_accessed=False)
    write_json(path / "pilot.json", result)
    print(json.dumps({k: v for k, v in result.items() if k not in {"environment", "source_hashes"}}, indent=2), flush=True)


def package(experiment, results, data_hash):
    experiment = Path(experiment).resolve()
    comparisons = {}
    for variant in VARIANTS:
        runs = [r for r in results if r["variant"] == variant]
        comparisons[variant] = dict(seeds=[r["seed"] for r in runs], runs=len(runs),
            macro_f1_mean=float(np.mean([r["development"]["macro_f1"] for r in runs])),
            macro_f1_sd=float(np.std([r["development"]["macro_f1"] for r in runs], ddof=1)) if len(runs) > 1 else None,
            recall_mean=float(np.mean([r["development"]["recall"] for r in runs])),
            false_positive_rate_mean=float(np.mean([r["development"]["false_positive_rate"] for r in runs])),
            ap_mean=float(np.mean([r["development"]["pr_auc"] for r in runs])),
            parameter_count=runs[0]["parameter_count"])
    candidates = [r for r in results if r["variant"] in {"cnn64_weighted", "cnn64_unweighted"}]
    selected = sorted(candidates, key=lambda r: (-r["development"]["macro_f1"], r["seed"], r["variant"]))[0]
    effects = []
    for seed in sorted({r["seed"] for r in results}):
        weighted = next(r for r in results if r["variant"] == "cnn64_weighted" and r["seed"] == seed)
        plain = next(r for r in results if r["variant"] == "cnn64_unweighted" and r["seed"] == seed)
        effects.append(dict(seed=seed, positive_weight=weighted["positive_weight"],
            macro_f1_delta=weighted["development"]["macro_f1"] - plain["development"]["macro_f1"],
            recall_delta=weighted["development"]["recall"] - plain["development"]["recall"],
            false_positive_rate_delta=weighted["development"]["false_positive_rate"] - plain["development"]["false_positive_rate"]))
    summary = dict(comparisons=comparisons, selected_baseline=selected, balancing_effect=effects,
        runs=results, seeds_requested=SEEDS, seeds_completed=sorted({r["seed"] for r in results}),
        smaller_budget_disclosed=len(results) < len(VARIANTS) * len(SEEDS),
        data_sha256=data_hash, final_threshold=None, calibration="deferred", protected_outcomes_accessed=False)
    write_json(experiment / "comparison.json", summary)
    bundle = experiment / "baseline_package"
    if bundle.exists():
        existing = verify_bundle(bundle)
        require(existing["checkpoint_sha256"] == selected["checkpoint_sha256"], "Existing package selects a different checkpoint")
        return
    bundle.mkdir()
    source = experiment / selected["run_directory"]
    for name in ("best.pt", "resume.pt", "development_predictions.parquet", "result.json", "config.json", "environment.json"):
        shutil.copyfile(source / name, bundle / name)
    for name in ("preprocess.json", "split_manifest.json", "parent_provenance.json", "fit_window_ids.json",
                 "feature_schema.json", "audit.json", "extraction_parity.json", "reserved_index.parquet", "outcome_access.json"):
        shutil.copyfile(experiment / "data" / name, bundle / name)
    shutil.copyfile(experiment / "registration.json", bundle / "registration.json")
    write_json(bundle / "architecture.json", architecture(selected["variant"]))
    audit = read_json(bundle / "audit.json")
    replay = f".\\.venv-phase2\\Scripts\\python.exe -m ids.training.train replay --bundle {bundle.relative_to(ROOT).as_posix()} --experiment {experiment.relative_to(ROOT).as_posix()}"
    command = (f".\\.venv-phase2\\Scripts\\python.exe -m ids.training.train run "
               f"--experiment {experiment.relative_to(ROOT).as_posix()} --resume")
    write_json(bundle / "handoff.json", dict(package_version="phase3_baseline_v1", trained=True,
        pruning_input_valid=True, deployment_ready=False, independently_validated=False,
        architecture=architecture(selected["variant"]), checkpoint_file="best.pt",
        checkpoint_sha256=selected["checkpoint_sha256"], state_dict_sha256=selected["state_dict_sha256"],
        preprocess_sha256=sha256(bundle / "preprocess.json"), split_manifest_sha256=sha256(bundle / "split_manifest.json"),
        feature_schema_version="device_window_v1", preprocessing_version="log1p_population_zscore_v1",
        development_predictions_sha256=sha256(bundle / "development_predictions.parquet"),
        independent_group_counts=audit["group_counts"], total_independent_source_groups=audit["total_independent_source_groups"],
        independent_heldout_development_groups=0, selected_seed=selected["seed"], selected_epoch=selected["best_epoch"],
        selection_threshold=.5, final_threshold=None, calibration="deferred to registered reserved subset",
        resume_command=command, deterministic_replay_command=replay,
        retraining="prepare a fresh experiment with ids.training.data, then pilot and run; same registered seeds/config",
        limitations=read_json(bundle / "registration.json")["limitations"],
        source_hashes=implementation_hashes(), data_sha256=data_hash))
    write_json(bundle / "checksums.json", {p.name: sha256(p) for p in sorted(bundle.iterdir()) if p.is_file()})
    verify_bundle(bundle)


def verify_bundle(bundle):
    """Reject bare weights, changed preprocessing, split or prediction provenance."""
    bundle = Path(bundle)
    required = {"best.pt", "resume.pt", "architecture.json", "preprocess.json", "feature_schema.json",
                "split_manifest.json", "parent_provenance.json", "registration.json", "audit.json",
                "fit_window_ids.json", "development_predictions.parquet", "handoff.json", "config.json"}
    checksums = read_json(bundle / "checksums.json")
    require(required <= checksums.keys(), "Incomplete pruning package")
    for name, expected in checksums.items():
        require(Path(name).name == name, "Invalid bundle path")
        require(sha256(bundle / name) == expected, f"Bundle checksum mismatch: {name}")
    h, config = read_json(bundle / "handoff.json"), read_json(bundle / "config.json")
    require(h["checkpoint_sha256"] == sha256(bundle / "best.pt"), "Wrong checkpoint")
    require(config["preprocess_sha256"] == h["preprocess_sha256"] == sha256(bundle / "preprocess.json"), "Wrong preprocessing")
    require(config["split_manifest_sha256"] == h["split_manifest_sha256"] == sha256(bundle / "split_manifest.json"), "Wrong split")
    require(read_json(bundle / "preprocess.json")["split_manifest_sha256"] == digest(read_json(bundle / "split_manifest.json")), "Preprocessor split binding failed")
    state = torch.load(bundle / "best.pt", map_location="cpu", weights_only=True)
    require(state["config"] == config and weight_hash(state["model_state"]) == h["state_dict_sha256"], "Checkpoint provenance mismatch")
    require(config["architecture"] == read_json(bundle / "architecture.json"), "Architecture mismatch")
    return h


def replay(bundle, experiment):
    h = verify_bundle(bundle)
    data, data_hash = load_training_data(experiment)
    require(data_hash == h["data_sha256"], "Replay data mismatch")
    require(implementation_hashes() == h["source_hashes"], "Replay implementation drift")
    state = torch.load(Path(bundle) / "best.pt", map_location="cpu", weights_only=True)
    config = state["config"]
    determinism(config["seed"])
    model = make_model(config["variant"])
    model.load_state_dict(state["model_state"])
    _, logits, scores = evaluate(model, *tensors(data)["development"], config["variant"])
    saved = pq.read_table(Path(bundle) / "development_predictions.parquet").to_pylist()
    require([r["sample_id"] for r in saved] == [r["sample_id"] for r in data["development"]["rows"]], "Prediction alignment mismatch")
    np.testing.assert_array_equal(logits, [r["logit"] for r in saved])
    np.testing.assert_array_equal(scores, [r["score"] for r in saved])
    print(json.dumps(dict(passed=True, exact_logit_and_score_replay=True, samples=len(saved),
                         checkpoint_sha256=h["checkpoint_sha256"])), flush=True)


def run(experiment, *, resume=False, seeds=None):
    experiment = Path(experiment).resolve()
    data, data_hash = load_training_data(experiment)
    measured = read_json(experiment / "pilot/pilot.json")
    require(measured["data_sha256"] == data_hash and measured["source_hashes"] == implementation_hashes(),
            "A matching CPU pilot is required before large runs")
    seeds = SEEDS if seeds is None else seeds
    require(seeds and len(set(seeds)) == len(seeds) and set(seeds) <= set(SEEDS), "Use registered distinct seeds")
    results = []
    for variant in VARIANTS:
        for seed in seeds:
            results.append(run_one(experiment, data, data_hash, variant, seed, resume=resume))
    package(experiment, results, data_hash)
    print(json.dumps(dict(complete=True, runs=len(results), seeds=seeds,
                         package=str(experiment / "baseline_package"))), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("pilot", "run", "replay"):
        p = commands.add_parser(name)
        p.add_argument("--experiment", type=Path, required=True)
        if name == "run":
            p.add_argument("--resume", action="store_true")
            p.add_argument("--seeds", type=int, nargs="+")
        elif name == "replay":
            p.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "pilot":
        pilot(args.experiment)
    elif args.command == "run":
        run(args.experiment, resume=args.resume, seeds=args.seeds)
    else:
        replay(args.bundle, args.experiment)


if __name__ == "__main__":
    main()
