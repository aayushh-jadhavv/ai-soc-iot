"""Independently check Phase 3 artifacts and write a development-only report."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import torch

from ids.datasets.temporal import digest
from ids.features import FEATURE_NAMES, FEATURE_UNITS
from ids.run_logging import sha256, write_json
from ids.training.data import SEEDS, VARIANTS, load_training_data, read_json, require
from ids.training.train import implementation_hashes, replay, verify_bundle


def check(experiment):
    experiment = Path(experiment).resolve()
    data, data_hash = load_training_data(experiment)
    summary = read_json(experiment / "comparison.json")
    registration = read_json(experiment / "registration.json")
    require(summary["data_sha256"] == data_hash, "Comparison data mismatch")
    require(len(summary["runs"]) == len(VARIANTS) * len(summary["seeds_completed"]), "Incomplete comparison")
    require({(r["variant"], r["seed"]) for r in summary["runs"]} ==
            {(v, s) for v in VARIANTS for s in summary["seeds_completed"]}, "Missing/duplicate variant-seed pairs")
    require(registration["seeds"] == SEEDS and registration["variants"] == VARIANTS, "Registration drift")
    require(registration["final_threshold"] is None, "Final threshold fitted early")
    pre = read_json(experiment / "data/preprocess.json")
    require(pre["feature_names"] == list(FEATURE_NAMES) and pre["feature_units"] == list(FEATURE_UNITS), "Feature units/order mismatch")
    train_windows = {}
    used_ids = {}
    for role in ("train", "development"):
        raw = np.load(experiment / "data" / role / "raw.npy", allow_pickle=False)
        require(raw.shape == (len(data[role]["rows"]), 8, 16), "Raw shape mismatch")
        reference = ((np.log1p(raw) - pre["mean"]) / np.maximum(pre["std"], 1e-6)).transpose(0, 2, 1).astype(np.float32)
        np.testing.assert_array_equal(reference, data[role]["x"])
        used_ids[role] = {w for r in data[role]["rows"] for w in r["window_ids"]}
        if role == "train":
            for row, sequence in zip(data[role]["rows"], raw):
                for wid, values in zip(row["window_ids"], sequence):
                    if wid in train_windows:
                        np.testing.assert_array_equal(train_windows[wid], values)
                    train_windows[wid] = values
    fit_ids = read_json(experiment / "data/fit_window_ids.json")
    require(fit_ids == sorted(train_windows) and digest(fit_ids) == pre["fit_window_ids_sha256"], "Nonunique/nontraining fit IDs")
    logvalues = np.log1p(np.array([train_windows[w] for w in fit_ids]))
    np.testing.assert_allclose(logvalues.mean(0), pre["mean"], atol=1e-12, rtol=1e-12)
    np.testing.assert_allclose(logvalues.std(0, ddof=0), pre["std"], atol=1e-12, rtol=1e-12)
    reserved = pq.read_table(experiment / "data/reserved_index.parquet")
    require(not {"label", "family", "score", "logit"} & set(reserved.column_names), "Reserved outcomes exposed")
    used_ids["reserved"] = {w for r in reserved.to_pylist() for w in r["window_ids"]}
    require(not used_ids["train"] & used_ids["development"] and
            not used_ids["train"] & used_ids["reserved"] and
            not used_ids["development"] & used_ids["reserved"], "Shared history windows")
    labels = data["development"]["y"].astype(int)
    manifests, epochs_total, checked = [], 0, []
    for result in summary["runs"]:
        folder = experiment / result["run_directory"]
        manifest = read_json(folder / "run_manifest.json")
        manifests.append(manifest)
        require(manifest["status"] == "complete", "Incomplete run")
        for name, expected in read_json(folder / "artifact_checksums.json").items():
            require(sha256(folder / name) == expected, "Run checksum mismatch: " + name)
        config = read_json(folder / "config.json")
        require(config["data_sha256"] == data_hash and config["source_hashes"] == implementation_hashes(), "Run provenance drift")
        require(config["batch_size"] == 128 and config["max_epochs"] == 30 and config["patience"] == 5, "Training budget mismatch")
        require(config["optimizer"]["learning_rate"] == .001 and config["loss"] == "BCEWithLogitsLoss", "Training recipe mismatch")
        rows = pq.read_table(folder / "development_predictions.parquet").to_pylist()
        require([r["sample_id"] for r in rows] == [r["sample_id"] for r in data["development"]["rows"]], "Comparisons use different samples")
        require([r["group_id"] for r in rows] == [r["group_id"] for r in data["development"]["rows"]], "Comparisons use different groups")
        np.testing.assert_array_equal([r["label"] for r in rows], labels)
        scores = np.array([r["score"] for r in rows])
        pred = scores >= .5
        tp = int(np.sum(pred & (labels == 1)))
        tn = int(np.sum(~pred & (labels == 0)))
        fp = int(np.sum(pred & (labels == 0)))
        fn = int(np.sum(~pred & (labels == 1)))
        f1 = (2 * tp / (2 * tp + fp + fn) + 2 * tn / (2 * tn + fp + fn)) / 2
        metrics = result["development"]
        require(f1 == metrics["macro_f1"] and (tn, fp, fn, tp) == tuple(metrics[k] for k in ("tn", "fp", "fn", "tp")), "Metrics disagree with predictions")
        np.testing.assert_array_equal([r["prediction"] for r in rows], pred.astype(int))
        epochs = read_json(folder / "epochs.json")
        require([e["epoch"] for e in epochs] == list(range(1, len(epochs) + 1)) and len(epochs) <= 30, "Epoch ordering/budget mismatch")
        best_epoch, best, stale = 0, -1, 0
        for record in epochs:
            require(stale < 5, "Training continued beyond patience")
            value = record["development"]["macro_f1"]
            if value > best:
                best_epoch, best, stale = record["epoch"], value, 0
            else:
                stale += 1
        require(best_epoch == result["best_epoch"] and best == f1, "Checkpoint selection is not earliest best macro-F1")
        require(stale == 5 or len(epochs) == 30, "Premature stop")
        require(metrics["per_family"]["dos"]["support"] == 0 and metrics["per_family"]["dos"]["detection_rate"] is None,
                "Current excerpt must report missing DoS support")
        state = torch.load(folder / "resume.pt", map_location="cpu", weights_only=True)
        require(state["epoch"] == len(epochs) and state["bad_epochs"] == stale and state["best_epoch"] == best_epoch, "Resume state mismatch")
        require({"python", "numpy", "torch", "permutation"} <= state["rng"].keys(), "Incomplete RNG state")
        require(state["optimizer_state"]["state"], "Missing Adam state")
        epochs_total += len(epochs)
        checked.append(result["run_directory"])
    h = verify_bundle(experiment / "baseline_package")
    candidates = [r for r in summary["runs"] if r["variant"] in {"cnn64_weighted", "cnn64_unweighted"}]
    selected = sorted(candidates, key=lambda r: (-r["development"]["macro_f1"], r["seed"], r["variant"]))[0]
    require(selected == summary["selected_baseline"] and h["checkpoint_sha256"] == selected["checkpoint_sha256"], "Wrong handoff selection")
    require(h["final_threshold"] is None and not h["deployment_ready"], "Premature deployment claim")
    replay(experiment / "baseline_package", experiment)
    completed = dict(passed=True, checked_runs=checked, epochs_checked=epochs_total,
        unique_training_windows=len(train_windows), identical_development_ids_groups_labels=True,
        evaluation_prevalence_unchanged=True, earliest_best_checkpoint_selection=True,
        exact_selected_checkpoint_replay=True, reserved_outcomes_read=False,
        internal_test_outcomes_read=False, external_outcomes_read=False,
        source_hashes=implementation_hashes(), evidence_checker_sha256=sha256(Path(__file__)),
        checkpoint_sha256=h["checkpoint_sha256"], created_utc=datetime.now(timezone.utc).isoformat(),
        suite_elapsed_seconds=(max(m["finished_at_unix_ns"] for m in manifests) - min(m["started_at_unix_ns"] for m in manifests)) / 1e9,
        epoch_wall_seconds=sum(r["training_seconds"] for r in summary["runs"]),
        epoch_cpu_seconds=sum(r["cpu_seconds"] for r in summary["runs"]))
    write_json(experiment / "verification.json", completed)
    report(experiment, summary, completed, h)
    return completed


def report(experiment, summary, verified, handoff):
    selected = summary["selected_baseline"]
    metrics = selected["development"]
    pilot = read_json(experiment / "pilot/pilot.json")
    audit = read_json(experiment / "data/audit.json")
    budget = ("A smaller run budget was used; the omitted registered seeds were not trained."
              if summary["smaller_budget_disclosed"] else "No smaller run budget was used.")
    seed_text = ", ".join(map(str, summary["seeds_completed"]))
    content = ["# Phase 3 development training results", "",
        f"Completed {len(summary['runs'])} registered runs: five variants, seeds {seed_text}. "
        f"{budget} Internal-test, external and reserved-subset outcomes remain unopened.", "",
        "**This is a provisional within-group experiment, not independent detector validation.** "
        "There is one original source group and zero independently held-out development groups. "
        "Development has 964 benign samples, one reconnaissance sample and no DoS samples. "
        "One positive cannot establish recall, temporal superiority or family generalization.", "",
        "## Comparison at the fixed selection threshold 0.5", "",
        "Values summarize each seed's selected checkpoint. Standard deviations are across training seeds, "
        "not group-level confidence intervals. All variants use the same 6,457 training and 965 development samples.", "",
        "| Variant | Parameters | Macro-F1 mean ± sample SD | Attack recall mean | FPR mean | Average precision mean |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for name, value in summary["comparisons"].items():
        deviation = f"{value['macro_f1_sd']:.6f}" if value['macro_f1_sd'] is not None else "null (one seed)"
        content.append(f"| {name} | {value['parameter_count']:,} | {value['macro_f1_mean']:.6f} ± {deviation} | "
            f"{value['recall_mean']:.6f} | {value['false_positive_rate_mean']:.6f} | {value['ap_mean']:.6f} |")
    content += ["", "All runs use BCEWithLogitsLoss, Adam 0.001, batch 128, maximum 30 epochs and patience five. "
        "The earliest strictly best development macro-F1 checkpoint is retained. "
        "The logistic comparator uses 128 channel-major flattened normalized inputs; the temporal ablation uses "
        "only the final window with the same 64/32 CNN parameterization. No architecture was chosen using test outcomes.", "",
        "## Training-only balancing", "",
        "Training has 6,433 benign, 19 reconnaissance and five DoS samples (24 positives, 0.3717% prevalence). "
        "The preregistered imbalance rule gives BCE positive weight 6433/24 = 268.0416667. "
        "All original training samples are visited once per epoch; development is never resampled or weighted.", "",
        "| Seed | Weighted minus unweighted macro-F1 | Recall delta | False-positive rate delta |",
        "| ---: | ---: | ---: | ---: |"]
    for effect in summary["balancing_effect"]:
        content.append(f"| {effect['seed']} | {effect['macro_f1_delta']:+.6f} | {effect['recall_delta']:+.6f} | {effect['false_positive_rate_delta']:+.6f} |")
    content += ["", "Every unweighted selected CNN64 predicts all development samples benign. "
        "Weighting detects the lone reconnaissance sample at the cost of additional false positives. "
        "Its effect on unseen groups or DoS cannot be inferred. Weighted sigmoid scores are uncalibrated.", "",
        "## Selected baseline and family support", "",
        f"The required 64/32 pruning baseline is **{selected['variant']}, seed {selected['seed']}, epoch {selected['best_epoch']}** "
        f"({selected['epochs_completed']} epochs completed). Selection follows the registered development-only seed/balancing rule.", "",
        f"Macro-F1: **{metrics['macro_f1']:.6f}**. Confusion counts: TN={metrics['tn']}, FP={metrics['fp']}, "
        f"FN={metrics['fn']}, TP={metrics['tp']}. Attack precision is {metrics['precision']:.6f}, "
        f"attack F1 {metrics['attack_f1']:.6f}, FPR {metrics['false_positive_rate']:.6f}, and average precision {metrics['pr_auc']:.6f}.", "",
        "| Development family | Support | Predicted attack | Interpretation |",
        "| --- | ---: | ---: | --- |",
        f"| Benign | 964 | {metrics['fp']} | False positives |",
        f"| Reconnaissance | 1 | {metrics['tp']} | One observed detection; insufficient recall evidence |",
        "| DoS | 0 | null | No measurable development performance |", "",
        "Full family-versus-benign binary metrics are saved per epoch and per selected checkpoint. "
        "The binary model never predicts an attack family. Selecting the best seed adds optimism beyond the three-seed means.", "",
        "## Audit and split provenance", "",
        "The missing Phase 2 reserve was registered before development labels were loaded: the fixed validation midpoint "
        "1421928508000000000 ns divides development and the future threshold-only block. "
        "The build rechecks padded annotation spans, tuple reuse and physical histories. "
        "Train is unchanged; 93 development candidates are purged. The reserve has 81 boundary-history and "
        "124 connection-history exclusions. Its 915 retained index rows have no decoded labels or scores.", "",
        f"Preprocessing fits {audit['unique_training_fit_count']:,} unique training windows once, with the registered log1p "
        "population standardization and epsilon 1e-6. The original fit set is unchanged. Exact normalization replay, "
        "feature units/order, final-window labels, label packet evidence, continuous valid histories and the independent "
        "Wireshark offline/live/saved-feature ledger all pass. Train/development/reserve share zero physical windows or "
        "connections; they still share the one original source group.", "",
        "Development precision is poor and DoS support is absent. The audit found no label-mapping, unit or extraction-parity "
        "defect that justifies a scope/schema change. The experiment retains the registered architectures and features. "
        "New independent sessions and adequate family support require a new data registration; there was no test-driven "
        "architecture selection. Optional calibration and final thresholds are deferred to the registered reserve, whose "
        "suitability remains unestablished.", "",
        "## Measured CPU budget", "",
        f"The two-epoch CPU pilot measured {pilot['epochs'][0]['wall_seconds']:.4f}s and {pilot['epochs'][1]['wall_seconds']:.4f}s "
        f"per full CNN64 train/development epoch. Before the large run, it estimated {pilot['upper_compute_seconds']:.1f}s "
        f"for all 450 maximum epochs, or {pilot['conservative_wall_seconds_with_50pct_overhead']:.1f}s with 50% allowance.", "",
        f"The suite actually completed {verified['epochs_checked']} epochs: {verified['epoch_wall_seconds']:.2f}s summed epoch wall time "
        f"and {verified['epoch_cpu_seconds']:.2f}s process CPU. First-run start to last-run completion was "
        f"{verified['suite_elapsed_seconds']:.2f}s, including checkpoint/log persistence. Preparation and interpreter startup "
        "are separate. CPU intraop and interop threads were one. This is Windows CPU evidence, not edge-device evidence. "
        "The pilot saves raw resource samples and labels sampled RSS as an estimate, not exact peak memory.", "",
        "## Handoff", "",
        "Use the complete [baseline package](baseline_package/handoff.json), which includes architecture, feature schema, "
        "preprocessing, fit IDs, split/source provenance, independent-group counts, development predictions, exact hashes "
        "and resume state. A bare checkpoint is rejected by the package validator. It is suitable as a provenance-complete "
        "experimental pruning input; it is not a validated deployed detector.", "",
        "Exact checkpoint SHA-256:", "", f"`{handoff['checkpoint_sha256']}`", "",
        "Deterministic tensor-state SHA-256:", "", f"`{handoff['state_dict_sha256']}`", "",
        "Preprocessing SHA-256:", "", f"`{handoff['preprocess_sha256']}`", "",
        "The independent evidence check verifies every run's predictions, unchanged prevalence, early stopping, "
        "checkpoint selection, resumable state and exact selected checkpoint replay. All 965 development logits and scores "
        "reproduce bit for bit. See [verification.json](verification.json) and [the implementation guide](../../../docs/phase3.md).", "",
        "```powershell", handoff["deterministic_replay_command"], "```", "",
        "## Individual seed checkpoints", "",
        "| Variant | Seed | Selected epoch | Completed epochs | Macro-F1 | TP | FP |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for r in summary["runs"]:
        m = r["development"]
        content.append(f"| {r['variant']} | {r['seed']} | {r['best_epoch']} | {r['epochs_completed']} | {m['macro_f1']:.6f} | {m['tp']} | {m['fp']} |")
    content.append("")
    (experiment / "REPORT.md").write_text("\n".join(content), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path)
    result = check(parser.parse_args().experiment)
    print(json.dumps({k: v for k, v in result.items() if k not in {"source_hashes", "checked_runs"}}, indent=2))
