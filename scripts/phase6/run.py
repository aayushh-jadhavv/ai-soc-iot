"""Run from the project root with the Phase 0 Linux environment."""

import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import traceback

import numpy as np
import pyarrow.parquet as pq
import torch

from ids.contracts import load_json
from ids.ga.search import implementation_hashes
from ids.run_logging import ResourceMonitor, RunLogger, sha256, write_json
from ids.training.data import ROOT, read_json, require
from ids.training.metrics import development_metrics
from .assessment import (FLOAT_ATOL, INT8_CAP, ITERATIONS, REPEATS, TOLERANCE_STEP, WARMUP,
                         assess, benchmark, predict, ptq_decision, scores, tolerance_registration)
from .inputs import calibration_sample, load_inputs, tolerance_partition
from .report import write_report
from .xnnpack import Runner, configure, lower, quantize


def code_hashes():
    paths = [*sorted(Path(__file__).parent.glob("*.py")), ROOT / "uv.lock",
             ROOT / "pyproject.toml", ROOT / ".python-version"]
    return {**implementation_hashes(), **{p.relative_to(ROOT).as_posix(): sha256(p) for p in paths}}


def references(data, split):
    idle = load_json(ROOT / "contracts/fixtures/positive/idle_sequence.json")
    fixture = data["processor"].transform(idle, model_id=idle["model_id"])
    inputs = torch.cat([torch.from_numpy(data["dev"]), fixture])
    roles = {i: key for key in ("fit", "guard", "check") for i in split[key]}
    entries = [dict(reference_index=i, role="development", tolerance_subset=roles[i],
                    **{k: row[k] for k in ("sample_id", "group_id", "label", "family")})
               for i, row in enumerate(data["rows"])]
    entries.append(dict(reference_index=len(entries), role="synthetic_reference", tolerance_subset=None,
                        sample_id="contract/idle_sequence", group_id=None, label=None, family=None))
    return inputs, entries


def register(output, data, calibration, split):
    reg = dict(version="phase6_v1", registered_unix_ns=time.time_ns(), models=list(data["models"]),
        selected_architecture=data["selected"], input_shape=[1, 16, 8], output_shape=[1, 1],
        weights={k: v["state_dict_sha256"] for k, v in data["bindings"].items()},
        score="float64 sigmoid of float32 logit", comparison_threshold=.5, positive_at_equality=True,
        float_score_atol=FLOAT_ATOL, float_reference="frozen eval-mode eager PyTorch, batch one, CPU",
        ptq="torchao PT2E, static per-tensor activations, symmetric per-channel INT8 weights, XNNPACKQuantizer",
        observer_inputs="only the recorded training indices in calibration.json, in listed order",
        incomplete_calibration="measure diagnostic PTQ with available training strata; retain float32",
        int8_tolerance_rule="maximum absolute runner/eager score difference on the earlier development prefix, "
            "rounded upward to the next grid point (inclusive), at least one grid step and capped",
        int8_grid=TOLERANCE_STEP, int8_cap=INT8_CAP, tolerance_partition=split,
        tolerance_check="later development rows sharing no window with prefix; also check every reference including guard and idle",
        quality_limits=dict(parent_recall_and_macro_f1_loss=.01, unpruned_recall_and_macro_f1_loss=.02),
        runtime_value="smaller PTE with both latency ratios <= 1.05, or no larger PTE with both ratios <= 0.95",
        int8_acceptance="Phase 5 eligibility, all required training strata, three INT8 affines, numerical, "
            "both quality gates and measured value; compare each checkpoint with its own float export",
        float_failure="preserve results and stop before PTQ if any float reference exceeds tolerance",
        benchmark=dict(warmup=WARMUP, iterations=ITERATIONS, repeats=REPEATS, threads=1, batch=1),
        calibration_sha256=sha256(output / "calibration.json"), validation_sha256=sha256(output / "validation_manifest.json"),
        input_hashes=data["access"], code_sha256=code_hashes(),
        contract_idle_sha256=sha256(ROOT / "contracts/fixtures/positive/idle_sequence.json"),
        independent_heldout_groups=data["validation"]["independent_heldout_groups"], deployment_threshold=None)
    write_json(output / "registration.json", reg)


def export_float(output, data, inputs, entries, split, runners, records):
    logits = {}
    for name, model in data["models"].items():
        folder = output / name / "float32"
        folder.mkdir(parents=True)
        delegation = lower(model, inputs[:1], folder)
        runner = Runner(folder / "model.pte")
        runners[name + "/float32"] = runner
        calls = dict(eager=model, exported=torch.export.load(folder / "exported.pt2").module(), runtime=runner)
        eager = predict(model, inputs)
        comparison, deployed = assess(folder, "float32", calls, inputs, entries, data["rows"], split, FLOAT_ATOL, eager)
        logits[name] = (eager, deployed)
        records[name] = dict(float32=dict(delegation=delegation, comparison=comparison),
                             phase5_quality_eligible=data["bindings"][name]["quality_gate"]["accepted"])
    require(all(r["float32"]["comparison"]["numerical_pass"] for r in records.values()),
            "Float32 score tolerance exceeded; see per-model references and threshold investigations")
    return logits


def export_int8(output, data, inputs, entries, split, calibration, runners, records, logits):
    indices = [r["tensor_index"] for r in calibration["samples"]]
    train_sample = torch.from_numpy(data["train"][indices])
    for name, model in data["models"].items():
        folder = output / name / "int8"
        folder.mkdir()
        try:
            converted = quantize(model, inputs[:1], train_sample)
            delegation = lower(converted, inputs[:1], folder)
            runner = Runner(folder / "model.pte")
        except (RuntimeError, NotImplementedError, ValueError) as exc:
            failure = dict(stage="PT2E conversion, XNNPACK lowering or runtime load", error=str(exc),
                           traceback=traceback.format_exc())
            write_json(folder / "failure.json", failure)
            records[name]["int8"] = dict(failure=failure)
            continue
        runners[name + "/int8"] = runner
        eager, fp = logits[name]
        fit = split["fit"]
        reg = tolerance_registration(eager[fit], predict(runner, inputs[fit]))
        reg["development_indices"] = fit
        reg["phase6_registration_sha256"] = sha256(output / "registration.json")
        write_json(folder / "tolerance.json", reg)  # Durable before scoring later development inputs.
        calls = dict(eager=model, exported=torch.export.load(folder / "exported.pt2").module(),
                     runtime=runner, float_runtime=runners[name + "/float32"])
        comparison, _ = assess(folder, "int8", calls, inputs, entries, data["rows"], split,
                               reg["score_atol"], eager, fp)
        require(comparison["tolerance_check"]["fit"]["max_score_error"] == reg["prefix_max_abs_error"],
                "Tolerance derivation failed replay")
        records[name]["int8"] = dict(delegation=delegation, comparison=comparison)


def select(records, costs, calibration, selected):
    baseline = records["unpruned"]["float32"]["comparison"]["metrics"]["runtime"]
    for name, r in records.items():
        fp, q = r["float32"], r["int8"]
        if "failure" in q:
            r["int8_decision"] = dict(accepted=False, failure_reasons=["backend_unavailable"])
        else:
            r["int8_decision"] = ptq_decision(q["comparison"], fp["comparison"]["metrics"]["runtime"],
                baseline, calibration, q["delegation"], fp["delegation"]["pte_bytes"],
                costs[name + "/float32"], costs[name + "/int8"], r["phase5_quality_eligible"])
    choice = "int8" if records[selected]["int8_decision"]["accepted"] else "float32"
    return choice


def run(output, frozen, data_dir, host):
    env = configure()
    data = load_inputs(frozen, data_dir)
    host_record = json.loads(host.read_text(encoding="utf-8-sig"))
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True)
    logger = RunLogger(output, dict(phase=6, source_commit=head.stdout.strip() or None,
        code_hashes=code_hashes(), host=host_record, host_manifest_sha256=sha256(host),
        environment=env, batch=1, seed=1729, reproduction_command="python -m scripts.phase6.run " + shlex.join(sys.argv[1:])))
    try:
        calibration = calibration_sample(data["raw"], data["train_rows"])
        split = tolerance_partition(data["rows"])
        write_json(output / "environment.json", dict(host=host_record, **env))
        write_json(output / "calibration.json", calibration)
        write_json(output / "validation_manifest.json", data["validation"])
        write_json(output / "outcome_access.json", dict(decoded_roles=["train", "development"],
            input_files=data["access"], threshold_reserve_files=[], internal_test_files=[], external_test_files=[]))
        register(output, data, calibration, split)
        shared = output / "shared"
        shared.mkdir()
        for name, path in data["shared"].items():
            shutil.copyfile(path, shared / name)
        inputs, entries = references(data, split)
        np.save(shared / "reference_tensors.npy", inputs.numpy(), allow_pickle=False)
        runners, records = {}, {}
        with torch.no_grad(), torch.autocast("cpu", enabled=False):
            with ResourceMonitor(output):
                logits = export_float(output, data, inputs, entries, split, runners, records)
                logger.event("float32_reference_gate_passed", models=len(records))
                export_int8(output, data, inputs, entries, split, calibration, runners, records, logits)
            costs = benchmark(output, runners, inputs[:len(data["rows"])])
        selected = data["selected"]
        precision = select(records, costs, calibration, selected)
        path = f"{selected}/{precision}/model.pte"
        handoff = dict(architecture=selected, precision=precision, artifact=path, pte_sha256=sha256(output / path),
            state_dict_sha256=data["bindings"][selected]["state_dict_sha256"], final_threshold=None,
            selection_threshold=.5, score_type="uncalibrated_sigmoid", independent_validation=False,
            shared_artifacts={n: sha256(shared / n) for n in data["shared"]},
            int8_decision=records[selected]["int8_decision"])
        write_json(output / "handoff.json", handoff)
        # Keep large graph and per-family details in their own model directories.
        summary = {}
        for name, r in records.items():
            row = dict(phase5_quality_eligible=r["phase5_quality_eligible"], int8_decision=r["int8_decision"])
            for kind in ("float32", "int8"):
                if "failure" in r[kind]:
                    row[kind] = dict(failure=r[kind]["failure"]["error"])
                    continue
                d, c = r[kind]["delegation"], r[kind]["comparison"]
                row[kind] = dict(pte_bytes=d["pte_bytes"], pte_sha256=d["pte_sha256"],
                    int8_affine_ops=d["int8_affine_ops"], fallback=d["runtime_fallback_operators"],
                    metrics=c["metrics"]["runtime"], development=c["development"], reviewed_crossings=c["reviewed_crossings"],
                    score_atol=c["score_atol"], all_reference_max_score_error=c["all_references"]["max_score_error"],
                    p50_ns=costs[name + "/" + kind]["p50_ns"], p95_ns=costs[name + "/" + kind]["p95_ns"])
            summary[name] = row
        write_json(output / "summary.json", summary)
        write_report(output, data["validation"], summary, calibration, handoff)
        held = pq.read_table(output / selected / precision / "references.parquet").to_pylist()
        logger.write_table("predictions", [dict(sample_id=r["sample_id"], group_id=r["group_id"], dataset="UNSW-NB15",
            family=r["family"], label=r["label"], score=r["runtime_score"], status="ok", exclusion_reason=None)
            for r in held if r["role"] == "development"])
        logger.write_table("ga_candidates", [])
        logger.finish("complete", handoff=handoff, registration_sha256=sha256(output / "registration.json"))
        write_json(output / "artifact_checksums.json", {p.relative_to(output).as_posix(): sha256(p)
            for p in sorted(output.rglob("*")) if p.is_file()})
    except Exception as exc:
        logger.finish("failed", error=str(exc))
        raise
    return handoff


def verify(output, frozen, data_dir):
    started = time.perf_counter()
    env = configure()
    reg = read_json(output / "registration.json")
    stored_env = read_json(output / "environment.json")
    for k in ("python", "library_versions", "flatc_sha256", "executorch_xnnpack_binary_sha256"):
        require(env[k] == stored_env[k], f"Replay toolchain changed: {k}")
    require(reg["code_sha256"] == code_hashes() and read_json(output / "run_manifest.json")["status"] == "complete",
            "Experiment source or completion status changed")
    for name, expected in read_json(output / "artifact_checksums.json").items():
        p = (output / name).resolve()
        require(p.is_relative_to(output.resolve()) and sha256(p) == expected, f"Artifact drift: {name}")
    data = load_inputs(frozen, data_dir)
    require(sorted(data["access"].values()) == sorted(reg["input_hashes"].values()), "Source archive drift")
    calibration = read_json(output / "calibration.json")
    require(calibration_sample(data["raw"], data["train_rows"]) == calibration, "Calibration ID drift")
    split = tolerance_partition(data["rows"])
    require(split == reg["tolerance_partition"], "Tolerance partition drift")
    inputs, entries = references(data, split)
    np.testing.assert_array_equal(inputs.numpy(), np.load(output / "shared/reference_tensors.npy", allow_pickle=False))
    summary = read_json(output / "summary.json")
    artifacts = 0
    # Register the quantized_decomposed operators used in serialized PT2E graphs.
    from torchao.quantization.pt2e import quantize_pt2e  # noqa: F401
    with torch.no_grad(), torch.autocast("cpu", enabled=False):
        for name, model in data["models"].items():
            eager = predict(model, inputs)
            for kind in ("float32", "int8"):
                if "failure" in summary[name][kind]:
                    continue
                folder = output / name / kind
                table = pq.read_table(folder / "references.parquet")
                require(table.select(list(entries[0])).to_pylist() == entries, "Reference ID/order drift")
                actual = predict(Runner(folder / "model.pte"), inputs)
                graph = predict(torch.export.load(folder / "exported.pt2").module(), inputs)
                stages = dict(runtime=actual, exported=graph, eager=eager)
                if kind == "float32":
                    fp = actual
                else:
                    stages["float_runtime"] = fp
                    fit = split["fit"]
                    limit = tolerance_registration(eager[fit], actual[fit])
                    require(limit["score_atol"] == summary[name][kind]["score_atol"], "INT8 tolerance drift")
                for stage, values in stages.items():
                    np.testing.assert_array_equal(values, table[stage + "_logit"].to_numpy())
                    np.testing.assert_array_equal(scores(values), table[stage + "_score"].to_numpy())
                decisions = np.array([scores(v) >= .5 for v in stages.values()])
                changes = np.flatnonzero(np.any(decisions != decisions[0], axis=0)).tolist()
                require(changes == [r["reference_index"] for r in read_json(folder / "threshold_crossings.json")],
                        "Threshold disagreement ledger incomplete")
                metrics = development_metrics(data["rows"], scores(actual)[:len(data["rows"])])
                require(metrics == summary[name][kind]["metrics"], "Per-family or overall metric drift")
                artifacts += 1
    result = dict(passed=True, replayed_models=artifacts, references_per_model=len(inputs),
                  calibration_ids_reproduced=True, all_logits_scores_decisions_metrics_exact=True,
                  input_and_output_hashes_verified=True, seconds=time.perf_counter() - started)
    write_json(output / "verification.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "verify"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--frozen", type=Path, default=Path("experiments/phase5/run-001"))
    parser.add_argument("--data", type=Path, default=Path("experiments/phase3/run-002/data"))
    parser.add_argument("--host-manifest", type=Path, default=Path("experiments/phase0/host.json"))
    args = parser.parse_args()
    if args.action == "run":
        result = run(args.output, args.frozen, args.data, args.host_manifest)
    else:
        result = verify(args.output, args.frozen, args.data)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
