"""Compare eager and deployed decisions, validation quality and measured costs."""

import csv
from decimal import Decimal
import math
import time

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import torch

from ids.compaction.run import quality_gate
from ids.run_logging import write_json
from ids.training.data import require
from ids.training.metrics import development_metrics

FLOAT_ATOL = 1e-4
INT8_CAP = .05
TOLERANCE_STEP = .001
WARMUP, ITERATIONS, REPEATS = 100, 1000, 3


def predict(call, inputs):
    # A runner may recycle its output storage. Materialize each scalar immediately.
    logits = np.array([call(x.unsqueeze(0)).item() for x in inputs], dtype=np.float32)
    require(np.isfinite(logits).all(), "Nonfinite reference or runner logit")
    return logits


def scores(logits):
    return torch.sigmoid(torch.from_numpy(logits).double()).numpy()


def tolerance_registration(eager, runtime):
    delta = np.abs(scores(runtime) - scores(eager))
    maximum = float(delta.max())
    limit = min(INT8_CAP, max(1, math.ceil(maximum / TOLERANCE_STEP)) / 1000)
    return dict(score_atol=limit, prefix_max_abs_error=maximum, prefix_count=len(delta),
                prefix_p95_abs_error=float(np.percentile(delta, 95)), ceiling=INT8_CAP,
                grid=TOLERANCE_STEP, registered_unix_ns=time.time_ns())


def differences(reference, actual):
    delta = np.abs(scores(actual) - scores(reference))
    crossings = int(np.count_nonzero((scores(actual) >= .5) != (scores(reference) >= .5)))
    return dict(count=len(delta), max_logit_error=float(np.abs(actual.astype(np.float64) - reference).max()),
                max_score_error=float(delta.max()), mean_score_error=float(delta.mean()),
                p95_score_error=float(np.percentile(delta, 95)), threshold_crossings=crossings,
                threshold_agreement=(len(delta) - crossings) / len(delta))


def investigate(index, entry, values, calls, tensor, precision):
    replay = {stage: float(call(tensor.unsqueeze(0)).item()) for stage, call in calls.items()}
    require(all(replay[k] == float(v[index]) for k, v in values.items()),
            "Threshold disagreement failed batch-one replay")
    s = {k: float(scores(np.array([logit], dtype=np.float32))[0]) for k, logit in replay.items()}
    decisions = {k: int(score >= .5) for k, score in s.items()}
    causes = []
    if decisions["eager"] != decisions["exported"]:
        causes.append("Decision first changes in the converted PT2E graph." if precision == "int8" else
                      "Decision changes in the exported ATen float graph.")
    if decisions["exported"] != decisions["runtime"]:
        causes.append("XNNPACK lowering/execution changes the exported graph decision.")
    if "float_runtime" in decisions and decisions["float_runtime"] != decisions["eager"]:
        causes.append("The float32 runner also differs from eager at this threshold.")
    return dict(**entry, threshold=.5, logits=replay, scores=s, decisions=decisions,
                signed_score_margins={k: v - .5 for k, v in s.items()}, stage_evidence=causes,
                runtime_correct=(decisions["runtime"] == entry["label"] if entry["label"] is not None else None),
                replay_exact=True)


def assess(folder, precision, calls, inputs, entries, dev_rows, split, limit, eager, float_runtime=None):
    values = dict(eager=eager, exported=predict(calls["exported"], inputs),
                  runtime=predict(calls["runtime"], inputs))
    if float_runtime is not None:
        values["float_runtime"] = float_runtime
    probabilities = {k: scores(v) for k, v in values.items()}
    decisions = np.stack([s >= .5 for s in probabilities.values()])
    changed = np.flatnonzero(np.any(decisions != decisions[0], axis=0))
    crossings = [investigate(i, entries[i], values, calls, inputs[i], precision) for i in changed]
    write_json(folder / "threshold_crossings.json", crossings)
    table = pa.Table.from_pylist(entries)
    for stage, logits in values.items():
        table = table.append_column(stage + "_logit", pa.array(logits))
        table = table.append_column(stage + "_score", pa.array(probabilities[stage]))
    pq.write_table(table, folder / "references.parquet", compression="zstd")
    n = len(dev_rows)
    runtime = values["runtime"]
    development = differences(eager[:n], runtime[:n])
    all_refs = differences(eager, runtime)
    report = dict(precision=precision, score_atol=limit, development=development, all_references=all_refs,
                  fixtures=differences(eager[n:], runtime[n:]), comparisons={
                      "eager_to_exported": differences(eager, values["exported"]),
                      "exported_to_runtime": differences(values["exported"], runtime)},
                  metrics={k: development_metrics(dev_rows, s[:n]) for k, s in probabilities.items()},
                  reviewed_crossings=len(crossings), numerical_pass=all_refs["max_score_error"] <= limit)
    if precision == "int8":
        report["comparisons"]["float_runtime_to_int8"] = differences(float_runtime[:n], runtime[:n])
        report["tolerance_check"] = {k: differences(eager[idx], runtime[idx])
                                     for k, idx in split.items() if k in ("fit", "check", "guard") and idx}
    write_json(folder / "comparison.json", report)
    return report, runtime


def benchmark(output, runners, dev):
    inputs = [(x.unsqueeze(0),) for x in dev]
    names = list(runners)
    repeats = {k: [] for k in names}
    orders = []
    with (output / "timing_samples.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["candidate/precision", "repeat", "iteration", "development_tensor_index", "elapsed_ns"])
        for rep in range(REPEATS):
            shift = (rep * max(1, len(names) // REPEATS)) % len(names)
            order = names[shift:] + names[:shift]
            if rep % 2:
                order.reverse()
            orders.append(order)
            for name in order:
                execute = runners[name].method.execute
                for i in range(WARMUP):
                    execute(inputs[i % len(inputs)])
                times = []
                for i in range(ITERATIONS):
                    idx = i % len(inputs)
                    args = inputs[idx]
                    start = time.perf_counter_ns()
                    execute(args)
                    times.append(time.perf_counter_ns() - start)
                writer.writerows((name, rep, i, i % len(inputs), v) for i, v in enumerate(times))
                repeats[name].append(dict(p50_ns=float(np.median(times)), p95_ns=float(np.percentile(times, 95)),
                                          mean_ns=float(np.mean(times))))
    costs = {k: dict(load_method_program_ns=runners[k].load_ns, repeats=v,
                     p50_ns=float(np.median([r["p50_ns"] for r in v])),
                     p95_ns=float(np.median([r["p95_ns"] for r in v]))) for k, v in repeats.items()}
    write_json(output / "benchmark_summary.json", dict(costs=costs, repeat_order=orders, batch=1, warmup=WARMUP,
        timed_per_repeat=ITERATIONS, repeats=REPEATS, clock="perf_counter_ns",
        scope="Python Method.execute on preprocessed development tensors, unmonitored; program/method load separate"))
    return costs


def ptq_decision(report, parent, baseline, calibration, delegation, fp_bytes, fp_cost, q_cost, eligible):
    metrics = report["metrics"]["runtime"]
    losses = {}
    within_parent = True
    for metric in ("recall", "macro_f1"):
        a, b = parent[metric], metrics[metric]
        defined = a is not None and b is not None and math.isfinite(a) and math.isfinite(b)
        losses[metric] = a - b if defined else None
        within_parent &= defined and Decimal(str(a)) - Decimal(str(b)) <= Decimal("0.01")
    baseline_gate = quality_gate(metrics, baseline)
    size_ratio = delegation["pte_bytes"] / fp_bytes
    p50_ratio, p95_ratio = (q_cost[k] / fp_cost[k] for k in ("p50_ns", "p95_ns"))
    value = (size_ratio < 1 and max(p50_ratio, p95_ratio) <= 1.05 or
             size_ratio <= 1 and max(p50_ratio, p95_ratio) <= .95)
    checks = dict(phase5_quality_eligible=eligible, calibration_coverage=calibration["representative"],
                  quantized_affines=delegation["int8_affine_ops"] == 3, numerical=report["numerical_pass"],
                  float_parent_quality=within_parent, unpruned_quality=baseline_gate["accepted"], measured_value=value)
    return dict(accepted=all(checks.values()), checks=checks, failure_reasons=[k for k, ok in checks.items() if not ok],
                parent_losses=losses, baseline_gate=baseline_gate, pte_size_ratio=size_ratio,
                measured_p50_ratio=p50_ratio, measured_p95_ratio=p95_ratio)
