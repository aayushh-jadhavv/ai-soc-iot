"""Human-readable evidence for the same measurements stored per exported program."""

from ids.training.data import read_json


def write_report(output, validation, models, calibration, handoff):
    selected = handoff["architecture"]
    summary = models[selected]
    reasons = ", ".join(summary["int8_decision"]["failure_reasons"]) or "all checks passed"
    lines = ["# Phase 6 export and validation", "",
        f"The Phase 5 selection **{selected}** carries forward as **{handoff['precision']}**. "
        f"Its INT8 decision records {reasons}. The program and checksum are in [the handoff](handoff.json).", "",
        f"All {len(models)} frozen checkpoints used the fixed batch-one input and their original weights. "
        f"The {validation['sample_count']} development histories contain "
        f"{validation['class_counts']['1']} attack example(s) across {validation['source_groups']} source group(s). "
        f"Independent held-out development groups total {validation['independent_heldout_groups']}. "
        "The comparisons use the Phase 5 score rule, float64 sigmoid of the float32 logit with a positive decision at 0.5 or above.",
        "", "## Export sizes, warm runtime and development agreement", "",
        "| Checkpoint | Precision | PTE bytes | p50 µs | p95 µs | Max score error vs eager | Crossings / rows | Recall | Macro-F1 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, row in models.items():
        for kind in ("float32", "int8"):
            item = row[kind]
            if "failure" in item:
                lines.append(f"| {name} | {kind} backend failure | — | — | — | — | — | — | — |")
                continue
            d, m = item["development"], item["metrics"]
            lines.append(f"| {name} | {kind} | {item['pte_bytes']:,} | {item['p50_ns']/1000:.3f} "
                f"| {item['p95_ns']/1000:.3f} | {d['max_score_error']:.7g} | {d['threshold_crossings']} / {d['count']} "
                f"| {m['recall']:.4f} | {m['macro_f1']:.6f} |")
    lines += ["", "Python timed the loaded ExecuTorch forward method on prebuilt input tuples in the x86-64 Linux VM. "
        "Each of three repeats per artifact used 100 warmups and 1,000 timed calls, cycling through the development inputs. "
        "The table gives the median of the three repeat p50s and p95s. Program/method load times, repeat order and raw "
        "nanoseconds are in [the benchmark](benchmark_summary.json) and [timing samples](timing_samples.csv). "
        "Process resource samples cover export and numerical evaluation. The monitor stopped before timing. "
        "These costs exclude preprocessing and service overhead.", "", "## PTQ calibration and acceptance", "",
        f"The seed-{calibration['seed']} observer sample contains {len(calibration['samples'])} unique training IDs from "
        f"{calibration['population']:,} eligible histories. At most {calibration['max_per_stratum']} were sampled per stratum. "
        f"The benign burst cutoff was {calibration['burst_min_packets']} packets in the final second. "
        "The shuffled observer order and original tensor indices are in [the calibration manifest](calibration.json).", "",
        "| Training stratum | Available | Used by observers |", "| --- | ---: | ---: |"]
    for group, count in sorted(calibration["available"].items()):
        lines.append(f"| {group} | {count} | {calibration['selected_counts'].get(group, 0)} |")
    if "idle" in calibration["absent_required_strata"]:
        lines += ["", f"The training data contains {calibration['benign_histories_with_any_idle_second']} benign histories "
            "with any zero-packet second. Representative idle calibration is unavailable. INT8 results are diagnostic. "
            "The synthetic healthy-idle contract fixture used the frozen training transform and ran only in the reference checks."]
    lines += ["", "The registered score tolerance for each INT8 program uses the earlier third of distinct development end "
        "times. The observed maximum absolute eager/runtime score difference is rounded up on a 0.001 grid, with a "
        "0.001 floor and 0.05 ceiling. Each tolerance was saved before running the remaining INT8 development rows. "
        "Later checks exclude histories sharing a window with the prefix. All rows, including the boundary rows and "
        "the separate idle fixture, also face the registered bound. The float32 limit is 0.0001.", "",
        "| Checkpoint | INT8 tolerance | Later check max | All references max | Recall loss vs float | Macro-F1 loss vs float | INT8 decision |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |"]
    for name, row in models.items():
        q, decision = row["int8"], row["int8_decision"]
        if "failure" in q:
            lines.append(f"| {name} | — | — | — | — | — | backend failure |")
            continue
        checked = read_json(output / name / "int8/comparison.json")["tolerance_check"]["check"]
        losses = decision["parent_losses"]
        reasons = ", ".join(decision["failure_reasons"]) or "accepted"
        lines.append(f"| {name} | {q['score_atol']:.3f} | {checked['max_score_error']:.6g} "
            f"| {q['all_reference_max_score_error']:.6g} | {losses['recall']:.4f} | {losses['macro_f1']:.6f} | {reasons} |")
    lines += ["", "Acceptance requires both recall and macro-F1 losses to be at most 0.01 against the matching float32 "
        "runner and 0.02 against the unpruned float32 runner. Phase 5 quality eligibility carries forward. Measured value "
        "requires a smaller program with p50 and p95 each within 5% of float32, or an equal-size program with both at "
        "least 5% faster. Ratios and each gate outcome appear in [the summary](summary.json).",
        "", "## Operator precision and fallback", ""]
    for kind in ("float32", "int8"):
        signatures, fallbacks = set(), set()
        for name, row in models.items():
            if "failure" in row[kind]:
                continue
            d = read_json(output / name / kind / "delegation.json")
            for delegate in d["delegates"]:
                for op in delegate["serialized_operators"]:
                    if op["op"] in ("XNNConv2d", "XNNFullyConnected"):
                        t = op["tensors"]
                        signatures.add(f"{op['op']} ({t['input1_id']} input, {t['filter_id']} weights, "
                                       f"{t['bias_id']} bias, {t['output_id']} output)")
            fallbacks.update(f"{o['name']}.{o['overload']} ({', '.join(o['tensor_dtypes'])})"
                             for o in d["runtime_fallback_operators"])
        lines += [f"- **{kind}**. " + ". ".join(sorted(signatures)) +
                  ". Portable fallback kernels observed were " + (", ".join(sorted(fallbacks)) or "none") + "."]
    lines += ["", "The exported ATen graph retains the two Conv1d layers. The pinned backend represents their "
        "convolutions internally as XNNConv2d. Each delegation record decodes the actual serialized XNNPACK "
        "operator operands and lists the portable execution-plan calls and tensor dtypes.", "",
        "## Per-family development decisions", "",
        "| Checkpoint | Precision | Family | Rows | Positive decisions | Positive rate |",
        "| --- | --- | --- | ---: | ---: | ---: |"]
    for name, row in models.items():
        for kind in ("float32", "int8"):
            if "failure" in row[kind]:
                continue
            for family, metrics in row[kind]["metrics"]["per_family"].items():
                rate = metrics["detection_rate"]
                lines.append(f"| {name} | {kind} | {family} | {metrics['support']} "
                    f"| {metrics['detected'] if rate is not None else '—'} | {format(rate, '.5f') if rate is not None else '—'} |")
    n_cross = sum(item[k].get("reviewed_crossings", 0) for item in models.values() for k in ("float32", "int8"))
    lines += ["", "The positive rate is the false-positive rate for benign rows and detection recall for attack-family rows. "
        "An em dash indicates zero support. Overall confusion counts, precision, recall, macro-F1, tied-score average "
        "precision and each supported family versus benign are in each program's comparison.json.", "",
        "## Threshold disagreement review", "",
        f"Across the exports, {n_cross} program/input pairs had a decision change between any recorded stages. "
        "For each pair, threshold_crossings.json records the sample ID, binary label when available, signed margins "
        "and decisions from a second batch-one execution. It identifies whether conversion or subsequent backend "
        "execution changed the side of the threshold. Each program's references.parquet joins logits and scores to "
        "shared/reference_tensors.npy by reference_index.", "",
        "Only training and model-selection development outcomes were accessed. The threshold reserve, internal test "
        "and external tests stayed sealed. The single development attack and shared source group limit recall and "
        "generalization claims. The handoff carries the comparison threshold and leaves the deployment threshold unset.", ""]
    (output / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
