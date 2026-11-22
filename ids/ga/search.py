"""Bounded, resumable Phase 4 search. Run with python -m ids.ga.search."""

import argparse
import copy
import csv
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import time

import numpy as np
import psutil
import pyarrow
import torch

from ids.datasets.temporal import digest
from ids.ga.data import BUNDLE_FILES, load_inputs
from ids.ga.masks import (ALL_ONES, Mask, crossover, initial_population, masked_forward,
                          mutate_and_repair, retention_cost, roulette)
from ids.run_logging import environment, sha256, write_json
from ids.training.data import ROOT, read_json, require
from ids.training.metrics import development_metrics
from ids.training.train import determinism, weight_hash


@dataclass(frozen=True)
class SearchConfig:
    seed: int = 1729
    max_generations: int = 15
    population: int = 20
    elites: int = 2
    crossover_probability: float = .6
    per_bit_mutation: float = .05
    minimum_channels: int = 4
    initial_bit_probability: float = .5
    patience: int = 5
    min_delta: float = 1e-6
    top_k: int = 3

    def __post_init__(self):
        require(type(self.seed) is int and 0 <= self.seed < 2**32, "Seed must be a uint32")
        require(type(self.max_generations) is int and 0 <= self.max_generations <= 15,
                "At most 15 replacement generations are allowed")
        fixed = dict(population=20, elites=2, crossover_probability=.6, per_bit_mutation=.05,
                     minimum_channels=4, initial_bit_probability=.5, patience=5, min_delta=1e-6, top_k=3)
        require(all(getattr(self, key) == value for key, value in fixed.items()),
                "Phase 4 uses the registered search constants")


FITNESS = dict(sparsity_weight=.1, macro_f1_weight=.9, threshold=.5,
    labels=[0, 1], prediction_rule="float64 sigmoid(float32 logit) >= 0.5",
    sparsity="1 - (retained_conv1 + retained_conv2) / 96",
    masking="post-ReLU hidden outputs, including biases; input/output unchanged",
    evaluation="frozen CPU float32 model, inference_mode, original order, no training",
    batch_size=1024, nonfinite="invalid, zero selection weight, ineligible for elites",
    zero_weight_fallback="uniform sampling among valid parents")


def array_hash(array):
    value = np.ascontiguousarray(array)
    h = hashlib.sha256()
    h.update(str(value.dtype).encode())
    h.update(str(value.shape).encode())
    h.update(value.tobytes())
    return h.hexdigest()


def implementation_hashes():
    # Include transitive project dependencies, not just the genetic operators.
    return {p.relative_to(ROOT).as_posix(): sha256(p) for p in sorted((ROOT / "ids").rglob("*.py"))
            if "__pycache__" not in p.parts}


def runtime_fingerprint():
    return dict(python=platform.python_version(), torch=str(torch.__version__), numpy=np.__version__,
        pyarrow=pyarrow.__version__, platform=platform.platform(), machine=platform.machine(),
        processor=platform.processor(), cpu_capability=torch.backends.cpu.get_cpu_capability(),
        torch_build=torch.__config__.show(), device="cpu", tensor_dtype="float32", score_dtype="float64",
        intraop_threads=torch.get_num_threads(), interop_threads=torch.get_num_interop_threads(),
        deterministic_algorithms=torch.are_deterministic_algorithms_enabled(),
        mkldnn_enabled=torch.backends.mkldnn.enabled, mkldnn_deterministic=torch.backends.mkldnn.deterministic,
        fp32_precision=torch.backends.fp32_precision,
        mkldnn_fp32_precision=torch.backends.mkldnn.fp32_precision,
        mkldnn_conv_precision=torch.backends.mkldnn.conv.fp32_precision,
        mkldnn_matmul_precision=torch.backends.mkldnn.matmul.fp32_precision,
        numerical_environment={k: v for k, v in sorted(os.environ.items())
            if k.startswith(("OMP_", "MKL_", "OPENBLAS_", "DNNL_", "ONEDNN_")) or k == "ATEN_CPU_CAPABILITY"})


class FitnessEvaluator:
    def __init__(self, model, x, rows, provenance, *, seed=1729):
        determinism(seed)
        self.model = copy.deepcopy(model).cpu().float().eval().requires_grad_(False)
        require(self.model.conv1.out_channels == 64 and self.model.conv2.out_channels == 32,
                "Fitness requires a 64/32 model")
        self.x = torch.from_numpy(np.array(x, dtype=np.float32, copy=True, order="C"))
        self.rows = copy.deepcopy(rows)
        require(self.x.shape == (len(rows), 16, 8) and bool(torch.isfinite(self.x).all()), "Invalid validation tensor")
        require({r["label"] for r in rows} == {0, 1}, "Fixed validation needs both binary classes")
        self.context = dict(version="phase4_fitness_v1", inputs=copy.deepcopy(provenance),
            state_dict_sha256=weight_hash(self.model.state_dict()), tensor_sha256=array_hash(self.x.numpy()),
            rows_sha256=digest(self.rows), fitness=copy.deepcopy(FITNESS),
            implementation=implementation_hashes(), runtime=runtime_fingerprint())
        self.context_sha256 = digest(self.context)

    @torch.inference_mode()
    def predict(self, mask=None):
        with torch.autocast("cpu", enabled=False):
            logits = torch.cat([self.model(batch) if mask is None else masked_forward(self.model, batch, mask)
                                for batch in self.x.split(self.context["fitness"]["batch_size"])])
            scores = torch.sigmoid(logits.double()).numpy().reshape(-1)
        return logits.numpy().reshape(-1), scores

    def evaluate(self, mask):
        started, cpu = time.perf_counter(), time.process_time()
        logits, scores = self.predict(mask)
        valid = bool(np.isfinite(logits).all() and np.isfinite(scores).all())
        metrics = development_metrics(self.rows, scores) if valid else None
        cost = retention_cost(mask)
        fitness = .1 * cost["channel_sparsity"] + .9 * metrics["macro_f1"] if valid else None
        if fitness is not None and not math.isfinite(fitness):
            valid, metrics, fitness = False, None, None
        result = dict(mask=mask.code, layers=[list(bits) for bits in mask.layers], **cost,
            valid=valid, invalid_reason=None if valid else "nonfinite_output_or_fitness",
            metrics=metrics, fitness=fitness, logits_sha256=array_hash(logits), scores_sha256=array_hash(scores))
        return result, dict(evaluation_seconds=time.perf_counter() - started,
                            evaluation_cpu_seconds=time.process_time() - cpu)

    def parity(self, saved):
        started, cpu = time.perf_counter(), time.process_time()
        original, original_scores = self.predict()
        masked, masked_scores = self.predict(ALL_ONES)
        np.testing.assert_array_equal(original, masked)
        np.testing.assert_array_equal(original_scores, masked_scores)
        np.testing.assert_array_equal(masked, [r["logit"] for r in saved])
        np.testing.assert_array_equal(masked_scores, [r["score"] for r in saved])
        return dict(passed=True, all_ones_exact=True, phase3_prediction_replay_exact=True,
            validation_samples=len(saved), additional_forward_passes=2,
            seconds=time.perf_counter() - started, cpu_seconds=time.process_time() - cpu)


def cache_key(context_sha256, mask):
    return digest(dict(context_sha256=context_sha256, mask=mask.code))


def ranking(record):
    return (not record["valid"], -record["fitness"] if record["valid"] else 0, record["mask"])


def replacement(population, cache, context_sha256, rng):
    records = [cache[cache_key(context_sha256, Mask.decode(code))] for code in population]
    valid = sorted((r for r in records if r["valid"]), key=ranking)
    require(bool(valid), "No valid population remains")
    # A single valid parent can supply both elites. Invalid candidates never breed.
    result = [Mask.decode(valid[i % len(valid)]["mask"]) for i in range(2)]
    weights = [r["fitness"] if r["valid"] else None for r in records]
    while len(result) < 20:
        first, second = [Mask.decode(population[roulette(weights, rng)]) for _ in range(2)]
        for child in crossover(first, second, rng):
            result.append(mutate_and_repair(child, rng))
    return [mask.code for mask in result]


def patience_update(previous_best, current_best, stale):
    # Compare with the previous generation's all-time best, including tiny gains.
    significant = current_best - previous_best >= 1e-6
    return (0 if significant else stale + 1), significant


def tuples(value):
    return tuple(tuples(v) for v in value) if isinstance(value, list) else value


def load_state(output, config, evaluator):
    envelope = read_json(Path(output) / "resume.json")
    state = envelope["state"]
    require(digest(state) == envelope["sha256"], "Resume checkpoint checksum mismatch")
    require(state["config"] == asdict(config) and state["context_sha256"] == evaluator.context_sha256,
            "Resume configuration, data, implementation or runtime drift")
    require(read_json(Path(output) / "config.json") == dict(search=asdict(config), context=evaluator.context),
            "Saved configuration drift")
    for key, record in state["cache"].items():
        require(key == cache_key(evaluator.context_sha256, Mask.decode(record["mask"])), "Invalid cache key")
    return state


def search(evaluator, output, config=SearchConfig(), *, resume=False, stop_after_requests=None, prepare_artifacts=None):
    """Commit after each candidate; an in-flight candidate is replayed on a crash.

    stop_after_requests is an absolute request count for controlled interruption.
    The JSON checkpoint is authoritative; exported tables are regenerated from it.
    """
    output = Path(output)
    rng = random.Random(config.seed)  # The sole RNG used by all search operators.
    if resume:
        state = load_state(output, config, evaluator)
        rng.setstate(tuples(state["rng_state"]))
    else:
        output.mkdir(parents=True, exist_ok=False)
        write_json(output / "config.json", dict(search=asdict(config), context=evaluator.context))
        state = dict(version="phase4_resume_v1", config=asdict(config), context_sha256=evaluator.context_sha256,
            population=[m.code for m in initial_population(rng)], generation=0, next_index=0,
            cache={}, requests=[], history=[], best_key=None, stale_generations=0,
            status="running", stopping_reason=None, search_wall_seconds=0., search_cpu_seconds=0.)
    tick, cpu_tick = time.perf_counter(), time.process_time()

    def commit():
        nonlocal tick, cpu_tick
        now, cpu_now = time.perf_counter(), time.process_time()
        state["search_wall_seconds"] += now - tick
        state["search_cpu_seconds"] += cpu_now - cpu_tick
        tick, cpu_tick = now, cpu_now
        state["rng_state"] = rng.getstate()
        write_json(output / "resume.json", dict(state=state, sha256=digest(state)))

    if not resume:
        commit()
    if prepare_artifacts is not None:
        prepare_artifacts(output)
        # Preparation has its own timing; exclude it from search timing.
        tick, cpu_tick = time.perf_counter(), time.process_time()
    if state["status"] == "complete":
        export_results(output, state, evaluator)
        return state
    process = psutil.Process()
    while True:
        while state["next_index"] < config.population:
            if stop_after_requests is not None and len(state["requests"]) >= stop_after_requests:
                export_results(output, state, evaluator)
                return state
            start = time.perf_counter()
            slot = state["next_index"]
            mask = Mask.decode(state["population"][slot])
            key = cache_key(evaluator.context_sha256, mask)
            hit = key in state["cache"]
            timing = dict(evaluation_seconds=0., evaluation_cpu_seconds=0.)
            if not hit:
                record, timing = evaluator.evaluate(mask)
                require(record["mask"] == mask.code, "Evaluator returned another mask")
                if record["valid"]:
                    require(record["fitness"] is not None and math.isfinite(record["fitness"]) and
                            0 <= record["fitness"] <= 1, "Invalid finite fitness")
                else:
                    require(record["fitness"] is None, "Invalid candidates must not receive fitness")
                state["cache"][key] = dict(record, first_generation=state["generation"], **timing)
            record = state["cache"][key]
            if mask == ALL_ONES:
                require(record["valid"], "The all-ones baseline is invalid; stop before searching")
            state["requests"].append(dict(request=len(state["requests"]), generation=state["generation"],
                slot=slot, cache_key=key, mask=mask.code, cache_hit=hit, valid=record["valid"],
                fitness=record["fitness"], retained_conv1=mask.retained[0], retained_conv2=mask.retained[1],
                **timing, request_seconds=time.perf_counter() - start, rss_bytes=process.memory_info().rss))
            state["next_index"] += 1
            commit()
            if len(state["requests"]) == 1:
                export_results(output, state, evaluator)

        records = [state["cache"][cache_key(evaluator.context_sha256, Mask.decode(code))]
                   for code in state["population"]]
        best = min((r for r in records if r["valid"]), key=ranking)
        old = state["cache"][state["best_key"]] if state["best_key"] else None
        if old is None or ranking(best) < ranking(old):
            state["best_key"] = cache_key(evaluator.context_sha256, Mask.decode(best["mask"]))
        overall = state["cache"][state["best_key"]]
        if old is None:
            significant = True
        else:
            state["stale_generations"], significant = patience_update(
                old["fitness"], overall["fitness"], state["stale_generations"])
        current_requests = state["requests"][-20:]
        state["history"].append(dict(generation=state["generation"], population=list(state["population"]),
            best_key=state["best_key"], best_fitness=overall["fitness"],
            improvement=None if old is None else overall["fitness"] - old["fitness"],
            significant_improvement=significant, stale_generations=state["stale_generations"],
            candidate_requests=20, cache_hits=sum(r["cache_hit"] for r in current_requests),
            evaluation_seconds=sum(r["evaluation_seconds"] for r in current_requests)))
        if state["stale_generations"] >= config.patience:
            state["status"], state["stopping_reason"] = "complete", "patience_5"
        elif state["generation"] >= config.max_generations:
            state["status"], state["stopping_reason"] = "complete", "generation_limit"
        else:
            state["population"] = replacement(state["population"], state["cache"], evaluator.context_sha256, rng)
            state["generation"] += 1
            state["next_index"] = 0
        commit()
        export_results(output, state, evaluator)
        if state["status"] == "complete":
            return state


def pareto_front(records):
    return [r for r in records if not any(
        q["retention"] <= r["retention"] and q["metrics"]["macro_f1"] >= r["metrics"]["macro_f1"] and
        (q["retention"] < r["retention"] or q["metrics"]["macro_f1"] > r["metrics"]["macro_f1"])
        for q in records)]


def export_results(output, state, evaluator):
    output = Path(output)
    valid = sorted((r for r in state["cache"].values() if r["valid"]), key=ranking)
    baseline = state["cache"].get(cache_key(evaluator.context_sha256, ALL_ONES))
    top = [r for r in valid if r["mask"] != ALL_ONES.code][:3]
    requests = state["requests"]
    front = sorted(pareto_front(valid), key=lambda r: (r["retention"], -r["metrics"]["macro_f1"], r["mask"]))
    summary = dict(status=state["status"], stopping_reason=state["stopping_reason"],
        completed_replacement_generations=max(0, len(state["history"]) - 1),
        candidate_requests=len(requests), unique_candidates=len(state["cache"]),
        inference_evaluations=sum(not r["cache_hit"] for r in requests), cache_hits=sum(r["cache_hit"] for r in requests),
        invalid_candidates=sum(not r["valid"] for r in state["cache"].values()),
        maximum_candidate_requests=20 * (state["config"]["max_generations"] + 1),
        maximum_unique_inferences=20 + 18 * state["config"]["max_generations"],
        candidate_evaluation_seconds=sum(r["evaluation_seconds"] for r in requests),
        candidate_cpu_seconds=sum(r["evaluation_cpu_seconds"] for r in requests),
        search_wall_seconds=state["search_wall_seconds"], search_cpu_seconds=state["search_cpu_seconds"],
        sampled_max_rss_bytes=max((r["rss_bytes"] for r in requests), default=None),
        cost_scope="committed search; setup/parity and cache verification separate; final write/export excluded; interrupted in-flight work unmeasured",
        memory_scope="process RSS sampled after each request, not an exact peak",
        baseline=baseline, best=valid[0] if valid else None, top_candidates=top, pareto_candidates=front,
        fitness_context_sha256=evaluator.context_sha256, threshold=.5,
        training_steps=0, final_threshold=None, calibration="not fitted", compact_models_created=0,
        dense_masking_speedup_claimed=False, test_or_external_data_accessed=False)
    write_json(output / "cache.json", dict(context_sha256=evaluator.context_sha256, entries=state["cache"]))
    write_json(output / "generations.json", state["history"])
    write_json(output / "top_candidates.json", dict(baseline=baseline, candidates=top,
        checkpoint_sha256=evaluator.context["inputs"].get("checkpoint_sha256"), context_sha256=evaluator.context_sha256))
    write_json(output / "summary.json", summary)
    if requests:
        with (output / "candidate_requests.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(requests[0]))
            writer.writeheader()
            writer.writerows(requests)
    columns = ["mask", "fitness", "macro_f1", "recall", "false_positive_rate", "retained_conv1", "retained_conv2",
               "channel_sparsity", "potential_compact_parameters", "potential_compact_macs"]
    with (output / "quality_retention.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for record in valid:
            writer.writerow({k: record[k] if k in record else record["metrics"][k] for k in columns})
    if baseline:
        write_json(output / "budget.json", dict(maximum_candidate_requests=summary["maximum_candidate_requests"],
            maximum_unique_inferences=summary["maximum_unique_inferences"],
            measured_baseline_seconds=baseline["evaluation_seconds"],
            estimated_remaining_inference_seconds_with_50pct_allowance=
                baseline["evaluation_seconds"] * (summary["maximum_unique_inferences"] - 1) * 1.5,
            basis="first all-ones evaluation; excludes persistence, setup and verification"))
        report(output, summary, evaluator.context["inputs"].get("validation", {}))


def report(output, summary, validation):
    lines = ["# Phase 4 validation-only genetic search", "",
        f"Status: {summary['status']}; stopping reason: {summary['stopping_reason']}. "
        f"Completed {summary['completed_replacement_generations']} replacement generations.", "",
        "Population 20; two elites; crossover 0.6 in one selected layer; per-bit mutation 0.05; "
        "minimum four channels per layer. Fitness is 0.1 × channel sparsity + 0.9 × binary macro-F1 "
        "at threshold 0.5. Five generations without a gain of at least 1e-6 stop the search.", "",
        f"Candidate requests: **{summary['candidate_requests']}**; unique candidates/inferences: "
        f"**{summary['unique_candidates']}**; cache hits: **{summary['cache_hits']}**; "
        f"invalid candidates: {summary['invalid_candidates']}. The request bound is "
        f"{summary['maximum_candidate_requests']}; the inference bound with cached elites is "
        f"{summary['maximum_unique_inferences']}.", "",
        f"Candidate evaluation wall time: {summary['candidate_evaluation_seconds']:.6f}s; "
        f"process CPU: {summary['candidate_cpu_seconds']:.6f}s. Committed search wall time: "
        f"{summary['search_wall_seconds']:.6f}s; CPU: {summary['search_cpu_seconds']:.6f}s. "
        f"Sampled process RSS maximum: {summary['sampled_max_rss_bytes']} bytes (not exact peak). "
        "Setup/parity and verification are recorded separately. Final persistence/export and lost in-flight "
        "work during a crash are outside the committed search timing.", "",
        "## Quality and retention", "",
        "Top candidates are the best three distinct pruned masks across the entire cache. "
        "The all-ones baseline is always preserved separately. Exact fitness ties use lexical mask order.", "",
        "| Candidate | Kept conv1/conv2 | Retention | Macro-F1 | Recall | FPR | Fitness | Potential parameters | Potential MACs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for label, row in [("Baseline", summary["baseline"])] + [(f"Top {i}", r) for i, r in enumerate(summary["top_candidates"], 1)]:
        m = row["metrics"]
        lines.append(f"| {label} | {row['retained_conv1']}/{row['retained_conv2']} | {row['retention']:.3%} | "
            f"{m['macro_f1']:.6f} | {m['recall']:.6f} | {m['false_positive_rate']:.6f} | {row['fitness']:.6f} | "
            f"{row['potential_compact_parameters']} | {row['potential_compact_macs']} |")
    lines += ["", "Every evaluation still uses the dense 9,345-parameter network (73,760 convolution/linear "
        "MACs per sample, excluding masks, activations and pooling). Potential counts describe a future "
        "compact architecture; they are not measured compression or latency savings. "
        "No compact model or per-candidate training was performed.", "",
        "`quality_retention.csv` records every valid unique mask. `summary.json` also preserves the full "
        "macro-F1/retention Pareto frontier, including recall and per-family metrics.", "",
        "## Validation scope", "",
        f"The same {validation.get('sample_count', 'fixed')} development samples are used for every candidate "
        f"in their frozen order. Class counts: {validation.get('class_counts', {})}; "
        f"family counts: {validation.get('family_counts', {})}; source groups: {validation.get('source_groups', 'unknown')}; "
        f"independently held-out groups: {validation.get('independent_heldout_groups', 'unknown')}.", "",
        "This is a model-selection experiment on the already-used development subset. Repeated mask selection "
        "adds validation optimism; the available one-positive, single-group excerpt cannot establish attack "
        "recall or generalization, and absent families have no measured quality. Test, external, training and "
        "threshold-reserve data are not opened by this search. No final threshold or calibration is fitted.", "",
        "## Artifacts", "",
        "`resume.json` atomically binds the population, cursor, sole search RNG state, cache, request log, "
        "best-so-far history and patience counter. `config.json` binds all fitness inputs, source hashes and "
        "numeric runtime settings. `validation_manifest.json` fixes the development subset. "
        "`candidate_requests.csv` includes evaluation times and cache status. `baseline/` preserves the "
        "original weights and inference provenance; `top_candidates.json` preserves selected masks. "
        "`parity.json`, `budget.json`, and `verification.json` record the entry check, measured budget and "
        "independent cache replay when the corresponding commands complete.", ""]
    (output / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")


def run(bundle, experiment, output, *, config=SearchConfig(), resume=False, stop_after_requests=None):
    started, cpu = time.perf_counter(), time.process_time()
    determinism(config.seed)
    model, x, rows, saved, provenance = load_inputs(bundle, experiment)
    evaluator = FitnessEvaluator(model, x, rows, provenance, seed=config.seed)
    parity = evaluator.parity(saved)
    setup = dict(seconds=time.perf_counter() - started, cpu_seconds=time.process_time() - cpu,
                 includes="input verification, load, evaluator construction and two parity forward passes")
    if resume:
        # Check drift before overwriting any artifact in an existing run.
        load_state(output, config, evaluator)
    def prepare_artifacts(destination):
        (destination / "baseline").mkdir(exist_ok=True)
        for name in BUNDLE_FILES:
            target = destination / "baseline" / name
            if target.exists():
                require(sha256(target) == provenance["bundle_checksums"][name], f"Preserved baseline changed: {name}")
            else:
                temporary = target.with_suffix(target.suffix + ".tmp")
                shutil.copyfile(Path(bundle) / name, temporary)
                temporary.replace(target)
        write_json(destination / "baseline/checksums.json", provenance["bundle_checksums"])
        write_json(destination / "validation_manifest.json", provenance["validation"])
        write_json(destination / "outcome_access.json", provenance["access"])
        if not (destination / "parity.json").exists():
            write_json(destination / "parity.json", parity)
            write_json(destination / "environment.json", environment())
        previous = read_json(destination / "setup_cost.json") if (destination / "setup_cost.json").exists() else []
        write_json(destination / "setup_cost.json", previous + [setup])

    state = search(evaluator, output, config, resume=resume, stop_after_requests=stop_after_requests,
                   prepare_artifacts=prepare_artifacts)
    output = Path(output)
    print(json.dumps({k: v for k, v in read_json(output / "summary.json").items()
                      if k not in {"baseline", "best", "top_candidates", "pareto_candidates"}}, indent=2), flush=True)
    return state


def verify(output, bundle, experiment):
    """Replay every cached candidate independently, without altering the search."""
    output = Path(output)
    config = SearchConfig(**read_json(output / "config.json")["search"])
    determinism(config.seed)
    model, x, rows, saved, provenance = load_inputs(bundle, experiment)
    evaluator = FitnessEvaluator(model, x, rows, provenance, seed=config.seed)
    state = load_state(output, config, evaluator)
    require(read_json(output / "cache.json") == dict(context_sha256=evaluator.context_sha256, entries=state["cache"]),
            "Exported cache differs from checkpoint")
    parity = evaluator.parity(saved)
    start, cpu = time.perf_counter(), time.process_time()
    for cached in state["cache"].values():
        actual, _ = evaluator.evaluate(Mask.decode(cached["mask"]))
        require(all(cached[key] == value for key, value in actual.items()), "Cached candidate did not reproduce")
    require(len(state["requests"]) == sum(r["cache_hit"] for r in state["requests"]) + len(state["cache"]),
            "Candidate accounting mismatch")
    require(len(state["requests"]) <= 20 * (config.max_generations + 1) and
            len(state["cache"]) <= 20 + 18 * config.max_generations, "Candidate budget exceeded")
    seen = set()
    for request in state["requests"]:
        key = cache_key(evaluator.context_sha256, Mask.decode(request["mask"]))
        require(request["cache_key"] == key and request["cache_hit"] == (key in seen), "Incorrect cache-hit accounting")
        require(request["fitness"] == state["cache"][key]["fitness"], "Request fitness mismatch")
        seen.add(key)
    for generation in state["history"]:
        require(len(generation["population"]) == 20, "Invalid population size")
        require(generation["best_fitness"] == state["cache"][generation["best_key"]]["fitness"], "Best-history mismatch")
    expected_top = sorted((r for r in state["cache"].values() if r["valid"] and r["mask"] != ALL_ONES.code), key=ranking)[:3]
    require(read_json(output / "top_candidates.json")["candidates"] == expected_top, "Top candidate archive mismatch")
    require(read_json(output / "validation_manifest.json") == provenance["validation"], "Validation selection drift")
    for name in BUNDLE_FILES:
        require(sha256(output / "baseline" / name) == provenance["bundle_checksums"][name], "Preserved baseline changed")
    result = dict(passed=True, cached_candidates_replayed=len(state["cache"]), exact_metrics_and_output_hashes=True,
        all_ones_parity=parity, additional_evaluation_seconds=time.perf_counter() - start,
        additional_cpu_seconds=time.process_time() - cpu, search_counts_unchanged=True,
        test_or_external_data_accessed=False)
    write_json(output / "verification.json", result)
    print(json.dumps(result, indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "verify"))
    parser.add_argument("--bundle", type=Path, default=Path("experiments/phase3/run-002/baseline_package"))
    parser.add_argument("--experiment", type=Path, default=Path("experiments/phase3/run-002"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--max-generations", type=int, default=15)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.command == "verify":
        verify(args.output, args.bundle, args.experiment)
    else:
        run(args.bundle, args.experiment, args.output,
            config=SearchConfig(seed=args.seed, max_generations=args.max_generations), resume=args.resume)


if __name__ == "__main__":
    main()
