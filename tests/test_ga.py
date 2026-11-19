"""Phase 4 behavioral tests use synthetic inputs only, never held-out data."""

import copy
from dataclasses import replace
import math
from pathlib import Path
import random

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import torch

from ids.datasets.temporal import digest
from ids.ga import data as ga_data
from ids.ga import search as ga
from ids.ga.masks import (ALL_ONES, Mask, crossover, initial_population, masked_forward,
                          mutate_and_repair, repair, retention_cost, roulette)
from ids.model import TemporalCNN
from ids.run_logging import sha256, write_json
from ids.training.data import read_json
from ids.training.train import architecture, determinism, weight_hash


def evaluator_fixture():
    determinism(19)
    model = TemporalCNN()
    x = np.random.default_rng(23).normal(size=(12, 16, 8)).astype(np.float32)
    rows = [dict(sample_id=f"sample-{i}", tensor_index=i, group_id="fixture", label=i % 2,
                 family="reconnaissance" if i % 2 else "benign") for i in range(len(x))]
    evaluator = ga.FitnessEvaluator(model, x, rows, {"synthetic_fixture": True})
    return evaluator, model, x, rows


def test_all_ones_and_bias_effects_in_both_layers():
    determinism(12)
    model = TemporalCNN().eval()
    x = torch.randn(7, 16, 8)
    torch.testing.assert_close(masked_forward(model, x, ALL_ONES), model(x), rtol=0, atol=0)
    removed_first = Mask((0,) + (1,) * 63, (1,) * 32)
    removed_second = Mask((1,) * 64, (0,) + (1,) * 31)
    with torch.no_grad():
        for p in model.parameters():
            p.zero_()
        model.conv1.bias[0] = 2
        model.conv2.weight[0, 0, 1] = 3
        model.output.weight[0, 0] = 5
        model.output.bias[0] = .25
    assert torch.all(masked_forward(model, x, ALL_ONES) == 30.25)
    assert torch.all(masked_forward(model, x, removed_first) == .25)
    with torch.no_grad():
        model.conv2.weight.zero_()
        model.conv2.bias[0] = 7
    assert torch.all(masked_forward(model, x, ALL_ONES) == 35.25)
    assert torch.all(masked_forward(model, x, removed_second) == .25)
    assert not masked_forward(model, x.requires_grad_(), ALL_ONES).requires_grad


def test_masks_repair_and_mutation_are_seeded_and_valid():
    empty = [[0] * 64, [0] * 32]
    fixed = repair(empty, random.Random(7))
    assert fixed == repair(empty, random.Random(7))
    assert fixed != repair(empty, random.Random(8))
    assert fixed.retained == (4, 4)
    assert empty == [[0] * 64, [0] * 32]
    assert repair(ALL_ONES.layers, random.Random(7)) == ALL_ONES
    population = initial_population(random.Random(5))
    assert len(population) == 20 and population[0] == ALL_ONES
    assert population == initial_population(random.Random(5))
    assert mutate_and_repair(fixed.layers, random.Random(9)) == mutate_and_repair(fixed.layers, random.Random(9))
    for mask in population:
        assert min(mask.retained) >= 4 and Mask.decode(mask.code) == mask
    with pytest.raises(ValueError, match="four"):
        Mask(*empty)
    with pytest.raises(ValueError, match="binary"):
        Mask((.5,) + (1,) * 63, (1,) * 32)
    with pytest.raises(ValueError, match="lengths"):
        Mask((1,) * 63, (1,) * 32)


def test_single_point_crossover_is_only_in_one_chosen_layer():
    a = ALL_ONES
    b = Mask((1,) * 4 + (0,) * 60, (1,) * 4 + (0,) * 28)
    class Controlled:
        def __init__(self, draw, layer):
            self.draw, self.values = draw, iter((layer, 8))
        def random(self):
            return self.draw
        def randrange(self, *args):
            return next(self.values)
    for layer in (0, 1):
        first, second = crossover(a, b, Controlled(.599, layer))
        assert first[1 - layer] == list(a.layers[1 - layer])
        assert second[1 - layer] == list(b.layers[1 - layer])
        assert first[layer] == list(a.layers[layer][:8] + b.layers[layer][8:])
        assert second[layer] == list(b.layers[layer][:8] + a.layers[layer][8:])
    assert crossover(a, b, Controlled(.6, 0)) == ([list(x) for x in a.layers], [list(x) for x in b.layers])
    class FlipAll(random.Random):
        def random(self):
            return .049
        def sample(self, population, k):
            return population[:k]
    assert mutate_and_repair(ALL_ONES.layers, FlipAll(9)).retained == (4, 4)
    class FlipNone(random.Random):
        def random(self):
            return .05
    assert mutate_and_repair(ALL_ONES.layers, FlipNone(9)) == ALL_ONES


def test_roulette_positive_weights_zero_fallback_and_invalid_candidates():
    rng = random.Random(91)
    weights = [0., 0., None, math.nan, math.inf, -1.]
    expected = random.Random(91)
    assert [roulette(weights, rng) for _ in range(30)] == [expected.choice([0, 1]) for _ in range(30)]
    assert {roulette([0, .5, None], random.Random(i)) for i in range(100)} == {1}
    rng = random.Random(3)
    samples = [roulette([.25, .75], rng) for _ in range(10000)]
    assert .72 < np.mean(samples) < .78
    with pytest.raises(ValueError, match="valid parents"):
        roulette([None, math.nan, -1], rng)


def test_evaluation_freezes_inputs_and_weights_and_uses_fixed_fitness():
    evaluator, model, x, rows = evaluator_fixture()
    before = weight_hash(model.state_dict())
    result, timing = evaluator.evaluate(ALL_ONES)
    assert result["fitness"] == .9 * result["metrics"]["macro_f1"]
    assert result["metrics"]["threshold"] == .5
    assert result["metrics"]["sample_count"] == len(x)
    assert timing["evaluation_seconds"] > 0
    assert all(p.grad is None and not p.requires_grad for p in evaluator.model.parameters())
    assert weight_hash(model.state_dict()) == before
    x[:] = 20
    rows[0]["label"] = 1
    with torch.no_grad():
        model.conv1.bias.fill_(100)
    assert evaluator.evaluate(ALL_ONES)[0] == result
    mask = repair([[0] * 64, [0] * 32], random.Random(1))
    pruned, _ = evaluator.evaluate(mask)
    assert pruned["fitness"] == .1 * (1 - 8 / 96) + .9 * pruned["metrics"]["macro_f1"]
    assert retention_cost(ALL_ONES)["potential_compact_parameters"] == 9345
    assert retention_cost(ALL_ONES)["potential_compact_macs"] == 73760


def test_nonfinite_candidates_are_invalid_and_never_elites(monkeypatch):
    evaluator, *_ = evaluator_fixture()
    monkeypatch.setattr(evaluator, "predict", lambda mask: (np.array([np.inf]), np.array([1.])))
    result, _ = evaluator.evaluate(ALL_ONES)
    assert result["valid"] is False and result["fitness"] is None and result["metrics"] is None
    population = initial_population(random.Random(3))
    records = {}
    for i, mask in enumerate(population):
        records[ga.cache_key("ctx", mask)] = dict(mask=mask.code, valid=i < 2, fitness=(.6 - i * .1) if i < 2 else None)
    new = ga.replacement([m.code for m in population], records, "ctx", random.Random(7))
    assert new[:2] == [m.code for m in population[:2]]


@pytest.mark.parametrize("field", ["weights", "tensor", "labels", "row_order", "preprocess", "checkpoint", "subset", "schema", "fitness", "runtime", "implementation"])
def test_cache_context_covers_every_fitness_input(field, monkeypatch):
    original, model, x, rows = evaluator_fixture()
    provenance = {"synthetic_fixture": True}
    if field == "weights":
        with torch.no_grad():
            model.output.bias.add_(.1)
    elif field == "tensor":
        x[0, 0, 0] += .1
    elif field == "labels":
        rows[0]["label"] = 1
    elif field == "row_order":
        rows = rows[::-1]
        x = x[::-1]
    elif field in {"preprocess", "checkpoint", "subset", "schema"}:
        provenance[field] = "changed"
    elif field == "fitness":
        monkeypatch.setitem(ga.FITNESS, "threshold", .6)
    elif field == "runtime":
        actual = ga.runtime_fingerprint()
        monkeypatch.setattr(ga, "runtime_fingerprint", lambda: {**actual, "torch": "changed"})
    else:
        actual = ga.implementation_hashes()
        monkeypatch.setattr(ga, "implementation_hashes", lambda: {**actual, "changed.py": "changed"})
    changed = ga.FitnessEvaluator(model, x, rows, provenance)
    assert changed.context_sha256 != original.context_sha256
    assert ga.cache_key(changed.context_sha256, ALL_ONES) != ga.cache_key(original.context_sha256, ALL_ONES)


def without_timings(state):
    value = copy.deepcopy(state)
    value.pop("search_wall_seconds")
    value.pop("search_cpu_seconds")
    for record in list(value["cache"].values()) + value["requests"] + value["history"]:
        for key in ("evaluation_seconds", "evaluation_cpu_seconds", "request_seconds", "rss_bytes"):
            record.pop(key, None)
    # Atomic JSON deserialization turns RNG tuples into lists.
    return digest(value)


def test_mid_generation_resume_is_exact_and_rejects_drift_and_corruption(tmp_path):
    evaluator, *_ = evaluator_fixture()
    config = ga.SearchConfig(max_generations=2)
    full = ga.search(evaluator, tmp_path / "full", config)
    partial = ga.search(evaluator, tmp_path / "continued", config, stop_after_requests=23)
    assert partial["generation"] == 1 and partial["next_index"] == 3
    continued = ga.search(evaluator, tmp_path / "continued", config, resume=True)
    assert without_timings(full) == without_timings(continued)
    assert len(full["requests"]) == 60 and len(full["cache"]) <= 56
    for history in full["history"][1:]:
        assert history["cache_hits"] >= 2
    assert len(read_json(tmp_path / "continued/top_candidates.json")["candidates"]) == 3
    complete_again = ga.search(evaluator, tmp_path / "continued", config, resume=True)
    assert without_timings(complete_again) == without_timings(continued)
    with pytest.raises(ValueError, match="drift"):
        ga.search(evaluator, tmp_path / "continued", replace(config, seed=2), resume=True)
    prior = evaluator.context_sha256
    evaluator.context_sha256 = "changed"
    with pytest.raises(ValueError, match="drift"):
        ga.search(evaluator, tmp_path / "continued", config, resume=True)
    evaluator.context_sha256 = prior
    envelope = read_json(tmp_path / "continued/resume.json")
    envelope["state"]["next_index"] = 1
    write_json(tmp_path / "continued/resume.json", envelope)
    with pytest.raises(ValueError, match="checksum"):
        ga.search(evaluator, tmp_path / "continued", config, resume=True)


def test_duplicate_cache_and_five_generation_stop(tmp_path, monkeypatch):
    evaluator, *_ = evaluator_fixture()
    monkeypatch.setattr(ga, "initial_population", lambda rng: [ALL_ONES] * 20)
    monkeypatch.setattr(ga, "replacement", lambda population, *args: population)
    state = ga.search(evaluator, tmp_path / "duplicates")
    assert state["stopping_reason"] == "patience_5"
    assert state["generation"] == state["stale_generations"] == 5
    assert len(state["requests"]) == 120 and len(state["cache"]) == 1
    assert sum(r["cache_hit"] for r in state["requests"]) == 119
    assert ga.patience_update(0., 1e-6, 4) == (0, True)
    assert ga.patience_update(0., .999e-6, 4) == (5, False)
    assert ga.patience_update(.5, .5, 4) == (5, False)
    with pytest.raises(ValueError, match="15"):
        ga.SearchConfig(max_generations=16)


def test_fifteen_replacements_have_320_requests_and_30_elite_hits(tmp_path, monkeypatch):
    evaluator, *_ = evaluator_fixture()
    template, _ = evaluator.evaluate(ALL_ONES)
    calls = 0
    def improving(mask):
        # A scripted objective isolates the generation bound from real stagnation.
        nonlocal calls
        calls += 1
        record = copy.deepcopy(template)
        record.update(mask=mask.code, layers=[list(layer) for layer in mask.layers], **retention_cost(mask))
        record["fitness"] = .6 + calls / 1000
        return record, dict(evaluation_seconds=0., evaluation_cpu_seconds=0.)
    monkeypatch.setattr(evaluator, "evaluate", improving)
    state = ga.search(evaluator, tmp_path / "limit")
    assert state["stopping_reason"] == "generation_limit"
    assert state["generation"] == 15 and len(state["history"]) == 16
    assert len(state["requests"]) == 320 and calls <= 290
    assert sum(r["cache_hit"] for r in state["requests"]) >= 30
    for previous, current in zip(state["history"], state["history"][1:]):
        ranked = sorted((state["cache"][ga.cache_key(evaluator.context_sha256, Mask.decode(code))]
                         for code in previous["population"]), key=ga.ranking)
        assert current["population"][:2] == [record["mask"] for record in ranked[:2]]


def fixture_package(root):
    evaluator, model, x, rows = evaluator_fixture()
    bundle, experiment = root / "bundle", root / "phase3"
    data = experiment / "data"
    bundle.mkdir(parents=True)
    (data / "development").mkdir(parents=True)
    for name in ga_data.BUNDLE_FILES:
        if name.endswith(".json"):
            write_json(bundle / name, {"synthetic_fixture": True})
    split = {"development_fixture": True}
    preprocess = {"split_manifest_sha256": digest(split)}
    for name, content in (("split_manifest.json", split), ("preprocess.json", preprocess), ("feature_schema.json", {})):
        write_json(bundle / name, content)
        write_json(data / name, content)
    np.save(data / "development/tensor.npy", x, allow_pickle=False)
    pq.write_table(pa.Table.from_pylist(rows), data / "development/samples.parquet")
    manifest = {name: sha256(data / name) for name in ga_data.DATA_FILES}
    # These must never be treated as paths to open, even for checksum verification.
    manifest.update({name: "unopened" for name in ("train/tensor.npy", "reserved_index.parquet", "../internal_test/labels.npy", "external.csv")})
    write_json(data / "artifact_checksums.json", manifest)
    arch = architecture("cnn64_weighted")
    config = dict(variant="cnn64_weighted", architecture=arch, data_sha256=digest(manifest),
                  preprocess_sha256=sha256(bundle / "preprocess.json"), split_manifest_sha256=sha256(bundle / "split_manifest.json"))
    write_json(bundle / "config.json", config)
    write_json(bundle / "architecture.json", arch)
    torch.save(dict(model_state=model.state_dict(), config=config), bundle / "best.pt")
    logits, scores = evaluator.predict()
    predictions = [dict(r, logit=float(logit), score=float(score)) for r, logit, score in zip(rows, logits, scores)]
    pq.write_table(pa.Table.from_pylist(predictions), bundle / "development_predictions.parquet")
    handoff = dict(trained=True, pruning_input_valid=True, architecture=arch, data_sha256=digest(manifest),
        checkpoint_sha256=sha256(bundle / "best.pt"), state_dict_sha256=weight_hash(model.state_dict()),
        preprocess_sha256=sha256(bundle / "preprocess.json"), split_manifest_sha256=sha256(bundle / "split_manifest.json"),
        development_predictions_sha256=sha256(bundle / "development_predictions.parquet"), independent_heldout_development_groups=0)
    write_json(bundle / "handoff.json", handoff)
    checksums = {name: sha256(bundle / name) for name in ga_data.BUNDLE_FILES}
    checksums.update({"resume.pt": "unopened", "reserved_index.parquet": "unopened", "../external.csv": "unopened"})
    write_json(bundle / "checksums.json", checksums)
    return bundle, experiment


def test_development_loader_allowlist_and_package_bindings(tmp_path, monkeypatch):
    bundle, experiment = fixture_package(tmp_path)
    reads = []
    def guard(function):
        def call(path, *args, **kwargs):
            p = Path(path)
            root = bundle if p.is_relative_to(bundle) else experiment / "data"
            names = ga_data.BUNDLE_FILES + ("checksums.json",) if root == bundle else ga_data.DATA_FILES + ("artifact_checksums.json",)
            assert p.relative_to(root).as_posix() in names
            reads.append(p)
            return function(path, *args, **kwargs)
        return call
    monkeypatch.setattr(ga_data, "sha256", guard(ga_data.sha256))
    monkeypatch.setattr(ga_data, "read_json", guard(ga_data.read_json))
    monkeypatch.setattr(pq, "read_table", guard(pq.read_table))
    monkeypatch.setattr(np, "load", guard(np.load))
    monkeypatch.setattr(torch, "load", guard(torch.load))
    model, x, rows, saved, provenance = ga_data.load_inputs(bundle, experiment)
    assert len(x) == len(rows) == len(saved) == 12
    assert provenance["access"]["decoded_outcome_roles"] == ["development"]
    assert reads and not any("reserved" in str(p) or "external" in str(p) for p in reads)
    (experiment / "data/development/tensor.npy").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        ga_data.load_inputs(bundle, experiment)


def test_full_command_preserves_baseline_and_replays_all_cache(tmp_path):
    bundle, experiment = fixture_package(tmp_path)
    output = tmp_path / "phase4"
    config = ga.SearchConfig(max_generations=0)
    state = ga.run(bundle, experiment, output, config=config)
    assert state["status"] == "complete" and len(state["requests"]) == 20
    assert ga.verify(output, bundle, experiment)["cached_candidates_replayed"] == len(state["cache"])
    assert sha256(output / "baseline/best.pt") == sha256(bundle / "best.pt")
    assert not (output / "baseline/reserved_index.parquet").exists()
    assert read_json(output / "parity.json")["all_ones_exact"]
    assert read_json(output / "validation_manifest.json")["sample_count"] == 12
    assert (output / "candidate_requests.csv").exists()
    assert (output / "REPORT.md").exists()
    ga.run(bundle, experiment, output, config=config, resume=True)
    assert len(read_json(output / "setup_cost.json")) == 2
    assert read_json(output / "summary.json")["candidate_requests"] == 20
