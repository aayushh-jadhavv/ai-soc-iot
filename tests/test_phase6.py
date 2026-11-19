"""Regression checks for Phase 6 calibration, tolerance and threshold decisions."""

import numpy as np
import pytest
import torch

from scripts.phase6.assessment import FLOAT_ATOL, investigate, ptq_decision, tolerance_registration
from scripts.phase6.inputs import calibration_sample, tolerance_partition


def test_calibration_uses_observed_training_strata_and_records_exact_ids():
    raw = np.zeros((61, 8, 16))
    raw[:, :, 0] = np.arange(len(raw))[:, None]
    rows = [dict(role="train", partition_id="train", tensor_index=i, sample_id=f"id-{i}",
                 label=int(i >= 55), family="reconnaissance" if i >= 55 else "benign") for i in range(len(raw))]
    a = calibration_sample(raw, rows, per_stratum=4)
    assert a == calibration_sample(raw, rows, per_stratum=4)
    assert a["representative"] and a["selected_counts"] == dict(idle=1, benign_burst=4, benign_other=4,
                                                               **{"attack/reconnaissance": 4})
    assert len({r["sample_id"] for r in a["samples"]}) == len(a["samples"])
    assert all(rows[r["tensor_index"]]["sample_id"] == r["sample_id"] for r in a["samples"])
    raw[0, :, 0] = 1
    b = calibration_sample(raw, rows)
    assert b["absent_required_strata"] == ["idle"] and b["fully_idle_benign_histories"] == 0
    rows[0]["role"] = "validation"
    with pytest.raises(ValueError, match="training rows"):
        calibration_sample(raw, rows)


def test_tolerance_prefix_and_later_check_are_window_disjoint():
    rows = [dict(final_time_ns=i, window_ids=list(range(i - 7, i + 1))) for i in range(36)]
    split = tolerance_partition(rows)
    assert split["fit"] == list(range(12)) and split["guard"] == list(range(12, 19))
    assert split["check"] == list(range(19, 36))
    logits = np.zeros(12, dtype=np.float32)
    registered = tolerance_registration(logits, logits + .01)
    assert registered["score_atol"] == .003 and registered["score_atol"] != FLOAT_ATOL
    assert tolerance_registration(logits, logits + 1)["score_atol"] == .05


def test_crossing_review_preserves_threshold_equality_and_backend_reversal():
    tensor = torch.zeros(16, 8)
    logits = dict(eager=0., exported=-.001, runtime=.001, float_runtime=0.)
    stages = {k: np.array([v], dtype=np.float32) for k, v in logits.items()}
    calls = {k: (lambda x, v=v: torch.tensor([[v]])) for k, v in logits.items()}
    r = investigate(0, dict(sample_id="row-3", label=0), stages, calls, tensor, "int8")
    assert r["decisions"] == dict(eager=1, exported=0, runtime=1, float_runtime=1)
    assert len(r["stage_evidence"]) == 2 and r["replay_exact"] and not r["runtime_correct"]
    calls["runtime"] = lambda x: torch.zeros(1, 1)
    with pytest.raises(ValueError, match="replay"):
        investigate(0, dict(sample_id="row-3", label=0), stages, calls, tensor, "int8")


def test_ptq_quality_size_and_measured_runtime_are_separate_gates():
    metrics = dict(recall=.89, macro_f1=.79)
    parent = dict(recall=.9, macro_f1=.8)
    baseline = dict(recall=.91, macro_f1=.81)
    report = dict(metrics=dict(runtime=metrics), numerical_pass=True)
    calibration = dict(representative=True)
    delegation = dict(int8_affine_ops=3, pte_bytes=80)
    fp = dict(p50_ns=100, p95_ns=200)
    def decide(p95):
        return ptq_decision(report, parent, baseline, calibration, delegation, 100, fp,
                            dict(p50_ns=104, p95_ns=p95), True)
    assert decide(210)["accepted"]  # The exact 0.01 and 0.02 quality boundaries are inclusive.
    assert decide(211)["failure_reasons"] == ["measured_value"]
    calibration["representative"] = False
    metrics["recall"] -= .00001
    assert decide(210)["failure_reasons"] == ["calibration_coverage", "float_parent_quality", "unpruned_quality"]
