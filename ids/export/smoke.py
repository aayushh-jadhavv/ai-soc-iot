"""Run from the repository root: python -m ids.export.smoke --output <new-dir>."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import platform
import shlex
import sys
import subprocess
import time
import traceback

import numpy as np
import torch

from ids.contracts import load_json
from ids.model import TemporalCNN
from ids.preprocessing import Preprocessor
from ids.run_logging import ResourceMonitor, RunLogger, environment, sha256, source_hashes, write_json


def call_ops(module):
    return [{"node": n.name, "target": str(n.target)} for n in module.graph.nodes if n.op == "call_function"]


def delegation_report(edge):
    module = edge.exported_program().graph_module
    delegates = []
    for name, child in module.named_modules():
        if hasattr(child, "backend_id") and hasattr(child, "original_module"):
            delegates.append({"name": name, "backend": child.backend_id,
                              "operators": call_ops(child.original_module.graph_module)})
    return {"delegates": delegates, "top_level_calls": call_ops(module),
            "note": "getitem is output unpacking. Runtime execution-plan operators below are the fallback kernel inventory."}


def time_calls(run, iterations, monitor_enabled):
    rows = []
    for i in range(iterations):
        start = time.perf_counter_ns()
        run()
        rows.append({"stage": "executorch_forward", "iteration": i,
                     "elapsed_ns": time.perf_counter_ns()-start, "monitor_enabled": monitor_enabled})
    return rows


def run(args, logger):
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.exir import to_edge_transform_and_lower
    from executorch.runtime import Runtime

    out = logger.output
    torch.manual_seed(args.seed)
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    model = TemporalCNN().eval()
    count = sum(p.numel() for p in model.parameters())
    if count != 9345:
        raise AssertionError(f"Unexpected parameter count: {count}")
    request = load_json(Path("contracts/fixtures/positive/sequence.json"))
    idle = load_json(Path("contracts/fixtures/positive/idle_sequence.json"))
    preprocess = Preprocessor(tuple([0.0]*16), tuple([1.0]*16))
    write_json(out / "preprocess.json", asdict(preprocess))
    prep_start = time.perf_counter_ns()
    raw_tensor = preprocess.transform(request, model_id=request["model_id"])
    prep_ns = time.perf_counter_ns()-prep_start
    examples = {
        "raw_fixture": raw_tensor,
        "healthy_idle": preprocess.transform(idle, model_id=request["model_id"]),
        "seeded_normal": torch.randn(1, 16, 8),
        "alternating": (torch.arange(128).reshape(1,16,8) % 2).float()*2-1,
        "large_finite": torch.full((1,16,8), 20.0),
    }
    torch.save(model.state_dict(), out / "untrained_state_dict.pt")
    with torch.inference_mode():
        ep = torch.export.export(model, (raw_tensor,), strict=True)
        torch.export.save(ep, out / "exported.pt2")
        (out / "exported_graph.txt").write_text(str(ep.graph_module.graph), encoding="utf-8")
        edge = to_edge_transform_and_lower(ep, partitioner=[XnnpackPartitioner()])
        report = delegation_report(edge)
        (out / "lowered_graph.txt").write_text(str(edge.exported_program().graph_module.graph), encoding="utf-8")
        for i, d in enumerate(report["delegates"]):
            logger.event("delegate", index=i, **d)
        if not report["delegates"] or any(d["backend"] != "XnnpackBackend" for d in report["delegates"]):
            raise AssertionError("No verified XNNPACK delegation")
        et = edge.to_executorch()
        pte = out / "model.pte"
        pte.write_bytes(et.buffer)
        plan = et.executorch_program.execution_plan[0]
        report["runtime_fallback_operators"] = [{"name": o.name, "overload": o.overload} for o in plan.operators]
        report["runtime_delegates"] = [d.id for d in plan.delegates]
        write_json(out / "delegation.json", report)
        load_start = time.perf_counter_ns()
        runtime = Runtime.get()
        program = runtime.load_program(str(pte))
        method = program.load_method("forward")
        load_ns = time.perf_counter_ns()-load_start
        refs = []
        for name, tensor in examples.items():
            eager = model(tensor)
            exported = ep.module()(tensor)
            deployed = method.execute((tensor,))[0].clone()
            torch.testing.assert_close(exported, eager, atol=1e-6, rtol=1e-5)
            torch.testing.assert_close(deployed, eager, atol=1e-5, rtol=1e-5)
            ref_score, score = torch.sigmoid(eager), torch.sigmoid(deployed)
            delta = (score-ref_score).abs().max().item()
            if delta > 1e-4:
                raise AssertionError(f"Score parity failed for {name}: {delta}")
            refs.append({"name": name, "tensor": tensor.tolist(), "eager_logit": eager.tolist(),
                         "exported_logit": exported.tolist(), "executorch_logit": deployed.tolist(),
                         "eager_score": ref_score.tolist(), "executorch_score": score.tolist(),
                         "logit_max_abs_error": (eager-deployed).abs().max().item(),
                         "score_max_abs_error": delta,
                         "diagnostic_0_5_threshold_crossing": bool(((score >= 0.5) != (ref_score >= 0.5)).any())})
        write_json(out / "reference_outputs.json", {"untrained": True, "raw_request": request,
            "logit_atol": 1e-5, "logit_rtol": 1e-5, "score_atol": 1e-4, "references": refs})
        for _ in range(args.warmup):
            method.execute((raw_tensor,))
        timing = time_calls(lambda: method.execute((raw_tensor,)), args.iterations, False)
        with ResourceMonitor(out):
            # Compatibility smoke resource sample, outside timed calls.
            # Ensure at least two 200 ms samples even for this very small model.
            until = time.perf_counter() + 0.5
            while time.perf_counter() < until:
                method.execute((raw_tensor,))
            timing += time_calls(lambda: method.execute((raw_tensor,)), args.iterations, True)
        medians = {}
        summary = {"purpose": "compatibility smoke, not a performance acceptance benchmark", "clock": "perf_counter_ns",
                   "load_ns": load_ns, "preprocessing_ns": prep_ns, "warmup_calls": args.warmup,
                   "iterations_per_monitor_condition": args.iterations, "batch": 1,
                   "eager_intraop_threads": torch.get_num_threads(), "eager_interop_threads": torch.get_num_interop_threads(),
                   "xnnpack_threads": "runtime default; not inferred from torch thread settings",
                   "http_round_trip": None, "stored_alert_latency": None,
                   "order": "unmonitored then monitored; order/background noise confound slowdown estimate"}
        for enabled in (False, True):
            values = [r["elapsed_ns"] for r in timing if r["monitor_enabled"] == enabled]
            medians[enabled] = float(np.median(values))
            summary["monitored" if enabled else "unmonitored"] = {"p50_ns": medians[enabled], "p95_ns": float(np.percentile(values, 95)), "samples": len(values)}
        summary["observed_median_ratio_monitored_over_unmonitored"] = medians[True]/medians[False]
        logger.record_timings(timing, summary)
    logger.write_table("ga_candidates", [])
    logger.write_table("predictions", [])
    write_json(out / "bundle_manifest.json", {"model_id": request["model_id"], "task": "attack_associated_traffic",
        "trained": False, "deployable_detector": False, "architecture": "Conv1d16x64k3-ReLU-Conv1d64x32k3-ReLU-mean-Linear32x1",
        "parameters": count, "parameter_bytes": sum(p.numel()*p.element_size() for p in model.parameters()),
        "analytical_macs": 73760, "pte_bytes": pte.stat().st_size, "input_shape": [1,16,8], "output_shape": [1,1],
        "dtype": "float32", "output": "logit", "score_type": "uncalibrated_sigmoid",
        "preprocess_fitted": False, "conv2d_substitution": False, "trained_families": [], "decision_threshold": None,
        "data_hashes": {}, "source_hashes": logger.manifest["code_hashes"],
        "checksums": {p.name: sha256(p) for p in out.iterdir() if p.is_file() and p.name not in ("run_manifest.json", "events.jsonl")}})
    logger.finish("passed", model_hash=sha256(pte), model_sha256=sha256(pte), compatibility={
        "system": platform.system(), "machine": platform.machine(), "native_linux_execution": platform.system() == "Linux",
        "vm_provenance": logger.manifest["host"], "batch": 1, "parameter_count": count,
        "max_score_abs_error": max(r["score_max_abs_error"] for r in refs),
        "max_logit_abs_error": max(r["logit_max_abs_error"] for r in refs),
        "delegate_count": len(report["delegates"]), "conv2d_substitution": False})
    print(json.dumps(logger.manifest["compatibility"], indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-manifest", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    if args.iterations < 1 or args.warmup < 1:
        parser.error("warmup and iterations must be positive")
    root = Path.cwd()
    flatc = Path(sys.executable).parent / "flatc"
    if flatc.is_file():
        os.environ.setdefault("FLATC_EXECUTABLE", str(flatc))
    host = json.loads(args.host_manifest.read_text(encoding="utf-8-sig"))
    logger = RunLogger(args.output, {"phase": 0, "seed": args.seed, "trained": False, "data_hashes": {},
        "code_commit": None, "code_commit_note": "Workspace has no Git repository; exact source hashes saved",
        "code_hashes": source_hashes(root), "environment": environment(), "host": host,
        "model_hash": None, "batch_size": 1, "requested_torch_threads": 1,
        "reproduction_command": "python -m ids.export.smoke " + shlex.join(sys.argv[1:]),
        "source_documents": {p.name: sha256(p) for p in (root/"output/documents").iterdir() if p.name.endswith(("_VM.docx", "_VM.odt"))}})
    write_json(logger.output / "environment_manifest.json", {"host": host, **logger.manifest["environment"]})
    try:
        flatc_version = subprocess.run([os.environ.get("FLATC_EXECUTABLE", "flatc"), "--version"],
                                      capture_output=True, text=True, check=True).stdout.strip()
        logger.manifest["flatc_version"] = flatc_version
        logger.manifest["quantization"] = {"enabled": False, "torchao_version": "0.14.0",
            "native_extension_status": "Upstream torchao 0.14.0 disables C++ extensions for torch 2.9.0; not used by this float32 XNNPACK proof",
            "pt2e_quantization": "Not executed; separate Phase 6 gate"}
        run(args, logger)
    except Exception as exc:
        (logger.output / "failure.txt").write_text(traceback.format_exc(), encoding="utf-8")
        logger.finish("failed", error_type=type(exc).__name__, error=str(exc))
        raise


if __name__ == "__main__":
    main()
