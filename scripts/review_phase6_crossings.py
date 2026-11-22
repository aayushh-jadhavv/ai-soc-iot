"""Trace any threshold changes from a completed Phase 6 run using its saved graphs."""

import argparse
from pathlib import Path

import numpy as np
import torch
from torch.utils._pytree import tree_leaves

from ids.run_logging import sha256, write_json
from ids.training.data import read_json, require
from scripts.phase6.xnnpack import configure


def trace_output(module, x):
    interpreter = torch.fx.Interpreter(module, garbage_collect_values=False)
    value = interpreter.run(x).item()
    output, = (node for node in module.graph.nodes if node.op == "output")
    last, = tree_leaves(output.args)
    trace = dict(graph_logit=value)
    if last.target == torch.ops.quantized_decomposed.dequantize_per_tensor.default:
        quantized, scale, zero, minimum, maximum, _ = last.args
        require(quantized.target == torch.ops.quantized_decomposed.quantize_per_tensor.default,
                "Unexpected output quantizer")
        before = interpreter.env[quantized.args[0]].item()
        code = interpreter.env[quantized].item()
        trace.update(pre_quantization_logit=before, scale=scale, zero_point=zero, integer_output=code,
                     integer_range=[minimum, maximum], pre_quantization_score=torch.sigmoid(torch.tensor(
                         before, dtype=torch.float64)).item(), rounded_to_zero=(code == zero))
    return trace


def review(output):
    configure()
    from torchao.quantization.pt2e import quantize_pt2e  # noqa: F401

    hashes = read_json(output / "artifact_checksums.json")
    def checked(relative):
        path = (output / relative).resolve()
        require(path.is_relative_to(output.resolve()) and sha256(path) == hashes[relative],
                f"Changed Phase 6 artifact: {relative}")
        return path

    inputs = torch.from_numpy(np.load(checked("shared/reference_tensors.npy"), allow_pickle=False))
    summary = read_json(checked("summary.json"))
    cases = []
    with torch.no_grad():
        for name, row in summary.items():
            for precision in ("float32", "int8"):
                if "failure" in row[precision]:
                    continue
                directory = f"{name}/{precision}"
                ledger = read_json(checked(directory + "/threshold_crossings.json"))
                require(len(ledger) == row[precision]["reviewed_crossings"], "Incomplete disagreement ledger")
                if not ledger:
                    continue
                graph = torch.export.load(checked(directory + "/exported.pt2")).module()
                for r in ledger:
                    i = r["reference_index"]
                    trace = trace_output(graph, inputs[i:i + 1])
                    require(trace["graph_logit"] == r["logits"]["exported"], "Graph trace failed replay")
                    if "integer_output" in trace:
                        trace["final_quantizer_changes_decision"] = (
                            int(trace["pre_quantization_score"] >= .5) != r["decisions"]["exported"])
                    cases.append(dict(checkpoint=name, precision=precision, **r, output_trace=trace))
    result = dict(artifact_manifest_sha256=sha256(output / "artifact_checksums.json"),
                  reviewer_sha256=sha256(Path(__file__)), reviewed_cases=len(cases), cases=cases)
    write_json(output / "threshold_review.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    print(f"Traced {review(parser.parse_args().output)['reviewed_cases']} threshold disagreements.")
