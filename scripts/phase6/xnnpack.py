"""Export and inspect a batch-one model with the pinned Phase 0 toolchain."""

from importlib import metadata, resources
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

import torch

from ids.export.smoke import delegation_report
from ids.run_logging import environment, sha256, write_json
from ids.training.data import require
from ids.training.train import determinism


def configure():
    pins = {"torch": "2.9.0+cpu", "executorch": "1.0.0", "torchao": "0.14.0",
            "numpy": "2.2.6", "pyarrow": "22.0.0"}
    require(platform.system() == "Linux" and platform.python_version() == "3.12.12",
            "Use the Phase 0 Linux CPython 3.12.12 environment")
    for package, version in pins.items():
        require(metadata.version(package) == version, f"Expected {package}=={version}")
    flatc = Path(sys.executable).with_name("flatc")
    version = subprocess.check_output([flatc, "--version"], text=True).strip()
    require(version == "flatc version 24.3.25", "Phase 0 flatc version mismatch")
    os.environ["FLATC_EXECUTABLE"] = str(flatc)
    determinism(1729)
    from executorch.extension.pybindings import _portable_lib
    # The pinned bindings expose this setter. Set it once, before creating any runner.
    _portable_lib._unsafe_reset_threadpool(1)
    return dict(**environment(), flatc=version, flatc_sha256=sha256(flatc),
                executorch_xnnpack_binary_sha256=sha256(_portable_lib.__file__),
                torch_git_version=torch.version.git_version, executorch_threadpool=1,
                torch_intraop_threads=torch.get_num_threads(), torch_interop_threads=torch.get_num_interop_threads())


def quantize(model, example, calibration):
    from executorch.backends.xnnpack.quantizer.xnnpack_quantizer import (
        XNNPACKQuantizer, get_symmetric_quantization_config)
    from torchao.quantization.pt2e.quantize_pt2e import convert_pt2e, prepare_pt2e

    quantizer = XNNPACKQuantizer().set_global(get_symmetric_quantization_config(is_per_channel=True))
    prepared = prepare_pt2e(torch.export.export(model, (example,), strict=True).module(), quantizer)
    for row in calibration:
        prepared(row.unsqueeze(0))
    return convert_pt2e(prepared)


def delegate_operators(blob):
    """Decode the exact serialized delegate payload using its own wheel's schema."""
    from executorch.backends.xnnpack.serialization.xnnpack_graph_serialize import XNNHeader

    header = XNNHeader.from_bytes(blob[:XNNHeader.EXPECTED_LENGTH])
    require(header.is_valid(), "Invalid XNNPACK header")
    schema = resources.files("executorch.backends.xnnpack.serialization").joinpath("schema.fbs")
    with tempfile.TemporaryDirectory() as temp, resources.as_file(schema) as schema_path:
        path = Path(temp, "graph.bin")
        path.write_bytes(blob[header.flatbuffer_offset:header.flatbuffer_offset + header.flatbuffer_size])
        subprocess.run([os.environ["FLATC_EXECUTABLE"], "--json", "--strict-json", "--defaults-json",
                        "-o", temp, schema_path, "--", path], check=True, capture_output=True)
        # flatc emits unquoted inf/-inf for the clamp bounds even in strict JSON mode.
        decoded = path.with_suffix(".json").read_text(encoding="utf-8")
        graph = json.loads(re.sub(r"(:\s*)(-?inf)(?=\s*[,}])", r'\1"\2"', decoded))
    types = {}
    for wrapped in graph["xvalues"]:
        value = wrapped["xvalue_union"]
        tensor = value.get("tensor_value", value)
        types[tensor["id_out"]] = tensor["datatype"].removeprefix("xnn_datatype_")
    return [dict(op=node["xnode_union_type"], output_range=node.get("output_min_max"), tensors={
        key: types[idx] for key, idx in node["xnode_union"].items()
        if key.endswith("_id") and idx in types}) for node in graph["xnodes"]]


def lower(module, example, folder):
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    from executorch.exir import to_edge_transform_and_lower
    from executorch.exir.schema import KernelCall, Tensor

    ep = torch.export.export(module, (example,), strict=True)
    torch.export.save(ep, folder / "exported.pt2")
    (folder / "exported_graph.txt").write_text(str(ep.graph), encoding="utf-8")
    edge = to_edge_transform_and_lower(ep, partitioner=[XnnpackPartitioner()])
    gm = edge.exported_program().graph_module
    (folder / "lowered_graph.txt").write_text(str(gm.graph), encoding="utf-8")
    report = delegation_report(edge)
    for delegate in report["delegates"]:
        child = gm.get_submodule(delegate["name"])
        delegate["serialized_operators"] = delegate_operators(child.processed_bytes)
    et = edge.to_executorch()
    pte = folder / "model.pte"
    pte.write_bytes(et.buffer)
    plan, = et.executorch_program.execution_plan
    report["runtime_delegates"] = [d.id for d in plan.delegates]
    require(report["runtime_delegates"] and all(n == "XnnpackBackend" for n in report["runtime_delegates"]),
            "Export requires executable XNNPACK delegation")
    report["runtime_fallback_operators"] = []
    for chain in plan.chains:
        for instruction in chain.instructions:
            call = instruction.instr_args
            if isinstance(call, KernelCall):
                op = plan.operators[call.op_index]
                values = [plan.values[i].val for i in call.args]
                report["runtime_fallback_operators"].append(dict(name=op.name, overload=op.overload,
                    tensor_dtypes=[v.scalar_type.name for v in values if isinstance(v, Tensor)]))
    affine = [op for d in report["delegates"] for op in d["serialized_operators"]
              if op["op"] in ("XNNConv2d", "XNNFullyConnected")]
    report["int8_affine_ops"] = sum(op["tensors"].get("input1_id") == "qint8" and
                                     op["tensors"].get("filter_id") in ("qint8", "qcint8") for op in affine)
    report["affine_ops"] = len(affine)
    report["pte_bytes"] = pte.stat().st_size
    report["pte_sha256"] = sha256(pte)
    write_json(folder / "delegation.json", report)
    return report


class Runner:
    def __init__(self, path):
        from executorch.runtime import Runtime

        start = time.perf_counter_ns()
        self.program = Runtime.get().load_program(str(path))
        self.method = self.program.load_method("forward")
        self.load_ns = time.perf_counter_ns() - start
        require(self.method is not None, "Missing ExecuTorch forward method")

    def __call__(self, tensor):
        output, = self.method.execute((tensor,))
        require(output.dtype == torch.float32 and output.shape == (1, 1), "Wrong runtime output")
        return output
