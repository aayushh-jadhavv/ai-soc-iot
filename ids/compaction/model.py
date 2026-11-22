"""Reconstruct ordinary dense modules, with no masks or pruning hooks."""

import numpy as np
import torch
from torch import nn

from ids.ga.masks import Mask, masked_forward
from ids.ga.search import array_hash
from ids.model import TemporalCNN
from ids.training.data import require
from ids.training.train import weight_hash

ATOL = 1e-6
RTOL = 1e-5
SYNTHETIC_SEED = 1729


def channel_map(mask):
    return dict(conv1=[i for i, bit in enumerate(mask.conv1) if bit],
                conv2=[i for i, bit in enumerate(mask.conv2) if bit],
                order="ascending original channel index", mask=mask.code)


def describe(model):
    require(type(model) is TemporalCNN, "Only the registered TemporalCNN is supported")
    c1, c2, out = model.conv1, model.conv2, model.output
    require(type(c1) is nn.Conv1d and type(c2) is nn.Conv1d and type(out) is nn.Linear,
            "Ordinary Conv1d and Linear modules required")
    require(c1.in_channels == 16 and c2.in_channels == c1.out_channels and
            out.in_features == c2.out_channels and out.out_features == 1, "Invalid channel wiring")
    require(all(c.kernel_size == (3,) and c.stride == (1,) and c.padding == (1,) and
                c.dilation == (1,) and c.groups == 1 and c.padding_mode == "zeros"
                for c in (c1, c2)), "Unexpected convolution configuration")
    require(all(c.bias is not None for c in (c1, c2, out)), "All affine biases are required")
    require(not any(m._forward_hooks or m._forward_pre_hooks for m in model.modules()) and
            not list(model.buffers()), "Masked/reparameterized modules are not compact artifacts")
    expected = {"conv1.weight", "conv1.bias", "conv2.weight", "conv2.bias", "output.weight", "output.bias"}
    require(set(model.state_dict()) == expected, "Unexpected model state")
    require(all(p.device.type == "cpu" and p.dtype == torch.float32 and
                bool(torch.isfinite(p).all()) for p in model.parameters()), "Finite CPU float32 weights required")
    return dict(version="phase5_architecture_v1", kind="temporal_cnn", input_shape=[1, 16, 8],
                channels=[c1.out_channels, c2.out_channels], kernel_size=3, stride=1, padding=1,
                bias=True, activation="ReLU", pooling="global temporal mean", output="binary logit",
                dtype="float32", masks=False,
                state_shapes={k: list(v.shape) for k, v in model.state_dict().items()})


def physical_cost(model):
    arch = describe(model)
    c1, c2 = arch["channels"]
    return dict(parameters=sum(p.numel() for p in model.parameters()),
                tensor_bytes=sum(p.numel() * p.element_size() for p in model.parameters()),
                conv_linear_macs_per_sample=8 * 16 * c1 * 3 + 8 * c1 * c2 * 3 + c2,
                mac_scope="analytical dense Conv1d/Linear only; excludes bias, ReLU and mean",
                channels=[c1, c2])


def rebuild(parent, mask):
    require(isinstance(mask, Mask), "A validated Phase 4 mask is required")
    require(describe(parent)["channels"] == [64, 32], "A 64/32 parent is required")
    mapping = channel_map(mask)
    i, j = torch.tensor(mapping["conv1"]), torch.tensor(mapping["conv2"])
    compact = TemporalCNN(mask.retained)
    with torch.no_grad():
        compact.conv1.weight.copy_(parent.conv1.weight.index_select(0, i))
        compact.conv1.bias.copy_(parent.conv1.bias.index_select(0, i))
        compact.conv2.weight.copy_(parent.conv2.weight.index_select(0, j).index_select(1, i))
        compact.conv2.bias.copy_(parent.conv2.bias.index_select(0, j))
        compact.output.weight.copy_(parent.output.weight.index_select(1, j))
        compact.output.bias.copy_(parent.output.bias)
    compact.eval()
    describe(compact)
    return compact


def synthetic_samples():
    rng = np.random.default_rng(SYNTHETIC_SEED)
    # Bias-only, positive/negative, random, and every channel/time impulse.
    impulses = np.eye(128, dtype=np.float32).reshape(128, 16, 8)
    return np.concatenate([np.zeros((1, 16, 8), dtype=np.float32),
                           np.ones((1, 16, 8), dtype=np.float32),
                           -np.ones((1, 16, 8), dtype=np.float32),
                           rng.normal(size=(32, 16, 8)).astype(np.float32), impulses, -impulses])


class WiringError(ValueError):
    def __init__(self, report):
        super().__init__("Compact/masked logit parity failed; stop before training")
        self.report = report


@torch.inference_mode()
def check_equivalence(parent, compact, mask, samples):
    """All fixed real/synthetic samples, both deployed-size and validation batches."""
    parent.eval()
    compact.eval()
    before = weight_hash(parent.state_dict())
    checks = []
    with torch.autocast("cpu", enabled=False):
        for name, array in samples.items():
            require(array.dtype == np.float32 and array.ndim == 3 and array.shape[1:] == (16, 8)
                    and len(array) > 0 and np.isfinite(array).all(), "Invalid equivalence fixture")
            x = torch.from_numpy(array)
            for batch_size in (1, 1024):
                reference = torch.cat([masked_forward(parent, b, mask) for b in x.split(batch_size)])
                actual = torch.cat([compact(b) for b in x.split(batch_size)])
                error = (actual.double() - reference.double()).abs()
                limit = ATOL + RTOL * reference.double().abs()
                finite = bool(torch.isfinite(actual).all() and torch.isfinite(reference).all())
                passed = finite and bool(torch.all(error <= limit))
                checks.append(dict(fixture=name, batch_size=batch_size, samples=len(x), passed=passed,
                    finite=finite, max_absolute_error=float(error.max()) if finite else None,
                    max_error_to_tolerance=float((error / limit).max()) if finite else None,
                    threshold_crossings=int(((actual >= 0) != (reference >= 0)).sum()),
                    reference_sha256=array_hash(reference.numpy()), compact_sha256=array_hash(actual.numpy()),
                    input_sha256=array_hash(array)))
    require(weight_hash(parent.state_dict()) == before, "Parent weights changed during equivalence check")
    report = dict(passed=all(c["passed"] for c in checks), atol=ATOL, rtol=RTOL,
                  comparison="abs(compact - masked) <= atol + rtol * abs(masked)", checks=checks)
    if not report["passed"]:
        raise WiringError(report)
    return report
