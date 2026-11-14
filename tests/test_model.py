from pathlib import Path

import numpy as np
import pytest
import torch

from ids.contracts import Abstention, load_json
from ids.model import TemporalCNN
from ids.preprocessing import Preprocessor

ROOT = Path(__file__).resolve().parents[1]


def test_architecture_and_export_batch_one():
    torch.manual_seed(1729)
    model = TemporalCNN().eval()
    assert sum(p.numel() for p in model.conv1.parameters()) == 3136
    assert sum(p.numel() for p in model.conv2.parameters()) == 6176
    assert sum(p.numel() for p in model.output.parameters()) == 33
    assert sum(p.numel() for p in model.parameters()) == 9345
    x = torch.randn(1, 16, 8)
    with torch.inference_mode():
        ep = torch.export.export(model, (x,))
        torch.testing.assert_close(ep.module()(x), model(x))
        assert model(x).shape == (1, 1)
        with pytest.raises(AssertionError, match="Guard failed"):
            ep.module()(torch.randn(2, 16, 8))


def test_preprocessing_known_value_axis_and_floor():
    seq = load_json(ROOT / "contracts/fixtures/positive/idle_sequence.json")
    # Positive synthetic continuous feature; expected log1p(3)=log(4).
    seq["windows"][3]["values"][12] = 3
    std = [2.0] * 16; std[15] = 0.0
    pre = Preprocessor(tuple([1.0] * 16), tuple(std))
    tensor = pre.transform(seq, model_id=seq["model_id"])
    assert tensor.dtype == torch.float32
    assert tensor.shape == (1,16,8)
    assert tensor.is_contiguous()
    assert tensor[0,12,3].item() == pytest.approx((np.log(4)-1)/2)
    assert tensor[0,12,2].item() == -0.5
    assert tensor[0,15,0].item() == -1_000_000
    assert seq["windows"][3]["values"][12] == 3


def test_preprocessing_rejects_degraded_and_bad_parameters():
    pre = Preprocessor(tuple([0.0]*16), tuple([1.0]*16))
    seq = load_json(ROOT / "contracts/fixtures/negative/invalid_coverage.json")
    with pytest.raises(Abstention):
        pre.transform(seq, model_id=seq["model_id"])
    with pytest.raises(ValueError):
        Preprocessor(tuple([0.0]*16), tuple([-1.0]*16))
    with pytest.raises(ValueError):
        Preprocessor(tuple([float("nan")]*16), tuple([1.0]*16))
