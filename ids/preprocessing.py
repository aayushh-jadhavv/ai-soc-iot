"""IDS owns preprocessing exactly once; synthetic parameters are smoke-only."""

from dataclasses import dataclass

import numpy as np
import torch

from ids.contracts import ContractError, validate_for_inference
from ids.features import FEATURE_NAMES


@dataclass(frozen=True)
class Preprocessor:
    mean: tuple[float, ...]
    std: tuple[float, ...]
    feature_names: tuple[str, ...] = FEATURE_NAMES
    version: str = "log1p_population_zscore_v1"
    fitted_on: str = "synthetic_smoke_only"

    def __post_init__(self):
        if self.feature_names != FEATURE_NAMES or self.version != "log1p_population_zscore_v1":
            raise ValueError("Preprocessing schema/transform mismatch")
        if len(self.mean) != 16 or len(self.std) != 16:
            raise ValueError("Exactly 16 means and population standard deviations required")
        if not np.isfinite(self.mean).all() or not np.isfinite(self.std).all() or np.any(np.asarray(self.std) < 0):
            raise ValueError("Invalid preprocessing parameters")

    def transform(self, request, *, model_id):
        validate_for_inference(request, model_id)
        try:
            raw = np.asarray([w["values"] for w in request["windows"]], dtype=np.float64)
            with np.errstate(over="ignore", invalid="ignore"):
                z = (np.log1p(raw) - np.asarray(self.mean)) / np.maximum(self.std, 1e-6)
                result = np.ascontiguousarray(z.T[None], dtype=np.float32)
        except (ValueError, OverflowError) as exc:
            raise ContractError("PREPROCESS_ERROR", "Cannot represent raw values safely") from exc
        if not np.isfinite(result).all():
            raise ContractError("PREPROCESS_ERROR", "Transformed values exceed float32 range")
        return torch.from_numpy(result)
