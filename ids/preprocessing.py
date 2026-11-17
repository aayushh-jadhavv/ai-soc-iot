"""IDS owns log1p population standardization exactly once."""

from dataclasses import dataclass

import numpy as np
import hashlib
import json

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
        import torch  # Data extraction/fitting does not require the training runtime.
        validate_for_inference(request, model_id)
        try:
            raw = np.asarray([w["values"] for w in request["windows"]], dtype=np.float64)
            result = self.transform_array(raw[None])
        except (ValueError, OverflowError) as exc:
            raise ContractError("PREPROCESS_ERROR", "Cannot represent raw values safely") from exc
        if not np.isfinite(result).all():
            raise ContractError("PREPROCESS_ERROR", "Transformed values exceed float32 range")
        return torch.from_numpy(result)

    def transform_array(self, raw):
        """Validated dataset arrays [N,8,16] -> float32 [N,16,8]."""
        raw = np.asarray(raw, dtype=np.float64)
        if raw.ndim != 3 or raw.shape[1:] != (8, 16):
            raise ValueError("Expected raw [N,8,16] measurements")
        if not np.isfinite(raw).all() or (raw < 0).any():
            raise ValueError("Cannot normalize invalid measurements")
        with np.errstate(over="ignore", invalid="ignore"):
            z = (np.log1p(raw) - self.mean) / np.maximum(self.std, 1e-6)
            result = np.ascontiguousarray(z.transpose(0, 2, 1), dtype=np.float32)
        if not np.isfinite(result).all():
            raise ValueError("Transformed values exceed float32 range")
        return result


def fit_unique_training_windows(windows):
    """Fit each physical training window once, even in overlapping samples.

    Callers pass only retained sample constituent windows, with explicit role,
    ID, values and validity. Non-training or invalid rows fail closed.
    """
    unique = {}
    for row in windows:
        if row["role"] != "train" or not row["valid"]:
            raise ValueError("Fitting accepts valid training windows only")
        values = tuple(row["values"])
        if len(values) != 16 or not np.isfinite(values).all() or min(values) < 0:
            raise ValueError("Invalid fit window")
        key = row["window_id"]
        if key in unique and unique[key] != values:
            raise ValueError("Window ID collision with different measurements")
        unique[key] = values
    if not unique:
        raise ValueError("No eligible unique training windows")
    ids = sorted(unique)
    data = np.log1p(np.asarray([unique[key] for key in ids], dtype=np.float64))
    mean, std = data.mean(axis=0), data.std(axis=0, ddof=0)
    fingerprint = hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest()
    processor = Preprocessor(tuple(mean), tuple(std), fitted_on="unique_training_sample_windows")
    return processor, dict(unique_training_window_count=len(ids), fit_window_ids_sha256=fingerprint,
                           fit_window_ids=ids, variance_ddof=0, epsilon=1e-6)
