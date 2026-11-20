"""Package the Phase 6 selection and warm an immutable ExecuTorch release."""

import hashlib
import io
import json
import math
import re
import tempfile
import time
from importlib import metadata, resources
from pathlib import Path

from ids.contracts import load_json, validate_for_inference, validator
from ids.features import FEATURE_UNITS
from ids.preprocessing import Preprocessor


MODEL_ID = "cnn-unsw-ga-v1"
RELEASE_DIGEST = "9d43e81a2e906bda779c9bc1a53053800acc382851d24be270eb4854a5b0e5d6"
SCHEMAS = ("FeatureWindow.schema.json", "FeatureSequence.schema.json", "InferenceResult.schema.json")
FILES = {"model.pte", "preprocess.json", "feature_schema.json", "warmup.json", *SCHEMAS}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def valid_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise ValueError("Invalid model ID")
    return value


def checked_bytes(path, expected):
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError(f"Checksum mismatch for {path.name}")
    return data


def pack(run, destination):
    """Only the build host needs the Phase 6 evidence and Parquet reader."""
    import pyarrow.parquet as pq

    checks = load_json(run / "artifact_checksums.json")
    handoff = json.loads(checked_bytes(run / "handoff.json", checks["handoff.json"]))
    program = "ga_3/float32/model.pte"
    if (handoff["artifact"] != program or handoff["score_type"] != "uncalibrated_sigmoid"
            or handoff["final_threshold"] is not None):
        raise ValueError("Unexpected Phase 6 release selection")
    payload = {"model.pte": checked_bytes(run / program, handoff["pte_sha256"])}
    for name in ("preprocess.json", "feature_schema.json"):
        payload[name] = checked_bytes(run / "shared" / name, handoff["shared_artifacts"][name])
    contracts = resources.files("contracts")
    for name in SCHEMAS:
        payload[name] = canonical(load_json(contracts / "v1" / name))
    refs = "ga_3/float32/references.parquet"
    rows = pq.read_table(io.BytesIO(checked_bytes(run / refs, checks[refs]))).to_pylist()
    reference, = [row for row in rows if row["sample_id"] == "contract/idle_sequence"]
    idle = load_json(contracts / "fixtures" / "positive" / "idle_sequence.json")
    idle["model_id"] = MODEL_ID
    payload["warmup.json"] = canonical(dict(request=idle, score=reference["eager_score"]))
    manifest = dict(format=1, model_id=MODEL_ID, runtime="1.0.0",
                    files={name: digest(data) for name, data in payload.items()})
    payload["manifest.json"] = canonical(manifest)
    if digest(payload["manifest.json"]) != RELEASE_DIGEST:
        raise ValueError("Build differs from the registered Phase 7 release")
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / MODEL_ID
    with tempfile.TemporaryDirectory(dir=destination) as temp:
        stage = Path(temp) / "release"
        stage.mkdir()
        for name, data in payload.items():
            (stage / name).write_bytes(data)
        try:
            stage.rename(target)
        except OSError:
            if not target.is_dir() or any((target / k).read_bytes() != v for k, v in payload.items()):
                raise
    return target


class Bundle:
    def __init__(self, path):
        import torch
        from executorch.runtime import Runtime

        manifest = load_json(path / "manifest.json")
        self.model_id = valid_version(manifest["model_id"])
        self.identity = digest(canonical(manifest))
        if self.model_id == MODEL_ID and self.identity != RELEASE_DIGEST:
            raise ValueError("Manifest differs from the registered Phase 7 release")
        version = metadata.version("executorch")
        if (path.name != self.model_id or manifest["format"] != 1 or
                version != manifest["runtime"] or set(manifest["files"]) != FILES):
            raise ValueError("Incompatible model bundle")
        data = {name: checked_bytes(path / name, sha) for name, sha in manifest["files"].items()}
        for name in SCHEMAS:
            if json.loads(data[name]) != validator(name.split(".")[0]).schema:
                raise ValueError(f"Incompatible {name}")
        schema = json.loads(data["feature_schema.json"])
        if schema != load_json(resources.files("contracts") / "v1" / "feature_schema.json"):
            raise ValueError("Feature schema mismatch")
        p = json.loads(data["preprocess.json"])
        self.processor = Preprocessor(tuple(p["mean"]), tuple(p["std"]), tuple(p["feature_names"]),
                                      p["version"], p["fitted_on"])
        if (tuple(p["feature_units"]) != FEATURE_UNITS or p["epsilon"] != 1e-6 or
                p["variance_ddof"] != 0 or p["feature_schema"] != schema["feature_schema"] or
                p["fitted_on"] != "unique_training_sample_windows"):
            raise ValueError("Incompatible preprocessing parameters")
        self.program = Runtime.get().load_program(data["model.pte"])
        self.method = self.program.load_method("forward")
        self.metadata = dict(model_id=self.model_id, task="attack_associated_traffic",
                             feature_schema="device_window_v1", input_shape=[1, 16, 8],
                             preprocess_hash=manifest["files"]["preprocess.json"],
                             model_hash=manifest["files"]["model.pte"], runtime_version=version,
                             calibration_status="uncalibrated")
        reference = json.loads(data["warmup.json"])
        validate_for_inference(reference["request"], self.model_id)
        with torch.inference_mode():
            score, _ = self.predict(reference["request"])
        if not math.isclose(score, reference["score"], rel_tol=0, abs_tol=0.0001):
            raise ValueError("Warm-up reference score mismatch")

    def predict(self, request):
        import torch

        tensor = self.processor.transform_validated(request)
        with torch.inference_mode():
            start = time.perf_counter_ns()
            output, = self.method.execute((tensor,))
            elapsed = (time.perf_counter_ns() - start) / 1e6
            if output.shape != (1, 1) or output.dtype != torch.float32:
                raise ValueError("Unexpected model output")
            logit = output.item()
        if not math.isfinite(logit):
            raise ValueError("Nonfinite model output")
        z = math.exp(-abs(logit))
        return (1 / (1 + z) if logit >= 0 else z / (1 + z)), elapsed
