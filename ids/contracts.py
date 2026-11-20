"""Strict JSON validation and cross-field invariants omitted by JSON Schema.

Validation errors are not inference scores. Syntactically valid degraded coverage
raises Abstention only at the inference boundary, after structural validation.
"""

import json
import math
from functools import lru_cache
from importlib.resources import files

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


class ContractError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class Abstention(ContractError):
    pass


def load_json(path):
    def reject(token):
        raise ContractError("INVALID_INPUT", f"Non-JSON numeric token: {token}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject)
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("INVALID_INPUT", str(exc)) from exc


@lru_cache
def validator(kind):
    schemas = [json.loads(p.read_text(encoding="utf-8"))
               for p in files("contracts").joinpath("v1").iterdir()
               if p.name.endswith(".schema.json")]
    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in schemas)
    schema = next(s for s in schemas if s["title"] == kind)
    return Draft202012Validator(schema, registry=registry)


def _finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError("INVALID_INPUT", "Every numeric value must be finite")
    if isinstance(value, dict):
        for v in value.values():
            _finite(v)
    elif isinstance(value, list):
        for v in value:
            _finite(v)


def _window_interval(window):
    if window["window_start_ms"] % 1000 or window["window_end_ms"] - window["window_start_ms"] != 1000:
        raise ContractError("INVALID_INPUT", "Windows must be aligned one-second intervals")


def validate(kind, value):
    _finite(value)
    if kind == "FeatureSequence" and isinstance(value, dict) and isinstance(value.get("windows"), list):
        for window in value["windows"]:
            if isinstance(window, dict) and (window.get("schema_version", "1.0") != "1.0" or
                                            window.get("feature_schema", "device_window_v1") != "device_window_v1"):
                raise ContractError("SCHEMA_MISMATCH", "Unsupported nested window version")
    if isinstance(value, dict) and value.get("schema_version", "1.0") != "1.0":
        raise ContractError("SCHEMA_MISMATCH", "Only wire schema 1.0 is supported")
    if isinstance(value, dict) and value.get("feature_schema", "device_window_v1") != "device_window_v1":
        raise ContractError("SCHEMA_MISMATCH", "Unsupported feature schema")
    errors = sorted(validator(kind).iter_errors(value), key=lambda e: str(e.path))
    if errors:
        raise ContractError("INVALID_INPUT", errors[0].message)
    if kind == "FeatureWindow":
        _window_interval(value)
    elif kind == "FeatureSequence":
        windows = value["windows"]
        same = ("gateway_id", "boot_id", "capture_session_id", "device_id",
                "binding_revision", "enforcement_revision", "feature_schema", "observed_mode", "schema_version")
        for w in windows:
            # The sequence schema already validated every nested window via $ref.
            _window_interval(w)
            if any(w[k] != windows[0][k] for k in same):
                raise ContractError("HISTORY_DISCONTINUITY", "Identity/session/revision changed")
        if len({w["window_id"] for w in windows}) != 8:
            raise ContractError("HISTORY_DISCONTINUITY", "Duplicate window IDs")
        for prev, cur in zip(windows, windows[1:]):
            if cur["window_start_ms"] != prev["window_end_ms"] or cur["sequence_number"] != prev["sequence_number"] + 1:
                raise ContractError("HISTORY_DISCONTINUITY", "Nonconsecutive time/sequence")
    return value


def validate_for_inference(value, model_id):
    validate("FeatureSequence", value)
    return check_model_and_coverage(value, model_id)


def check_model_and_coverage(value, model_id):
    """Apply model and quality checks after structural validation."""
    if value["model_id"] != model_id:
        raise ContractError("MODEL_MISMATCH", "Requested model is not loaded")
    if any(not w["quality"]["valid"] for w in value["windows"]):
        raise Abstention("INVALID_COVERAGE", "Eight fresh valid windows are required")
    return value
