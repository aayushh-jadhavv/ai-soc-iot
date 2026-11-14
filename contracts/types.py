"""Python wire types for schema 1.0. Runtime checks live in ids.contracts.

These hints do not validate JSON, finiteness, lengths or cross-window invariants.
"""

from typing import Literal, TypedDict


class Quality(TypedDict):
    valid: bool
    reasons: list[str]


class FeatureWindow(TypedDict):
    schema_version: Literal["1.0"]
    feature_schema: Literal["device_window_v1"]
    window_id: str
    gateway_id: str
    boot_id: str
    capture_session_id: str
    device_id: str
    binding_revision: int
    sequence_number: int
    window_start_ms: int
    window_end_ms: int
    observed_mode: Literal["live", "offline"]
    enforcement_revision: int
    quality: Quality
    values: list[int | float]


class FeatureSequence(TypedDict):
    schema_version: Literal["1.0"]
    request_id: str
    model_id: str
    windows: list[FeatureWindow]


class InferenceResult(TypedDict):
    schema_version: Literal["1.0"]
    request_id: str
    device_id: str
    binding_revision: int
    last_window_id: str
    enforcement_revision: int
    model_id: str
    status: Literal["ok", "abstain", "error"]
    task: Literal["attack_associated_traffic"]
    attack_score: float | None
    score_type: Literal["uncalibrated_sigmoid"]
    inference_ms: float
    error_code: str | None
