"""Regenerate reviewable v1 schemas and synthetic contract fixtures (no labels)."""

from copy import deepcopy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://ai-soc.local/contracts/v1/"
ID = {"type": "string", "minLength": 1, "maxLength": 128, "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"}
INT = {"type": "integer", "minimum": 0, "maximum": 9223372036854775807}
TIME = {"type": "integer", "minimum": -9223372036854775808, "maximum": 9223372036854775807}
NUM = {"type": "number", "minimum": 0}
ERRORS = ["INVALID_INPUT", "SCHEMA_MISMATCH", "HISTORY_DISCONTINUITY", "MODEL_MISMATCH",
          "INVALID_COVERAGE", "INSUFFICIENT_HISTORY", "MODEL_NOT_READY", "OVERLOADED",
          "DEADLINE_EXCEEDED", "REQUEST_ID_CONFLICT", "PREPROCESS_ERROR", "RUNTIME_ERROR"]
ABSTAIN = ["INVALID_COVERAGE", "INSUFFICIENT_HISTORY"]


def obj(props, **extra):
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False, **extra}


def save(path, value):
    path = ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def schema(name, props, **extra):
    value = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": BASE + name + ".schema.json",
             "title": name, **obj(props, **extra)}
    save(f"contracts/v1/{name}.schema.json", value)


def main():
    quality = obj({"valid": {"type": "boolean"}, "reasons": {"type": "array", "maxItems": 32,
        "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 128}}},
        allOf=[{"if": {"properties": {"valid": {"const": True}}},
                "then": {"properties": {"reasons": {"maxItems": 0}}},
                "else": {"properties": {"reasons": {"minItems": 1}}}}])
    schema("FeatureWindow", {
        "schema_version": {"const": "1.0"}, "feature_schema": {"const": "device_window_v1"},
        **{key: ID for key in ["window_id", "gateway_id", "boot_id", "capture_session_id", "device_id"]},
        **{key: INT for key in ["binding_revision", "sequence_number", "enforcement_revision"]},
        "window_start_ms": TIME, "window_end_ms": TIME,
        "observed_mode": {"enum": ["live", "offline"]}, "quality": quality,
        "values": {"type": "array", "minItems": 16, "maxItems": 16,
                   "prefixItems": [INT] * 12 + [NUM] * 4, "items": False},
    })
    schema("FeatureSequence", {"schema_version": {"const": "1.0"}, "request_id": ID, "model_id": ID,
        "windows": {"type": "array", "minItems": 8, "maxItems": 8,
                    "items": {"$ref": BASE + "FeatureWindow.schema.json"}}})
    schema("InferenceResult", {
        "schema_version": {"const": "1.0"},
        **{key: ID for key in ["request_id", "device_id", "last_window_id", "model_id"]},
        "binding_revision": INT, "enforcement_revision": INT,
        "task": {"const": "attack_associated_traffic"}, "status": {"enum": ["ok", "abstain", "error"]},
        "attack_score": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
        "score_type": {"const": "uncalibrated_sigmoid"}, "inference_ms": NUM,
        "error_code": {"enum": [None] + ERRORS},
    }, allOf=[
        {"if": {"properties": {"status": {"const": "ok"}}},
         "then": {"properties": {"attack_score": {"type": "number"}, "error_code": {"const": None}}},
         "else": {"properties": {"attack_score": {"type": "null"}, "error_code": {"type": "string"}}}},
        {"if": {"properties": {"status": {"const": "abstain"}}},
         "then": {"properties": {"error_code": {"enum": ABSTAIN}}}},
        {"if": {"properties": {"status": {"const": "error"}}},
         "then": {"properties": {"error_code": {"enum": [e for e in ERRORS if e not in ABSTAIN]}}}},
    ])
    from ids.features import FEATURE_NAMES, FEATURE_UNITS
    save("contracts/v1/feature_schema.json", {"feature_schema": "device_window_v1", "schema_version": "1.0",
        "features": [{"index": i, "name": n, "unit": u, "integral": i < 12}
                     for i, (n, u) in enumerate(zip(FEATURE_NAMES, FEATURE_UNITS))],
        "window_ms": 1000, "history_rows": 8, "raw_shape": [8, 16], "tensor_shape": [1, 16, 8],
        "dtype": "float32", "time_interval": "[start,end)", "statistics": "population",
        "preprocessing_owner": "ids", "transform_version": "log1p_population_zscore_v1"})
    w = {"schema_version": "1.0", "feature_schema": "device_window_v1", "window_id": "boot7-device12-103",
         "gateway_id": "gw-lab-01", "boot_id": "boot7", "capture_session_id": "capture-004",
         "device_id": "device12", "binding_revision": 3, "sequence_number": 103,
         "window_start_ms": 1794376800000, "window_end_ms": 1794376801000,
         "observed_mode": "live", "enforcement_revision": 0, "quality": {"valid": True, "reasons": []},
         "values": [5, 3, 300, 120, 1, 5, 5, 0, 0, 5, 0, 3, 60, 0, 75, 25]}
    seq = {"schema_version": "1.0", "request_id": "req-device12-110", "model_id": "cnn-phase0-untrained", "windows": []}
    for i in range(8):
        row = deepcopy(w)
        row.update(window_id=f"boot7-device12-{103+i}", sequence_number=103+i,
                   window_start_ms=w["window_start_ms"]+i*1000, window_end_ms=w["window_end_ms"]+i*1000)
        seq["windows"].append(row)
    result = {"schema_version": "1.0", "request_id": seq["request_id"], "device_id": "device12", "binding_revision": 3,
              "last_window_id": seq["windows"][-1]["window_id"], "enforcement_revision": 0,
              "model_id": seq["model_id"], "status": "ok", "task": "attack_associated_traffic",
              "attack_score": 0.5, "score_type": "uncalibrated_sigmoid", "inference_ms": 0, "error_code": None}
    cases = []
    def fixture(name, kind, payload, expected="valid", code=None):
        rel = f"contracts/fixtures/{'positive' if expected == 'valid' else 'negative'}/{name}.json"
        save(rel, payload)
        cases.append({"path": rel, "kind": kind, "expected": expected, "error_code": code})
    fixture("window", "FeatureWindow", w)
    fixture("sequence", "FeatureSequence", seq)
    idle = deepcopy(seq)
    for row in idle["windows"]:
        row["values"] = [0]*16
    fixture("idle_sequence", "FeatureSequence", idle)
    one = deepcopy(w); one["values"] = [1,0,60,0,1,1,1,0,0,1,0,0,60,0,0,0]
    fixture("single_packet", "FeatureWindow", one)
    degraded = deepcopy(w); degraded["quality"] = {"valid": False, "reasons": ["CAPTURE_DROP"]}
    fixture("degraded_window", "FeatureWindow", degraded)
    fixture("ok_result", "InferenceResult", result)
    for status, code in [("abstain", "INVALID_COVERAGE"), ("error", "RUNTIME_ERROR")]:
        r = deepcopy(result); r.update(status=status, attack_score=None, error_code=code)
        fixture(status+"_result", "InferenceResult", r)
    for name, field, value, code in [
        ("wrong_version", "schema_version", "2.0", "SCHEMA_MISMATCH"),
        ("wrong_features", "feature_schema", "device_window_v2", "SCHEMA_MISMATCH"),
        ("short_values", "values", [0]*15, "INVALID_INPUT"),
        ("negative_values", "values", [-1]+[0]*15, "INVALID_INPUT"),
        ("fractional_count", "values", [0.5]+[0]*15, "INVALID_INPUT"),
        ("boolean_count", "values", [True]+[0]*15, "INVALID_INPUT"),
        ("bad_duration", "window_end_ms", w["window_end_ms"]+1, "INVALID_INPUT"),
        ("unaligned", "window_start_ms", w["window_start_ms"]+1, "INVALID_INPUT"),
        ("oversized_id", "device_id", "a"*129, "INVALID_INPUT"),
        ("timestamp_overflow", "window_start_ms", 2**63, "INVALID_INPUT"),
        ("valid_with_reason", "quality", {"valid": True, "reasons": ["CAPTURE_DROP"]}, "INVALID_INPUT"),
        ("invalid_without_reason", "quality", {"valid": False, "reasons": []}, "INVALID_INPUT"),
    ]:
        x = deepcopy(w); x[field] = value; fixture(name, "FeatureWindow", x, "error", code)
    for field in ["device_id", "gateway_id", "boot_id", "capture_session_id", "binding_revision", "enforcement_revision", "observed_mode"]:
        x = deepcopy(seq); x["windows"][4][field] = 99 if isinstance(w[field], int) else ("offline" if field == "observed_mode" else "changed")
        fixture("mixed_"+field, "FeatureSequence", x, "error", "HISTORY_DISCONTINUITY")
    for name in ["time_gap", "sequence_gap", "duplicate_window", "short_history", "wrong_model", "invalid_coverage"]:
        x = deepcopy(seq); code = "HISTORY_DISCONTINUITY"; expected = "error"
        if name == "time_gap":
            x["windows"][4]["window_start_ms"] += 1000; x["windows"][4]["window_end_ms"] += 1000
        elif name == "sequence_gap": x["windows"][4]["sequence_number"] += 1
        elif name == "duplicate_window": x["windows"][4]["window_id"] = x["windows"][0]["window_id"]
        elif name == "short_history": x["windows"].pop(); code = "INVALID_INPUT"
        elif name == "wrong_model": x["model_id"] = "other-model"; code = "MODEL_MISMATCH"
        else: x["windows"][4]["quality"] = degraded["quality"]; code = "INVALID_COVERAGE"; expected = "abstain"
        fixture(name, "FeatureSequence", x, expected, code)
    for name, fields in [
        ("error_has_score", {"status": "error", "error_code": "RUNTIME_ERROR"}),
        ("ok_null_score", {"attack_score": None}), ("score_out_of_range", {"attack_score": 1.1}),
        ("ok_has_error", {"error_code": "RUNTIME_ERROR"}),
        ("abstain_runtime_error", {"status": "abstain", "attack_score": None, "error_code": "RUNTIME_ERROR"}),
        ("unknown_field", {"attack_family": "invented"}),
    ]:
        x = deepcopy(result); x.update(fields); fixture(name, "InferenceResult", x, "error", "INVALID_INPUT")
    save("contracts/fixtures/index.json", {"note": "Synthetic validation cases, not benign/attack labels or model measurements", "cases": cases})
    problem = obj({"schema_version": {"const": "1.0"}, "status": {"const": "error"},
                   "request_id": {"type": ["string", "null"], "maxLength": 128},
                   "error_code": {"enum": ERRORS + ["UNAUTHORIZED"]},
                   "detail": {"type": "string", "maxLength": 512}})
    result_ref = {"$ref": "./v1/InferenceResult.schema.json"}
    error_response = {"description": "Explicit failure, no benign fallback. Problem when identity is not trustworthy.",
                      "content": {"application/json": {"schema": {"oneOf": [result_ref, {"$ref": "#/components/schemas/Problem"}]}}}}
    metadata = obj({"model_id": ID, "task": {"const": "attack_associated_traffic"},
        "feature_schema": {"const": "device_window_v1"}, "input_shape": {"const": [1,16,8]},
        "preprocess_hash": {"type": "string"}, "model_hash": {"type": "string"},
        "runtime_version": {"type": "string"}, "calibration_status": {"const": "uncalibrated"}})
    health = obj({"ready": {"type": "boolean"}, "model_loading": {"type": "boolean"},
                  "recent_errors": {"type": "array", "maxItems": 32, "items": {"type": "string"}}})
    save("contracts/openapi.json", {"openapi": "3.1.0", "info": {"title": "IDS Phase 7 boundary specification", "version": "1.0",
         "description": "Authenticated local inference worker. X-IDS-History-Epoch changes on worker restart or bundle change."},
         "servers": [{"url": "http://127.0.0.1:8000", "description": "Gateway loopback default"}],
         "security": [{"ServiceCredential": []}],
         "components": {"securitySchemes": {"ServiceCredential": {"type": "http", "scheme": "bearer"}},
                        "schemas": {"Problem": problem}},
         "paths": {
             "/v1/predict": {"post": {"operationId": "predict", "requestBody": {"required": True,
                  "content": {"application/json": {"schema": {"$ref": "./v1/FeatureSequence.schema.json"}}}},
                  "responses": {"200": {"description": "ok or abstain (score null on abstain)",
                      "content": {"application/json": {"schema": result_ref}}},
                      **{str(code): error_response for code in [401,409,422,500,503,504]}}}},
             "/v1/metadata": {"get": {"operationId": "metadata", "responses": {
                 "200": {"description": "Loaded bundle identity", "content": {"application/json": {"schema": metadata}}},
                 "401": error_response, "503": error_response}}},
             "/v1/health": {"get": {"operationId": "health", "responses": {
                 "200": {"description": "Readiness and recent errors", "content": {"application/json": {"schema": health}}},
                 "401": error_response}}},
         }})


if __name__ == "__main__":
    main()
