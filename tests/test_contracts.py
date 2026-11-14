from copy import deepcopy
from pathlib import Path

import pytest

from ids.contracts import Abstention, ContractError, load_json, validate, validate_for_inference, validator

ROOT = Path(__file__).resolve().parents[1]
INDEX = load_json(ROOT / "contracts/fixtures/index.json")


@pytest.mark.parametrize("case", INDEX["cases"], ids=lambda c: Path(c["path"]).stem)
def test_fixtures(case):
    value = load_json(ROOT / case["path"])
    def check():
        if case["kind"] == "FeatureSequence":
            return validate_for_inference(value, "cnn-phase0-untrained")
        return validate(case["kind"], value)
    if case["expected"] == "valid":
        check()
    else:
        with pytest.raises(ContractError) as error:
            check()
        assert error.value.code == case["error_code"]
        assert isinstance(error.value, Abstention) == (case["expected"] == "abstain")


@pytest.mark.parametrize("kind", ["FeatureWindow", "FeatureSequence", "InferenceResult"])
def test_schema_validity(kind):
    validator(kind).check_schema(validator(kind).schema)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_in_memory(value):
    window = load_json(ROOT / "contracts/fixtures/positive/window.json")
    window["values"][12] = value
    with pytest.raises(ContractError, match="finite"):
        validate("FeatureWindow", window)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_nonstandard_json_rejected(tmp_path, token):
    path = tmp_path / "bad.json"
    path.write_text('{"value":'+token+'}')
    with pytest.raises(ContractError):
        load_json(path)


def test_structural_validation_precedes_abstention():
    seq = load_json(ROOT / "contracts/fixtures/negative/invalid_coverage.json")
    seq["windows"][0]["values"] = [0]
    with pytest.raises(ContractError) as error:
        validate_for_inference(seq, seq["model_id"])
    assert not isinstance(error.value, Abstention)
    assert error.value.code == "INVALID_INPUT"


def test_future_feature_version_nested_error():
    seq = load_json(ROOT / "contracts/fixtures/positive/sequence.json")
    seq["windows"][0]["feature_schema"] = "device_window_v2"
    with pytest.raises(ContractError) as error:
        validate_for_inference(seq, seq["model_id"])
    assert error.value.code == "SCHEMA_MISMATCH"
