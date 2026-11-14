import csv
import json

import pyarrow.parquet as pq
import pytest

from ids.run_logging import RunLogger


def test_durable_run_records_and_no_overwrite(tmp_path):
    out = tmp_path / "run"
    log = RunLogger(out, {"phase": 0, "trained": False})
    log.event("test", valid=True, name="named delegate")
    assert json.loads((out / "events.jsonl").read_text())["name"] == "named delegate"
    log.write_table("ga_candidates", [])
    log.write_table("predictions", [])
    assert pq.read_table(out / "predictions.parquet").num_rows == 0
    with pytest.raises(FileExistsError):
        log.write_table("predictions", [])
    with pytest.raises(FileExistsError):
        RunLogger(out, {})
    log.finish("passed")
    assert json.loads((out / "run_manifest.json").read_text())["status"] == "passed"
    assert list(csv.DictReader((out / "epoch_metrics.csv").open())) == []
    with pytest.raises(ValueError):
        log.event("bad", value=float("nan"))
