import csv
import gzip
import io
import json

import pytest

from evaluation.run import HERE, read_protocol, summarize


def test_locked_report_recomputes_from_scores():
    plan, checksum = read_protocol()
    payload = gzip.decompress((HERE / "scores.csv.gz").read_bytes())
    report = summarize(plan, checksum, payload)
    assert report == json.loads((HERE / "results.json").read_bytes())
    assert report["compact_vs_unpruned"]["within_limit_on_this_block"] is False


def test_duplicate_history_rejected_even_when_class_totals_match():
    plan, checksum = read_protocol()
    with gzip.open(HERE / "scores.csv.gz", "rt", newline="") as source:
        rows = list(csv.DictReader(source))
    rows[1]["sample_id"] = rows[0]["sample_id"]
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    with pytest.raises(ValueError, match="Duplicate test history"):
        summarize(plan, checksum, out.getvalue().encode())
