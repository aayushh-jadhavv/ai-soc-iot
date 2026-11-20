"""Replay the captured windows through the same request builder and client as main.py."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
from urllib.request import Request, urlopen

from cnn_client import CNNClient
from config import IDS_BASE_URL, IDS_TOKEN_FILE
from contracts import canonical_request, new_predict_request


HANDOFF_DIGEST = "e3f135f4148754b6d46d254038eec15586587ced5cd19934c8f2aae31255cea4"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--report", type=Path, help="Save machine, worker and response details")
    args = parser.parse_args()
    original = args.fixture.read_bytes()
    source = json.loads(original)
    if set(source) == {"request_id", "model_id", "windows"}:
        request = new_predict_request(source["model_id"], source["windows"], source["request_id"])
    else:
        request = source
    client = CNNClient(IDS_BASE_URL, request["model_id"], IDS_TOKEN_FILE)
    if args.report:
        headers = {"Authorization": "Bearer " + Path(IDS_TOKEN_FILE).read_text().strip()}
        report = {"architecture": platform.machine(), "kernel": platform.release(),
                  "fixture_sha256": hashlib.sha256(original).hexdigest()}
        board = Path("/proc/device-tree/model")
        report["board"] = board.read_bytes().rstrip(b"\0").decode() if board.exists() else None
        for endpoint in ("health", "metadata"):
            with urlopen(Request(IDS_BASE_URL + "/v1/" + endpoint, headers=headers), timeout=2) as r:
                report[endpoint] = json.load(r)
        if not report["health"]["ready"] or report["metadata"]["model_id"] != request["model_id"]:
            raise RuntimeError("Expected model is not ready")
    response = client.predict(request)
    if args.report:
        report["result"] = response
        if hashlib.sha256(canonical_request(request).encode()).hexdigest() == HANDOFF_DIGEST:
            score = response.get("attack_score")
            report["reference_passed"] = (
                response.get("status") == "ok" and type(score) in (float, int)
                and response.get("score_type") == "uncalibrated_sigmoid"
                and abs(score - 0.01076234454486233) <= 0.0001)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if report.get("reference_passed") is False:
            raise RuntimeError(f"Fixture score differs from the reference. See {args.report}")
    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()
