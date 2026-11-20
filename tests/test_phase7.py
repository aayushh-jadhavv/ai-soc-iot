"""Gateway handoff, real loopback service, release changes and queue behavior."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time

import pytest

from ids.contracts import validate
from ids.runtime.bundle import MODEL_ID, canonical, digest, pack
from ids.runtime.worker import Worker


ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / ("predict_b4447618-e363-4704-8edf-9bbfe25bb8de_"
                  "c12cf37c-64e4-4926-8e5d-865303207612.json")
RELEASES = ROOT / "models/phase7"
RUN = ROOT / "experiments/phase6/run-001"


def request():
    return dict(json.loads(HANDOFF.read_bytes()), schema_version="1.0")


def test_release_reproduces_and_matches_export(tmp_path):
    import torch
    from ids.runtime.bundle import Bundle

    dest = pack(RUN, tmp_path)
    assert pack(RUN, tmp_path) == dest
    assert all(p.read_bytes() == (RELEASES / MODEL_ID / p.name).read_bytes() for p in dest.iterdir())
    model = Bundle(dest)
    raw = request()
    tensor = model.processor.transform(raw, model_id=MODEL_ID)
    graph = torch.export.load(RUN / "ga_3/float32/exported.pt2").module()
    with torch.inference_mode():
        expected = graph(tensor).double().sigmoid().item()
    assert model.predict(raw)[0] == pytest.approx(expected, abs=1e-4)


def cli(*args, **kwargs):
    return subprocess.run([sys.executable, "-m", "ids.runtime", *map(str, args)], cwd=ROOT,
                          capture_output=True, text=True, timeout=60, **kwargs)


def test_gateway_and_release_lifecycle(tmp_path):
    releases = tmp_path / "releases"
    shutil.copytree(RELEASES, releases)
    nxt = releases / "test-next"
    shutil.copytree(releases / MODEL_ID, nxt)
    manifest = json.loads((nxt / "manifest.json").read_bytes())
    manifest["model_id"] = nxt.name
    ref = json.loads((nxt / "warmup.json").read_bytes())
    ref["request"]["model_id"] = nxt.name
    (nxt / "warmup.json").write_bytes(canonical(ref))
    manifest["files"]["warmup.json"] = digest(canonical(ref))
    (nxt / "manifest.json").write_bytes(canonical(manifest))
    tokenfile = tmp_path / "token"
    cli("init-token", "--token-file", tokenfile, check=True)
    token = tokenfile.read_text().strip()
    assert tokenfile.stat().st_mode & 0o077 == 0
    assert cli("init-token", "--token-file", tokenfile).returncode != 0
    assert tokenfile.read_text().strip() == token
    with TemporaryDirectory() as state:
        server = subprocess.Popen([sys.executable, "-m", "ids.runtime", "serve", "--port", "0",
                                   "--token-file", str(tokenfile), "--state", state, "--releases",
                                   str(releases)], stdout=subprocess.PIPE, text=True, cwd=ROOT)
        try:
            port = int(server.stdout.readline().strip().rsplit(":", 1)[1])
            def call(path, body=None, bearer=token):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
                try:
                    conn.request("POST" if body is not None else "GET", "/v1/" + path,
                                 body, {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
                    response = conn.getresponse()
                    return response.status, json.load(response), response.getheader("X-IDS-History-Epoch")
                finally:
                    conn.close()

            until = time.monotonic() + 60
            while not call("health")[1]["ready"]:
                assert time.monotonic() < until and server.poll() is None
                time.sleep(.1)
            for path, body in [("health", None), ("metadata", None), ("predict", b"{}")]:
                assert call(path, body, "wrong")[0] == 401
            _, meta, epoch = call("metadata")
            assert meta["model_id"] == MODEL_ID and meta["calibration_status"] == "uncalibrated"
            invalid_status, invalid, _ = call("predict", HANDOFF.read_bytes())
            assert (invalid_status, invalid["error_code"]) == (422, "INVALID_INPUT")
            assert call("predict", b"{")[0] == 422

            report = tmp_path / "smoke.json"
            gateway = subprocess.run([sys.executable, str(ROOT / "iot_gateway_final/predict_fixture.py"),
                                      str(HANDOFF), "--report", str(report)], env=dict(os.environ, IOT_IDS_TOKEN_FILE=str(tokenfile),
                                      IOT_IDS_URL=f"http://127.0.0.1:{port}"), check=True,
                                     capture_output=True, text=True, timeout=8)
            reply = json.loads(gateway.stdout)
            evidence = json.loads(report.read_bytes())
            assert evidence["reference_passed"] and evidence["health"]["ready"] and evidence["result"] == reply
            assert evidence["metadata"] == meta and token not in report.read_text()
            validate("InferenceResult", reply)
            raw = request()
            assert reply["attack_score"] == pytest.approx(.0107623445, abs=.0001)
            assert reply["last_window_id"] == raw["windows"][-1]["window_id"]
            assert call("predict", canonical(raw)) == (200, reply, epoch)
            for code, change, status in [
                ("REQUEST_ID_CONFLICT", {"model_id": "other"}, 409),
                ("MODEL_MISMATCH", {"request_id": "stale", "model_id": "other"}, 409),
                ("INVALID_COVERAGE", {"request_id": "gap"}, 200),
            ]:
                payload = deepcopy(raw)
                payload.update(change)
                if code == "INVALID_COVERAGE":
                    payload["windows"][0]["quality"] = {"valid": False, "reasons": ["input_gap"]}
                actual, obj, _ = call("predict", canonical(payload))
                validate("InferenceResult", obj)
                assert (actual, obj["error_code"], obj["attack_score"]) == (status, code, None)

            def switch(*args):
                return cli(*args, "--state", state)
            assert switch("activate", nxt.name).returncode == 0
            _, meta, second = call("metadata")
            assert meta["model_id"] == nxt.name and epoch != second
            assert call("predict", canonical(raw))[1]["error_code"] == "MODEL_MISMATCH"
            assert switch("rollback").returncode == 0
            assert call("metadata")[1]["model_id"] == MODEL_ID
            third = call("metadata")[2]
            assert third not in (epoch, second)
            pte = nxt / "model.pte"
            pte.write_bytes(b"damaged")
            assert switch("activate", nxt.name).returncode != 0
            assert call("metadata")[2] == third
            assert call("health")[1]["recent_errors"][-1] == "BUNDLE_LOAD_FAILED"
            assert json.loads((Path(state) / "activation.json").read_bytes())["active"] == MODEL_ID
        finally:
            server.terminate()
            server.wait(10)


def test_deadlines_backpressure_and_inflight_retry(tmp_path):
    entered, release = threading.Event(), threading.Event()
    class Slow:
        model_id = MODEL_ID
        identity = "test"
        calls = 0

        def predict(self, obj):
            self.calls += 1
            entered.set()
            assert release.wait(3)
            return .2, 1

    model = Slow()
    worker = Worker(tmp_path, tmp_path / "state.json", capacity=1, loader=lambda path: model)
    req = request()
    def send(payload, seconds=2):
        return worker.predict(payload, time.monotonic() + seconds)[0]
    assert send(req)[0] == 503
    worker.activate(MODEL_ID)
    try:
        with ThreadPoolExecutor(2) as clients:
            first = clients.submit(send, req)
            assert entered.wait(1)
            assert send(dict(req, request_id="new"))[1]["error_code"] == "OVERLOADED"
            assert send(dict(req, model_id="changed"))[1]["error_code"] == "REQUEST_ID_CONFLICT"
            assert send(req, .05)[0] == 504
            retry = clients.submit(send, req)
            release.set()
            assert retry.result() == first.result()
        assert model.calls == 1
        assert send(req) == first.result()
        worker.cache[req["request_id"]].expires = time.monotonic() - 1
        assert send(req)[0] == 200 and model.calls == 2
        for i in range(257):
            worker._remember(str(i), str(i), (200, {}))
        assert len(worker.cache) == 256 and "0" not in worker.cache
    finally:
        release.set()
        worker.executor.shutdown()
