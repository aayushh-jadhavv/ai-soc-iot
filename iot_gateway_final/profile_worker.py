"""Measure the loopback worker with 20 staggered fixture clients for 15 seconds."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import argparse
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

import psutil

from cnn_client import CNNClient
from contracts import new_predict_request


ROOT = Path(__file__).resolve().parents[1]
CLIENTS, ROUNDS = 20, 15


def percentiles(values):
    ordered = sorted(values)
    return {f"p{p}": ordered[math.ceil(len(ordered) * p / 100) - 1] for p in (50, 95)}


def measure(server, url, token, started):
    source = json.loads((ROOT / "tests/fixtures/gateway-request.json").read_bytes())
    probe = CNNClient(url, source["model_id"], token, timeout=4)
    until = time.monotonic() + 90
    while True:
        if server.poll() is not None or time.monotonic() >= until:
            raise RuntimeError("Worker failed to become ready")
        try:
            if probe.info("health")["ready"]:
                break
        except (TimeoutError, ConnectionError):
            pass  # The native library may still be loading.
        time.sleep(.05)
    cold_seconds = time.monotonic() - started
    process = psutil.Process(server.pid)
    initial_cpu = process.cpu_times()
    first = time.monotonic() + .25

    def run_client(index):
        client = CNNClient(url, source["model_id"], token)
        windows = deepcopy(source["windows"])
        for i, w in enumerate(windows):
            w["device_id"] = f"profile-{index}"
            w["window_id"] = f"profile-{index}-{i}"
        timings = []
        for repeat in range(ROUNDS):
            request = new_predict_request(source["model_id"], windows)
            due = first + repeat + index / CLIENTS
            time.sleep(max(0, due - time.monotonic()))
            send = time.monotonic()
            try:
                result = client.predict(request)
                if result["status"] != "ok":
                    raise ValueError(result["status"])
                ms, error = result["inference_ms"], None
            except (OSError, ValueError) as exc:
                ms, error = None, type(exc).__name__
            finish = time.monotonic()
            timings.append((send - due, (finish - send) * 1000, ms, error, finish))
        return timings

    rss = [process.memory_info().rss]
    with ThreadPoolExecutor(CLIENTS) as pool:
        futures = [pool.submit(run_client, i) for i in range(CLIENTS)]
        while any(not task.done() for task in futures):
            rss.append(process.memory_info().rss)
            time.sleep(.05)
        records = [r for task in futures for r in task.result()]
    final_cpu = process.cpu_times()
    successes = [r for r in records if r[3] is None]
    return {
        "platform": platform.platform(), "python": platform.python_version(),
        "logical_cpus_available": len(process.cpu_affinity()), "guest_ram_bytes": psutil.virtual_memory().total,
        "workload": "20 local fixture clients, one distinct request ID per second per client, 15 rounds",
        "clients": CLIENTS, "rounds": ROUNDS, "requests": len(records), "ok": len(successes),
        "errors": {e: sum(r[3] == e for r in records) for e in sorted({r[3] for r in records if r[3]})},
        "cold_start_to_ready_seconds": cold_seconds,
        "elapsed_workload_seconds": max(r[4] for r in records) - first,
        "max_client_schedule_lag_ms": max(r[0] for r in records) * 1000,
        "successful_round_trip_ms": percentiles([r[1] for r in successes]) if successes else None,
        "successful_forward_ms": percentiles([r[2] for r in successes]) if successes else None,
        "worker_cpu_seconds": final_cpu.user + final_cpu.system - initial_cpu.user - initial_cpu.system,
        "worker_sampled_peak_rss_bytes": max(rss), "rss_sampling_interval_ms": 50,
        "omp_num_threads": 1, "openblas_num_threads": 1,
        "scope": "Loopback HTTP, validation, preprocessing and model execution; excludes packet capture and policy."
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        token = Path(tmp) / "token"
        cmd = [sys.executable, "-m", "ids.runtime"]
        subprocess.run([*cmd, "init-token", "--token-file", str(token)], cwd=ROOT,
                       stdout=subprocess.DEVNULL, check=True)
        start = time.monotonic()
        server = subprocess.Popen([*cmd, "serve", "--token-file", str(token), "--port", "0",
                                   "--state", str(Path(tmp) / "state")], cwd=ROOT, stdout=subprocess.PIPE,
                                  text=True, env=dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1"))
        try:
            port = int(server.stdout.readline().strip().rsplit(":", 1)[1])
            result = measure(server, f"http://127.0.0.1:{port}", token, start)
        finally:
            server.terminate()
            server.wait(10)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{result['ok']}/{result['requests']} requests returned correlated scores")
    return int(result["ok"] != result["requests"])


if __name__ == "__main__":
    sys.exit(main())
