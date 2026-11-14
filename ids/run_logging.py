"""Section 14 durable run records; a separate process samples worker resources.

CPU 100% means one logical core. RSS samples are per process, never summed.
Monitor collection cost is saved; it is not total observer-induced slowdown.
"""

import csv
import hashlib
import importlib.metadata
import json
import multiprocessing as mp
import os
from pathlib import Path
import platform
import sys
import time
import uuid

import psutil


def write_json(path, value):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_hashes(root):
    paths = []
    for folder in ("ids", "contracts", "scripts", "tests", "docs"):
        paths.extend(p for p in (root / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    paths.extend(root / name for name in ("pyproject.toml", "uv.lock", ".python-version") if (root / name).exists())
    return {p.relative_to(root).as_posix(): sha256(p) for p in sorted(paths)}


def environment():
    return {"python": platform.python_version(), "python_executable": sys.executable, "platform": platform.platform(),
            "guest_architecture": platform.machine(), "guest_kernel": platform.release(),
            "guest_distribution": platform.freedesktop_os_release() if platform.system() == "Linux" else None,
            "vcpus": psutil.cpu_count(), "guest_ram_bytes": psutil.virtual_memory().total,
            "process_affinity": psutil.Process().cpu_affinity() if hasattr(psutil.Process(), "cpu_affinity") else None,
            "library_versions": dict(sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions())),
            "thread_environment": {k: os.environ.get(k) for k in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS")}}


def _monitor(pid, output, stop, ready, interval):
    worker = psutil.Process(pid)
    processes = {}
    maxima = {}
    collection_ns = 0
    start = time.perf_counter_ns()
    with Path(output, "resource_samples.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["elapsed_ns", "pid", "role", "cpu_percent_one_core", "rss_bytes"])
        writer.writeheader()
        while not stop.is_set():
            tick = time.perf_counter_ns()
            try:
                candidates = [worker] + worker.children(recursive=True)
            except psutil.NoSuchProcess:
                break
            for process in candidates:
                if process.pid == os.getpid():
                    continue
                try:
                    key = (process.pid, process.create_time())
                    if key not in processes:
                        processes[key] = process
                        process.cpu_percent(None)  # prime; first value is not a measurement
                        continue
                    p = processes[key]
                    rss = p.memory_info().rss
                    writer.writerow({"elapsed_ns": time.perf_counter_ns()-start, "pid": p.pid,
                        "role": "worker" if p.pid == pid else "child", "cpu_percent_one_core": p.cpu_percent(None), "rss_bytes": rss})
                    maxima[str(key)] = max(maxima.get(str(key), 0), rss)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            f.flush()
            collection_ns += time.perf_counter_ns()-tick
            ready.set()
            stop.wait(interval)
    duration = time.perf_counter_ns()-start
    write_json(Path(output, "resource_summary.json"), {"interval_seconds": interval,
        "cpu_convention": "100 percent = one logical core", "sampled_max_rss_by_pid_create_time": maxima,
        "monitor_collection_ns": collection_ns, "monitor_elapsed_ns": duration,
        "monitor_collection_fraction": collection_ns / duration if duration else None,
        "limitations": "Sampled RSS is not exact peak; child RSS is not summed. Collection time is not observer slowdown."})


class ResourceMonitor:
    def __init__(self, output, interval=0.2):
        ctx = mp.get_context("spawn")
        self.stop_event, self.ready = ctx.Event(), ctx.Event()
        self.process = ctx.Process(target=_monitor, args=(os.getpid(), str(output), self.stop_event, self.ready, interval))

    def __enter__(self):
        self.process.start()
        if not self.ready.wait(15):
            self.__exit__(None, None, None)
            raise RuntimeError("Resource monitor did not become ready")
        return self

    def __exit__(self, *args):
        self.stop_event.set()
        self.process.join(5)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join()
            raise RuntimeError("Resource monitor failed to stop")
        if self.process.exitcode != 0:
            raise RuntimeError(f"Resource monitor failed: {self.process.exitcode}")


class RunLogger:
    """Single writer per run; immutable directory, JSON manifest and raw records.

    Future phases use log_epoch, write_table, event, and record_timings. Empty
    tables explicitly mean not performed; no fake training or accuracy records.
    """
    EPOCH_FIELDS = ["epoch", "split", "loss", "learning_rate", "precision", "recall", "macro_f1",
                    "pr_auc", "pr_auc_method", "sample_count", "epoch_seconds", "examples_per_second"]

    def __init__(self, output, manifest):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.manifest = {"record_schema_version": "1.0", "run_id": str(uuid.uuid4()),
                         "started_at_unix_ns": time.time_ns(), "status": "running", **manifest}
        write_json(self.output / "run_manifest.json", self.manifest)
        with (self.output / "epoch_metrics.csv").open("w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=self.EPOCH_FIELDS).writeheader()

    def event(self, event_name, **fields):
        with (self.output / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event": event_name, "monotonic_ns": time.perf_counter_ns(), **fields}, allow_nan=False)+"\n")

    def log_epoch(self, **fields):
        if set(fields) != set(self.EPOCH_FIELDS):
            raise ValueError("Epoch record fields must match shared schema")
        # Reject nonfinite metrics. Use None for undefined values, not zero.
        json.dumps(fields, allow_nan=False)
        with (self.output / "epoch_metrics.csv").open("a", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=self.EPOCH_FIELDS).writerow(fields)

    def write_table(self, kind, rows):
        import pyarrow as pa
        import pyarrow.parquet as pq
        schemas = {
            "ga_candidates": pa.schema([("mask", pa.string()), ("retained_conv1", pa.int64()), ("retained_conv2", pa.int64()),
                ("fitness", pa.float64()), ("metrics_json", pa.string()), ("cache_status", pa.string()), ("evaluation_seconds", pa.float64())]),
            "predictions": pa.schema([("sample_id", pa.string()), ("group_id", pa.string()), ("dataset", pa.string()),
                ("family", pa.string()), ("label", pa.int64()), ("score", pa.float64()), ("status", pa.string()), ("exclusion_reason", pa.string())]),
        }
        if kind not in schemas:
            raise ValueError("Unknown record table")
        path = self.output / (kind + ".parquet")
        if path.exists():
            raise FileExistsError(path)
        for row in rows:
            if set(row) != set(schemas[kind].names):
                raise ValueError("Table fields must match shared schema")
            json.dumps(row, allow_nan=False)
        pq.write_table(pa.Table.from_pylist(rows, schema=schemas[kind]), path)

    def record_timings(self, rows, summary):
        with (self.output / "timing_samples.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["stage", "iteration", "elapsed_ns", "monitor_enabled"])
            writer.writeheader(); writer.writerows(rows)
        write_json(self.output / "benchmark_summary.json", summary)

    def finish(self, status, **fields):
        self.manifest.update(status=status, finished_at_unix_ns=time.time_ns(), **fields)
        write_json(self.output / "run_manifest.json", self.manifest)
