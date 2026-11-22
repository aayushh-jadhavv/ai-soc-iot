"""Serialized native inference, bounded retries and atomic release changes."""

import json
import os
import threading
import time
import uuid
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

from ids.contracts import ContractError, check_model_and_coverage, validate
from ids.runtime.bundle import Bundle, canonical, digest, valid_version


HTTP = {"INVALID_INPUT": 422, "SCHEMA_MISMATCH": 422, "HISTORY_DISCONTINUITY": 422,
        "MODEL_MISMATCH": 409, "REQUEST_ID_CONFLICT": 409, "INVALID_COVERAGE": 200,
        "MODEL_NOT_READY": 503, "OVERLOADED": 503, "DEADLINE_EXCEEDED": 504,
        "PREPROCESS_ERROR": 500, "RUNTIME_ERROR": 500, "UNAUTHORIZED": 401}


def problem(code, detail):
    return HTTP[code], dict(schema_version="1.0", status="error", request_id=None,
                            error_code=code, detail=detail[:512])


def result(request, code=None, score=None, ms=0):
    last = request["windows"][-1]
    status = "ok" if code is None else ("abstain" if code == "INVALID_COVERAGE" else "error")
    return (HTTP[code] if code else 200), dict(
        schema_version="1.0", request_id=request["request_id"], device_id=last["device_id"],
        binding_revision=last["binding_revision"], enforcement_revision=last["enforcement_revision"],
        last_window_id=last["window_id"], model_id=request["model_id"], status=status,
        task="attack_associated_traffic", attack_score=score, score_type="uncalibrated_sigmoid",
        inference_ms=ms, error_code=code)


@dataclass
class Entry:
    fingerprint: str
    expires: float
    response: tuple | None = None


class Worker:
    def __init__(self, releases, state_file, *, capacity=8, loader=Bundle):
        self.releases = releases
        self.state_file = state_file
        self.loader = loader
        self.capacity = capacity
        self.lock = threading.RLock()
        self.switch_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ids-forward")
        self.loading = False
        self.bundle = None
        self.epoch = uuid.uuid4().hex
        self.errors = deque(maxlen=32)
        self.cache = OrderedDict()
        self.pending = {}
        self.state = (json.loads(state_file.read_bytes()) if state_file.exists()
                      else dict(active=None, previous=None, identities={}))

    def activate(self, model_id=None, *, rollback=False):
        with self.switch_lock:
            target = self.state["previous"] if rollback else model_id
            valid_version(target)
            with self.lock:
                self.loading = True
            try:
                candidate = self.loader(self.releases / target)
                identities = dict(self.state["identities"])
                if identities.setdefault(target, candidate.identity) != candidate.identity:
                    raise ValueError("Model ID already registered for a different release")
                with self.lock:
                    if self.bundle and self.bundle.identity == candidate.identity:
                        return
                    previous = self.state["previous"] if self.state["active"] == target else self.state["active"]
                    state = dict(active=target, previous=previous, identities=identities)
                    self._persist(state)
                    self.state, self.bundle = state, candidate
                    self.epoch = uuid.uuid4().hex
                    self.cache.clear()
            except Exception:
                with self.lock:
                    self.errors.append("BUNDLE_LOAD_FAILED")
                raise
            finally:
                with self.lock:
                    self.loading = False

    def _persist(self, state):
        out = NamedTemporaryFile(dir=self.state_file.parent, delete=False)
        temporary = Path(out.name)
        try:
            with out:
                out.write(canonical(state))
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, self.state_file)
        finally:
            temporary.unlink(missing_ok=True)

    def info(self, health):
        with self.lock:
            if health:
                response = 200, dict(ready=self.bundle is not None, model_loading=self.loading,
                                     recent_errors=list(self.errors))
            elif self.bundle:
                response = 200, self.bundle.metadata
            else:
                response = problem("MODEL_NOT_READY", "No validated release is active")
            return response, self.epoch

    def predict(self, request, deadline):
        try:
            validate("FeatureSequence", request)
            fingerprint = digest(canonical(request))
        except (ContractError, RecursionError) as exc:
            return problem(getattr(exc, "code", "INVALID_INPUT"), "Invalid feature sequence"), self.epoch
        rid = request["request_id"]
        with self.lock:
            now = time.monotonic()
            epoch = self.epoch
            key = (epoch, rid)
            if now >= deadline:
                return result(request, "DEADLINE_EXCEEDED"), epoch
            if self.bundle is None:
                return result(request, "MODEL_NOT_READY"), epoch
            for old in list(self.cache):
                if self.cache[old].expires <= now:
                    del self.cache[old]
            entry = self.cache.get(rid)
            pending = self.pending.get(key)
            if (entry and entry.fingerprint != fingerprint) or (pending and pending[0] != fingerprint):
                return result(request, "REQUEST_ID_CONFLICT"), epoch
            if entry and entry.response:
                return entry.response, epoch
            if pending:
                future = pending[1]
            else:
                try:
                    check_model_and_coverage(request, self.bundle.model_id)
                except ContractError as exc:
                    response = result(request, exc.code)
                    self._remember(rid, fingerprint, response)
                    return response, epoch
                if len(self.pending) >= self.capacity:
                    self._remember(rid, fingerprint, None)
                    self.errors.append("OVERLOADED")
                    return result(request, "OVERLOADED"), epoch
                future = self.executor.submit(self._forward, self.bundle, request, deadline, epoch)
                self.pending[key] = fingerprint, future
                future.add_done_callback(lambda f: self._finished(key, fingerprint, f))
        try:
            response = future.result(timeout=max(0, deadline - time.monotonic()))
        except TimeoutError:
            response = result(request, "DEADLINE_EXCEEDED")
        with self.lock:
            if epoch != self.epoch:
                return result(request, "MODEL_MISMATCH"), self.epoch
            if time.monotonic() >= deadline:
                return result(request, "DEADLINE_EXCEEDED"), epoch
            return response, epoch

    def _forward(self, bundle, request, deadline, epoch):
        if time.monotonic() >= deadline:
            return result(request, "DEADLINE_EXCEEDED")
        if self.epoch != epoch:
            return result(request, "MODEL_MISMATCH")
        try:
            score, ms = bundle.predict(request)
        except ContractError as exc:
            return result(request, exc.code)
        except Exception:
            return result(request, "RUNTIME_ERROR")
        if time.monotonic() >= deadline:
            return result(request, "DEADLINE_EXCEEDED", ms=ms)
        return result(request, score=score, ms=ms)

    def _finished(self, key, fingerprint, future):
        with self.lock:
            del self.pending[key]
            if key[0] == self.epoch:
                response = future.result()
                if response[0] >= 500:
                    self.errors.append(response[1]["error_code"])
                self._remember(key[1], fingerprint, response if response[0] == 200 else None)

    def _remember(self, rid, fingerprint, response):
        self.cache[rid] = Entry(fingerprint, time.monotonic() + 60, response)
        self.cache.move_to_end(rid)
        if len(self.cache) > 256:
            self.cache.popitem(last=False)
