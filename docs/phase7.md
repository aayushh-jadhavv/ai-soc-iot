# Phase 7 local inference worker

The physical target is the Raspberry Pi 3+. The worker serves the Phase 6
`ga_3` float32 ExecuTorch model under the gateway's model ID
`cnn-unsw-ga-v1`. Local integration tests replayed the supplied eight live
windows through the gateway client, HTTP service, training-time transform and
exported program. Hardware acceptance and live gateway failure handling are
pending on the Pi.

## Run on the Raspberry Pi

The handoff archive contains the worker, model bundle, gateway source, captured
fixture and dependency lock. Copy `phase7-pi-handoff.tar.gz` to the Pi. From
the directory containing it, run the following as your normal gateway user.

```sh
tar -xzf phase7-pi-handoff.tar.gz
cd phase7-pi-handoff
```

Alternatively, run the remaining commands from the root of the updated
repository on the board. Keep both terminals in that same directory. The
packaged Python runtime needs 64-bit Linux userspace (ARM64), glibc 2.28 or
later and CPython 3.12. The lock contains ARM64 wheels for the pinned CPU
PyTorch and ExecuTorch releases. The ARM64 install plan was resolved offline.
The startup warm-up and fixture replay below exercise the native libraries on
the board. A 32-bit userspace needs a different runtime build. Preserve the
board's current installation if it already hosts the gateway.

If `uv` is absent, install it into a separate user environment with
`python3 -m venv ~/.local/share/phase7-uv`, then
`~/.local/share/phase7-uv/bin/pip install uv==0.9.10` and
`export PATH="$HOME/.local/share/phase7-uv/bin:$PATH"`.
The following installs the worker environment. Core ML is an export dependency
with no locked Linux ARM64 wheel. The worker uses the XNNPACK backend.

```sh
uv python install 3.12
uv sync --frozen --python 3.12 --no-install-package coremltools
export IOT_DATA_DIR="$HOME/.local/share/iot-gateway"
export IOT_IDS_TOKEN_FILE="$IOT_DATA_DIR/ids-token"
if [ ! -e "$IOT_IDS_TOKEN_FILE" ]; then
    .venv/bin/python -m ids.runtime init-token
fi
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv/bin/python -m ids.runtime serve
```

The command starts the worker on `127.0.0.1:8000`. Credential generation
creates a private file and refuses to overwrite an existing credential. The
gateway reads the same file. `--port`, `--token-file`, `--releases` and
`--state` are worker options. Set `IOT_IDS_URL` and `IOT_IDS_TOKEN_FILE` on
the gateway when overriding the defaults. Live capture run as a different
user needs the explicit absolute token path.

When the worker prints `Ready: cnn-unsw-ga-v1`, replay the saved request in the second terminal.
Python's standard library is sufficient for this client. New packet capture
and capture privileges are only needed for a later live session.

```sh
python3 iot_gateway_final/predict_fixture.py \
  predict_b4447618-e363-4704-8edf-9bbfe25bb8de_c12cf37c-64e4-4926-8e5d-865303207612.json \
  --report pi-phase7.json
```

The hardware handoff is `pi-phase7.json`. It contains the board model, CPU
architecture, kernel, fixture checksum, health, model metadata and gateway
response. Expect `ready: true`, `status: ok`, model `cnn-unsw-ga-v1`, request
`ae493940-c200-4b6f-881f-28dbadf578a1` and the last window ending in `-37`.
The client checks the reference score **0.01076234** with absolute tolerance
**0.0001** and records `reference_passed` for this fixture.
This score is an uncalibrated sigmoid. The deployment threshold is unset.
The recorded forward time describes one replay. If startup or replay fails,
retain the first error from the worker or client and the output of
`uname -m`, `getconf LONG_BIT` and `getconf GNU_LIBC_VERSION`.

## Gateway handoff and failure behavior

The original captured JSON omits the required outer `schema_version`.
Posting its original bytes returns HTTP 422. The gateway request builder now
adds `"schema_version": "1.0"`. The replay tool rebuilds this legacy envelope
using its recorded request ID, requested model and eight unmodified windows.
These run through the same builder and client as the live gateway. The server
preserves the evidence identifiers and applies preprocessing once to the
raw features in oldest-first order.

The client retries one transport failure with an identical request. It checks
request, model, last window, device and both revisions on successful responses.
HTTP errors propagate to the live caller, which logs inference unavailability.
The worker exercises abstention, timeout, overload and stale or conflicting
requests independently of gateway policy. Gateway-side history reset on
worker change, late-result discard and recovery under live capture still need
integration on the physical board. The current gateway client does not
consume the worker's reset signal. [Gateway client](../iot_gateway_final/cnn_client.py)

## Worker behavior

- All three HTTP endpoints require a bearer credential. Health exposes readiness,
  loading state and recent worker errors. Metadata exposes the loaded model,
  feature schema, input shape, artifact hashes and calibration status.
- Untrusted input receives a Problem envelope. A valid correlated request can
  receive an InferenceResult with a null score on error or abstention. A
  well-formed sequence with degraded coverage returns HTTP 200 and
  `INVALID_COVERAGE`. A stale model returns 409. A missing model returns 503.
- One native inference executes at a time. The default capacity is eight running
  plus queued requests **in total**. Saturation returns 503. The one-second
  deadline includes input handling, validation, queueing and execution.
  The worker discards a late native result and retains its capacity slot
  until native execution finishes.
- Exact retries share in-flight work or reuse a completed response. The cache
  holds up to 256 IDs for 60 seconds. Conflicting content under a retained ID
  returns 409. An activation clears the cache and changes the
  `X-IDS-History-Epoch` response header. Restarts also change the epoch. Gateway
  integration should discard old evidence and gather eight fresh windows on a change.

## Bundle management and tests

`models/phase7/cnn-unsw-ga-v1` is ready to copy. It includes the executable,
frozen transform, feature and wire schemas, file hashes and a reference
request/score. At startup the worker validates the manifest, checks each
payload, compares schemas and runs the reference before declaring readiness.
The registered manifest SHA-256 is
`9d43e81a2e906bda779c9bc1a53053800acc382851d24be270eb4854a5b0e5d6`.

For a future release, stage a trusted bundle under a new model ID in the
releases directory. Run `.venv/bin/python -m ids.runtime activate MODEL_ID`
as the worker user. It warms the candidate before atomically recording and
switching the active version. Failed candidate validation leaves the current
worker serving. After a successful switch, run
`.venv/bin/python -m ids.runtime rollback` to restore the previous verified
release. Both commands use a local Unix socket in the private state directory.
The first deployment has one release. Rollback becomes available after the
second release activates.

From the full development checkout with the test and records dependencies
installed, reproduce the release with `python -m ids.runtime pack`. Run
`python -m pytest -q tests/test_phase7.py` and run
`python -m unittest discover -s tests` from `iot_gateway_final`.
The HTTP tests run the gateway's actual client and a real ExecuTorch worker.
Deterministic queue tests hold a forward call to exercise deadline and retry
behavior. [Phase 6 selection](../experiments/phase6/run-001/handoff.json) ·
[HTTP and error contracts](../contracts/openapi.json)
