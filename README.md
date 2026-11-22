# AI SoC IoT gateway and intrusion detection

The gateway observes IPv4 traffic on the IoT-facing interface, groups packet-header measurements by device, and sends eight consecutive one-second windows to a local intrusion detection worker. The worker runs a compact CNN with ExecuTorch/XNNPACK and returns an uncalibrated score for attack-associated traffic. The gateway operates in **OBSERVE** mode. Live inference is opt-in and the deployment threshold is unset.

The frozen model detected 9 of 12 attack-labeled histories and flagged 2 of 2,501 benign histories in the available UNSW-NB15 test block. The block comes from the same recording group as training. The compact model missed the macro-F1 retention target. The release includes the measurements, the failed target and the conditions tested on a Raspberry Pi 3B+. [Model card and evaluation](MODEL_CARD.md)

## Phone integration

[Run the live report feed and Android app](PHONE_INTEGRATION.md).

## Run the worker

Use a 64-bit Linux machine with CPython 3.12.12 and uv 0.9.10. The tested targets were Ubuntu under WSL2 on x86-64 and an ARM64 Raspberry Pi 3B+. Run the commands from the repository root. The frozen lock includes the CPU runtime. Core ML is an optional export component for other targets.

```sh
uv python install 3.12.12
uv sync --frozen --python 3.12.12 --no-install-package coremltools
export IOT_DATA_DIR="$HOME/.local/share/iot-gateway"
export IOT_IDS_TOKEN_FILE="$IOT_DATA_DIR/ids-token"
if [ ! -e "$IOT_IDS_TOKEN_FILE" ]; then
    .venv/bin/python -m ids.runtime init-token
fi
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 .venv/bin/python -m ids.runtime serve
```

Wait for `Ready: cnn-unsw-ga-v1`. From a second terminal in the same checkout, replay the included gateway request. The defaults use the same credential path for both processes. Export the same `IOT_IDS_TOKEN_FILE` in both terminals if you customize it.

```sh
python3 iot_gateway_final/predict_fixture.py tests/fixtures/gateway-request.json --report /tmp/ids-replay.json
```

The JSON response should contain `status: ok`. The replay report checks the score against **0.01076234** with absolute tolerance **0.0001** and records `reference_passed`. The worker authenticates all three loopback endpoints on port 8000. A successful prediction identifies the request, model, device, binding revision, enforcement revision and final window. Errors and abstentions carry a null score. [HTTP contract](contracts/openapi.json)

## Observe traffic on a gateway

Install Scapy in a separate environment. On Linux, the capture interface must support packet capture and libpcap must be available for the capture filter. Set the interface, subnet and gateway address to match the client-facing network before NAT. These commands use the values from the Pi trials.

```sh
python3 -m venv .gateway-venv
.gateway-venv/bin/pip install -r iot_gateway_final/requirements.txt
sudo env IOT_LAN_INTERFACE=wlan0 IOT_LAN_SUBNET=10.10.0.0/24 IOT_GATEWAY_IP=10.10.0.1 \
    IOT_ENABLE_INFERENCE=1 IOT_DATA_DIR="$HOME/.local/share/iot-gateway" \
    IOT_IDS_TOKEN_FILE="$HOME/.local/share/iot-gateway/ids-token" \
    .gateway-venv/bin/python iot_gateway_final/main.py --quiet-windows
```

The gateway writes a registry and one request fixture per device and boot under `IOT_DATA_DIR`. Set `IOT_FIXTURE_DIR` to change the fixture destination. Omit `IOT_ENABLE_INFERENCE=1` to collect fixtures with the worker offline. A worker restart or rollback invalidates the live rolling history. The gateway waits for eight fresh windows before reporting a score.

To replay an existing capture offline, set the same subnet and gateway address used at capture time. The replay needs enough ordered traffic to form eight windows for a device.

```sh
.gateway-venv/bin/python iot_gateway_final/replay_pcap.py capture.pcap --output /tmp/gateway-request.json
python3 iot_gateway_final/predict_fixture.py /tmp/gateway-request.json
```

## Verify the release

```sh
uv sync --frozen --extra test --extra records --no-install-package coremltools
.venv/bin/python -m pytest -q
.venv/bin/python -m unittest discover -s iot_gateway_final/tests -q
.venv/bin/python -m ids.runtime pack
.venv/bin/python -m evaluation.run verify
```

The tests exercise the packet/window contract, training and export code, the real HTTP worker, reference-score parity, request deadlines, overload, activation and rollback. The pack command rebuilds the selected bundle from the retained export inputs and checks its registered manifest. The final command recomputes all 14 model reports from the published score ledger.

To repeat the native scoring experiment, supply the original checksum-matched Phase 2 run directory containing `internal_test/raw.npy`, `tensor.npy` and `samples.parquet` under that partition. The command applies the shipped transform to the raw windows and verifies every tensor against the saved version. It loads the shipped model from this checkout and the comparison programs from the pinned source commit in a full Git clone. For a shallow checkout, pass `--exports /path/to/phase6/run-001` from that revision.

```sh
.venv/bin/python -m evaluation.run score --data /path/to/phase2/run-002 --output /tmp/ids-phase9-repeat
.venv/bin/python -m evaluation.run verify --results /tmp/ids-phase9-repeat
cmp evaluation/results.json /tmp/ids-phase9-repeat/results.json
```

The build recipe for the private test inputs and the original capture and label requirements are recorded in the training revision. The release ledger contains per-history scores, labels, group and opaque sample IDs. [Dataset build recipe](https://github.com/aayushh-jadhavv/ai-soc-iot/blob/ebc89bd71523bef874e486ca2afa2a89070e71dd/docs/phase2.md) · [Frozen protocol](evaluation/freeze.json)

To repeat the Linux worker timing experiment, run `.venv/bin/python iot_gateway_final/profile_worker.py --output /tmp/worker-profile.json`. It starts its own loopback worker and sends 300 requests using the included fixture. The charts can be regenerated from the report with `python -m evaluation.plot` in an environment with ReportLab 4.4.9.

## Repository contents

| Path | Purpose |
| --- | --- |
| `iot_gateway_final/` | Live capture, device bindings, window aggregation, HTTP client and offline replay |
| `ids/` | Worker, preprocessing, packet features, datasets, training and model compaction |
| `models/cnn-unsw-ga-v1/` | Selected program, fitted transform, schemas, checksums and startup reference |
| `contracts/` | Versioned wire schemas, OpenAPI and accepted/rejected examples |
| `evaluation/` | Frozen protocol, locked score ledger, results, plots, hardware evidence summaries and bundle build inputs |
| `tests/`, `scripts/` | Regression tests, hand-checked fixtures, contract generation and export tooling |
