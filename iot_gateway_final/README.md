# IoT Gateway: `device_window_v1` prototype

This is a **gateway/fixture prototype**, not an IDS, not a firewall policy engine,
and not a benchmarked Pi 5/ExecuTorch deployment. Inference is optional and is
**disabled by default**. It does not decrypt TLS or inspect payloads.

It implements the documented 16 features for IPv4, 1-second event-time rows,
8 consecutive valid rows, no preprocessing on the gateway, and a JSON fixture
for `POST /v1/predict`. Source requirements: *Modular IoT security gateway
software design* Sections 4-6 and *Compact CNN IDS Implementation and
Optimization Plan* Phase 0/7.

## Files
- `config.py`: Pi network and worker configuration (default: wlan0 / 10.10.0.0/24).
- `device_registry.py`: UUID identity tied to observed MAC and revisioned IP binding.
- `packet_parser.py`: IPv4 packet observations and invalid-coverage diagnostics.
- `packet_capture.py`: bounded capture-to-parser queue.
- `feature_extractor.py`: 16 features and live/offline 1-second windows.
- `contracts.py`: strict window/sequence/request validator.
- `cnn_client.py`: optional loopback HTTP client (disabled by default).
- `main.py`: live capture and real fixture generation.
- `replay_pcap.py`: deterministic replay from a capture on the IoT subnet.
- `tests/`: deterministic correctness tests.

## Raspberry Pi 3B+ setup over SSH

```bash
cd ~/iot_gateway_final
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
ip -br addr  # check wlan0=10.10.0.1/24
sudo .venv/bin/python main.py
```

Connect a phone to the **Pi's** hotspot (not directly to the upstream TP-Link).
Generate at least 8 seconds of observable IP traffic. A fixture is saved under
`fixtures/predict_<boot_uuid>_<device_uuid>.json` and `[SEQUENCE READY]` should appear. The packet
capture point is `wlan0` before NAT.

To replay a saved PCAP offline:

```bash
.venv/bin/python replay_pcap.py /path/to/lab_capture.pcap --output fixtures/offline_predict.json
```

To inspect JSON:

```bash
.venv/bin/python -m json.tool fixtures/predict_<boot_uuid>_<device_uuid>.json | head -50
```

## Optional CNN worker (only once teammate has a matching implementation)

The **real** `model_id` and HTTP response/error format MUST be confirmed with
teammate's OpenAPI and model metadata. For local loopback requests, provision a
bearer token in a file outside Git and chat:

```bash
mkdir -p ~/.local/share/iot-gateway
chmod 700 ~/.local/share/iot-gateway
# Edit ~/.local/share/iot-gateway/ids-token securely (chmod 600)
IOT_ENABLE_INFERENCE=1 sudo -E .venv/bin/python main.py
```

**Caution:** running under sudo changes HOME/path defaults; explicitly configure
`IOT_DATA_DIR`, `IOT_IDS_TOKEN_FILE`, `IOT_FIXTURE_DIR` and ownership in a
service for actual operation. Do not share the token or open the worker to LAN.
Use OBSERVE mode only until policy/inference tests pass.

## Known limitations / deliberate exclusions

- The prototype does not implement policy, nftables enforcement, SQLite incidents,
  Android reporting, ExecuTorch, or CNN training.
- Capture drops from the Linux kernel/NIC are not measured by this Scapy adapter.
  Queue-overflow events are tracked conservatively; full PCAP/libpcap stats and
  validation against live captures remain needed.
- IPv6 is outside `device_window_v1`. The BPF filter captures IPv4 only; the isolated lab must prohibit alternate
  IPv6 routing and report IPv6 coverage as unsupported. If an IPv6 record is
  explicitly fed to the parser, it flags global degradation.
- Only IPv4 nonfragmented packets with supported accessible headers are counted.
- MAC addresses/DHCP assignments are spoofable. Conflict detection is a safety
  flag, not authenticated identity. Device identity remains provisional.
- The live idle-window timer uses wall clock plus 100ms proposed allowance; high
  clock discontinuities and synchronization must be tested for production.
- No reverse DNS, TLS decryption, full payload capture, or malicious URL lookup.
- Large captures need a higher-throughput C/libpcap adapter; this reference is
  optimized for correctness/fixture handoff rather than high-rate production use.
- `replay_pcap.py` assumes monotonically ordered packets and a known lab IP map;
  it does not join ground-truth labels or reconstruct unrelated public datasets.
- Verify the exact API/IDs/error semantics against teammate's **actual OpenAPI**.

## Pinned commit handoff

Initialize/commit **your own** repository and provide a real Git SHA:

```bash
git init
git add .gitignore *.py requirements.txt README.md tests
# git commit -m 'Implement device_window_v1 gateway fixture producer'
# git rev-parse HEAD
```

Never claim a pinned commit without running those commands and checking the SHA.
