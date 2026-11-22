# Raspberry Pi and Android integration

The Pi uses the existing capture gateway and authenticated loopback IDS worker. The gateway publishes recent validated results through a separate, read-only report API. The phone uses its installed Llama model to explain the fetched facts. The gateway runs in OBSERVE mode and does not apply restrictions.

## Start the Pi

1. Follow [Run the worker](README.md#run-the-worker) in the repository README. Keep the worker on loopback port 8000. If the worker is already installed, retain its Python environment, model bundle and token settings. Run the gateway from the integrated checkout.
2. Determine the Pi's phone-facing IPv4 with `hostname -I`. Use the capture interface/subnet configured for your IoT clients. The example uses the earlier Pi setup with `10.10.0.1` on the IoT network and `192.168.1.124` on the phone-facing LAN. Substitute current values.

```sh
sudo env IOT_LAN_INTERFACE=wlan0 IOT_LAN_SUBNET=10.10.0.0/24 IOT_GATEWAY_IP=10.10.0.1 \
    IOT_ENABLE_INFERENCE=1 IOT_DATA_DIR="$HOME/.local/share/iot-gateway" \
    IOT_IDS_TOKEN_FILE="$HOME/.local/share/iot-gateway/ids-token" \
    .gateway-venv/bin/python iot_gateway_final/main.py --quiet-windows \
    --report-host 192.168.1.124 --report-port 8080
```

Create `.gateway-venv` as shown in the [gateway instructions](README.md#observe-traffic-on-a-gateway) if needed. The report API is opt-in, unauthenticated HTTP on the selected lab interface. Use a trusted local test network. The model worker's token and prediction endpoint stay on the Pi. The phone receives no packet payloads, IP addresses of observed devices, feature vectors or credentials.

## Fetch and explain a real result

1. From the Pi, run `curl http://192.168.1.124:8080/health` and then `curl http://192.168.1.124:8080/v1/reports`. An empty list is valid until the gateway produces a recent IDS result.
2. Generate benign traffic from an IoT device on the monitored network. Wait until the gateway logs `[INFERENCE]` after receiving eight fresh valid one-second windows for the device. Check the returned report ID, timestamp, score and action. An unavailable score remains null for worker abstentions and errors. Request exceptions clear the corresponding report instead of presenting a previous score as current.
3. Build and install the [Android debug app](android/README.md). With the S24 on the phone-facing LAN, enter `http://192.168.1.124:8080` and tap **Fetch reports**. Expect **Fetched from Pi · Live IDS** and `GET /v1/reports ... 200` on the Pi. If the Pi-local request works and the phone request never arrives, check the phone's LAN connection. It must be able to reach the chosen Pi interface.
4. Open **View report** and compare the IDS status, score and **Not executed** action to the Pi output. Explain it with **Explain report**. With the report still on screen, disable Wi-Fi and retry the explanation. It should preserve the score availability and action status.
5. With the report screen open, stop the gateway via Ctrl+C and try fetching again. The app should show a connection error and keep the displayed report for the current session.

The feed holds at most the latest result per device for up to 40 devices and expires entries after 60 seconds. It clears results on worker epoch changes and device binding changes, and discards a device report on invalid window coverage. Already fetched reports remain snapshots in the phone UI. The numerical score is an uncalibrated model output. This release has no deployment threshold.

## Contract

`GET /v1/reports` returns schema version 1, `gateway_id`, `data_source: live` and a `reports` array. Each report uses the existing phone fields `report_id`, `revision`, `device`, `factual_summary`, `coverage`, `score`, `recommendation` and `action_status`. Live entries also carry `detector_status`, `score_type`, `model_id`, `error_code`, `window_start_ms` and `window_end_ms`. The report ID is the last scored window ID, and timestamps cover the full evidence interval. The action is always `NOT_EXECUTED`.
