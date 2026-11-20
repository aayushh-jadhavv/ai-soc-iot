"""Live Raspberry Pi gateway fixture producer; defaults to OBSERVE-only."""
import argparse
import json
import time
import uuid
from pathlib import Path

from config import (GATEWAY_ID, LAN_NET, LAN_INTERFACE, GATEWAY_IP, REGISTRY_FILE,
                    CAPTURE_FILTER, SEQUENCE_LENGTH, INACTIVITY_TIMEOUT_SECONDS,
                    ORDERING_ALLOWANCE_MS, FIXTURE_DIR, MODEL_ID, IDS_BASE_URL,
                    IDS_TOKEN_FILE, ENABLE_INFERENCE, CAPTURE_QUEUE_SIZE)
from contracts import new_predict_request
from cnn_client import CNNClient
from device_registry import DeviceRegistry
from feature_extractor import FeatureExtractor, FEATURE_NAMES
from packet_capture import PacketCapture


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--fixture-dir', default=str(FIXTURE_DIR))
    p.add_argument('--quiet-windows', action='store_true')
    args = p.parse_args()
    boot_id = str(uuid.uuid4())
    capture_session_id = str(uuid.uuid4())
    fixture_dir = Path(args.fixture_dir)
    fixture_dir.mkdir(parents=True, exist_ok=True)
    worker = CNNClient(IDS_BASE_URL, MODEL_ID, IDS_TOKEN_FILE) if ENABLE_INFERENCE else None
    print('[GATEWAY] interface=', LAN_INTERFACE, 'subnet=', LAN_NET)
    print('[GATEWAY] 16-feature order:', FEATURE_NAMES)
    print('[GATEWAY] boot_id=', boot_id, 'capture_session_id=', capture_session_id)
    print('[GATEWAY] mode=OBSERVE; firewall actions disabled')

    def on_window(w):
        if not args.quiet_windows:
            print(f'[WINDOW] {w["device_id"]} {w["window_start_ms"]} '
                  f'valid={w["quality"]["valid"]} {w["values"]}', flush=True)

    def on_sequence(seq):
        try:
            request = new_predict_request(MODEL_ID, seq['windows'])
        except ValueError as exc:
            print('[INVALID SEQUENCE]', exc, flush=True)
            return
        # Save one reproducible valid fixture per session/device. Never store credentials.
        filepath = fixture_dir / ('predict_' + boot_id + '_' + seq['device_id'] + '.json')
        if not filepath.exists():
            filepath.write_text(json.dumps(request, indent=2, allow_nan=False) + '\n')
            print('[FIXTURE]', filepath, flush=True)
        if worker:
            try:
                result = worker.predict(request)
                print('[INFERENCE]', json.dumps(result), flush=True)
            except Exception as exc:
                print('[INFERENCE UNAVAILABLE]', str(exc), flush=True)
        else:
            print('[SEQUENCE READY]', seq['device_id'], 'shape=(8,16)', flush=True)

    extractor = FeatureExtractor(GATEWAY_ID, boot_id, capture_session_id,
                                 sequence_length=SEQUENCE_LENGTH,
                                 inactivity_timeout_seconds=INACTIVITY_TIMEOUT_SECONDS,
                                 ordering_allowance_ms=ORDERING_ALLOWANCE_MS,
                                 on_window=on_window, on_sequence=on_sequence)
    registry = DeviceRegistry(LAN_NET, gateway_ip=GATEWAY_IP, path=REGISTRY_FILE,
                              on_change=lambda ip, d: extractor.reset_device(ip, d))
    capture = PacketCapture(LAN_INTERFACE, CAPTURE_FILTER, registry, extractor,
                            queue_size=CAPTURE_QUEUE_SIZE)
    extractor.start()
    try:
        capture.run()
    except KeyboardInterrupt:
        print('[STOP] user interrupted')
    finally:
        extractor.stop()


if __name__ == '__main__':
    main()
