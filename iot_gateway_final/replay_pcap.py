"""Offline replay through the same parser and feature extractor as live capture.

Requires a PCAP containing packets for the configured IoT subnet. PCAP is
processed in timestamp order, with no model training or inferred labels.
"""
import argparse
import json
import uuid
from pathlib import Path
from scapy.utils import PcapReader
from config import LAN_NET, GATEWAY_ID, GATEWAY_IP
from device_registry import DeviceRegistry
from packet_parser import parse_packet
from feature_extractor import FeatureExtractor
from contracts import new_predict_request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap', type=Path)
    ap.add_argument('--output', type=Path, default=Path('fixtures/offline_predict.json'))
    ap.add_argument('--model-id', default='cnn-unsw-ga-v1')
    args = ap.parse_args()
    device_registry = DeviceRegistry(LAN_NET, gateway_ip=GATEWAY_IP)
    sequences = []
    extractor = FeatureExtractor(GATEWAY_ID, str(uuid.uuid4()), str(uuid.uuid4()),
                                 on_sequence=lambda seq: sequences.append(seq), live=False)
    with PcapReader(str(args.pcap)) as capture:
        last_ms = None
        for packet in capture:
            current_ms = int(float(packet.time) * 1000)
            if last_ms is not None and current_ms < last_ms:
                extractor.mark_capture_loss('out_of_order_pcap')
            # Leave a 100-ms allowance while processing increasing timestamps.
            extractor.advance_to(current_ms)
            device_registry.learn_packet(packet)
            for record in parse_packet(packet, device_registry):
                extractor.add_packet(record)
            last_ms = current_ms
    if last_ms is not None:
        extractor.advance_to(last_ms + 1100)
    if not sequences:
        raise SystemExit('No complete valid 8-second sequence found in PCAP')
    body = new_predict_request(args.model_id, sequences[0]['windows'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(body, indent=2) + '\n')
    print('Saved', args.output)


if __name__ == '__main__':
    main()
