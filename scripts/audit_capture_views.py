"""Measure paired Linux SLL receive/forward observations without deleting packets."""

import argparse
from collections import Counter, defaultdict, deque
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ids.datasets.packet_audit import read_pcap, write_json, decode, load_annotations, matching, candidate_label


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    indexes, _ = load_annotations(Path(config["csv_root"]), Path(config["bro_root"]),
                                 config["start_us"], config["end_us"])
    pending = defaultdict(deque)
    expire = deque()
    counts = Counter()
    examples = []
    unpaired_examples = []
    time_gaps = Counter()
    paired_forward_labels = Counter()
    unpaired_forward_labels = Counter()
    unpaired_forward_endpoints = Counter()
    timestamp_gaps = []
    previous_time = None
    previous_max = 0
    for file_index, filename in enumerate(config["captures"]):
        for packet in read_pcap(filename):
            if previous_time is not None and packet.time_us - previous_time > 1_000_000:
                timestamp_gaps.append({"following_file": filename, "following_packet": packet.number,
                    "previous_time_us": previous_time, "next_time_us": packet.time_us,
                    "gap_us": packet.time_us - previous_time})
            previous_time = packet.time_us
            if len(packet.data) < 36 or struct.unpack_from("!H", packet.data, 14)[0] != 0x0800:
                continue
            ip = bytearray(packet.data[16:])
            length = struct.unpack_from("!H", ip, 2)[0]
            if ip[0] >> 4 != 4 or len(ip) < length or length < 20:
                continue
            kind = struct.unpack_from("!H", packet.data)[0]
            ttl = ip[8]
            ip = ip[:length]
            ip[8] = ip[10] = ip[11] = 0
            key = hashlib.sha256(ip).digest()
            counts[f"ipv4_sll_type_{kind}"] += 1
            # Expiration uses a monotonic watermark and permits the measured
            # small file-order reversals. A 100 ms tolerance is diagnostic.
            previous_max = max(previous_max, packet.time_us)
            while expire and previous_max - expire[0][0] > 100000:
                old_time, old_key, old_number = expire.popleft()
                queue = pending.get(old_key)
                if queue and queue[0][0] == old_time and queue[0][3] == old_number:
                    queue.popleft()
                    counts["unpaired_receive_older_than_100ms"] += 1
                    if not queue:
                        del pending[old_key]
            if kind == 0:
                pending[key].append((packet.time_us, ttl, file_index, packet.number))
                expire.append((packet.time_us, key, packet.number))
            elif kind == 4:
                decoded = decode(packet)
                packet_key = decoded["key"]
                if decoded["issues"]:
                    label = "excluded:" + decoded["issues"][0]
                elif packet_key is None:
                    label = "icmp_annotation_adapter_required"
                else:
                    gt = matching(indexes["gt"], packet_key, packet.time_us, 1_000_000, 1_000_000)
                    flows = matching(indexes["flow"], packet_key, packet.time_us, 1_000_000, 1_000_000)
                    label = candidate_label(gt, flows)
                queue = pending.get(key)
                match = None
                if queue:
                    for candidate in queue:
                        if 0 <= packet.time_us-candidate[0] <= 100000 and candidate[1] == ttl+1:
                            match = candidate
                            break
                if match:
                    paired_forward_labels[label] += 1
                    queue.remove(match)
                    if not queue:
                        del pending[key]
                    counts["receive_forward_pairs"] += 1
                    gap = packet.time_us-match[0]
                    time_gaps["le_100us" if gap<=100 else "le_1ms" if gap<=1000 else "le_10ms" if gap<=10000 else "le_100ms"] += 1
                    cross_file = match[2] != file_index
                    if cross_file:
                        counts["cross_file_pairs"] += 1
                    if len(examples)<10 or cross_file:
                        examples.append({"receive_file": config["captures"][match[2]],
                            "receive_packet": match[3], "receive_time_us": match[0],
                            "forward_file": filename, "forward_packet": packet.number,
                            "forward_time_us": packet.time_us, "receive_ttl": match[1],
                            "forward_ttl": ttl, "gap_us": gap, "normalized_ip_sha256": key.hex()})
                else:
                    unpaired_forward_labels[label] += 1
                    unpaired_forward_endpoints[str((decoded["src"], decoded["dst"]))] += 1
                    counts["unpaired_forward"] += 1
                    if len(unpaired_examples)<10:
                        unpaired_examples.append({"file": filename,"packet":packet.number,"time_us":packet.time_us})
    counts["unpaired_receive_at_excerpt_end"] = sum(len(q) for q in pending.values())
    write_json(Path(config["output"]) / "capture_views.json", {"counts":dict(counts),
        "pair_gap_buckets":dict(time_gaps), "examples":examples,
        "paired_forward_candidate_labels": dict(paired_forward_labels),
        "unpaired_forward_candidate_labels": dict(unpaired_forward_labels),
        "unpaired_forward_endpoint_pairs": dict(unpaired_forward_endpoints),
        "record_gaps_over_one_second": timestamp_gaps,
        "unpaired_forward_examples":unpaired_examples,
        "method":"One-to-one same complete IPv4 bytes except TTL/header checksum; SLL 0 then 4; TTL decrement exactly 1; delay 0..100000us",
        "limitations":"Diagnostic pairing cannot independently certify capture interfaces or every repeated datagram; no packets removed"})
    print(json.dumps(counts),flush=True)


if __name__ == "__main__":
    main()
