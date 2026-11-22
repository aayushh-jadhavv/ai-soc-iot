"""Phase 1 PCAP evidence audit. Produces diagnostics, never feature tensors.

Classic PCAP with Linux SLL v1 is supported for the supplied UNSW excerpt.
Annotation joins are explicitly provisional pending source timing semantics.
"""

import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import socket
import struct

from ids.datasets.audit import family, rows, sha256, tuple_key


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def microseconds(text):
    value = Decimal(text) * 1_000_000
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError("Timestamp does not resolve to microseconds")
    return int(value)


def canonical(key):
    proto, src, sport, dst, dport = key
    # String ports keep sorting defined for legacy nonnumeric port tokens.
    left, right = (src, str(sport)), (dst, str(dport))
    return (proto, *min(left, right), *max(left, right))


@dataclass
class Record:
    number: int
    offset: int
    time_us: int
    captured: int
    original: int
    data: bytes


def read_pcap(path):
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise ValueError("Only classic microsecond PCAP is supported")
        endian = "<" if header[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", header)
        if (major, minor) != (2, 4) or linktype != 113:
            raise ValueError("Expected PCAP 2.4 LINKTYPE_LINUX_SLL=113")
        number = 0
        while True:
            offset = stream.tell()
            raw = stream.read(16)
            if not raw:
                break
            if len(raw) != 16:
                raise ValueError(f"Partial packet header at {offset}")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", raw)
            if fraction >= 1_000_000 or captured > snaplen or captured > original:
                raise ValueError(f"Invalid PCAP record at {offset}")
            data = stream.read(captured)
            if len(data) != captured:
                raise ValueError(f"Partial packet data at {offset}")
            number += 1
            yield Record(number, offset, seconds * 1_000_000 + fraction, captured, original, data)


def decode(record):
    data = record.data
    result = {"issues": [], "key": None, "src": None, "dst": None}
    if record.captured < record.original:
        result["issues"].append("capture_truncation")
    if len(data) < 16:
        result["issues"].append("short_sll")
        return result
    packet_type, hardware, address_length = struct.unpack_from("!HHH", data)
    result.update(sll_packet_type=packet_type, sll_hardware=hardware,
                  sll_address=data[6:6 + min(address_length, 8)].hex(),
                  ether_type=struct.unpack_from("!H", data, 14)[0])
    if result["ether_type"] != 0x0800:
        result["issues"].append("arp_registry" if result["ether_type"] == 0x0806 else "non_ipv4")
        return result
    ip = data[16:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        result["issues"].append("invalid_ipv4")
        return result
    ihl = (ip[0] & 15) * 4
    total = struct.unpack_from("!H", ip, 2)[0]
    result.update(src=socket.inet_ntoa(ip[12:16]), dst=socket.inet_ntoa(ip[16:20]),
                  protocol_number=ip[9], ip_length=total,
                  ip_id=struct.unpack_from("!H", ip, 4)[0])
    if ihl < 20 or total < ihl or len(ip) < total:
        result["issues"].append("invalid_or_truncated_ipv4")
        return result
    result["ip_fingerprint"] = hashlib.sha256(ip[:total]).digest()
    fragments = struct.unpack_from("!H", ip, 6)[0]
    if fragments & 0x3fff:
        result["issues"].append("ipv4_fragment")
        return result
    payload = ip[ihl:total]
    protocol = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip[9])
    if protocol is None:
        result["issues"].append("unsupported_ipv4_protocol")
        return result
    result["protocol"] = protocol
    if protocol == "icmp":
        if len(payload) < 8:
            result["issues"].append("malformed_icmp")
        else:
            result.update(icmp_type=payload[0], icmp_code=payload[1])
        return result
    minimum = 20 if protocol == "tcp" else 8
    if len(payload) < minimum:
        result["issues"].append("malformed_transport")
        return result
    sport, dport = struct.unpack_from("!HH", payload)
    if protocol == "tcp":
        tcp_length = (payload[12] >> 4) * 4
        if tcp_length < 20 or tcp_length > len(payload):
            result["issues"].append("malformed_tcp_header")
            return result
        result.update(tcp_flags=payload[13], tcp_sequence=struct.unpack_from("!I", payload, 4)[0])
    elif not 8 <= struct.unpack_from("!H", payload, 4)[0] <= len(payload):
        result["issues"].append("malformed_udp_length")
        return result
    result["key"] = (protocol, result["src"], sport, result["dst"], dport)
    return result


def load_annotations(csv_root, bro_root, start, end):
    indexes = {name: defaultdict(list) for name in ("gt", "flow", "bro")}
    profiles = []
    gt_path = csv_root / "NUSW-NB15_GT.csv"
    for number, row in enumerate(rows(gt_path)):
        if number == 0:
            continue
        a, b = microseconds(row[0]), microseconds(row[1])
        if b + 1_000_000 < start or a - 1_000_000 > end:
            continue
        key = tuple_key(row[4], *row[5:9])
        indexes["gt"][canonical(key)].append({"start": a, "end": b, "key": key,
            "family": family(row[2]), "row": number + 1, "file": str(gt_path),
            "name": row[9]})
    for path in sorted(csv_root.glob("UNSW-NB15_[1-4].csv")):
        retained = 0
        for number, row in enumerate(rows(path), 1):
            a, b = microseconds(row[28]), microseconds(row[29])
            if b + 1_000_000 < start or a - 1_000_000 > end:
                continue
            key = tuple_key(row[4], *row[:4])
            indexes["flow"][canonical(key)].append({"start": a, "end": b, "key": key,
                "family": family(row[47]), "label": row[48], "row": number,
                "file": str(path), "duration": row[6]})
            retained += 1
        profiles.append({"file": str(path), "retained_rows": retained})
    for path in sorted(bro_root.rglob("conn.log")):
        fields = None
        kept = total = 0
        minimum = maximum = None
        with path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if line.startswith("#fields\t"):
                    fields = line.rstrip().split("\t")[1:]
                if line.startswith("#"):
                    continue
                row = dict(zip(fields, line.rstrip("\r\n").split("\t")))
                a = microseconds(row["ts"])
                b = a + (0 if row["duration"] == "-" else microseconds(row["duration"]))
                total += 1
                minimum = a if minimum is None else min(minimum, a)
                maximum = b if maximum is None else max(maximum, b)
                if b < start or a > end:
                    continue
                key = tuple_key(row["proto"], row["id.orig_h"], row["id.orig_p"],
                                row["id.resp_h"], row["id.resp_p"])
                indexes["bro"][canonical(key)].append({"start": a, "end": b, "key": key,
                    "row": number, "file": str(path), "uid": row["uid"],
                    "missed_bytes": row["missed_bytes"], "state": row["conn_state"],
                    "orig_pkts": row["orig_pkts"], "resp_pkts": row["resp_pkts"]})
                kept += 1
        profiles.append({"file": str(path), "rows": total, "retained_rows": kept,
                         "min_start_us": minimum, "max_end_us": maximum})
    return indexes, profiles


def matching(index, key, time, padding_before=0, padding_after=0):
    return [ann for ann in index.get(canonical(key), [])
            if ann["start"] - padding_before <= time <= ann["end"] + padding_after]


def candidate_label(gt, flows):
    gt_families = {a["family"] for a in gt}
    flow_families = {a["family"] for a in flows}
    if len(gt_families | flow_families) > 1:
        return "conflicting_candidates"
    if gt_families:
        return "in_scope_attack_candidate" if gt_families <= {"reconnaissance", "dos"} else "out_of_scope_attack_candidate"
    if flow_families == {"benign"}:
        return "csv_benign_candidate"
    if flow_families:
        return "flow_attack_without_gt_candidate"
    return "unmatched"


def audit(config_path):
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    output = Path(config["output"])
    if (output / "packet_summary.json").exists():
        raise FileExistsError("Use a new evidence directory")
    output.mkdir(parents=True, exist_ok=True)
    paths = [Path(p) for p in config["captures"]]
    start, end = config["start_us"], config["end_us"]
    indexes, annotation_profiles = load_annotations(Path(config["csv_root"]),
        Path(config["bro_root"]), start, end)
    print("Annotation indexes loaded", flush=True)
    write_json(output / "annotation_profiles.json", annotation_profiles)
    counts = Counter()
    file_stats = []
    endpoints = defaultdict(Counter)
    windows = defaultdict(Counter)
    traces = defaultdict(list)
    seen_records = set()
    recent_ips = {}
    duplicate_examples = []
    bro_starts = {}
    previous = None
    for path in paths:
        stats = Counter()
        minimum = maximum = None
        first_time = last_time = None
        before = path.stat()
        digest = sha256(path)
        for packet in read_pcap(path):
            stats["packets"] += 1
            if packet.number % 500000 == 0:
                print(f"{path.name}: {packet.number:,} packets", flush=True)
            t = packet.time_us
            minimum = t if minimum is None else min(minimum, t)
            maximum = t if maximum is None else max(maximum, t)
            if first_time is None:
                first_time = t
            last_time = t
            if previous is not None and t < previous:
                stats["backward_adjacent_timestamps"] += 1
                stats["maximum_backward_us"] = max(stats["maximum_backward_us"], previous - t)
                if previous - t > 100000:
                    stats["backward_over_100ms"] += 1
            previous = t
            decoded = decode(packet)
            packet_hash = hashlib.sha256(packet.data).hexdigest()
            fingerprint = hashlib.sha256(struct.pack("!QI", t, packet.original) + packet.data).digest()
            if fingerprint in seen_records:
                stats["exact_record_repeat_occurrences"] += 1
            seen_records.add(fingerprint)
            stats["sll_type:" + str(decoded.get("sll_packet_type"))] += 1
            for issue in decoded["issues"]:
                stats["issue:" + issue] += 1
            ip_digest = decoded.get("ip_fingerprint")
            if ip_digest:
                last = recent_ips.get(ip_digest)
                if last and 0 <= t - last[0] <= 1000:
                    stats["identical_ip_bytes_within_1ms"] += 1
                    pair = f"{last[1]}->{decoded['sll_packet_type']}"
                    stats["repeat_sll_pair:" + pair] += 1
                    if len(duplicate_examples) < 12:
                        duplicate_examples.append({"first_file": last[2], "first_packet": last[3],
                            "second_file": path.name, "second_packet": packet.number,
                            "gap_us": t-last[0], "sll_pair": pair, "ip_sha256": ip_digest.hex()})
                recent_ips[ip_digest] = (t, decoded["sll_packet_type"], path.name, packet.number)
                # Keep a bounded diagnostic cache. Exact repeats above are global.
                if len(recent_ips) > 150000:
                    recent_ips = {h: v for h, v in recent_ips.items() if t-v[0] < 1_000_000}
            key = decoded["key"]
            gt = flows = bro = []
            boundary_gt = []
            if decoded["issues"]:
                status = "excluded:" + decoded["issues"][0]
            elif key is None:
                status = "icmp_annotation_adapter_required"
            else:
                # Diagnostic only. Integer-second source rounding is unresolved.
                gt = matching(indexes["gt"], key, t, 1_000_000, 1_000_000)
                flows = matching(indexes["flow"], key, t, 1_000_000, 1_000_000)
                bro = matching(indexes["bro"], key, t)
                status = candidate_label(gt, flows)
                boundary_gt = [a for a in gt if not a["start"] <= t <= a["end"]]
                if gt and len(boundary_gt) == len(gt):
                    stats["gt_matches_only_with_boundary_padding"] += 1
                if gt:
                    stats["with_gt_candidate"] += 1
                    stats["gt_forward_candidate" if any(tuple(a["key"]) == key for a in gt)
                          else "gt_reverse_candidate"] += 1
                if bro:
                    stats["with_bro_interval_match"] += 1
                    for ann in bro:
                        aid = (ann["file"], ann["row"])
                        bro_starts[aid] = min(bro_starts.get(aid, t), t)
                if flows:
                    stats["with_flow_candidate"] += 1
            stats["label:" + status] += 1
            if gt:
                for category in {a["family"] for a in gt}:
                    stats["gt_family_membership:" + category] += 1
            for addr, direction in ((decoded["src"], "out"), (decoded["dst"], "in")):
                if addr is None:
                    continue
                endpoints[addr][direction + "_packets"] += 1
                endpoints[addr]["label:" + status] += 1
                if addr in config["monitored_ips"]:
                    windows[(addr, t // 1_000_000)][status] += 1
            trace_kind = status
            if gt and any(tuple(a["key"]) != key for a in gt):
                trace_kind += ":reverse"
            if len(traces[trace_kind]) < 3:
                traces[trace_kind].append({"capture_file": str(path), "packet_number": packet.number,
                    "record_byte_offset": packet.offset, "timestamp_us": t,
                    "packet_sha256": packet_hash, "captured_length": packet.captured,
                    "original_length": packet.original,
                    "decoded": {k: v for k, v in decoded.items() if k != "ip_fingerprint"},
                    "candidate_status": status, "gt_candidates": gt, "flow_candidates": flows,
                    "bro_matches": bro, "boundary_padding_required": bool(gt) and len(boundary_gt)==len(gt),
                    "supervised_label": None, "reason": "provisional_source_timing_and_capture_coverage"})
            # Always retain the reconnaissance anchor and near-boundary witnesses.
            if key and canonical(key) == canonical(("tcp", "175.45.176.0", 13284, "149.171.126.16", 80)):
                if len(traces["reconnaissance_anchor"]) < 100:
                    traces["reconnaissance_anchor"].append({"capture_file": str(path), "packet_number": packet.number,
                        "timestamp_us": t, "packet_sha256": packet_hash, "key": key,
                        "sll_type": decoded["sll_packet_type"], "tcp_flags": decoded.get("tcp_flags"),
                        "status": status, "gt_rows": [a["row"] for a in gt],
                        "bro_uids": [a["uid"] for a in bro]})
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError("Capture changed during scan")
        counts.update({k: v for k, v in stats.items() if k != "maximum_backward_us"})
        file_stats.append({"file": str(path), "sha256": digest, "bytes": before.st_size,
            "first_record_us": first_time, "last_record_us": last_time,
            "earliest_us": minimum, "latest_us": maximum, "counts": dict(stats)})
    timing = Counter()
    for anns in indexes["bro"].values():
        for ann in anns:
            earliest = bro_starts.get((ann["file"], ann["row"]))
            if earliest is not None:
                timing["matched_bro_rows"] += 1
                if earliest == ann["start"]:
                    timing["earliest_packet_equals_bro_start_us"] += 1
    window_totals = Counter()
    with (output / "endpoint_second_diagnostics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["endpoint", "second_epoch", "candidate_window_status", "observed_packets", "packet_status_counts_json"])
        for (addr, second), c in sorted(windows.items()):
            if any(s.startswith("excluded:") and s != "excluded:arp_registry" for s in c):
                status = "invalid_observed_coverage"
            elif "conflicting_candidates" in c:
                status = "conflicting_candidates"
            elif "out_of_scope_attack_candidate" in c or "flow_attack_without_gt_candidate" in c:
                status = "out_of_scope_or_unresolved_attack"
            elif "in_scope_attack_candidate" in c:
                status = "positive_candidate_mixed_unknown" if any(s in c for s in ("unmatched", "icmp_annotation_adapter_required")) else "positive_candidate"
            elif set(c) <= {"csv_benign_candidate"}:
                status = "benign_candidate"
            else:
                status = "unknown"
            window_totals[status] += 1
            writer.writerow([addr, second, status, sum(c.values()), json.dumps(c, sort_keys=True)])
    write_json(output / "packet_summary.json", {"counts": dict(counts), "files": file_stats,
        "observed_endpoint_seconds": len(windows), "window_candidate_counts": dict(window_totals),
        "timing": dict(timing), "packet_candidate_join_padding_us": 1_000_000,
        "padding_is_diagnostic_not_verified_interval": True, "accepted_supervised_sequences": 0,
        "record_end_integrity": "both_files_read_to_clean_record_boundary"})
    write_json(output / "packet_traces.json", dict(traces))
    write_json(output / "endpoint_observations.json", endpoints)
    write_json(output / "duplicate_packet_examples.json", duplicate_examples)
    print(json.dumps({"packets": counts["packets"], "observed_endpoint_seconds": len(windows)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    audit(parser.parse_args().config)
