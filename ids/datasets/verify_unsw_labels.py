"""Verify final-window labels on the audited UNSW excerpt, without feature extraction."""

import argparse
from collections import Counter, defaultdict, deque
import csv
from dataclasses import dataclass, field
from decimal import Decimal
import gzip
import hashlib
from pathlib import Path
import json

from ids.datasets.audit import family, rows, sha256, tuple_key
from ids.datasets.label_policy import final_window_label
from ids.datasets.packet_audit import canonical, decode, load_annotations, read_pcap, write_json


SECOND = 1_000_000
HALF = SECOND // 2
SCOPE = {"benign", "reconnaissance", "dos"}


def whole_second(time_us):
    return (time_us + HALF) // SECOND


@dataclass
class Flow:
    file: str
    row: int
    key: tuple
    start: int
    end: int
    duration_us: Decimal
    signature: tuple
    family: str
    label: str
    first: int | None = None
    last: int | None = None
    ambiguous: bool = False
    raw_totals: list = field(default_factory=lambda: [0, 0, 0, 0])
    witnesses: dict = field(default_factory=dict)

    def observe(self, time, direction, length):
        self.first = time if self.first is None else min(time, self.first)
        self.last = time if self.last is None else max(time, self.last)
        self.raw_totals[direction] += 1
        self.raw_totals[2 + direction] += length

def read_flows(csv_root, start, stop):
    flows = []
    by_tuple = defaultdict(list)
    for path in sorted(csv_root.glob("UNSW-NB15_[1-4].csv")):
        for row_number, row in enumerate(rows(path), 1):
            if row[4] not in {"tcp", "udp"}:
                continue
            a, b = int(row[28]), int(row[29])
            if b < start or a > stop:
                continue
            key = tuple_key(row[4], *row[:4])
            signature = tuple(int(row[i]) for i in (16, 17, 7, 8))
            by_tuple[canonical(key)].append(len(flows))
            flows.append(Flow(str(path), row_number, key, a, b, Decimal(row[6]) * SECOND,
                              signature, family(row[47]), row[48]))
    return flows, by_tuple


def read_argus(path):
    by_signature = defaultdict(list)
    for number, row in enumerate(rows(path), 1):
        if row[1] not in {"tcp", "udp"}:
            continue
        key = tuple_key(row[1], *row[2:6])
        signature = tuple(int(row[i]) for i in (9, 10, 11, 12))
        # Use only the corroborated tuple, bounds, packet counts and byte totals
        # from this headerless export.
        by_signature[(key, int(row[0]), int(row[8]), signature)].append(number)
    return by_signature


class CaptureViews:
    """Consume a forwarded copy at most once, keeping the receive timestamp."""

    def __init__(self):
        self.queue = defaultdict(deque)
        self.events = deque()
        self.watermark = 0
        self.counts = Counter()

    def paired_forward(self, packet, decoded, file_number):
        kind = decoded.get("sll_packet_type")
        if kind not in {0, 4} or "ip_fingerprint" not in decoded:
            return False
        ip = bytearray(packet.data[16:16 + decoded["ip_length"]])
        ttl = ip[8]
        ip[8] = ip[10] = ip[11] = 0
        key = hashlib.sha256(ip).digest()
        time = packet.time_us
        self.watermark = max(time, self.watermark)
        while self.events and self.watermark - self.events[0][0] > 100_000:
            old_time, old_key, old_ttl, old_file, old_packet = self.events.popleft()
            pending = self.queue.get(old_key)
            if pending and pending[0] == (old_time, old_ttl, old_file, old_packet):
                pending.popleft()
                if not pending:
                    del self.queue[old_key]
        if kind == 0:
            self.queue[key].append((time, ttl, file_number, packet.number))
            self.events.append((time, key, ttl, file_number, packet.number))
            return False
        pending = self.queue.get(key)
        for received in pending or ():
            if 0 <= time - received[0] <= 100_000 and received[1] == ttl + 1:
                pending.remove(received)
                if not pending:
                    del self.queue[key]
                self.counts["paired_forward"] += 1
                if file_number != received[2]:
                    self.counts["cross_file_pair"] += 1
                return True
        self.counts["unpaired_forward"] += 1
        return False


def verify_flow(flow, argus_index, indexes, first_us, last_us):
    key = canonical(flow.key)
    gt = [a for a in indexes["gt"].get(key, ())
          if whole_second(a["start"]) <= flow.end and whole_second(a["end"]) >= flow.start]
    families = {a["family"] for a in gt} | {flow.family}
    if len(families) > 1 or (flow.family == "benign" and flow.label != "0") or (
            flow.family != "benign" and flow.label != "1"):
        return "conflict", None
    if flow.family != "benign" and (len(gt) != 1 or tuple(gt[0]["key"]) != flow.key
            or gt[0]["start"] != flow.start * SECOND or gt[0]["end"] != flow.end * SECOND):
        return "attack_annotation_not_unique", None
    if flow.ambiguous:
        return "multiple_flow_candidates", None
    if flow.first is None:
        return "no_packets", None
    if flow.start * SECOND - HALF < first_us or flow.end * SECOND + HALF > last_us:
        return "flow_near_capture_edge", None
    if whole_second(flow.first) != flow.start or whole_second(flow.last) != flow.end:
        return "rounded_extrema_disagree", None
    if tuple(flow.raw_totals) != flow.signature:
        return "packet_or_byte_totals_disagree", None
    if abs((flow.last - flow.first) - flow.duration_us) > 1:
        return "packet_duration_disagrees", None
    argus = argus_index.get((flow.key, flow.start, flow.end, flow.signature), ())
    if len(argus) != 1:
        return "argus_signature_not_unique", None
    bro = [a for a in indexes["bro"].get(key, ())
           if tuple(a["key"]) == flow.key and a["start"] == flow.first]
    if len(bro) != 1:
        return "bro_first_packet_anchor_not_unique", None
    if bro[0]["missed_bytes"] != "0":
        return "bro_content_gap", None
    return flow.family, {"bro": bro[0], "argus_csv_row": argus[0], "gt": gt}


def packet_witness(packet, path, key):
    return {"file": str(path), "packet": packet.number, "record_offset": packet.offset,
            "unix_us": packet.time_us, "tuple": key,
            "packet_sha256": hashlib.sha256(packet.data).hexdigest()}


def verify(config_path, output):
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    start, stop = cfg["start_us"], cfg["end_us"]
    monitored = set(cfg["monitored_ips"])
    csv_root, bro_root = Path(cfg["csv_root"]), Path(cfg["bro_root"])
    argus_path = bro_root.parents[1] / "Argus Files" / "Argus Files 22-1-2015" / "CSV of Argus" / "1.csv"
    inputs = [Path(p) for p in cfg["captures"]]
    flows, flow_index = read_flows(csv_root, whole_second(start), whole_second(stop))
    argus = read_argus(argus_path)
    annotations, profiles = load_annotations(csv_root, bro_root, start, stop)
    # Hash the exact originals, anchored to the reviewed inventory when available.
    audited = json.loads((config_path.parent / "source_manifest.json").read_text(encoding="utf-8"))
    expected = {Path(x["path"]).resolve(): x["sha256"] for x in audited["files"]}
    source_paths = {*inputs, argus_path, csv_root / "NUSW-NB15_GT.csv",
                    *(Path(p["file"]) for p in profiles)}
    source_hashes = {}
    for source in sorted(source_paths):
        digest = sha256(source)
        if digest != expected.get(source.resolve()):
            raise ValueError(f"Source differs from the reviewed inventory: {source}")
        source_hashes[str(source)] = digest
    source_stats = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in source_paths}
    print(f"Loaded {len(flows):,} TCP/UDP source flows", flush=True)

    views = CaptureViews()
    windows = defaultdict(Counter)
    counts = Counter()
    gaps = set()
    watermark = None
    for file_idx, path in enumerate(inputs):
        for packet in read_pcap(path):
            counts["raw_records"] += 1
            t = packet.time_us
            second = t // SECOND
            if watermark is not None and t - watermark > SECOND:
                gaps.update(range(watermark // SECOND, second + 1))
            if watermark is not None and watermark - t > 100_000:
                raise ValueError("Clock regression exceeds the audited ordering allowance")
            watermark = t if watermark is None else max(t, watermark)
            d = decode(packet)
            paired = views.paired_forward(packet, d, file_idx)
            if not paired:
                counts["retained_observations"] += 1
            endpoints = monitored.intersection((d["src"], d["dst"]))
            if d["issues"] or d["key"] is None:
                if not paired:
                    issue = d["issues"][0] if d["issues"] else "unsupported_icmp"
                    counts["retained:" + issue] += 1
                    if issue != "arp_registry":
                        affected = endpoints if d["src"] is not None else monitored
                        for ip in affected:
                            windows[ip, second]["invalid:" + issue] += 1
                continue
            key = d["key"]
            ckey = canonical(key)
            rounded = whole_second(t)
            potential = [i for i in flow_index.get(ckey, ()) if flows[i].start <= rounded <= flows[i].end]
            if len(potential) != 1:
                for i in potential:
                    flows[i].ambiguous = True
                families = {flows[i].family for i in potential}
                families.update(a["family"] for a in annotations["gt"].get(ckey, ())
                                if a["start"] <= rounded * SECOND <= a["end"])
                outcome = ("conflict" if len(families) > 1 else
                           "outside_scope_possible" if families - SCOPE else "unverified_tuple")
                if not paired:
                    counts["retained:" + outcome] += 1
                    for ip in endpoints:
                        windows[ip, second][outcome] += 1
                continue
            index = potential[0]
            flow = flows[index]
            direction = 0 if key == flow.key else 1
            flow.observe(t, direction, d["ip_length"])
            if not paired:
                for ip in endpoints:
                    windows[ip, second][index] += 1
                if endpoints:
                    witness_key = (second, direction)
                    if witness_key not in flow.witnesses:
                        flow.witnesses[witness_key] = packet_witness(packet, path, key)
            if packet.number % 500_000 == 0:
                print(f"{path.name}: {packet.number:,} packet records", flush=True)

    classified = [verify_flow(f, argus, annotations, start, stop) for f in flows]
    flow_reasons = Counter(label for label, _ in classified)
    print(f"Verified connections by class: {dict((f, flow_reasons[f]) for f in sorted(SCOPE))}", flush=True)
    observed_window_counts = Counter()
    labeled = {}
    clean = set()
    valid_start, valid_stop = (start + SECOND - 1) // SECOND, stop // SECOND
    for (ip, s), evidence in windows.items():
        outcomes = Counter()
        ids = defaultdict(list)
        for index, count in evidence.items():
            if isinstance(index, int):
                outcome, verified = classified[index]
                if verified:
                    ids[outcome].append(index)
                elif outcome == "bro_content_gap":
                    outcome = "invalid:bro_content_gap"
                elif flows[index].family not in SCOPE and outcome != "conflict":
                    outcome = "outside_scope_possible"
            else:
                outcome = index
            outcomes[outcome] += count
        coverage = valid_start <= s < valid_stop and s not in gaps and not any(
            k.startswith("invalid:") for k in outcomes)
        if coverage:
            clean.add((ip, s))
        attack_families = set(ids) & {"reconnaissance", "dos"}
        categories = set()
        for name in outcomes:
            if name in attack_families:
                categories.add("attack")
            elif name == "benign" and ids[name]:
                categories.add("benign")
            elif name == "conflict":
                categories.add("conflict")
            elif name in {"outside_scope_possible"} or (name not in SCOPE and ids[name]):
                categories.add("excluded")
            else:
                categories.add("unknown")
        result = final_window_label([{"label": v} for v in categories],
                                    coverage_valid=coverage, identity_valid=True,
                                    normal_coverage=categories == {"benign"})
        label = result["label"]
        name = ("+".join(sorted(attack_families)) if label == 1 else
                "benign" if label == 0 else result["reason"])
        observed_window_counts[name] += 1
        if label is not None:
            labeled[ip, s] = (label, name, result["mixed_unknown"], ids, outcomes)

    # Count positive evidence with eight observed, valid seconds as a stricter
    # demonstrable subset. Silence is never used to establish capture health.
    context_counts = Counter()
    examples = {}
    with (output / "verified_final_windows.csv").open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["endpoint", "start_unix_second", "binary_label", "family",
                         "mixed_unknown", "eight_observed_valid_seconds", "verified_flow_refs"])
        for (ip, s), (label, name, mixed, ids, outcomes) in sorted(labeled.items(), key=lambda x: x[0][::-1]):
            context = all((ip, s - delta) in clean for delta in range(8))
            if context:
                context_counts[name] += 1
            relevant = sorted(i for category in name.split("+") for i in ids[category])
            refs = "|".join(f"{Path(flows[i].file).name}:{flows[i].row}" for i in relevant)
            writer.writerow([ip, s, label, name, mixed, context, refs])
            if name not in examples or (context and not examples[name]["eight_observed_valid_seconds"]):
                i = relevant[0]
                examples[name] = {"endpoint": ip, "start_unix_second": s, "binary_label": label,
                    "family": name, "eight_observed_valid_seconds": context, "source_flow_index": i,
                    "packet_outcomes": outcomes, "window_witnesses": [w for (sec, _), w in
                       flows[i].witnesses.items() if sec == s]}

    with gzip.open(output / "verified_joins.jsonl.gz", "wt", encoding="utf-8", newline="\n") as file:
        for i, (label, support) in enumerate(classified):
            if support:
                f = flows[i]
                file.write(json.dumps({"index": i, "family": label, "source_csv": f.file, "source_row": f.row,
                    "tuple": f.key, "first_packet_us": f.first, "last_packet_us": f.last,
                    "half_open_interval_us": [f.first, f.last + 1], "csv_duration_us": str(f.duration_us),
                    "raw_forward_reverse_packet_counts_and_ip_bytes": f.signature,
                    "bro": support["bro"], "gt": support["gt"], "argus_csv": str(argus_path),
                    "argus_csv_row": support["argus_csv_row"],
                    "receive_view_witnesses": list(f.witnesses.values())}, separators=(",", ":")) + "\n")
    for source, stat in source_stats.items():
        if (source.stat().st_size, source.stat().st_mtime_ns) != stat:
            raise ValueError(f"Source changed during verification: {source}")
    report = {"source_sha256": source_hashes, "source_group": cfg["local_group_id"],
        "audit_config_sha256": sha256(config_path),
        "verification_code_sha256": sha256(Path(__file__)),
        "original_session_id": cfg["original_session_id"], "packet_counts": counts,
        "capture_view_counts": views.counts, "flow_join_outcomes": flow_reasons,
        "endpoint_seconds_with_observations": len(windows),
        "full_endpoint_seconds": (valid_stop - valid_start) * len(monitored),
        "full_endpoint_seconds_without_observations": sum((ip, s) not in windows
            for ip in monitored for s in range(valid_start, valid_stop)),
        "gap_affected_unix_seconds": sorted(gaps), "observed_final_window_outcomes": observed_window_counts,
        "labels_with_eight_observed_valid_seconds": context_counts,
        "class_witnesses": examples,
        "label_signoff": all(context_counts[f] > 0 for f in SCOPE),
        "independent_train_validation_test_feasible": False,
        "bulk_extraction_performed": False,
        "physical_sensor_drop_counts_available": False}
    write_json(output / "verification.json", report)
    print(json.dumps({"final_windows": observed_window_counts, "with_context": context_counts,
                      "label_signoff": report["label_signoff"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    verify(args.config, args.output)
