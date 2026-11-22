"""Read-only supplied-file audit, deliberately incapable of bulk extraction.

Run: python -m ids.datasets.audit --data-root CSV-Files --output NEW_DIRECTORY
Uses only the standard library. CSV row counts are NOT packet label coverage.
Original sessions remain null unless supplied in a future reviewed manifest.
"""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import sys


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def family(value):
    name = value.strip().lower()
    return {"": "benign", "normal": "benign", "backdoors": "backdoor"}.get(name, name)


def port(value):
    text = value.strip().lower()
    # Hex port tokens occur in UNSW records. Preserve all nonnumeric sentinels.
    try:
        return int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return text


def tuple_key(proto, src, sport, dst, dport):
    return (proto.strip().lower(), src.strip(), port(sport), dst.strip(), port(dport))


def reverse(key):
    return (key[0], key[3], key[4], key[1], key[2])


def rows(path):
    # The feature-description CSV contains legacy byte 0x92, not UTF-8.
    # Latin-1 is lossless for auditing source bytes; no silent replacement.
    with path.open("rb") as stream:
        utf8_bom = stream.read(3) == b"\xef\xbb\xbf"
    with path.open(encoding="utf-8-sig" if utf8_bom else "latin-1", newline="") as stream:
        yield from csv.reader(stream)


def stamp(value):
    number = Decimal(value)
    if not number.is_finite():
        raise ValueError("nonfinite time")
    return number


def iso(value):
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


def summarize(path, kind, seen, samples, gt_index):
    records = rows(path)
    header = next(records) if kind != "full_flows" else None
    counts, dates, widths = Counter(), Counter(), Counter()
    labels, raw_families, protocols = Counter(), Counter(), Counter()
    lo = hi = previous = None
    endpoints = set()
    examples = []
    for row_number, row in enumerate(records, 2 if header else 1):
        counts["rows"] += 1
        widths[len(row)] += 1
        expected = {"full_flows": 49, "ground_truth": 12}.get(kind, len(header or []))
        if len(row) != expected:
            counts["malformed_width"] += 1
            if len(examples) < 5:
                examples.append({"row": row_number, "reason": "malformed_width"})
            continue
        # Exact decoded-cell fingerprint, before trimming or family aliasing.
        payload = row[1:] if kind == "prepared_split" else row
        digest = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).digest()
        prior = seen.get(digest)
        if prior:
            counts["duplicate_rows_within_file" if prior == path.name else
                   "duplicate_rows_from_prior_file"] += 1
        else:
            seen[digest] = path.name
        if kind == "full_flows":
            cat, label = row[47], row[48].strip()
            start, end = row[28], row[29]
            key = tuple_key(row[4], *row[:4])
        elif kind == "ground_truth":
            cat, label, start, end = row[2], "1", row[0], row[1]
            key = tuple_key(row[4], *row[5:9])
        elif kind == "prepared_split":
            data = dict(zip(header, row))
            cat, label = data["attack_cat"], data["label"].strip()
            start = end = key = None
        else:
            continue
        cat_norm = family(cat)
        labels[label] += 1
        raw_families[cat] += 1
        counts["family:" + cat_norm] += 1
        if label not in {"0", "1"} or (label == "0") != (cat_norm == "benign"):
            counts["family_label_conflict"] += 1
        if start is None:
            continue
        protocols[key[0]] += 1
        endpoints.update((key[1], key[3]))
        try:
            ipaddress.IPv4Address(key[1])
            ipaddress.IPv4Address(key[3])
        except ipaddress.AddressValueError:
            counts["invalid_ipv4_endpoint"] += 1
        if key[0] in {"tcp", "udp"} and any(
                type(p) is not int or not 0 <= p <= 65535 for p in (key[2], key[4])):
            counts["invalid_transport_port"] += 1
        try:
            begin, finish = stamp(start), stamp(end)
            day = iso(begin)[:10]
        except (ValueError, InvalidOperation, OverflowError, OSError):
            counts["invalid_timestamp"] += 1
            continue
        dates[day] += 1
        if begin != begin.to_integral_value() or finish != finish.to_integral_value():
            counts["fractional_timestamp_rows"] += 1
        if finish < begin:
            counts["negative_interval"] += 1
        if finish == begin:
            counts["zero_duration_timestamp_interval"] += 1
        if previous is not None and begin < previous:
            counts["backward_start_in_row_order"] += 1
        previous = begin
        lo = begin if lo is None else min(lo, begin)
        hi = finish if hi is None else max(hi, finish)
        if kind == "ground_truth":
            gt_index[key].append((begin, finish, cat_norm, row_number))
        elif kind == "full_flows":
            # Deterministic, bounded first 32 rows per family/day/file. Not a
            # statistical packet-coverage sample or random prevalence estimate.
            bucket = (path.name, day, cat_norm)
            if len(samples[bucket]) < 32:
                samples[bucket].append({"file": path.name, "row": row_number,
                    "family": cat_norm, "label": label, "tuple": list(key),
                    "start": str(begin), "end": str(finish),
                    "original_session_id": None})
    return {"kind": kind, "header": header, "counts": dict(counts),
            "column_widths": dict(widths), "labels": dict(labels),
            "raw_families": dict(raw_families), "protocols": dict(protocols),
            "utc_dates_if_epoch_seconds": dict(dates),
            "min_start": str(lo) if lo is not None else None,
            "max_end": str(hi) if hi is not None else None,
            "min_start_utc_if_seconds": iso(lo) if lo is not None else None,
            "max_end_utc_if_seconds": iso(hi) if hi is not None else None,
            "observed_ips": sorted(endpoints), "parse_examples": examples,
            "original_session_id": None,
            "timestamp_unit": "candidate_epoch_seconds" if lo is not None else None,
            "clock_offset_verified": False, "monitored_endpoint_mapping_verified": False}


def candidate_joins(samples, gt_index):
    traces = []
    for bucket in sorted(samples):
        for row in samples[bucket]:
            key = tuple(row["tuple"])
            begin, end = Decimal(row["start"]), Decimal(row["end"])
            hits = []
            for direction, lookup in (("forward", key), ("reverse", reverse(key))):
                if direction == "reverse" and lookup == key:
                    continue
                for a, b, cat, row_number in gt_index.get(lookup, []):
                    # Inclusive coarse interval overlap is only a diagnostic
                    # candidate search. It is NOT a verified packet-time join.
                    if a <= end and b >= begin:
                        hits.append({"gt_row": row_number, "family": cat,
                                     "direction": direction, "start": str(a), "end": str(b)})
            cats = {h["family"] for h in hits}
            outcome = "unmatched" if not hits else "candidate"
            if len(cats) > 1 or (cats and cats != {row["family"]}):
                outcome = "candidate_conflict"
            elif len(hits) > 1:
                outcome = "multiple_candidates"
            traces.append({**row, "outcome": outcome, "candidate_annotations": hits,
                           "verified_packet_trace": False})
    return traces


def audit(root, output):
    root = Path(root).resolve()
    output = Path(output).resolve()
    if not root.is_dir():
        raise ValueError("Data root must be an existing directory")
    if output == root or root in output.parents:
        raise ValueError("Evidence output must be outside the source data root")
    paths = sorted(p for p in root.rglob("*") if p.is_file())
    output.mkdir(parents=True, exist_ok=False)
    inventory, profiles = [], {}
    gt_index, samples = defaultdict(list), defaultdict(list)
    known = {f"UNSW-NB15_{i}.csv": "full_flows" for i in range(1, 5)}
    known.update({"NUSW-NB15_GT.csv": "ground_truth", "UNSW-NB15_GT.csv": "ground_truth",
                  "UNSW_NB15_training-set.csv": "prepared_split",
                  "UNSW_NB15_testing-set.csv": "prepared_split"})
    # Shared fingerprints only within equivalent tables. Never treat a GT row
    # and feature row as independent observations of the same schema.
    for p in paths:
        inventory.append({"path": p.relative_to(root).as_posix(), "bytes": p.stat().st_size,
            "sha256": sha256(p), "original_session_id": None,
            "kind": known.get(p.name, "capture" if p.suffix.lower() in
                              {".pcap", ".pcapng", ".cap"} else "supporting_or_unrecognized"),
            "source_url_verified_for_local_copy": False})
    for kind in ("ground_truth", "full_flows", "prepared_split"):
        seen = {}
        for p in paths:
            if known.get(p.name) == kind:
                print(f"Auditing {p.name}", flush=True)
                profiles[p.relative_to(root).as_posix()] = summarize(p, kind, seen, samples, gt_index)
        del seen
    traces = candidate_joins(samples, gt_index)
    hashes = defaultdict(list)
    for entry in inventory:
        hashes[entry["sha256"]].append(entry["path"])
    events = Counter()
    event_path = root / "UNSW-NB15_LIST_EVENTS.csv"
    if event_path.exists():
        for row in list(rows(event_path))[1:]:
            if len(row) == 3 and row[1].strip().lower() != "total":
                events[family(row[0])] += int(row[2])
    report = {"audit_version": 1, "data_root": str(root),
        "scope": "file_hashes_and_csv_consistency_only", "bulk_extraction_allowed": False,
        "gate": "BLOCKED_PENDING_RAW_CAPTURE_AUDIT", "inventory": inventory,
        "identical_file_groups": [v for v in hashes.values() if len(v) > 1],
        "profiles": profiles, "event_summary_by_family": dict(events),
        "sample_candidate_outcomes": dict(Counter(t["outcome"] for t in traces)),
        "sample_policy": "first 32 rows per family/UTC-date/file; coarse inclusive overlap; no clock correction",
        "coverage": {"supplied_capture_files": sum(e["kind"] == "capture" for e in inventory),
            "verified_original_sessions": 0, "verified_packet_traces": 0,
            "packet_label_coverage_fraction": None, "window_label_coverage_fraction": None,
            "eligible_temporal_sequences": 0,
            "reason": "No implemented or verified raw capture adapter, session map, clock or endpoint mapping"},
        "external_adapters": {"CSE-CIC-IDS2018": "not_supplied_not_validated",
                              "BoT-IoT": "not_supplied_not_validated"},
        "environment": {"python": sys.version, "platform": platform.platform()},
        "code_sha256": {p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")}}
    # Reject an input changing while being audited instead of publishing stale hashes.
    for p, entry in zip(paths, inventory):
        if sha256(p) != entry["sha256"]:
            raise RuntimeError(f"Input changed during audit: {p}")
    (output / "audit.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output / "flow_annotation_candidates.json").write_text(
        json.dumps(traces, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "gate": report["gate"],
                      "candidate_outcomes": report["sample_candidate_outcomes"]}), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    audit(args.data_root, args.output)
