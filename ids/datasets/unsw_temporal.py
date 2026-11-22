"""Phase 2 adapter for the hash-bound Phase 1 UNSW evidence, not flow features."""

from collections import Counter, defaultdict
import csv
import gzip
from functools import lru_cache
import json
from pathlib import Path

from ids.datasets.audit import sha256
from ids.datasets.label_policy import final_window_label
from ids.datasets.packet_audit import load_annotations
from ids.datasets.temporal import LabeledWindow, digest
from ids.datasets.verify_unsw_labels import read_flows, whole_second
from ids.features import Binding, Registry
from ids.features.packets import canonical_tuple, SECOND


class UNSWEvidence:
    def __init__(self, config_path, verification_dir, split_plan):
        self.config_path = Path(config_path)
        self.cfg = json.loads(self.config_path.read_text())
        self.verification_dir = Path(verification_dir)
        verification_path = self.verification_dir / "verification.json"
        self.verification = json.loads(verification_path.read_text())
        if not self.verification["label_signoff"]:
            raise ValueError("Phase 1 verified label evidence is required")
        if sha256(self.config_path) != self.verification["audit_config_sha256"]:
            raise ValueError("Audited configuration changed")
        if sha256(Path(__file__).with_name("verify_unsw_labels.py")) != self.verification["verification_code_sha256"]:
            raise ValueError("Phase 1 label verifier changed; revalidate its evidence")
        self.input_hashes = {}
        for name, expected in self.verification["source_sha256"].items():
            path = Path(name)
            if sha256(path) != expected:
                raise ValueError(f"Source differs from the label verification: {path}")
            self.input_hashes[str(path)] = expected
        for path in (verification_path, self.verification_dir / "verified_joins.jsonl.gz",
                     self.verification_dir / "verified_final_windows.csv", self.config_path,
                     self.config_path.parent / "endpoint_mapping.csv"):
            self.input_hashes[str(path)] = sha256(path)
        self.source_stats = {path: (Path(path).stat().st_size, Path(path).stat().st_mtime_ns)
                             for path in self.input_hashes}
        self.group_id = self.cfg["local_group_id"]
        self.plan = split_plan
        self.start_ns = self.cfg["start_us"] * 1000
        self.end_ns = self.cfg["end_us"] * 1000 + 1000
        self.by_ip = {}
        bindings = []
        with (self.config_path.parent / "endpoint_mapping.csv").open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                if row["monitored"] != "true":
                    continue
                self.by_ip[row["ip"]] = row
                bindings.append(Binding(row["endpoint_id"], row["ip"], int(row["valid_from_us"]) * 1000,
                    int(row["valid_until_us_exclusive"]) * 1000, revision=1, original_device_id=None))
        if set(self.by_ip) != set(self.cfg["monitored_ips"]):
            raise ValueError("Endpoint map differs from audited scope")
        self.registry = Registry(bindings)
        self.by_device = {row["endpoint_id"]: row for row in self.by_ip.values()}
        self.flows, self.flow_index = read_flows(Path(self.cfg["csv_root"]),
            whole_second(self.cfg["start_us"]), whole_second(self.cfg["end_us"]))
        self.annotations, _ = load_annotations(Path(self.cfg["csv_root"]), Path(self.cfg["bro_root"]),
                                              self.cfg["start_us"], self.cfg["end_us"])
        self.verified = {}
        with gzip.open(self.verification_dir / "verified_joins.jsonl.gz", "rt", encoding="utf-8") as stream:
            for line in stream:
                join = json.loads(line)
                flow = self.flows[join["index"]]
                if tuple(join["tuple"]) != flow.key or join["source_row"] != flow.row or join["family"] != flow.family:
                    raise ValueError("Verified join no longer identifies the original source flow")
                self.verified[join["index"]] = join
        self.boundaries = sorted({p.start_ns for p in split_plan.partitions if p.group_id == self.group_id}
                                 | {p.end_ns for p in split_plan.partitions if p.group_id == self.group_id})
        self.crossing = set()
        # Purge every annotated crossing, even when it has no packet on one side.
        for flow in self.flows:
            self._crossing(flow.key, (flow.start * 1_000_000 - 500_000) * 1000,
                           (flow.end * 1_000_000 + 500_000) * 1000)
        for index in self.annotations.values():
            for annotations in index.values():
                for ann in annotations:
                    # Coarse full CSV/GT bounds are conservative candidates, not
                    # verified positive packet spans. BRO is exact microseconds.
                    self._crossing(ann["key"], (ann["start"] - 500_000) * 1000,
                                   (ann["end"] + 500_000) * 1000 + 1)
        self.evidence = defaultdict(Counter)
        self.connections = defaultdict(set)
        self.references = defaultdict(set)
        self.families = defaultdict(set)
        self.counts = Counter()
        self.rows = []
        self.extractor = None

    @lru_cache(maxsize=100_000)
    def connection_id(self, key):
        # A reused tuple is one conservative leakage unit. This can over-purge
        # unrelated reuse, but cannot split a real connection or reverse view.
        return digest([self.group_id, canonical_tuple(key)])

    def _crossing(self, key, start_ns, end_ns):
        if any(start_ns < b < end_ns for b in self.boundaries[1:-1]):
            self.crossing.add(self.connection_id(key))

    def attach(self, extractor):
        self.extractor = extractor
        for second in self.verification["gap_affected_unix_seconds"]:
            extractor.quality(second * SECOND, (second + 1) * SECOND, "audited_capture_gap")

    def on_packet(self, packet):
        endpoints = {self.by_ip[ip]["endpoint_id"] for ip in (packet.src, packet.dst) if ip in self.by_ip}
        if packet.registry_only:
            return
        second = packet.time_ns // SECOND
        category, family, refs = "unknown", None, []
        if packet.supported:
            key, time_us = packet.tuple_key, packet.time_ns // 1000
            ckey = canonical_tuple(key)
            rounded = whole_second(time_us)
            potential = [i for i in self.flow_index.get(ckey, ())
                         if self.flows[i].start <= rounded <= self.flows[i].end]
            candidate_families = {self.flows[i].family for i in potential}
            candidate_families.update(a["family"] for a in self.annotations["gt"].get(ckey, ())
                                     if a["start"] <= rounded * 1_000_000 <= a["end"])
            if len(candidate_families) > 1:
                category = "conflict"
            elif candidate_families - {"benign", "reconnaissance", "dos"}:
                category = "excluded"
            elif len(potential) == 1:
                join = self.verified.get(potential[0])
                if join and join["half_open_interval_us"][0] <= time_us < join["half_open_interval_us"][1]:
                    family = join["family"]
                    category = "benign" if family == "benign" else "attack"
                    refs = [f"{Path(join['source_csv']).name}:{join['source_row']}",
                            "bro:" + join["bro"]["uid"]]
                else:
                    # A corroborated BRO missed-byte report degrades capture,
                    # unlike a missing/ambiguous label, which is only unknown.
                    gaps = [a for a in self.annotations["bro"].get(ckey, ())
                            if a["missed_bytes"] != "0" and a["start"] <= time_us <= a["end"]]
                    if gaps and endpoints:
                        self.extractor.quality(packet.time_ns, packet.time_ns + 1,
                                               "bro_content_gap", device_ids=endpoints)
            for device in endpoints:
                self.connections[device, second].add(self.connection_id(key))
        self.counts["packet_label:" + category] += 1
        for device in endpoints:
            slot = device, second
            self.evidence[slot][category] += 1
            self.references[slot].update(refs)
            if family:
                self.families[slot].add(family)

    def on_window(self, window):
        w = window.wire
        slot = w["device_id"], w["window_start_ms"] // 1000
        evidence = self.evidence.pop(slot, Counter())
        categories = set(evidence)
        # Keep annotation certainty independent of capture validity. Supervised
        # eligibility separately rejects invalid coverage in form_samples.
        result = final_window_label([{"label": c} for c in categories],
            coverage_valid=True, identity_valid=True, normal_coverage=categories == {"benign"})
        families = self.families.pop(slot, set())
        family = ("+".join(sorted(families - {"benign"})) if result["label"] == 1
                  else "benign" if result["label"] == 0 else None)
        quality = dict(**result, packet_evidence=dict(evidence),
                       normal_coverage_basis="every relevant packet verified normal" if result["label"] == 0 else None,
                       physical_drop_counters_available=False)
        self.rows.append(LabeledWindow(window, self.group_id, self.cfg["original_session_id"],
            original_device_id=None, label=result["label"], family=family, label_reason=result["reason"],
            label_quality=quality, connection_ids=tuple(sorted(self.connections.pop(slot, set()))),
            source_refs=tuple(sorted(self.references.pop(slot, set())))))

    def verify_unchanged(self):
        for path, expected in self.source_stats.items():
            stat = Path(path).stat()
            if (stat.st_size, stat.st_mtime_ns) != expected:
                raise ValueError(f"Source changed during extraction: {path}")
