"""Reproduce Phase 2 from the audited January UNSW excerpt; never trains."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import time

import numpy as np

from ids.datasets.audit import sha256
from ids.datasets.temporal import Partition, SplitPlan, form_samples, save_dataset, write_json
from ids.datasets.unsw_temporal import UNSWEvidence
from ids.features import OfflineAdapter, WindowExtractor
from ids.features.packets import SECOND
from ids.features.views import UNSWCaptureView


def build(config_path, verification_dir, output, scratch):
    started = time.perf_counter()
    config_path, verification_dir, output, scratch = map(Path, (config_path, verification_dir, output, scratch))
    source_paths = [*Path("ids/features").glob("*.py"), Path("ids/preprocessing.py"),
                    *(Path("ids/datasets") / name for name in ("temporal.py", "unsw_temporal.py",
                      "build_temporal.py", "check_temporal.py", "label_policy.py", "verify_unsw_labels.py", "packet_audit.py", "audit.py"))]
    code_hashes = {str(p): sha256(p) for p in source_paths}
    cfg = json.loads(config_path.read_text())
    proposal = json.loads((config_path.parent / "partition_proposal.json").read_text())
    bounds = proposal["chronological_fallback"]
    partitions = []
    for role in ("train", "validation", "internal_test"):
        a, b = bounds[role + "_epoch_seconds_half_open"]
        partitions.append(Partition(role, cfg["local_group_id"], role, a * SECOND, b * SECOND,
                                    original_session_id=cfg["original_session_id"]))
    plan = SplitPlan(partitions, mode="within_group_chronological")
    output.mkdir(parents=True, exist_ok=False)
    scratch.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(scratch)
    capture_bytes = sum(Path(p).stat().st_size for p in cfg["captures"])
    if disk.free < max(4 * 1024**3, 2 * capture_bytes):
        raise ValueError("Insufficient scratch space; reserve at least twice the source bytes")
    # This durable assignment precedes extraction, labels and sequence assembly.
    write_json(output / "split_manifest.json", plan.to_dict())
    print("Fixed chronological partitions; verifying source/evidence hashes", flush=True)
    evidence = UNSWEvidence(config_path, verification_dir, plan)
    events = []
    extractor = WindowExtractor(evidence.registry, start_ns=evidence.start_ns,
        capture_session_id=cfg["local_group_id"], boot_id="phase2-replay",
        on_window=evidence.on_window, on_quality=events.append, require_observed_coverage=True)
    evidence.attach(extractor)
    view = UNSWCaptureView()
    def observe(packet):
        evidence.on_packet(packet)
        if view.counts["retained_observations"] % 250_000 == 0:
            print(f"Aggregated {view.counts['retained_observations']:,} retained observations", flush=True)

    adapter = OfflineAdapter(extractor, view=view, on_packet=observe, scratch=scratch)
    print("Parsing and externally sorting the original capture group", flush=True)
    adapter.run([Path(p) for p in cfg["captures"]], end_ns=evidence.end_ns)
    evidence.verify_unchanged()
    if view.counts["paired_forward"] != evidence.verification["capture_view_counts"]["paired_forward"]:
        raise ValueError("Capture view selection differs from the accepted Phase 1 evidence")
    print(f"Extracted {len(evidence.rows):,} endpoint-seconds; purging connections and forming samples", flush=True)
    raw, samples, windows, report = form_samples(evidence.rows, plan,
                                                annotated_crossing_connections=evidence.crossing)
    reasons = Counter(reason for row in windows for reason in row["coverage_reasons"])
    report.update(capture_quality_reason_counts=dict(reasons), packet_counts=dict(adapter.counts),
        capture_view_counts=dict(view.counts), extractor_counts=dict(extractor.counts),
        packet_label_evidence_counts=dict(evidence.counts),
        verified_source_connections_by_family=dict(Counter(j["family"] for j in evidence.verified.values())),
        retained_retransmissions=True, physical_sensor_drop_counters_available=False,
        healthy_silence_in_this_capture="unverified; no silent row certified valid",
        coverage_valid_windows=sum(w["capture_valid"] for w in windows),
        labeled_windows=sum(w["label"] is not None for w in windows),
        labeled_valid_windows=sum(w["label"] is not None and w["capture_valid"] for w in windows),
        quality_events=len(events), threshold_subset=None, external_evaluation_performed=False)
    blockers = ["Only one connected original capture group; evaluation is within-group, not independent.",
                "Original provider session and device IDs are unavailable and remain null.",
                "Physical sensor drop counters are unavailable; coverage is observational."]
    for p in plan.partitions:
        counts = report["counts_by_partition"].get(p.partition_id, {})
        for family in ("benign", "reconnaissance", "dos"):
            if not counts.get("samples:" + family, 0):
                blockers.append(f"{p.partition_id} has no retained {family} samples.")
    report["dataset_freeze_ready"] = not blockers
    report["limitations_and_freeze_blockers"] = blockers
    preprocess = save_dataset(output, raw, samples, windows, report)
    write_json(output / "quality_events.json", events)
    if {str(p): sha256(p) for p in source_paths} != code_hashes:
        raise ValueError("Extraction implementation changed during the run; rerun on stable source")
    manifest = dict(created_utc=datetime.now(timezone.utc).isoformat(),
        stage="phase2_only_no_training", status="implementation_validated_dataset_provisional",
        source_collection=cfg["source_collection"], original_test_name=cfg["original_test_name"],
        original_group_id=cfg["original_session_id"], local_group_id=cfg["local_group_id"],
        original_capture_ids=[Path(p).name for p in cfg["captures"]],
        capture_interval_ns=[evidence.start_ns, evidence.end_ns],
        time_basis="integer nanosecond Unix UTC; original PCAP microseconds; no inferred offset",
        linktype=113, observation_view="audited one-to-one SLL receive/forward selection",
        source_url="https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        dataset_version="local hash-bound UNSW January 22 excerpt",
        attribution="UNSW-NB15, Moustafa and Slay; academic use and attribution terms in Phase 1 manifest",
        additional_capture_access="Official SharePoint link redirected to Microsoft sign-in on 2026-11-17",
        source_hashes=evidence.input_hashes, code_hashes=code_hashes,
        python=platform.python_version(), numpy=np.__version__, platform=platform.platform(),
        capture_bytes=capture_bytes, free_scratch_bytes_before=disk.free,
        elapsed_seconds=time.perf_counter() - started, configuration=dict(unique_cap=4096, max_devices=128,
            inactivity_seconds=60, ordering_allowance_ms=100, offline_sort_chunk_packets=50_000,
            health_policy="observed_endpoint_seconds_with_audit_gaps_and_known_quality_events"),
        excluded_external_sources=["CSE-CIC-IDS2018: no accepted captures", "BoT-IoT: no accepted captures"],
        tensor_layout="float32 [N,16,8]; IDs/labels/families/coverage in samples.parquet",
        raw_layout="float64 [N,8,16] without identifiers or labels")
    write_json(output / "data_manifest.json", manifest)
    body = ["# Phase 2 extraction and leakage report", "",
        "Shared extraction and temporal dataset construction completed on the audited two-file UNSW excerpt. "
        "No model was trained. The dataset remains provisional; independent evaluation and complete family support are not established.", "",
        "The fixed Phase 1 chronological ranges were saved before extraction. Both original files and both endpoint views "
        "retain the same source group. This is explicitly within-group evaluation; it does not meet an independent-session split.", "",
        "| Partition | Endpoint-seconds | Benign samples | Reconnaissance samples | DoS samples |", "| --- | ---: | ---: | ---: | ---: |"]
    for p in plan.partitions:
        c = report["counts_by_partition"].get(p.partition_id, {})
        body.append(f"| {p.partition_id} | {c.get('windows', 0):,} | {c.get('samples:benign', 0):,} | "
                    f"{c.get('samples:reconnaissance', 0):,} | {c.get('samples:dos', 0):,} |")
    body += ["", f"Raw packet records: {adapter.counts['raw_records']:,}. Retained observations: "
             f"{view.counts['retained_observations']:,}. Identified forwarded copies removed: {view.counts['paired_forward']:,}. "
             "All receive observations and genuine retransmissions are retained.", "",
             f"Emitted endpoint-seconds: {len(windows):,}; retained eight-row samples: {len(samples):,}. "
             f"Preprocessing uses {preprocess['unique_training_window_count']:,} unique windows appearing in training samples, "
             "once each, with log1p and population standard deviation. Held-out rows never enter the fit.", "",
             "Exclusions are counted by primary reason below; coverage reasons and label certainty remain separate "
             "columns in windows.parquet. A final label never propagates through the earlier seven seconds.", "",
             "| Primary exclusion | Endpoint-seconds |", "| --- | ---: |"]
    body += [f"| {reason} | {count:,} |" for reason, count in sorted(report["exclusions"].items())]
    body += ["", "Every pair of sample partitions has zero shared window IDs and zero shared conservative connection IDs "
        "after purging complete affected windows. Connection IDs group bidirectional tuples conservatively, including reuse. "
        "All annotated boundary-crossing connections are also purged. The first seven final seconds in each new partition "
        "cannot form a sample. Source-group overlap remains disclosed because all data came from one source group.", "",
        "Capture validity is independent of label availability. Supported ICMP contributes to v1 features; it can still have "
        "an unknown label. Silent rows in these files are not certified healthy without capture-health evidence. "
        "In a declared healthy adapter interval, silent seconds produce valid zero rows. Partial edges, observed gaps, "
        "BRO missed-byte reports, unsupported packets and malformed packets reset histories. Inactive devices stop emitting "
        "full rows after 60 seconds and require eight fresh rows on reactivation.", "", "Remaining limitations:", ""]
    body += ["- " + item for item in blockers]
    body += ["", "The original PCAPs were read in place; temporary sorted runs were removed automatically. "
        "Additional provider captures could not be fetched without Microsoft sign-in. External datasets and threshold "
        "calibration remain untouched. No performance claim or training readiness is inferred from this run.", "",
        "Reproduce with `python -m ids.datasets.build_temporal --output NEW_DIRECTORY`. "
        "See `docs/phase2.md` for setup, shared gateway APIs, fixture calculations and tests.", ""]
    (output / "REPORT.md").write_text("\n".join(body), encoding="utf-8")
    write_json(output / "artifact_checksums.json", {str(p.relative_to(output)): sha256(p)
        for p in sorted(output.rglob("*")) if p.is_file()})
    print(json.dumps({"samples": len(samples), "counts_by_partition": report["counts_by_partition"],
                      "dataset_freeze_ready": report["dataset_freeze_ready"],
                      "elapsed_seconds": manifest["elapsed_seconds"]}, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("experiments/phase1/raw-audit-001/config.json"))
    parser.add_argument("--verification", type=Path, default=Path("experiments/phase1/raw-label-verification-002"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, default=Path("tmp/phase2/sort"))
    args = parser.parse_args()
    build(args.config, args.verification, args.output, args.scratch)


if __name__ == "__main__":
    main()
