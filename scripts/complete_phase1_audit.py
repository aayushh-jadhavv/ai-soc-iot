"""Build January 22 excerpt metadata and timing/split diagnostics from audit evidence.

No features, tensors, training labels or model scores are produced. The endpoint
roles below are transcribed from the supplied provider report, not inferred labels.
"""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ids.datasets.packet_audit import canonical, load_annotations, write_json
from ids.datasets.audit import rows, tuple_key


def utc(us):
    seconds, fraction = divmod(us, 1_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=fraction).isoformat(timespec="microseconds")


def role(ip):
    if ip.startswith("59.166.0.") and int(ip.split(".")[-1]) < 10:
        return "Server1_normal_application_client_pool"
    if ip.startswith("175.45.176.") and int(ip.split(".")[-1]) < 4:
        return "Server2_security_component_client_pool"
    if ip.startswith("149.171.126.") and int(ip.split(".")[-1]) < 20:
        return "Server3_server_pool"
    return "infrastructure_or_unmapped"


def stats(values):
    if not values:
        return {"n": 0}
    values = sorted(values)
    return {"n": len(values), "min_us": values[0], "median_us": values[len(values)//2],
            "max_us": values[-1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    out = Path(cfg["output"])
    summary = json.loads((out / "packet_summary.json").read_text())
    manifest_path = out / "source_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    # Correctly distinguish user notes from publisher source material.
    for source in manifest["files"]:
        if Path(source["path"]).parent.name == "metadata":
            source["source_origin"] = "locally prepared metadata; not a publisher artifact"
            source["source_page_url"] = None
    write_json(manifest_path, manifest)
    source_hashes = {str(Path(f["path"]).resolve()): f["sha256"] for f in manifest["files"]}
    indexes, profiles = load_annotations(Path(cfg["csv_root"]), Path(cfg["bro_root"]),
                                 cfg["start_us"], cfg["end_us"])
    write_json(out / "annotation_profiles.json", profiles)
    print("Loaded annotation indexes", flush=True)
    timing = Counter()
    starts, ends, durations = [], [], []
    examples = []
    bro_rows = [a for group in indexes["bro"].values() for a in group]
    for bro in bro_rows:
        if bro["key"][0] not in ("tcp", "udp"):
            timing["bro_non_tcp_udp"] += 1
            continue
        timing["bro_tcp_udp_rows"] += 1
        candidates = [a for a in indexes["flow"].get(canonical(bro["key"]), [])
                      if abs(a["start"]-bro["start"]) <= 1_000_000
                      and abs(a["end"]-bro["end"]) <= 1_000_000]
        timing[f"flow_endpoint_candidates_{'zero' if not candidates else 'one' if len(candidates)==1 else 'multiple'}"] += 1
        if len(candidates) != 1:
            continue
        flow = candidates[0]
        starts.append(flow["start"]-bro["start"])
        ends.append(flow["end"]-bro["end"])
        duration_delta = float(Decimal(flow["duration"])*1_000_000 - (bro["end"]-bro["start"]))
        durations.append(duration_delta)
        timing["unique_same_orientation" if tuple(flow["key"]) == tuple(bro["key"]) else "unique_reverse_orientation"] += 1
        nearest_start = (bro["start"]+500000)//1_000_000*1_000_000
        nearest_end = (bro["end"]+500000)//1_000_000*1_000_000
        if flow["start"] == nearest_start:
            timing["unique_start_agrees_nearest_second"] += 1
        if flow["end"] == nearest_end:
            timing["unique_end_agrees_nearest_second"] += 1
        if duration_delta == 0:
            timing["unique_duration_agrees_exact_microsecond"] += 1
        if len(examples)<10 and (flow["start"] != nearest_start or flow["end"] != nearest_end or abs(duration_delta)>1000):
            examples.append({"bro_row": bro["row"], "bro_uid":bro["uid"], "flow_row":flow["row"],
                "start_delta_us": starts[-1], "end_delta_us":ends[-1], "duration_delta_us":duration_delta})
    for group in indexes["gt"].values():
        for gt in group:
            timing["retained_gt_rows"] += 1
            candidates = [a for a in indexes["flow"].get(canonical(gt["key"]), [])
                          if a["start"]==gt["start"] and a["end"]==gt["end"]]
            timing["gt_exact_coarse_interval_with_flow" if candidates else "gt_no_exact_coarse_flow"] += 1
            if any(a["family"] != gt["family"] for a in candidates):
                timing["gt_exact_coarse_interval_family_disagreement"] += 1
    write_json(out / "timestamp_alignment.json", {"counts":dict(timing),
        "flow_minus_bro_start":stats(starts), "flow_minus_bro_end":stats(ends),
        "flow_minus_bro_duration":stats(durations), "discrepancy_examples":examples,
        "method":"Bidirectional TCP/UDP tuple; both interval endpoints within 1s; statistics only for unique candidate",
        "pcap_bro_offset_us":0, "pcap_bro_evidence":summary["timing"],
        "gt_and_flow_unit":"integer Unix seconds; microsecond details lost",
        "provider_report_time_unit":"relative seconds; epoch origin unverified",
        "global_gt_offset_applied_us":0,
        "verified_global_gt_rounding_rule":None,
        "warning":"Bro/Argus aggregation and duration semantics differ; diagnostic 1s tolerance is not a labeling rule"})

    endpoints = json.loads((out / "endpoint_observations.json").read_text())
    with (out / "endpoint_mapping.csv").open("w", encoding="utf-8", newline="") as stream:
        fields = ["endpoint_id", "ip", "monitored", "role", "valid_from_us", "valid_until_us_exclusive",
                  "binding_revision", "mac_identity", "nat_status", "evidence", "observed_packet_incidences"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for ip in sorted(set(endpoints) | set(cfg["monitored_ips"])):
            monitored = ip in cfg["monitored_ips"]
            writer.writerow({"endpoint_id": "jan22-ip-"+ip if monitored else "",
                "ip":ip,"monitored":str(monitored).lower(), "role":role(ip),
                "valid_from_us":cfg["start_us"], "valid_until_us_exclusive":cfg["end_us"]+1,
                "binding_revision":"jan22_excerpt_ip_map_v1", "mac_identity":"not_a_unique_host_identifier",
                "nat_status":"report_static_pool_not_behind_nat" if monitored else "unverified",
                "evidence":"provider report pp13-14,175,532 + observed IPv4" if monitored else "observed IPv4 only; not enrolled",
                "observed_packet_incidences":sum(endpoints.get(ip,{}).get(k,0) for k in ("in_packets","out_packets"))})
    group_packets = defaultdict(Counter)
    for ip, c in endpoints.items():
        group_packets[role(ip)].update(c)
    group_windows = defaultdict(Counter)
    observed_full_windows = set()
    first = (cfg["start_us"]+999999)//1_000_000
    stop = cfg["end_us"]//1_000_000
    with (out / "endpoint_second_diagnostics.csv").open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            group_windows[role(row["endpoint"])][row["candidate_window_status"]] += 1
            sec = int(row["second_epoch"])
            if first <= sec < stop:
                observed_full_windows.add((row["endpoint"],sec))
    full_grid = (stop-first)*len(cfg["monitored_ips"])
    write_json(out / "coverage_by_endpoint_group.json", {"packet_incidences":group_packets,
        "observed_window_candidates":group_windows,
        "packet_denominator_note":"A packet contributes to both endpoint roles; self-addressed traffic contributes twice. Raw capture views retained.",
        "full_second_grid":full_grid, "observed_full_endpoint_seconds":len(observed_full_windows),
        "silent_full_endpoint_seconds_unknown":full_grid-len(observed_full_windows),
        "partial_boundary_endpoint_seconds_excluded":2*len(cfg["monitored_ips"]),
        "initial_seven_context_seconds_before_first_8s_sequence":7*len(cfg["monitored_ips"]),
        "boundaries_seconds":{"first_complete":first, "complete_stop_exclusive":stop},
        "supervised_label_coverage_verified":None,
        "accepted_training_sequences":0})

    files = []
    for n, source in enumerate(summary["files"],1):
        files.append({"local_path":source["file"], "sha256":source["sha256"], "bytes":source["bytes"],
            "presumed_provider_relative_path":f"pcap files/pcaps 22-1-2015/{n}.pcap",
            "publisher_filename_mapping_verified":False, "original_session_id":None,
            "original_test_name":cfg["original_test_name"], "source_collection":cfg["source_collection"],
            "local_group_id":cfg["local_group_id"], "derived_chunk_order":n,
            "earliest_unix_us":source["earliest_us"], "latest_unix_us":source["latest_us"],
            "earliest_utc":utc(source["earliest_us"]), "latest_utc":utc(source["latest_us"]),
            "timestamp_unit":"microseconds", "pcap_linktype":113, "snaplen":65535,
            "capture_interface_id":None, "capture_drop_count":None,
            "packet_count":source["counts"]["packets"], "clean_record_end":True})
    write_json(out / "capture_manifest.json", {"captures":files,
        "source_session_identity_note":"Date folder and repeated test name are retained as supplied labels, not authenticated unique session IDs",
        "raw_files_copied_or_modified":False})

    # Concrete fallback ranges are a proposal only. A source-group split has
    # one indivisible group; percentages cannot manufacture independence.
    length = stop-first
    b1, b2 = first+int(length*.6), first+int(length*.8)
    crossings = []
    for boundary in (b1,b2):
        crossed = [a for a in bro_rows if a["start"] < boundary*1_000_000 <= a["end"]]
        crossings.append({"boundary_epoch_second":boundary,"bro_connections":len(crossed),
            "bro_uids":[a["uid"] for a in crossed], "source_rows":[a["row"] for a in crossed]})
    proposal = {"status":"one_connected_excerpt_group; independent_three_way_split_infeasible",
        "groups":[{"group_id":cfg["local_group_id"],"files":cfg["captures"],"assignment":None,
                   "reason":"continuous capture plus receive/forward pair across file boundary"}],
        "verified_original_session_count":0, "connected_source_group_count":1,
        "preferred_fractions":{"train":.6,"validation":.2,"internal_test":.2},
        "separate_threshold_subset_feasible_now":False,
        "chronological_fallback":{"status":"proposal_only_within_session_evaluation; not assigned",
            "train_epoch_seconds_half_open":[first,b1],
            "validation_epoch_seconds_half_open":[b1,b2],
            "internal_test_epoch_seconds_half_open":[b2,stop],
            "minimum_warmup_seconds_after_each_boundary":7,
            "first_possible_right_sequence_end":"boundary + 8 seconds (exclusive end)",
            "crossing_bro_connections_to_purge":crossings,
            "also_purge_gt_argus_or_packet_identified_crossing_connections":True,
            "purge_entire_windows_touched_by_crossing_connections_and_sequences_using_them":True,
            "final_class_support_and_continuity_check":"not established; must precede assignments"},
        "four_way_independent_target_if_groups_become_available":{"train":.6,"selection_validation":.1,"threshold_validation":.1,"internal_test":.2},
        "external_scores_used_for_tuning":False, "bulk_extraction_allowed":False}
    write_json(out / "partition_proposal.json",proposal)

    # Add immutable source hashes and corresponding Argus rows to witnesses.
    traces = json.loads((out / "packet_traces.json").read_text())
    argus_path = Path(cfg["bro_root"]).parents[1]/"Argus Files"/"Argus Files 22-1-2015"/"CSV of Argus"/"1.csv"
    argus_index = defaultdict(list)
    for number,row in enumerate(rows(argus_path),1):
        if row[1] not in ("tcp","udp"):
            continue
        key = tuple_key(row[1],row[2],row[3],row[4],row[5])
        argus_index[canonical(key)].append({"file":str(argus_path),"row":number,
            "candidate_start_us":int(row[0])*1_000_000, "candidate_end_us":int(row[8])*1_000_000,
            "original_cells":row, "schema":"headerless; positions inferred from tuples"})
    for group in traces.values():
        for trace in group:
            trace["capture_sha256"] = source_hashes[str(Path(trace["capture_file"]).resolve())]
            if "decoded" not in trace:
                continue
            for kind in ("gt_candidates","flow_candidates","bro_matches"):
                for annotation in trace[kind]:
                    annotation["sha256"] = source_hashes[str(Path(annotation["file"]).resolve())]
            key = trace["decoded"]["key"]
            if key:
                trace["argus_candidates"] = [a for a in argus_index.get(canonical(key),[])
                    if a["candidate_start_us"]-1_000_000 <= trace["timestamp_us"] <= a["candidate_end_us"]+1_000_000]
                for annotation in trace["argus_candidates"]:
                    annotation["sha256"] = source_hashes[str(argus_path.resolve())]
    write_json(out / "packet_traces_with_provenance.json",traces)
    print(json.dumps({"timing":dict(timing),"full_seconds":length,
        "crossing_connections":[x["bro_connections"] for x in crossings]}),flush=True)


if __name__ == "__main__":
    main()
