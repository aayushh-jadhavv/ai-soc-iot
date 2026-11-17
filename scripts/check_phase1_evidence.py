"""Verify audit invariants and (optionally) extracted archive member CRCs."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ids.datasets.packet_audit import write_json


def check(out, archive_root=None):
    read = lambda name: json.loads((out / name).read_text(encoding="utf-8"))
    manifest, summary, views = (read(n) for n in ("source_manifest.json","packet_summary.json","capture_views.json"))
    primary = {k.removeprefix("label:"):v for k,v in summary["counts"].items() if k.startswith("label:")}
    assert sum(primary.values()) == summary["counts"]["packets"]
    assert sum(summary["window_candidate_counts"].values()) == summary["observed_endpoint_seconds"]
    copies = views["paired_forward_candidate_labels"]
    assert sum(copies.values()) == views["counts"]["receive_forward_pairs"]
    retained = {k:v-copies.get(k,0) for k,v in primary.items()}
    assert all(v>=0 for v in retained.values())
    assert sum(retained.values()) == summary["counts"]["packets"]-views["counts"]["receive_forward_pairs"]
    write_json(out / "single_view_candidate_diagnostics.json", {
        "status":"counterfactual diagnostic only; original captures unchanged",
        "rule":"Retain receive observation for every one-to-one paired datagram; retain all unpaired observations for separate exclusion",
        "raw_record_denominator":summary["counts"]["packets"],
        "paired_forward_observations":sum(copies.values()),
        "retained_observation_denominator":sum(retained.values()),
        "retained_candidate_counts":retained,
        "training_labels_accepted":0,
        "warning":"Coarse annotation tolerance remains provisional; these are observation counts, not unique network events"})
    hashes = {str(Path(x["path"]).resolve()):x["sha256"] for x in manifest["files"]}
    checked = 0
    for group in read("packet_traces_with_provenance.json").values():
        for witness in group:
            if "record_byte_offset" not in witness:
                continue
            assert witness["capture_sha256"] == hashes[str(Path(witness["capture_file"]).resolve())]
            with Path(witness["capture_file"]).open("rb") as stream:
                stream.seek(witness["record_byte_offset"])
                sec,micro,caplen,origlen = struct.unpack("<IIII",stream.read(16))
                data = stream.read(caplen)
            assert sec*1_000_000+micro == witness["timestamp_us"]
            assert caplen == witness["captured_length"] and origlen == witness["original_length"]
            assert hashlib.sha256(data).hexdigest() == witness["packet_sha256"]
            checked += 1
            for kind in ("gt_candidates","flow_candidates","bro_matches","argus_candidates"):
                for annotation in witness.get(kind,[]):
                    assert annotation["sha256"] == hashes[str(Path(annotation["file"]).resolve())]
    extraction = None
    if archive_root:
        extraction = []
        root = archive_root.resolve()
        for archive in read("archive_members.json"):
            result = {"archive":archive["path"],"checked_members":0,"matches":0,"problems":[]}
            for member in archive.get("members",[]):
                path = (root / member["name"]).resolve()
                path.relative_to(root)
                result["checked_members"] += 1
                if not path.is_file():
                    result["problems"].append({"member":member["name"],"issue":"missing_extracted_member"})
                    continue
                crc = 0
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024*1024),b""):
                        crc = zlib.crc32(block,crc)
                if path.stat().st_size==member["bytes"] and f"{crc:08x}"==member["crc32"]:
                    result["matches"] += 1
                else:
                    result["problems"].append({"member":member["name"],"issue":"size_or_crc_mismatch"})
            extraction.append(result)
        write_json(out / "archive_extraction_verification.json",{
            "method":"Extracted file bytes/CRC32 compared with local ZIP central directory; no archive payload decompression and no publisher authentication",
            "archives":extraction})
        assert not any(a["problems"] for a in extraction)
    evidence = {"status":"passed", "trace_records_reread_and_hash_checked":checked,
        "primary_packet_counts_sum_to_denominator":True,
        "window_counts_sum_to_observed_denominator":True,
        "paired_forward_counts_sum_to_pair_denominator":True,
        "single_view_counts_sum_to_retained_denominator":True,
        "capinfos_matches":True}
    capinfos = (out / "capinfos.txt").read_text()
    for capture in summary["files"]:
        assert capture["sha256"] in capinfos
        assert f'Number of packets:   {capture["counts"]["packets"]}' in capinfos
        assert capture["sha256"] == hashes[str(Path(capture["file"]).resolve())]
    write_json(out / "evidence_verification.json",evidence)
    print(json.dumps(evidence),flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True)
    parser.add_argument("--archive-root")
    args = parser.parse_args()
    check(Path(args.output),Path(args.archive_root) if args.archive_root else None)
