"""Inventory the supplied Phase 1 material without copying large source files."""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--csv-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root, output = Path(args.data_root).resolve(), Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "source_manifest.json").exists():
        raise FileExistsError("Source inventory already exists")
    paths = sorted(set(p for p in root.rglob("*") if p.is_file()) |
                   set(p for p in Path(args.csv_root).resolve().rglob("*") if p.is_file()) |
                   {Path(args.report).resolve()})
    records = []
    hash_groups = defaultdict(list)
    for i, path in enumerate(paths):
        if i % 100 == 0:
            print(f"Hashing source file {i+1}/{len(paths)}", flush=True)
        stat = path.stat()
        record = {"path": str(path), "bytes": stat.st_size, "sha256": digest(path),
            "local_mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "downloaded_at_utc": None, "download_time_note": "Filesystem mtime is not acquisition evidence",
            "original_session_id": None, "publisher_checksum": None,
            "source_origin": "official UNSW provider, user-reported",
            "source_page_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset"}
        if path.parent.name == "metadata":
            record["source_origin"] = "locally prepared metadata; not a publisher artifact"
            record["source_page_url"] = None
        if "22-1-2015" in str(path):
            record["source_collection_label"] = "22-1-2015"
        elif "17-2-2015" in str(path):
            record["source_collection_label"] = "17-2-2015"
        else:
            record["source_collection_label"] = None
        after = path.stat()
        if (stat.st_size, stat.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError(f"Source changed while hashing: {path}")
        records.append(record)
        hash_groups[record["sha256"]].append(str(path))
    write_json(output / "source_manifest.json", {"files": records,
        "file_count": len(records), "bytes": sum(r["bytes"] for r in records),
        "duplicate_file_groups": [p for p in hash_groups.values() if len(p)>1]})
    with (output / "source_checksums.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["path", "bytes", "sha256"], extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    archives = []
    for path in sorted((root / "downloads").glob("*.zip")):
        try:
            with zipfile.ZipFile(path) as archive:
                members = [{"name": m.filename, "bytes": m.file_size,
                            "compressed_bytes": m.compress_size, "crc32": f"{m.CRC:08x}"}
                           for m in archive.infolist() if not m.is_dir()]
            archives.append({"path": str(path), "directory_readable": True,
                "members": members, "member_payload_crc_test": "not_performed"})
        except zipfile.BadZipFile as exc:
            archives.append({"path": str(path), "directory_readable": False, "error": str(exc)})
    write_json(output / "archive_members.json", archives)
    # Read-only Argus CSV index. Numbered Argus files are not assumed to map 1:1
    # to numbered PCAP files. These CSVs have no supplied column header.
    argus_profiles = []
    for path in sorted((root / "Argus Files" / "Argus Files 22-1-2015" / "CSV of Argus").glob("*.csv")):
        widths = Counter()
        first = last = None
        count = overlap = 0
        with path.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.reader(stream):
                widths[len(row)] += 1
                count += 1
                a, b = int(row[0]), int(row[8])
                first = a if first is None else min(first, a)
                last = b if last is None else max(last, b)
                if b >= 1421927376 and a <= 1421928995:
                    overlap += 1
        argus_profiles.append({"path": str(path), "rows": count,
            "column_widths": dict(widths), "candidate_start_epoch_seconds": first,
            "candidate_end_epoch_seconds": last, "rows_overlapping_capture_span": overlap,
            "schema_status": "positions inferred from values and matching tuples; header unavailable"})
    write_json(output / "argus_profiles.json", argus_profiles)
    print(json.dumps({"files": len(records), "archives": len(archives)}), flush=True)


if __name__ == "__main__":
    main()
