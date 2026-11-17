"""Compare a hand-calculated real UNSW second, live replay and saved features."""

import argparse
import csv
import json
from pathlib import Path
import statistics
import struct

import numpy as np
import pyarrow.parquet as pq

from ids.datasets.audit import sha256
from ids.datasets.packet_audit import read_pcap as read_original
from ids.datasets.temporal import write_json
from ids.features import Binding, LiveAdapter, OfflineAdapter, Registry, WindowExtractor, read_pcap
from ids.features.packets import SECOND


def check(dataset, validation):
    validation = Path(validation)
    start, end = 1421927421 * SECOND, 1421927422 * SECOND
    source = Path(r"C:\Users\aayus\datasets-aisoc\pcap files\22-1-2015_1.pcap")
    with (validation / "real-window-tshark.csv").open(newline="", encoding="utf-8-sig") as stream:
        decoded = list(csv.DictReader(stream))
    received = [r for r in decoded if r["sll.pkttype"] == "0"]
    frames = [int(r["frame.number"]) for r in received]
    assert frames == [932, 934, 936, 942, 944, 946, 948, 950]
    assert len(decoded) == 16  # each receive record has its audited forwarded copy
    assert (validation / "tshark-prefix-end.txt").read_text().strip() == "3000\t1421927437.423870000"
    selected = []
    for record in read_original(source):
        if record.number in frames:
            selected.append(record)
        if record.number >= 3000:
            break
    assert len(selected) == 8
    target = validation / "hand_checked_unsw_window.pcap"
    with target.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113))
        for record in selected:
            seconds, fraction = divmod(record.time_us, 1_000_000)
            stream.write(struct.pack("<IIII", seconds, fraction, record.captured, record.original))
            stream.write(record.data)
    # Independently transcribed from the Wireshark packet ledger:
    # outgoing lengths 56,52,73,56,52; incoming 56,89,56;
    # outgoing IATs .753,99.262,1.316,.707 ms; ports 5190,53,80.
    lengths = [56, 52, 73, 56, 52]
    gaps = [0.753, 99.262, 1.316, 0.707]
    expected = [5, 3, 289, 201, 3, 3, 4, 1, 0, 2, 2, 0,
                57.8, statistics.pstdev(lengths), 25.5095, statistics.pstdev(gaps)]

    def extractor(result):
        return WindowExtractor(Registry([Binding("endpoint", "59.166.0.1", start, end)]),
                               start_ns=start, on_window=result.append)

    offline, live = [], []
    OfflineAdapter(extractor(offline)).run([target], end_ns=end)
    adapter = LiveAdapter(extractor(live), event_anchor_ns=start, monotonic_anchor_ns=100,
                          interface="fixture")
    for raw in read_pcap(target, interface="fixture"):
        adapter.receive(raw, monotonic_ns=raw.time_ns - start + 100)
    adapter.tick(end - start + 100_000_000 + 100)
    assert len(offline) == len(live) == 1
    np.testing.assert_allclose(offline[0].wire["values"], expected, atol=1e-12, rtol=1e-12)
    assert offline[0].wire["values"] == live[0].wire["values"]
    assert offline[0].wire["quality"] == live[0].wire["quality"] == {"valid": True, "reasons": []}
    saved = pq.read_table(Path(dataset) / "windows.parquet", filters=[
        ("device_id", "=", "jan22-ip-59.166.0.1"), ("start_ns", "=", start)]).to_pylist()
    assert len(saved) == 1 and saved[0]["capture_valid"] and saved[0]["label"] == 0
    np.testing.assert_allclose(saved[0]["values"], expected, atol=1e-12, rtol=1e-12)
    evidence = dict(passed=True, source_capture=source.name,
        source_sha256="5f5c1b558d42e818f169b4035c7cf185a7c15da7718127927b316dd1189e2b61",
        source_frame_numbers=frames, original_two_view_records=16, retained_receive_observations=8,
        epoch_interval_ns=[start, end], endpoint="59.166.0.1", expected_values=expected,
        outgoing_lengths=lengths, outgoing_gaps_ms=gaps, population_statistics=True,
        offline_live_equal=True, full_dataset_window_equal=True, raw_fixture_sha256=sha256(target),
        compared_fields=["values", "quality"],
        independent_decoder="Wireshark tshark; see real-window-tshark.csv",
        fixture_kind="eight actual original capture records, single audited receive view",
        original_collection="UNSW-NB15 January 22; academic attribution applies")
    write_json(validation / "real_window_handcheck.json", evidence)
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--validation", type=Path, default=Path("experiments/phase2/validation"))
    args = parser.parse_args()
    print(json.dumps(check(args.dataset, args.validation), indent=2))
