from dataclasses import replace
import json
import math
from pathlib import Path
import struct

import numpy as np
import pytest

from ids.contracts import validate
from ids.features import (Binding, FeatureHistory, LiveAdapter, OfflineAdapter, Registry,
                          WindowExtractor, parse_packet, read_pcap)
from ids.features.adapters import sorted_packets
from ids.features.packets import SECOND
from ids.features.views import UNSWCaptureView
from tests.packet_fixtures import A, B, C, frame, golden_packets, pcap_bytes, raw

FIXTURES = Path(__file__).parent / "fixtures"


def engine(**kwargs):
    output, events = [], []
    registry = kwargs.pop("registry", Registry([Binding(x, ip, 0, 200 * SECOND) for x, ip in (("a", A), ("b", B), ("c", C))]))
    extractor = WindowExtractor(registry, start_ns=kwargs.pop("start_ns", 0),
                                on_window=output.append, on_quality=events.append, **kwargs)
    return extractor, output, events


def test_hand_checked_pcap_and_live_parity():
    e, offline, _ = engine()
    OfflineAdapter(e, chunk_size=2).run([FIXTURES / "device_window_v1.pcap"], end_ns=8 * SECOND)
    expected = json.loads((FIXTURES / "device_window_v1.expected.json").read_text())
    for row in offline:
        validate("FeatureWindow", row.wire)
        key = f"{row.wire['device_id']}:{row.wire['window_start_ms'] // 1000}"
        np.testing.assert_allclose(row.wire["values"], expected.get(key, [0] * 16), atol=1e-12, rtol=1e-12)
        assert row.wire["quality"]["valid"]
    e, live, _ = engine()
    adapter = LiveAdapter(e, event_anchor_ns=0, monotonic_anchor_ns=100, interface="fixture")
    packets = golden_packets()
    # Packets arrive out of event order, but before window finalization.
    for p in (packets[1], packets[0], *packets[2:]):
        adapter.receive(p, monotonic_ns=max(adapter.last_monotonic_ns, p.time_ns + 100))
    adapter.tick(8 * SECOND + 100_000_000 + 100)
    def comparable(row):
        return ({k: v for k, v in row.wire.items() if k not in {"window_id", "observed_mode"}},
                row.diagnostics, row.lifecycle)
    assert list(map(comparable, offline)) == list(map(comparable, live))
    assert {r.wire["observed_mode"] for r in live} == {"live"}
    assert {r.wire["observed_mode"] for r in offline} == {"offline"}
    assert len(offline) == 24
    assert offline[0].wire["values"][0] == 4  # includes the retransmission


@pytest.mark.parametrize("nano,endian", [(False, "<"), (False, ">"), (True, "<"), (True, ">")])
def test_pcap_integer_time_and_boundaries(tmp_path, nano, endian):
    quantum = 1 if nano else 1000
    packets = [raw(SECOND - quantum), raw(SECOND)]
    path = tmp_path / "boundary.pcap"
    path.write_bytes(pcap_bytes(packets, nano=nano, endian=endian))
    assert [p.time_ns for p in read_pcap(path)] == [SECOND - quantum, SECOND]
    e, rows, _ = engine()
    OfflineAdapter(e).run([path], end_ns=2 * SECOND)
    a = [r for r in rows if r.wire["device_id"] == "a"]
    assert [r.wire["values"][0] for r in a] == [1, 1]
    assert all(r.wire["values"][13:] == [0.0, 0.0, 0.0] for r in a)


def test_zero_outgoing_one_gap_and_broadcast():
    e, rows, _ = engine()
    for p in [raw(100), raw(500_000_100), raw(SECOND, dst="255.255.255.255", protocol=17, length=28)]:
        e.ingest(parse_packet(p))
    e.finish(2 * SECOND)
    a, b = rows[:2]
    assert a.wire["values"][14:] == [500.0, 0.0]
    assert b.wire["values"][12:] == [0.0] * 4
    assert rows[4].wire["values"] == [0] * 16  # no broadcast fan-out to B


@pytest.mark.parametrize("data,reason", [
    (frame(fragment=0x2000), "ipv4_fragment"),
    (frame()[:-1], "truncated_ipv4"),
    (frame(protocol=47), "unsupported_ipv4_protocol"),
    (frame(ether=0x86dd), "unsupported_ipv6"),
    (b"broken", "malformed_ethernet"),
])
def test_unsupported_and_malformed_degrade(data, reason):
    e, rows, _ = engine()
    e.ingest(parse_packet(raw(100, data=data)))
    e.finish(SECOND)
    assert reason in rows[0].wire["quality"]["reasons"]
    assert rows[0].wire["values"] == [0] * 16


def test_arp_and_container_failures(tmp_path):
    e, rows, _ = engine()
    e.ingest(parse_packet(raw(100, data=frame(ether=0x0806))))
    e.finish(SECOND)
    assert all(r.wire["quality"]["valid"] and r.wire["values"] == [0] * 16 for r in rows)
    path = tmp_path / "bad.pcap"
    for data in [b"pcapng", pcap_bytes([raw(0)])[:-1]]:
        path.write_bytes(data)
        with pytest.raises(ValueError):
            list(read_pcap(path))
    assert "unsupported_linktype" in parse_packet(replace(raw(0), linktype=999)).issues
    assert "capture_truncation" in parse_packet(replace(raw(0), original_length=100)).issues


def test_caps_and_ambiguous_registry():
    with pytest.raises(ValueError, match="tracked_device_cap"):
        Registry([Binding("a", A, 0, SECOND), Binding("b", B, 0, SECOND)], max_devices=1)
    e, rows, _ = engine(unique_cap=1)
    e.ingest(parse_packet(raw(100)))
    e.ingest(parse_packet(raw(200, dst=C, dport=53)))
    e.finish(SECOND)
    assert rows[0].wire["quality"]["reasons"] == ["destination_cap", "port_cap"]
    assert rows[0].wire["values"][4:6] == [1, 1]
    assert rows[0].diagnostics["unique_counts_are_lower_bounds"]
    registry = Registry([Binding("a", A, 0, 2 * SECOND), Binding("b", A, 0, 2 * SECOND)])
    e, rows, _ = engine(registry=registry)
    e.ingest(parse_packet(raw(100)))
    e.finish(SECOND)
    assert all("ambiguous_identity" in r.wire["quality"]["reasons"] for r in rows)


def test_late_drop_queue_and_ordering_allowance():
    e, rows, events = engine()
    live = LiveAdapter(e, event_anchor_ns=0, monotonic_anchor_ns=0, interface="fixture", queue_cap=1)
    live.receive(raw(0), monotonic_ns=0)
    assert not live.receive(raw(1), monotonic_ns=1)
    live.tick(1_099_999_999)
    assert not rows
    live.tick(1_100_000_000)
    assert len(rows) == 3
    assert "queue_overflow" in rows[0].wire["quality"]["reasons"]
    frozen = dict(rows[0].wire)
    assert not live.receive(raw(100), monotonic_ns=1_100_000_001)
    live.report_drop(SECOND, 2 * SECOND, 4)
    live.tick(2_100_000_000)
    assert rows[0].wire == frozen
    assert {"late_packet", "capture_drop"} <= set(rows[3].wire["quality"]["reasons"])
    assert any(v["reported_after_finalization"] for v in events)


def test_known_gap_vs_healthy_silence_and_fresh_history():
    e, rows, _ = engine()
    e.quality(8 * SECOND, 9 * SECOND, "input_gap")
    e.finish(18 * SECOND)
    history = FeatureHistory()
    ready = [r.wire["window_start_ms"] // 1000 for r in rows if r.wire["device_id"] == "a"
             and history.append(r)]
    assert ready == [7, 16, 17]
    e, rows, _ = engine(require_observed_coverage=True)
    e.finish(SECOND)
    assert all("capture_health_unverified" in r.wire["quality"]["reasons"] for r in rows)


def test_inactivity_and_lifecycle_resets():
    e, rows, _ = engine()
    e.ingest(parse_packet(raw(100_000_000)))
    e.advance(70 * SECOND)
    assert max(r.wire["window_end_ms"] for r in rows) == 60_000
    e.ingest(parse_packet(raw(70 * SECOND)))
    e.finish(78 * SECOND)
    history = FeatureHistory()
    ready = [r.wire["window_start_ms"] // 1000 for r in rows if r.wire["device_id"] == "a"
             and history.append(r)]
    assert ready[-1] == 77 and 70 not in ready
    e, rows, _ = engine()
    e.advance(8 * SECOND)
    e.reset(8 * SECOND, "enforcement_change", enforcement_revision=1, boot_id="new", capture_session_id="new")
    e.finish(17 * SECOND)
    history = FeatureHistory()
    ready = [r.wire["window_start_ms"] // 1000 for r in rows if r.wire["device_id"] == "a"
             and history.append(r)]
    assert ready == [7, 16]


def test_binding_change_and_partial_edges():
    registry = Registry([Binding("a", A, 0, 8 * SECOND), Binding("a", A, 8 * SECOND, 30 * SECOND, revision=2)])
    e, rows, _ = engine(registry=registry, start_ns=100)
    e.finish(16 * SECOND + 100)
    assert not rows[0].wire["quality"]["valid"] and not rows[-1].wire["quality"]["valid"]
    assert rows[8].wire["binding_revision"] == 2
    history = FeatureHistory()
    assert [r.wire["window_start_ms"] for r in rows if history.append(r)] == [15000]


def test_external_sort_is_stable_and_preserves_equal_packets(tmp_path):
    packets = [parse_packet(raw(t)) for t in [9, 1, 1, 5, 0]]
    actual = list(sorted_packets(packets, scratch=tmp_path, chunk_size=2))
    assert [p.time_ns for p in actual] == [0, 1, 1, 5, 9]
    assert not list(tmp_path.iterdir())
    # Force a second merge pass and its bounded file-handle fan-in.
    many = [parse_packet(raw(t)) for t in range(130, 0, -1)]
    assert [p.time_ns for p in sorted_packets(many, scratch=tmp_path, chunk_size=1)] == list(range(1, 131))
    assert not list(tmp_path.iterdir())


def test_audited_view_selection_keeps_retransmissions():
    packet = replace(parse_packet(raw(100)), linktype=113, capture_kind=0, ttl=64)
    view = UNSWCaptureView()
    assert view.keep(packet)
    assert not view.keep(replace(packet, time_ns=200, capture_kind=4, ttl=63))
    assert view.keep(replace(packet, time_ns=1000))  # a real retransmission
    assert not view.keep(replace(packet, time_ns=1100, capture_kind=4, ttl=63))
    assert view.keep(replace(packet, time_ns=1200, capture_kind=4, ttl=63))  # unpaired
    assert view.counts["retained_observations"] == 3


def test_clock_discontinuity_and_libpcap_timestamp():
    e, rows, _ = engine()
    live = LiveAdapter(e, event_anchor_ns=0, monotonic_anchor_ns=0, interface="fixture")
    assert not live.receive(raw(20 * SECOND), monotonic_ns=0)
    live.from_libpcap(0, 123, frame(), len(frame()), linktype=1, monotonic_ns=123_000)
    live.tick(SECOND + 100_000_000)
    assert "timestamp_discontinuity" in rows[0].wire["quality"]["reasons"]
    with pytest.raises(ValueError, match="regressed"):
        live.tick(0)


@pytest.mark.parametrize("linktype", [113, 276, 101, 1])
def test_supported_link_headers_share_ipv4_semantics(linktype):
    original = raw(10)
    ip = original.data[14:]
    if linktype == 113:
        data = struct.pack("!HHH8sH", 0, 1, 6, bytes(8), 0x0800) + ip
    elif linktype == 276:
        data = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, bytes(8)) + ip
    elif linktype == 101:
        data = ip
    else:  # two VLAN tags
        data = original.data[:12] + struct.pack("!HHHHH", 0x88a8, 7, 0x8100, 9, 0x0800) + ip
    parsed = parse_packet(replace(original, data=data, original_length=len(data), linktype=linktype))
    assert parsed.supported and parsed.tuple_key == ("tcp", A, 1234, B, 80) and parsed.ip_length == 40


def test_reset_cannot_turn_unprocessed_backlog_into_healthy_silence():
    e, rows, _ = engine()
    live = LiveAdapter(e, event_anchor_ns=0, monotonic_anchor_ns=0, interface="fixture")
    live.receive(raw(100), monotonic_ns=100)
    live.reset(event_ns=2 * SECOND, monotonic_ns=2 * SECOND, boot_id="new")
    assert rows and all(not row.wire["quality"]["valid"] for row in rows)
    assert not live.queue


def test_drop_flags_are_coalesced_and_device_scoped():
    e, rows, _ = engine()
    for i in range(1000):
        e.quality(i, i + 1, "capture_drop", device_ids={"a"})
    assert len(e.intervals) == 1
    e.finish(SECOND)
    assert not rows[0].wire["quality"]["valid"]
    assert rows[1].wire["quality"]["valid"]


@pytest.mark.parametrize("field,value", [("boot_id", "changed"), ("capture_session_id", "changed"),
    ("binding_revision", 2), ("enforcement_revision", 2), ("device_id", "changed"),
    ("observed_mode", "live"), ("gateway_id", "changed")])
def test_history_identity_fields_each_reset(field, value):
    e, rows, _ = engine()
    e.finish(8 * SECOND)
    a = [r for r in rows if r.wire["device_id"] == "a"]
    a[-1] = replace(a[-1], wire={**a[-1].wire, field: value})
    history = FeatureHistory()
    assert not any(history.append(row) for row in a)


def test_midsecond_identity_conflict_invalidates_both_silent_owners():
    registry = Registry([Binding("a", A, 0, 2 * SECOND), Binding("b", A, SECOND // 2, 2 * SECOND)])
    e, rows, _ = engine(registry=registry)
    e.finish(SECOND)
    assert all("ambiguous_identity" in r.wire["quality"]["reasons"] for r in rows)
