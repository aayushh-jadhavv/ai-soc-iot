"""Offline sorting and bounded live libpcap callback adapters for one engine."""

from collections import Counter
import heapq
import itertools
from pathlib import Path
import pickle
from tempfile import TemporaryDirectory

from ids.features.packets import SECOND, RawPacket, parse_packet, read_pcap


def sorted_packets(packets, *, scratch=None, chunk_size=50_000):
    """Stable external merge sort across all chunks of one original group.

    Pickle is used ONLY for internally created temporary runs in this context;
    no caller-supplied serialized file is loaded. Memory is bounded by a chunk.
    No deduplication, float timestamp conversion, or lossy timestamp bucketing.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    with TemporaryDirectory(prefix="ids-sort-", dir=scratch) as directory:
        paths, chunk = [], []

        def spill():
            chunk.sort(key=lambda pair: (pair[1].time_ns, pair[0]))
            path = Path(directory) / f"{len(paths)}.run"
            with path.open("wb") as stream:
                for item in chunk:
                    pickle.dump(item, stream, protocol=5)
            paths.append(path)
            chunk.clear()

        for ordinal, packet in enumerate(packets):
            chunk.append((ordinal, packet))
            if len(chunk) >= chunk_size:
                spill()
        if not paths:
            yield from (p for _, p in sorted(chunk, key=lambda pair: (pair[1].time_ns, pair[0])))
            return
        if chunk:
            spill()

        def run(path):
            with path.open("rb") as stream:
                while True:
                    try:
                        ordinal, packet = pickle.load(stream)
                    except EOFError:
                        return
                    yield packet.time_ns, ordinal, packet

        # Bound open file handles as well as packet memory for larger groups.
        generation = 0
        while len(paths) > 128:
            reduced = []
            for offset in range(0, len(paths), 128):
                target = Path(directory) / f"merge-{generation}-{offset}.run"
                batch = paths[offset:offset + 128]
                with target.open("wb") as stream:
                    for _, ordinal, packet in heapq.merge(*(run(p) for p in batch)):
                        pickle.dump((ordinal, packet), stream, protocol=5)
                reduced.append(target)
                for path in batch:
                    path.unlink()
            paths = reduced
            generation += 1
        for _, _, packet in heapq.merge(*(run(p) for p in paths)):
            yield packet


class OfflineAdapter:
    def __init__(self, extractor, *, view=None, on_packet=None, scratch=None, chunk_size=50_000):
        if extractor.counts["windows"] or extractor.counts["packet_records"]:
            raise ValueError("Attach an adapter before processing any records")
        extractor.context["observed_mode"] = "offline"
        self.extractor, self.view, self.on_packet = extractor, view, on_packet
        self.scratch, self.chunk_size = scratch, chunk_size
        self.counts = Counter()

    def run(self, paths, *, end_ns, interface="offline"):
        def packets():
            for path in paths:
                for raw in read_pcap(path, interface=interface):
                    self.counts["raw_records"] += 1
                    yield parse_packet(raw)
        return self.run_records(packets(), end_ns=end_ns)

    def run_records(self, packets, *, end_ns):
        for packet in sorted_packets(packets, scratch=self.scratch, chunk_size=self.chunk_size):
            if packet.time_ns < self.extractor.started_ns or packet.time_ns >= end_ns:
                raise ValueError("Capture record falls outside declared capture interval")
            if self.view and not self.view.keep(packet):
                continue
            self.counts["retained_observations"] += 1
            if self.on_packet:
                self.on_packet(packet)
            self.extractor.ingest(packet)
        self.extractor.finish(end_ns)
        return dict(self.counts)


class LiveAdapter:
    """Single-owner libpcap callback/timer bridge; no capture privileges needed.

    Call receive/from_libpcap with frames copied from ONE selected observation
    interface, and tick on a monotonic timer even during silence. Entire seconds
    are sorted before they reach the engine, 100 ms after their event-time end.
    The gateway must forward libpcap/OS drop counter deltas through report_drop.
    Do not call methods concurrently; serialize callbacks on the capture worker.
    """

    def __init__(self, extractor, *, event_anchor_ns, monotonic_anchor_ns,
                 interface, allowance_ns=100_000_000, queue_cap=65_536,
                 timestamp_tolerance_ns=5 * SECOND, on_packet=None):
        if allowance_ns < 0 or queue_cap < 1 or not interface:
            raise ValueError("Invalid live adapter configuration")
        if extractor.counts["windows"] or extractor.counts["packet_records"]:
            raise ValueError("Attach an adapter before processing any records")
        extractor.context["observed_mode"] = "live"
        self.extractor = extractor
        self.event_anchor_ns, self.monotonic_anchor_ns = event_anchor_ns, monotonic_anchor_ns
        self.interface, self.allowance_ns, self.queue_cap = interface, allowance_ns, queue_cap
        self.timestamp_tolerance_ns, self.on_packet = timestamp_tolerance_ns, on_packet
        self.last_monotonic_ns = monotonic_anchor_ns
        self.queue, self.ordinals, self.counts = [], itertools.count(), Counter()

    def event_time(self, monotonic_ns):
        if type(monotonic_ns) is not int or monotonic_ns < self.last_monotonic_ns:
            raise ValueError("Monotonic clock regressed; explicitly re-anchor the adapter")
        self.last_monotonic_ns = monotonic_ns
        return self.event_anchor_ns + monotonic_ns - self.monotonic_anchor_ns

    def receive(self, raw, *, monotonic_ns):
        now = self.event_time(monotonic_ns)
        if raw.interface != self.interface:
            self.extractor.quality(now, now + 1, "wrong_observation_interface")
            self.counts["wrong_interface"] += 1
            return False
        packet = parse_packet(raw)
        if abs(packet.time_ns - now) > self.timestamp_tolerance_ns:
            self.extractor.quality(now, now + 1, "timestamp_discontinuity")
            self.counts["timestamp_discontinuity"] += 1
            return False
        if packet.time_ns < self.extractor.cursor:
            self.extractor.ingest(packet)  # immutable old row + current reset event
            self.counts["late_packets"] += 1
            return False
        if len(self.queue) >= self.queue_cap:
            self.extractor.quality(packet.time_ns, packet.time_ns + 1, "queue_overflow")
            self.counts["queue_drops"] += 1
            return False
        heapq.heappush(self.queue, (packet.time_ns, next(self.ordinals), packet))
        self.counts["queued_packets"] += 1
        return True

    def from_libpcap(self, seconds, fraction, captured_bytes, original_length, *,
                    linktype, monotonic_ns, precision="us"):
        multiplier = {"us": 1000, "ns": 1}[precision]
        if type(seconds) is not int or type(fraction) is not int or not 0 <= fraction * multiplier < SECOND:
            raise ValueError("Invalid integer libpcap timestamp")
        raw = RawPacket(seconds * SECOND + fraction * multiplier, bytes(captured_bytes),
                        original_length, linktype, self.interface)
        return self.receive(raw, monotonic_ns=monotonic_ns)

    def tick(self, monotonic_ns):
        watermark = self.event_time(monotonic_ns) - self.allowance_ns
        while self.queue and (self.queue[0][0] // SECOND + 1) * SECOND <= watermark:
            _, _, packet = heapq.heappop(self.queue)
            if self.on_packet:
                self.on_packet(packet)
            self.extractor.ingest(packet)
        self.extractor.advance(watermark)

    def report_drop(self, start_ns, end_ns, count, *, device_ids=None):
        self.extractor.quality(start_ns, end_ns, "capture_drop", count=count, device_ids=device_ids)

    def reset(self, *, event_ns, monotonic_ns, reason="worker_restart", **context):
        if self.queue:
            self.extractor.quality(min(p[0] for p in self.queue),
                max(event_ns + 1, max(p[0] for p in self.queue) + 1), "reset_discarded_backlog",
                count=len(self.queue))
            self.counts["reset_discarded_backlog"] += len(self.queue)
        self.queue.clear()
        self.extractor.reset(event_ns, reason, **context)
        self.event_anchor_ns, self.monotonic_anchor_ns = event_ns, monotonic_ns
        self.last_monotonic_ns = monotonic_ns
