"""Shared, event-ordered device_window_v1 aggregation and lifecycle.

Adapters order records and report capture health. Label availability never
changes feature validity. The engine does not import a dataset or ML framework.
"""

from collections import Counter, deque
from dataclasses import dataclass, field
import hashlib
import ipaddress
import math

from ids.features.packets import SECOND, PacketRecord


@dataclass(frozen=True)
class Binding:
    device_id: str
    ip: str
    start_ns: int
    end_ns: int
    revision: int = 1
    original_device_id: str | None = None

    def __post_init__(self):
        address = ipaddress.IPv4Address(self.ip)
        if address.is_multicast or self.ip == "255.255.255.255":
            raise ValueError("Cannot enroll multicast/broadcast as a device")
        if not self.device_id or self.end_ns <= self.start_ns or self.revision < 0:
            raise ValueError("Invalid device binding")


class Registry:
    """Static interval map. Ambiguous simultaneous owners remain visible."""

    def __init__(self, bindings, max_devices=128):
        self.bindings = tuple(bindings)
        self.device_ids = sorted({b.device_id for b in self.bindings})
        if len(self.device_ids) > max_devices:
            raise ValueError("tracked_device_cap: registry exceeds configured cap")
        self.by_ip = {}
        self.by_device = {}
        for binding in self.bindings:
            self.by_ip.setdefault(binding.ip, []).append(binding)
            self.by_device.setdefault(binding.device_id, []).append(binding)

    def resolve(self, ip, time_ns):
        return [b for b in self.by_ip.get(ip, ()) if b.start_ns <= time_ns < b.end_ns]


@dataclass
class Moments:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, value):
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)

    @property
    def std(self):
        return math.sqrt(max(0.0, self.m2 / self.n)) if self.n else 0.0


@dataclass
class Accumulator:
    counts: list = field(default_factory=lambda: [0] * 12)
    destinations: set = field(default_factory=set)
    ports: set = field(default_factory=set)
    lengths: Moments = field(default_factory=Moments)
    gaps: Moments = field(default_factory=Moments)
    last_out_ns: int | None = None
    reasons: set = field(default_factory=set)
    diagnostics: Counter = field(default_factory=Counter)

    def observe(self, packet, outgoing, cap):
        self.diagnostics["packet_observations"] += 1
        if packet.issues:
            self.reasons.update(packet.issues)
            self.diagnostics.update(packet.issues)
            return
        if not packet.supported:
            return
        c = self.counts
        c[0 if outgoing else 1] += 1
        c[2 if outgoing else 3] += packet.ip_length
        if outgoing:
            for value, values, name in ((packet.dst, self.destinations, "destination_cap"),
                                        (packet.dport, self.ports, "port_cap")):
                if value is None or value in values:
                    continue
                if len(values) >= cap:
                    self.reasons.add(name)
                    self.diagnostics[name + "_overflow_observations"] += 1
                else:
                    values.add(value)
            c[{"tcp": 6, "udp": 7, "icmp": 8}[packet.protocol]] += 1
            c[9] += packet.protocol == "tcp" and bool(packet.tcp_flags & 2) and not packet.tcp_flags & 16
            self.lengths.add(packet.ip_length)
            if self.last_out_ns is not None:
                if packet.time_ns < self.last_out_ns:
                    raise ValueError("Aggregator requires event-ordered packets")
                self.gaps.add((packet.time_ns - self.last_out_ns) / 1_000_000)
            self.last_out_ns = packet.time_ns
        elif packet.protocol == "tcp":
            c[10] += packet.tcp_flags & 0x12 == 0x12
            c[11] += bool(packet.tcp_flags & 4)

    def values(self):
        self.counts[4:6] = [len(self.destinations), len(self.ports)]
        return [*self.counts, self.lengths.mean, self.lengths.std,
                self.gaps.mean, self.gaps.std]


@dataclass(frozen=True)
class Window:
    wire: dict
    diagnostics: dict
    lifecycle: int


@dataclass
class DeviceState:
    binding_revision: int
    last_seen_ns: int
    sequence: int = 0
    lifecycle: int = 0
    active: bool = True
    accumulator: Accumulator = field(default_factory=Accumulator)


class FeatureHistory:
    """Eight fresh valid rows; label uncertainty is deliberately absent here."""

    def __init__(self):
        self.rows = deque(maxlen=8)

    def reset(self):
        self.rows.clear()

    @staticmethod
    def identity(row):
        w = row.wire
        return (row.lifecycle, *(w[k] for k in ("device_id", "gateway_id", "boot_id",
                "capture_session_id", "binding_revision", "enforcement_revision", "observed_mode")))

    def append(self, row):
        if not row.wire["quality"]["valid"]:
            self.reset()
            return None
        if self.rows:
            prev = self.rows[-1]
            if (self.identity(prev) != self.identity(row)
                    or prev.wire["window_end_ms"] != row.wire["window_start_ms"]
                    or prev.wire["sequence_number"] + 1 != row.wire["sequence_number"]):
                self.reset()
        self.rows.append(row)
        return tuple(self.rows) if len(self.rows) == 8 else None


class WindowExtractor:
    def __init__(self, registry, *, start_ns, gateway_id="dataset", boot_id="replay",
                 capture_session_id="capture", observed_mode="offline", enforcement_revision=0,
                 unique_cap=4096, inactivity_ns=60 * SECOND, on_window=None,
                 on_quality=None, require_observed_coverage=False):
        if type(start_ns) is not int or start_ns < 0 or unique_cap < 1 or inactivity_ns < SECOND:
            raise ValueError("Invalid extractor limits/start time")
        if observed_mode not in {"offline", "live"}:
            raise ValueError("Invalid observation mode")
        self.registry = registry
        self.cursor = start_ns // SECOND * SECOND
        self.started_ns = start_ns
        self.context = dict(gateway_id=gateway_id, boot_id=boot_id,
                            capture_session_id=capture_session_id, observed_mode=observed_mode,
                            enforcement_revision=enforcement_revision)
        self.unique_cap, self.inactivity_ns = unique_cap, inactivity_ns
        self.on_window, self.on_quality = on_window, on_quality
        self.require_observed_coverage = require_observed_coverage
        self.states = {device: DeviceState(registry.by_device[device][0].revision, start_ns)
                       for device in registry.device_ids}
        self.intervals = []
        self.counts = Counter()
        self.last_packet_ns = None

    def quality(self, start_ns, end_ns, reason, *, device_ids=None, count=1):
        """Report known lost/unsupported coverage with half-open affected time.

        Finalized windows are immutable. A late report emits their affected
        interval, and invalidates the current row to reset live histories.
        """
        if end_ns <= start_ns or count < 1:
            raise ValueError("Quality event needs a nonempty interval and count")
        targets = set(self.states) if device_ids is None else set(device_ids)
        if not targets <= self.states.keys():
            raise ValueError("Quality event refers to an unknown device")
        event = dict(start_ns=start_ns, end_ns=end_ns, reason=reason,
                     device_ids=sorted(targets), count=count, reported_after_finalization=start_ns < self.cursor)
        self.counts["quality:" + reason] += count
        if self.on_quality:
            self.on_quality(event)
        if start_ns < self.cursor:
            for device in targets:
                self.states[device].accumulator.reasons.add(reason)
                self.states[device].lifecycle += 1
        if end_ns > self.cursor:
            # Store coverage by affected seconds and coalesce repeated drops.
            # A full queue must not create another unbounded queue of flags.
            a = max(start_ns // SECOND * SECOND, self.cursor)
            b = (end_ns + SECOND - 1) // SECOND * SECOND
            remaining = []
            for old in self.intervals:
                if old[2] == reason and old[3] == targets and old[0] <= b and old[1] >= a:
                    a, b, count = min(a, old[0]), max(b, old[1]), count + old[4]
                else:
                    remaining.append(old)
            self.intervals = [*remaining, (a, b, reason, targets, count)]

    def advance(self, watermark_ns):
        """Finalize all ends <= watermark, including healthy idle zero rows."""
        while self.cursor + SECOND <= watermark_ns:
            start, end = self.cursor, self.cursor + SECOND
            for device, state in self.states.items():
                acc = state.accumulator
                if end > state.last_seen_ns + self.inactivity_ns:
                    if state.active:
                        state.active = False
                        state.lifecycle += 1
                        self.counts["inactivity_resets"] += 1
                    state.accumulator = Accumulator()
                    continue
                if not state.active:
                    continue
                bindings = [b for b in self.registry.by_device[device]
                            if b.start_ns < end and b.end_ns > start]
                if not bindings:
                    state.accumulator = Accumulator()
                    continue
                revisions = {b.revision for b in bindings}
                if len(revisions) != 1 or not any(b.start_ns <= start and b.end_ns >= end for b in bindings):
                    acc.reasons.add("binding_transition")
                elif state.binding_revision != next(iter(revisions)):
                    state.binding_revision = next(iter(revisions))
                    state.lifecycle += 1
                if any(other.device_id != device and max(start, b.start_ns, other.start_ns) < min(end, b.end_ns, other.end_ns)
                       for b in bindings for other in self.registry.by_ip[b.ip]):
                    acc.reasons.add("ambiguous_identity")
                if start < self.started_ns:
                    acc.reasons.add("partial_capture_edge")
                for a, b, reason, targets, count in self.intervals:
                    if a < end and b > start and device in targets:
                        acc.reasons.add(reason)
                        acc.diagnostics[reason] += count
                if self.require_observed_coverage and not acc.diagnostics["packet_observations"]:
                    acc.reasons.add("capture_health_unverified")
                reasons = sorted(acc.reasons)
                identity = f"{self.context}|{device}|{state.binding_revision}|{start}|{state.lifecycle}"
                wire = dict(schema_version="1.0", feature_schema="device_window_v1",
                            window_id=hashlib.sha256(identity.encode()).hexdigest(),
                            device_id=device, binding_revision=state.binding_revision,
                            sequence_number=state.sequence, window_start_ms=start // 1_000_000,
                            window_end_ms=end // 1_000_000, values=acc.values(),
                            quality=dict(valid=not reasons, reasons=reasons), **self.context)
                diagnostics = dict(acc.diagnostics)
                diagnostics["unique_counts_are_lower_bounds"] = bool(acc.reasons & {"destination_cap", "port_cap"})
                if self.on_window:
                    self.on_window(Window(wire, diagnostics, state.lifecycle))
                self.counts["windows"] += 1
                self.counts["valid_windows" if not reasons else "invalid_windows"] += 1
                state.sequence += 1
                state.accumulator = Accumulator()
            self.cursor = end
            self.intervals = [v for v in self.intervals if v[1] > end]

    def ingest(self, packet: PacketRecord):
        if packet.time_ns < self.cursor:
            targets = {b.device_id for ip in (packet.src, packet.dst)
                       for b in self.registry.resolve(ip, packet.time_ns)}
            self.quality(packet.time_ns, packet.time_ns + 1, "late_packet",
                         device_ids=targets if packet.src is not None else None)
            return False
        if self.last_packet_ns is not None and packet.time_ns < self.last_packet_ns:
            raise ValueError("Adapters must order packets before aggregation")
        self.advance(packet.time_ns)
        self.last_packet_ns = packet.time_ns
        self.counts["packet_records"] += 1
        if packet.registry_only and not packet.issues:
            self.counts["arp_registry"] += 1
            return True
        incidences = []
        for ip, outgoing in ((packet.src, True), (packet.dst, False)):
            bindings = self.registry.resolve(ip, packet.time_ns)
            ambiguous = len({(b.device_id, b.revision) for b in bindings}) > 1
            for b in {(b.device_id, b.revision): b for b in bindings}.values():
                incidences.append((b, outgoing, ambiguous))
        if packet.issues and packet.src is None:
            for state in self.states.values():
                state.accumulator.reasons.update(packet.issues)
                state.accumulator.diagnostics.update(packet.issues)
        for binding, outgoing, ambiguous in incidences:
            state = self.states[binding.device_id]
            if packet.time_ns - state.last_seen_ns >= self.inactivity_ns:
                state.lifecycle += 1
                self.counts["reactivations"] += 1
            state.active = True
            if state.binding_revision != binding.revision:
                state.binding_revision = binding.revision
                state.lifecycle += 1
                if packet.time_ns != self.cursor or state.accumulator.diagnostics["packet_observations"]:
                    state.accumulator.reasons.add("binding_transition")
            state.last_seen_ns = packet.time_ns
            if ambiguous:
                state.accumulator.reasons.add("ambiguous_identity")
            state.accumulator.observe(packet, outgoing, self.unique_cap)
        return True

    def reset(self, time_ns, reason="worker_restart", **context):
        """Gateway notifies boot/session/enforcement/schema/model changes here."""
        if time_ns < self.cursor or not context.keys() <= self.context.keys():
            raise ValueError("Reset requires current event time and known context fields")
        self.advance(time_ns)
        self.context.update(context)
        self.last_packet_ns = None
        for state in self.states.values():
            state.lifecycle += 1
            state.accumulator.reasons.add(reason)
        self.counts["reset:" + reason] += 1

    def finish(self, end_ns):
        if end_ns % SECOND:
            self.quality(end_ns, (end_ns // SECOND + 1) * SECOND, "partial_capture_edge")
        self.advance(((end_ns + SECOND - 1) // SECOND) * SECOND)
