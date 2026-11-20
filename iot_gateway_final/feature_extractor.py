"""Contract-faithful device_window_v1 aggregation and rolling 8-row history.

The live clock closes windows after the ordering allowance; PCAP replay can
supply a deterministic watermark. All callbacks run outside the state lock.
"""
import math
import threading
import time
from collections import deque

FEATURE_SCHEMA = 'device_window_v1'
SCHEMA_VERSION = '1.0'
WINDOW_MS = 1000
FEATURE_NAMES = [
    'out_packets', 'in_packets', 'out_ip_bytes', 'in_ip_bytes',
    'out_unique_dst_ips', 'out_unique_dst_ports',
    'out_tcp_packets', 'out_udp_packets', 'out_icmp_packets',
    'out_syn_no_ack', 'in_syn_ack', 'in_rst',
    'out_len_mean', 'out_len_std', 'out_iat_mean_ms', 'out_iat_std_ms',
]


class _Window:
    def __init__(self, start_ms):
        self.start_ms = start_ms
        self.out_count = self.in_count = self.out_bytes = self.in_bytes = 0
        self.ips, self.ports = set(), set()
        self.out_tcp = self.out_udp = self.out_icmp = 0
        self.out_syn = self.in_syn_ack = self.in_rst = 0
        self.length_count = 0
        self.length_sum = self.length_sum_sq = 0
        self.times = []  # bounded only by capture rate for this 1-second window
        self.invalid = set()

    def add(self, r):
        if not r.get('valid', True):
            self.invalid.add(str(r.get('reason') or 'bad_packet'))
            return
        size = int(r['ip_bytes'])
        if r['direction'] == 'OUT':
            self.out_count += 1
            self.out_bytes += size
            self.length_count += 1
            self.length_sum += size
            self.length_sum_sq += size * size
            self.times.append(int(r['event_time_ms']))
            self.ips.add(r['dst_ip'])
            if r['protocol'] in ('TCP', 'UDP') and r.get('dst_port') is not None:
                self.ports.add(int(r['dst_port']))
            if r['protocol'] == 'TCP':
                self.out_tcp += 1
                self.out_syn += int(bool(r.get('syn_no_ack')))
            elif r['protocol'] == 'UDP':
                self.out_udp += 1
            elif r['protocol'] == 'ICMP':
                self.out_icmp += 1
            if len(self.ips) > 4096 or len(self.ports) > 4096:
                self.invalid.add('unique_set_overflow')
        elif r['direction'] == 'IN':
            self.in_count += 1
            self.in_bytes += size
            if r['protocol'] == 'TCP':
                self.in_syn_ack += int(bool(r.get('syn_ack')))
                self.in_rst += int(bool(r.get('rst_set')))

    @staticmethod
    def _stats(values):
        if not values:
            return 0.0, 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return float(mean), float(math.sqrt(max(variance, 0.0)))

    def vector(self):
        if self.length_count:
            mean = self.length_sum / self.length_count
            variance = self.length_sum_sq / self.length_count - mean * mean
            std = math.sqrt(max(variance, 0.0))
        else:
            mean = std = 0.0
        ordered = sorted(self.times)
        gaps = [b - a for a, b in zip(ordered, ordered[1:])]
        iat_mean, iat_std = self._stats(gaps)
        return [self.out_count, self.in_count, self.out_bytes, self.in_bytes,
                len(self.ips), len(self.ports), self.out_tcp, self.out_udp,
                self.out_icmp, self.out_syn, self.in_syn_ack, self.in_rst,
                float(mean), float(std), iat_mean, iat_std]


class FeatureExtractor:
    def __init__(self, gateway_id, boot_id, capture_session_id, sequence_length=8,
                 inactivity_timeout_seconds=60, ordering_allowance_ms=100,
                 on_window=None, on_sequence=None, live=True):
        self.gateway_id, self.boot_id, self.capture_session_id = gateway_id, boot_id, capture_session_id
        self.sequence_length = sequence_length
        self.timeout_ms = int(inactivity_timeout_seconds * 1000)
        self.allowance_ms = int(ordering_allowance_ms)
        self.on_window = on_window or (lambda row: None)
        self.on_sequence = on_sequence or (lambda seq: None)
        self.live = live
        self.lock = threading.RLock()
        self.state = {}  # device_id -> active window, revision, rolling history, counters
        self.global_invalid_reason = None
        self.running = False
        self.thread = None

    def _new_state(self, r):
        return {'device_id': r['device_id'], 'ip': r['device_ip'],
                'binding_revision': r['binding_revision'],
                'enforcement_revision': 0, 'active': {}, 'history': deque(maxlen=self.sequence_length),
                'sequence_number': 0, 'last_seen_ms': int(r['event_time_ms']),
                'next_start_ms': (int(r['event_time_ms']) // WINDOW_MS) * WINDOW_MS,
                'closed_before_ms': None}

    def reset_device(self, ip, device=None):
        """Clear history on confirmed binding update (new packets will warm up)."""
        with self.lock:
            for did, state in list(self.state.items()):
                if state['ip'] == ip or (device and state['device_id'] == device.get('device_id')):
                    del self.state[did]

    def mark_capture_loss(self, reason='capture_drop'):
        """Unattributable drops or unsupported coverage invalidate every active history."""
        with self.lock:
            self.global_invalid_reason = reason
            for state in self.state.values():
                state['history'].clear()
                for w in state['active'].values():
                    w.invalid.add(reason)

    def add_packet(self, r):
        if r.get('scope') == 'global':
            self.mark_capture_loss(r.get('reason', 'unsupported_traffic'))
            return
        if not r.get('device_id'):
            return
        with self.lock:
            did = r['device_id']
            ms = int(r['event_time_ms'])
            bucket = (ms // WINDOW_MS) * WINDOW_MS
            s = self.state.get(did)
            if s is None:
                s = self._new_state(r)
                self.state[did] = s
            elif (s['ip'] != r['device_ip'] or s['binding_revision'] != r['binding_revision']):
                s = self._new_state(r)
                self.state[did] = s
            if s['closed_before_ms'] is not None and bucket < s['closed_before_ms']:
                # A late packet means some previously emitted history may be incomplete.
                s['history'].clear()
                for w in s['active'].values():
                    w.invalid.add('late_packet')
                self.global_invalid_reason = 'late_packet'
                return
            s['active'].setdefault(bucket, _Window(bucket)).add(r)
            s['last_seen_ms'] = max(s['last_seen_ms'], ms)
            s['next_start_ms'] = min(s['next_start_ms'], bucket)

    def _emit_window(self, s, w):
        s['sequence_number'] += 1
        seq = s['sequence_number']
        reasons = sorted(w.invalid)
        row = {'schema_version': SCHEMA_VERSION, 'feature_schema': FEATURE_SCHEMA,
               'window_id': f'{self.boot_id}-{s["device_id"]}-{seq}',
               'gateway_id': self.gateway_id, 'boot_id': self.boot_id,
               'capture_session_id': self.capture_session_id,
               'device_id': s['device_id'], 'binding_revision': s['binding_revision'],
               'sequence_number': seq, 'window_start_ms': w.start_ms,
               'window_end_ms': w.start_ms + WINDOW_MS, 'observed_mode': 'live' if self.live else 'offline',
               'enforcement_revision': s['enforcement_revision'],
               'quality': {'valid': not bool(reasons), 'reasons': reasons},
               'values': w.vector()}
        hist = s['history']
        if hist and (hist[-1]['window_end_ms'] != row['window_start_ms'] or
                     hist[-1]['sequence_number'] + 1 != row['sequence_number']):
            hist.clear()
        if not row['quality']['valid']:
            hist.clear()
        else:
            hist.append(row)
        seq_obj = None
        if len(hist) == self.sequence_length:
            seq_obj = {'device_id': s['device_id'], 'windows': list(hist),
                       'matrix_8x16': [x['values'] for x in hist]}
        return row, seq_obj

    def advance_to(self, watermark_ms):
        """Close complete windows whose end+allowance <= watermark_ms.

        Live mode: watermark is current wall clock. Offline mode: use next
        packet timestamp (or end-of-capture) as watermark.
        """
        out_rows, out_sequences = [], []
        with self.lock:
            finalizable_start = ((int(watermark_ms) - self.allowance_ms - WINDOW_MS) // WINDOW_MS) * WINDOW_MS
            for did, s in list(self.state.items()):
                # After timeout, no more idle inference; wait for fresh activity.
                last_allowed_start = ((s['last_seen_ms'] + self.timeout_ms - 1) // WINDOW_MS) * WINDOW_MS
                while s['next_start_ms'] <= min(finalizable_start, last_allowed_start):
                    bucket = s['next_start_ms']
                    w = s['active'].pop(bucket, _Window(bucket))
                    row, seq = self._emit_window(s, w)
                    out_rows.append(row)
                    if seq is not None:
                        out_sequences.append(seq)
                    s['next_start_ms'] += WINDOW_MS
                    s['closed_before_ms'] = s['next_start_ms']
                if s['next_start_ms'] > last_allowed_start:
                    # A new packet starts a fresh eight-row history.
                    del self.state[did]
        for row in out_rows:
            self.on_window(row)
        for seq in out_sequences:
            self.on_sequence(seq)

    def _tick(self):
        while self.running:
            self.advance_to(int(time.time() * 1000))
            time.sleep(0.05)

    def start(self):
        if not self.live or self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._tick, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.advance_to(int(time.time() * 1000) if self.live else 2**63 - 1)
