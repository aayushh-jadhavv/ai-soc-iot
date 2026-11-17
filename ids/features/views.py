"""Explicit, audited UNSW receive/forward selection; never generic deduplication."""

from collections import Counter, defaultdict, deque


class UNSWCaptureView:
    """Remove only one-to-one SLL outgoing copies within 100 ms and TTL - 1.

    Use only for the Phase 1 audited capture group. Equal bytes alone are not
    enough. Every receive observation, including identical retransmissions, is
    retained. Unpaired forwarded observations are retained and counted.
    """

    def __init__(self):
        self.pending = defaultdict(deque)
        self.expiry = deque()
        self.watermark = 0
        self.counts = Counter()

    def keep(self, packet):
        self.counts["raw_records"] += 1
        if packet.linktype != 113:
            raise ValueError("UNSW view selection requires the audited SLL v1 capture")
        self.watermark = max(self.watermark, packet.time_ns)
        while self.expiry and self.watermark - self.expiry[0][0] > 100_000_000:
            old = self.expiry.popleft()
            queue = self.pending.get(old[1])
            if queue and queue[0] == old:
                queue.popleft()
                if not queue:
                    del self.pending[old[1]]
        key = packet.view_fingerprint
        if key is not None and packet.capture_kind in {0, 4}:
            if packet.capture_kind == 0:
                item = (packet.time_ns, key, packet.ttl, packet.source_id, packet.number)
                self.pending[key].append(item)
                self.expiry.append(item)
            else:
                for item in self.pending.get(key, ()):
                    if 0 <= packet.time_ns - item[0] <= 100_000_000 and item[2] == packet.ttl + 1:
                        self.pending[key].remove(item)
                        if not self.pending[key]:
                            del self.pending[key]
                        self.counts["paired_forward"] += 1
                        self.counts["cross_file_pair"] += packet.source_id != item[3]
                        return False
                self.counts["unpaired_forward"] += 1
        self.counts["retained_observations"] += 1
        return True
