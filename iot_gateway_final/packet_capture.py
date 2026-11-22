"""Bounded capture queue: never run parsing/inference on libpcap callback."""
import queue
import threading
import time
import traceback
from scapy.all import sniff
from packet_parser import parse_packet


class PacketCapture:
    def __init__(self, interface, capture_filter, registry, feature_extractor, queue_size=4096):
        self.interface, self.capture_filter = interface, capture_filter
        self.registry, self.extractor = registry, feature_extractor
        self.queue = queue.Queue(maxsize=queue_size)
        self.dropped = 0
        self.running = False
        self.worker = None

    def packet_callback(self, pkt):
        try:
            self.queue.put_nowait(pkt)
        except queue.Full:
            self.dropped += 1
            self.extractor.mark_capture_loss('capture_queue_overflow')

    def _worker(self):
        while self.running or not self.queue.empty():
            try:
                pkt = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self.registry.learn_packet(pkt)
                for record in parse_packet(pkt, self.registry):
                    self.extractor.add_packet(record)
            except Exception as exc:
                print(f'[PACKET WARNING] {exc}', flush=True)
                traceback.print_exc()
                self.extractor.mark_capture_loss('parser_exception')
            finally:
                self.queue.task_done()

    def run(self):
        self.running = True
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()
        print(f'[CAPTURE] interface={self.interface} filter={self.capture_filter}', flush=True)
        try:
            sniff(iface=self.interface, filter=self.capture_filter,
                  prn=self.packet_callback, store=False, promisc=True)
        finally:
            self.running = False
            self.queue.join()
            if self.worker:
                self.worker.join(timeout=2)
            print(f'[CAPTURE] callback queue overflow drops={self.dropped}', flush=True)
