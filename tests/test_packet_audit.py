import struct
import tempfile
import unittest
from pathlib import Path

from ids.datasets.packet_audit import Record, canonical, decode, read_pcap, candidate_label, load_annotations


def sll_udp(fragment=0):
    sll = struct.pack("!HHH8sH", 0, 1, 6, bytes.fromhex("0011223344550000"), 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 7, fragment, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    udp = struct.pack("!HHHH", 12345, 53, 8, 0)
    return sll + ip + udp


class PacketAuditTests(unittest.TestCase):
    def test_nested_bro_log_is_inventoried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "NUSW-NB15_GT.csv").write_text("header\n")
            nested = root / "bro" / "3" / "4"
            nested.mkdir(parents=True)
            fields = "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration missed_bytes conn_state orig_pkts resp_pkts".split()
            cells = "1421927414.035467 abc 192.0.2.1 12345 192.0.2.2 53 udp 0.001 0 SF 2 2".split()
            (nested / "conn.log").write_text("#fields\t"+"\t".join(fields)+"\n"+"\t".join(cells)+"\n")
            indexes, profiles = load_annotations(root, root / "bro", 1421927414000000, 1421927415000000)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0]["retained_rows"], 1)
            self.assertEqual(next(iter(indexes["bro"].values()))[0]["uid"], "abc")

    def test_sll_ipv4_offset_and_udp_ports(self):
        data = sll_udp()
        packet = decode(Record(1, 24, 10, len(data), len(data), data))
        self.assertEqual(packet["key"], ("udp", "192.0.2.1", 12345, "192.0.2.2", 53))
        self.assertEqual(packet["ip_length"], 28)
        self.assertEqual(packet["issues"], [])
        self.assertEqual(canonical(packet["key"]), canonical(("udp", "192.0.2.2", 53, "192.0.2.1", 12345)))

    def test_fragment_has_no_transport_label(self):
        data = sll_udp(0x2000)
        packet = decode(Record(1, 24, 10, len(data), len(data), data))
        self.assertIn("ipv4_fragment", packet["issues"])
        self.assertIsNone(packet["key"])

    def test_truncated_ipv4(self):
        data = sll_udp()[:-1]
        packet = decode(Record(1, 24, 10, len(data), len(data)+1, data))
        self.assertIn("capture_truncation", packet["issues"])
        self.assertIn("invalid_or_truncated_ipv4", packet["issues"])

    def test_pcap_precise_clock_and_partial_record_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.pcap"
            data = sll_udp()
            header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113)
            packet = struct.pack("<IIII", 1421927414, 123456, len(data), len(data)) + data
            path.write_bytes(header + packet)
            records = list(read_pcap(path))
            self.assertEqual(records[0].time_us, 1421927414123456)
            self.assertEqual(records[0].offset, 24)
            path.write_bytes(header + packet[:-1])
            with self.assertRaisesRegex(ValueError, "Partial packet data"):
                list(read_pcap(path))

    def test_conflicts_and_normal_candidates(self):
        self.assertEqual(candidate_label([{"family": "dos"}], [{"family": "benign"}]), "conflicting_candidates")
        self.assertEqual(candidate_label([], [{"family": "benign"}]), "csv_benign_candidate")
        self.assertEqual(candidate_label([{"family": "exploits"}], []), "out_of_scope_attack_candidate")
        self.assertEqual(candidate_label([], []), "unmatched")


if __name__ == "__main__":
    unittest.main()
