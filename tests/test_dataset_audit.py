"""Synthetic policy fixtures, never represented as supplied packet traces."""

import csv
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

from ids.datasets.audit import audit, candidate_joins, port, rows
from ids.datasets.label_policy import Annotation, Packet, final_window_label, match_packet, timestamp_ns


class LabelPolicyTests(unittest.TestCase):
    def setUp(self):
        self.packet = Packet("synthetic:1", "session-a", 1_500_000_000,
                             "tcp", "192.0.2.1", 50000, "192.0.2.2", 80)
        self.annotation = Annotation("synthetic:gt1", "session-a", 1_000_000_000,
                                     2_000_000_000, "tcp", "192.0.2.1", 50000,
                                     "192.0.2.2", 80, "reconnaissance", True)

    def verdict(self, evidence, **kwargs):
        settings = dict(coverage_valid=True, identity_valid=True, normal_coverage=False)
        settings.update(kwargs)
        return final_window_label(evidence, **settings)

    def test_explicit_units_and_offset(self):
        self.assertEqual(timestamp_ns("1.000000001", "s", -1), 10**9)
        self.assertEqual(timestamp_ns("1000", "ms"), 10**9)
        with self.assertRaises(KeyError):
            timestamp_ns("1421927414", "auto")
        for value in ("NaN", "Infinity", "0.0000000001"):
            with self.assertRaises(ValueError):
                timestamp_ns(value, "s")

    def test_bidirectional_attack_and_role(self):
        forward = match_packet(self.packet, [self.annotation])
        reverse_packet = replace(self.packet, src=self.packet.dst, sport=80,
                                 dst=self.packet.src, dport=50000)
        reverse = match_packet(reverse_packet, [self.annotation])
        self.assertEqual(forward["label"], "attack")
        self.assertEqual(reverse["matches"][0]["direction"], "reverse")
        self.assertEqual(self.verdict([reverse])["label"], 1)
        self.assertEqual(self.verdict([reverse])["endpoint_role"], "not_inferred")

    def test_half_open_time_tuple_protocol_and_session(self):
        self.assertEqual(match_packet(replace(self.packet, time_ns=10**9),
                                      [self.annotation])["label"], "attack")
        for change in ({"time_ns": 2 * 10**9}, {"session_id": "session-b"},
                       {"sport": 50001}, {"protocol": "udp"}, {"session_id": ""}):
            self.assertEqual(match_packet(replace(self.packet, **change),
                                          [self.annotation])["label"], "unknown")
        self.assertEqual(match_packet(self.packet, [replace(self.annotation, verified=False)])[
            "label"], "unknown")

    def test_conflicting_and_duplicate_annotations(self):
        conflict = match_packet(self.packet, [self.annotation,
            replace(self.annotation, annotation_id="gt2", family="benign")])
        self.assertEqual(conflict["label"], "conflict")
        self.assertIsNone(self.verdict([conflict])["label"])
        same = match_packet(self.packet, [self.annotation, self.annotation])
        self.assertEqual(same["label"], "attack")
        self.assertEqual(len(same["matches"]), 2)

    def test_positive_unknown_and_invalid_coverage(self):
        mixed = [{"label": "attack"}, {"label": "unknown"}]
        self.assertEqual(self.verdict(mixed)["label"], 1)
        self.assertTrue(self.verdict(mixed)["mixed_unknown"])
        self.assertIsNone(self.verdict(mixed, coverage_valid=False)["label"])
        self.assertIsNone(self.verdict(mixed, identity_valid=False)["label"])

    def test_normal_idle_and_out_of_scope(self):
        benign = match_packet(self.packet, [replace(self.annotation, family="benign")])
        self.assertEqual(self.verdict([benign], normal_coverage=True)["label"], 0)
        self.assertIsNone(self.verdict([benign])["label"])
        self.assertIsNone(self.verdict([])["label"])
        self.assertEqual(self.verdict([], normal_coverage=True)["label"], 0)
        excluded = match_packet(self.packet, [replace(self.annotation, family="exploits")])
        self.assertEqual(excluded["label"], "excluded")
        self.assertIsNone(self.verdict([excluded, {"label": "attack"}])["label"])
        self.assertIsNone(self.verdict([{"label": "unknown"}], normal_coverage=True)["label"])


class AuditTests(unittest.TestCase):
    def test_bom_does_not_become_endpoint_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.csv"
            path.write_bytes(b"\xef\xbb\xbf59.166.0.0,80\n")
            self.assertEqual(list(rows(path)), [["59.166.0.0", "80"]])

    def test_csv_evidence_gate_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "input"
            root.mkdir()
            for name, row_id in (("training", "7"), ("testing", "4")):
                with (root / f"UNSW_NB15_{name}-set.csv").open("w", newline="") as stream:
                    writer = csv.writer(stream)
                    writer.writerows([["id", "attack_cat", "label"], [row_id, "Normal", "0"]])
            result = audit(root, Path(tmp) / "result")
            self.assertFalse(result["bulk_extraction_allowed"])
            self.assertIsNone(result["coverage"]["packet_label_coverage_fraction"])
            self.assertEqual(result["profiles"]["UNSW_NB15_training-set.csv"]["counts"][
                "duplicate_rows_from_prior_file"], 1)
            self.assertTrue(all(e["original_session_id"] is None for e in result["inventory"]))
            with self.assertRaises(FileExistsError):
                audit(root, Path(tmp) / "result")

    def test_candidate_overlap_is_not_packet_verification(self):
        key = ("tcp", "a", 1, "b", 2)
        sample = {"file": "x", "row": 1, "tuple": list(key), "family": "dos",
                  "start": "10", "end": "11"}
        index = {("tcp", "b", 2, "a", 1): [(Decimal(11), Decimal(11), "dos", 2)]}
        result = candidate_joins({("x",): [sample]}, index)[0]
        self.assertEqual(result["candidate_annotations"][0]["direction"], "reverse")
        self.assertFalse(result["verified_packet_trace"])
        self.assertEqual(port("0x0050"), 80)
        self.assertEqual(port("-"), "-")


if __name__ == "__main__":
    unittest.main()
