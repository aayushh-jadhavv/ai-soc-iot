import unittest
from decimal import Decimal

from ids.datasets.audit import reverse
from ids.datasets.packet_audit import canonical
from ids.datasets.verify_unsw_labels import Flow, verify_flow


class VerifyUNSWLabelTests(unittest.TestCase):
    def setUp(self):
        self.key = ("tcp", "192.0.2.1", 1234, "192.0.2.2", 80)
        self.flow = Flow("flow.csv", 1, self.key, 10, 11, Decimal(200_000),
                         (1, 1, 40, 40), "dos", "1")
        self.flow.observe(10_400_000, 0, 40)
        self.flow.observe(10_600_000, 1, 40)
        # The raw ACK/reply crosses the nearest-second boundary even though
        # both packets fall in the same actual [10,11) second.
        self.gt = {"family": "dos", "key": self.key, "start": 10_000_000, "end": 11_000_000}
        self.argus = {(self.key, 10, 11, self.flow.signature): [3]}
        self.annotations = {
            "gt": {canonical(self.key): [self.gt]},
            "bro": {canonical(self.key): [{"key": self.key, "start": 10_400_000, "uid": "u",
                                         "missed_bytes": "0"}]},
        }

    def verify(self):
        return verify_flow(self.flow, self.argus, self.annotations, 9_000_000, 12_000_000)

    def test_coarse_bins_link_to_exact_observed_connection(self):
        label, evidence = self.verify()
        self.assertEqual(label, "dos")
        self.assertEqual(evidence["argus_csv_row"], 3)
        self.assertEqual(evidence["bro"]["uid"], "u")

    def test_reverse_gt_alone_cannot_authenticate_initiator(self):
        self.gt["key"] = reverse(self.key)
        self.assertEqual(self.verify(), ("attack_annotation_not_unique", None))

    def test_benign_requires_matching_aggregate_and_no_attack_annotation(self):
        self.flow.family, self.flow.label = "benign", "0"
        self.assertEqual(self.verify(), ("conflict", None))
        self.annotations["gt"].clear()
        self.assertEqual(self.verify()[0], "benign")
        self.flow.observe(10_600_002, 1, 40)
        self.assertEqual(self.verify(), ("packet_or_byte_totals_disagree", None))

    def test_connection_collision_excluded_even_if_aggregate_matches(self):
        self.flow.ambiguous = True
        self.assertEqual(self.verify(), ("multiple_flow_candidates", None))

    def test_reported_content_gap_excluded_even_if_aggregate_matches(self):
        self.annotations["bro"][canonical(self.key)][0]["missed_bytes"] = "1"
        self.assertEqual(self.verify(), ("bro_content_gap", None))
