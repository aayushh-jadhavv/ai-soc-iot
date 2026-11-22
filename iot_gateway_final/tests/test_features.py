import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from feature_extractor import FeatureExtractor, FEATURE_NAMES
from contracts import validate_window, validate_sequence, new_predict_request, ContractError


def record(ms, direction='OUT', proto='TCP', ip='10.10.0.42', dst='8.8.8.8',
           port=443, size=100, syn=False, synack=False, rst=False, revision=1):
    return {'event_time_ms': ms, 'device_ip': ip, 'device_id': 'dev-42',
            'binding_revision': revision, 'valid': True, 'direction': direction,
            'dst_ip': dst, 'dst_port': port, 'ip_bytes': size, 'protocol': proto,
            'syn_no_ack': syn, 'syn_ack': synack, 'rst_set': rst}


class FeatureTests(unittest.TestCase):
    def create(self):
        self.rows = []
        self.sequences = []
        return FeatureExtractor('gw-test', 'boot-test', 'session-test', live=False,
                                on_window=self.rows.append,
                                on_sequence=self.sequences.append)

    def test_feature_values_and_population_std(self):
        ex = self.create()
        ex.add_packet(record(1_000_100, size=100, port=80, syn=True))
        ex.add_packet(record(1_000_300, size=300, port=443, dst='1.1.1.1'))
        ex.add_packet(record(1_000_500, direction='IN', size=90, synack=True))
        ex.add_packet(record(1_000_700, direction='IN', size=50, rst=True))
        ex.advance_to(1_001_150)
        self.assertEqual(len(self.rows), 1)
        self.assertEqual(len(FEATURE_NAMES), 16)
        self.assertEqual(self.rows[0]['values'],
                         [2, 2, 400, 140, 2, 2, 2, 0, 0, 1, 1, 1,
                          200.0, 100.0, 200.0, 0.0])
        self.assertTrue(validate_window(self.rows[0]))

    def test_eight_contiguous_windows_and_idle_rows(self):
        ex = self.create()
        ex.add_packet(record(1_000_100))
        ex.advance_to(1_008_200)
        self.assertEqual(len(self.rows), 8)
        self.assertEqual([w['sequence_number'] for w in self.rows], list(range(1, 9)))
        self.assertEqual(self.rows[1]['values'], [0] * 16)
        self.assertEqual(len(self.sequences), 1)
        self.assertTrue(validate_sequence(self.sequences[0]['windows']))
        payload = new_predict_request('model-v1', self.sequences[0]['windows'])
        self.assertEqual(payload['model_id'], 'model-v1')
        self.assertEqual(len(payload['windows']), 8)

    def test_binding_change_resets_history(self):
        ex = self.create()
        ex.add_packet(record(1_000_100))
        ex.advance_to(1_004_200)
        self.assertEqual(len(self.rows), 4)
        ex.add_packet(record(1_004_300, revision=2))
        ex.advance_to(1_009_200)
        self.assertEqual(len(self.sequences), 0)
        self.assertTrue(all(w['binding_revision'] == 2 for w in ex.state['dev-42']['history']))

    def test_invalid_coverage_clears_history(self):
        ex = self.create()
        ex.add_packet(record(1_000_100))
        ex.advance_to(1_004_150)
        bad = record(1_004_200)
        bad.update(valid=False, reason='fragmented_ipv4')
        ex.add_packet(bad)
        ex.advance_to(1_005_150)
        self.assertFalse(self.rows[-1]['quality']['valid'])
        self.assertEqual(len(ex.state['dev-42']['history']), 0)

    def test_reject_changed_revision_and_bad_value(self):
        ex = self.create()
        ex.add_packet(record(1_000_100))
        ex.advance_to(1_008_150)
        windows = [dict(w) for w in self.sequences[0]['windows']]
        windows[-1] = dict(windows[-1], binding_revision=2)
        with self.assertRaises(ContractError):
            validate_sequence(windows)
        windows[-1] = dict(windows[-1], values=[float('nan')] + [0] * 15)
        with self.assertRaises(ContractError):
            validate_sequence(windows)

    def test_window_boundary(self):
        ex = self.create()
        ex.add_packet(record(1_000_999))
        ex.add_packet(record(1_001_000))
        ex.advance_to(1_002_200)
        self.assertEqual([w['values'][0] for w in self.rows], [1, 1])

    def test_submillisecond_interarrival_matches_training_units(self):
        ex = self.create()
        for offset in (100_000, 350_000):
            ex.add_packet(dict(record(1_000_100), event_time_ns=1_000_100_000_000 + offset))
        ex.advance_to(1_001_100)
        self.assertEqual(self.rows[0]['values'][14:], [0.25, 0.0])

    def test_worker_restart_discards_old_and_partial_windows(self):
        ex = self.create()
        ex.add_packet(record(1_000_100))
        ex.advance_to(1_008_100)
        previous, = self.sequences
        self.assertTrue(ex.is_current(previous, 1_008_100))
        self.assertFalse(ex.is_current(previous, 1_009_100))
        ex.reset_worker_history(1_008_500)
        ex.add_packet(record(1_008_600))
        self.assertFalse(ex.is_current(previous, 1_008_700))
        ex.advance_to(1_016_100)
        self.assertEqual(len(self.sequences), 1)
        ex.advance_to(1_017_100)
        new = self.sequences[1]
        self.assertEqual(new['windows'][0]['window_start_ms'], 1_009_000)
        self.assertTrue(ex.is_current(new, 1_017_100))
        ex.mark_capture_loss()
        self.assertFalse(ex.is_current(new, 1_017_100))


if __name__ == '__main__':
    unittest.main()
