import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cnn_client import CNNClient, WorkerRestarted
from contracts import ContractError


class ClientTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        token = Path(directory.name) / 'credential'
        token.write_text('unit-test')
        self.client = CNNClient('http://127.0.0.1:8000', 'demo', token)
        self.last = dict(window_id='w', device_id='d', binding_revision=1, enforcement_revision=0)
        self.request = dict(request_id='r', model_id='demo', windows=[self.last])
        self.result = dict(schema_version='1.0', request_id='r', model_id='demo', last_window_id='w',
                           device_id='d', binding_revision=1, enforcement_revision=0, status='ok',
                           task='attack_associated_traffic', attack_score=0, score_type='uncalibrated_sigmoid',
                           inference_ms=0.1, error_code=None)

    def response(self, epoch, **changes):
        body = io.BytesIO(json.dumps(dict(self.result, **changes)).encode())
        body.headers = {'X-IDS-History-Epoch': epoch}
        return body

    def test_epoch_change_discards_response_even_after_rollback_to_same_model(self):
        with patch.object(self.client.opener, 'open', side_effect=[
                self.response('a'), self.response('b'), self.response('b')]):
            self.assertEqual(self.client.predict(self.request), self.result)
            with self.assertRaises(WorkerRestarted):
                self.client.predict(self.request)
            self.assertEqual(self.client.predict(self.request), self.result)

    def test_deadline_applies_across_retry_and_response_read(self):
        with patch.object(self.client.opener, 'open', side_effect=[URLError('offline'), self.response('a')]) as op:
            with patch('cnn_client.time.monotonic', side_effect=[0, 0, .8, 1.01]):
                with self.assertRaises(TimeoutError):
                    self.client.predict(self.request)
        first, second = op.call_args_list
        self.assertIs(first.args[0], second.args[0])
        self.assertAlmostEqual(second.kwargs['timeout'], .2)

    def test_abstention_cannot_supply_a_score(self):
        with patch.object(self.client.opener, 'open', return_value=self.response(
                'a', status='abstain', error_code='INVALID_COVERAGE')):
            with self.assertRaises(ContractError):
                self.client.predict(self.request)
