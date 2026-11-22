"""Regression checks for the phone-facing HTTP contract."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.error import HTTPError
from urllib.request import urlopen
import unittest

GATEWAY_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GATEWAY_DIR))
from cnn_client import CNNClient
from phone_reports import PhoneReports, start_report_server


class PhoneReportTest(unittest.TestCase):
    def setUp(self):
        self.request = json.loads(
            (GATEWAY_DIR.parent / 'tests/fixtures/gateway-request.json').read_text()
        )
        last = self.request['windows'][-1]
        self.result = {
            'schema_version': '1.0', 'request_id': self.request['request_id'],
            'device_id': last['device_id'], 'binding_revision': last['binding_revision'],
            'last_window_id': last['window_id'], 'enforcement_revision': last['enforcement_revision'],
            'model_id': self.request['model_id'], 'status': 'ok', 'task': 'attack_associated_traffic',
            'attack_score': 0.01076234, 'score_type': 'uncalibrated_sigmoid',
            'inference_ms': 1, 'error_code': None,
        }
        self.reports = PhoneReports(last['gateway_id'], 60)
        self.server = start_report_server('127.0.0.1', 0, self.reports)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path='/v1/reports'):
        with urlopen(f'http://127.0.0.1:{self.server.server_port}{path}', timeout=3) as response:
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            return json.load(response)

    def test_empty_health_and_absent_demo_route(self):
        self.assertEqual(self.get('/health'), {'status': 'ok'})
        self.assertEqual(self.get()['reports'], [])
        with self.assertRaises(HTTPError) as error:
            self.get('/demo/reports')
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_validated_worker_response_reaches_phone_endpoint(self):
        result = self.result

        class FixtureWorker(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if (self.path != '/v1/predict' or self.headers['Authorization'] != 'Bearer test-token'
                        or request['request_id'] != result['request_id']):
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header('X-IDS-History-Epoch', 'test')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())

        with TemporaryDirectory() as directory, HTTPServer(('127.0.0.1', 0), FixtureWorker) as worker:
            Thread(target=worker.serve_forever, daemon=True).start()
            try:
                token = Path(directory) / 'token'
                token.write_text('test-token')
                client = CNNClient(f'http://127.0.0.1:{worker.server_port}', result['model_id'], token)
                validated = client.predict(self.request)
            finally:
                worker.shutdown()
        self.reports.publish(self.request, validated, lambda: True)
        payload = self.get()
        report, = payload['reports']
        self.assertEqual(payload['data_source'], 'live')
        self.assertEqual(report['report_id'], result['last_window_id'])
        self.assertEqual(report['score'], result['attack_score'])
        self.assertEqual(report['action_status'], 'NOT_EXECUTED')
        self.assertEqual(report['window_end_ms'] - report['window_start_ms'], 8000)
        self.assertNotIn('values', report)
        self.assertNotIn('test-token', json.dumps(payload))

    def test_unavailable_stale_and_cleared_results(self):
        for status in ('abstain', 'error'):
            result = dict(self.result, status=status, attack_score=None, error_code='TEST_ERROR')
            self.reports.publish(self.request, result, lambda: False)
            self.assertEqual(self.get()['reports'], [])
            self.reports.publish(self.request, result, lambda: True)
            report, = self.get()['reports']
            self.assertIsNone(report['score'])
            self.assertEqual(report['detector_status'], status)
            self.reports.discard(result['device_id'])
            self.assertEqual(self.get()['reports'], [])
        self.reports.publish(self.request, self.result, lambda: True)
        self.reports.max_age = 0
        self.assertEqual(self.get()['reports'], [])
        self.reports.max_age = 60
        self.reports.clear()
        self.assertEqual(self.get()['reports'], [])


if __name__ == '__main__':
    unittest.main()
