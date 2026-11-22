"""Read-only, opt-in report feed for the phone on a trusted lab network."""
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from threading import Lock, Thread
from time import monotonic


class PhoneReports:
    def __init__(self, gateway_id, max_age):
        self.gateway_id = gateway_id
        self.max_age = max_age
        self.entries = OrderedDict()
        self.lock = Lock()

    def publish(self, request, result, is_current):
        windows = request['windows']
        last = windows[-1]
        status = result['status']
        summary = {
            'ok': 'The IDS scored eight consecutive one-second traffic windows.',
            'abstain': 'The IDS abstained and supplied no score.',
            'error': 'The IDS could not score this traffic sequence.',
        }[status]
        report = {
            'report_id': result['last_window_id'],
            'revision': 1,
            'device': result['device_id'],
            'factual_summary': summary,
            'coverage': 'The gateway validated eight contiguous one-second windows.',
            'score': result['attack_score'],
            'recommendation': 'Review the recorded evidence. The gateway is in OBSERVE mode.',
            'action_status': 'NOT_EXECUTED',
            'detector_status': status,
            'score_type': result['score_type'],
            'model_id': result['model_id'],
            'error_code': result['error_code'],
            'window_start_ms': windows[0]['window_start_ms'],
            'window_end_ms': last['window_end_ms'],
        }
        with self.lock:
            if not is_current():
                return
            self.entries[result['device_id']] = (monotonic(), report)
            self.entries.move_to_end(result['device_id'])
            while len(self.entries) > 40:
                self.entries.popitem(last=False)

    def discard(self, device_id):
        with self.lock:
            self.entries.pop(device_id, None)

    def clear(self):
        with self.lock:
            self.entries.clear()

    def snapshot(self):
        with self.lock:
            now = monotonic()
            reports = [report for observed, report in reversed(self.entries.values())
                       if now - observed < self.max_age]
        return {'schema_version': 1, 'gateway_id': self.gateway_id,
                'data_source': 'live', 'reports': reports}


def start_report_server(host, port, reports):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(2)
            super().setup()

        def do_GET(self):
            if self.path == '/v1/reports':
                status, result = 200, reports.snapshot()
            elif self.path == '/health':
                status, result = 200, {'status': 'ok'}
            else:
                status, result = 404, {'error': 'Unknown route'}
            body = json.dumps(result, allow_nan=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer((host, port), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server
