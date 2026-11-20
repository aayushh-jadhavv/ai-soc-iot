"""Optional loopback-only HTTP client; fails closed when worker is unavailable."""
import json
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from contracts import ContractError, canonical_request


class CNNClient:
    def __init__(self, base_url, model_id, token_file, timeout=1.0):
        url = urlsplit(base_url)
        if url.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('CNN worker must bind to local loopback in this prototype')
        self.base_url, self.model_id = base_url.rstrip('/'), model_id
        self.token_file = Path(token_file)
        self.timeout = timeout

    def predict(self, request_body):
        token = self.token_file.read_text().strip()
        if not token:
            raise ContractError('empty IDS bearer token')
        payload = canonical_request(request_body).encode('utf-8')
        request = Request(self.base_url + '/v1/predict', data=payload, method='POST',
                          headers={'Authorization': 'Bearer ' + token,
                                   'Content-Type': 'application/json'})
        # Exactly one retry for a transport failure with identical request ID/body.
        for attempt in range(2):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    result = json.load(response)
                expected = request_body['windows'][-1]
                if (result.get('request_id') != request_body['request_id'] or
                    result.get('last_window_id') != expected['window_id'] or
                    result.get('device_id') != expected['device_id'] or
                    result.get('binding_revision') != expected['binding_revision'] or
                    result.get('enforcement_revision') != expected['enforcement_revision'] or
                    result.get('model_id') != self.model_id):
                    raise ContractError('STALE_OR_MISMATCHED_INFERENCE_RESULT')
                return result
            except HTTPError:
                raise  # protocol errors are not silently retried
            except (URLError, TimeoutError):
                if attempt:
                    raise
