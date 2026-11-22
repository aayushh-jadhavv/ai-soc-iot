"""Optional loopback-only HTTP client; fails closed when worker is unavailable."""
import json
import time
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from urllib.parse import urlsplit
from contracts import ContractError, canonical_request


class WorkerRestarted(ContractError):
    """Evidence collected under the previous worker generation has expired."""


class _LocalOnly(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CNNClient:
    def __init__(self, base_url, model_id, token_file, timeout=1.0):
        url = urlsplit(base_url)
        if (url.scheme not in ('http', 'https') or url.hostname not in ('127.0.0.1', 'localhost', '::1')
                or url.username is not None or url.query or url.fragment):
            raise ValueError('Expected a loopback HTTP worker URL')
        self.base_url, self.model_id = base_url.rstrip('/'), model_id
        self.token_file = Path(token_file)
        self.timeout = timeout
        self.epoch = None
        self.opener = build_opener(ProxyHandler({}), _LocalOnly())

    def _request(self, endpoint, payload=None):
        token = self.token_file.read_text().strip()
        if not token:
            raise ContractError('empty IDS bearer token')
        return Request(self.base_url + '/v1/' + endpoint, data=payload,
                       headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})

    def _observe_epoch(self, epoch):
        if not epoch:
            raise ContractError('Missing worker history epoch')
        previous, self.epoch = self.epoch, epoch
        if previous is not None and previous != epoch:
            raise WorkerRestarted('Worker changed; collecting eight fresh windows')

    def info(self, endpoint):
        if endpoint not in ('health', 'metadata'):
            raise ValueError('Unknown worker information endpoint')
        with self.opener.open(self._request(endpoint), timeout=self.timeout) as response:
            info = json.load(response)
            if endpoint == 'metadata' or info.get('ready'):
                self._observe_epoch(response.headers.get('X-IDS-History-Epoch'))
            return info

    def predict(self, request_body):
        deadline = time.monotonic() + self.timeout
        request = self._request('predict', canonical_request(request_body).encode('utf-8'))
        # A transport retry uses the same evidence, ID and overall deadline.
        for attempt in range(2):
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Inference deadline elapsed')
                with self.opener.open(request, timeout=remaining) as response:
                    self._observe_epoch(response.headers.get('X-IDS-History-Epoch'))
                    result = json.load(response)
                if time.monotonic() >= deadline:
                    raise TimeoutError('Late inference result')
                expected = request_body['windows'][-1]
                if (result.get('request_id') != request_body['request_id'] or
                    result.get('last_window_id') != expected['window_id'] or
                    result.get('device_id') != expected['device_id'] or
                    result.get('binding_revision') != expected['binding_revision'] or
                    result.get('enforcement_revision') != expected['enforcement_revision'] or
                    result.get('model_id') != self.model_id):
                    raise ContractError('STALE_OR_MISMATCHED_INFERENCE_RESULT')
                status, score = result.get('status'), result.get('attack_score')
                if (result.get('schema_version') != '1.0' or result.get('task') != 'attack_associated_traffic'
                        or result.get('score_type') != 'uncalibrated_sigmoid' or 'attack_score' not in result
                        or 'error_code' not in result or status not in ('ok', 'abstain', 'error')):
                    raise ContractError('Invalid inference response')
                if status == 'ok':
                    if type(score) not in (float, int) or not 0 <= score <= 1 or result['error_code'] is not None:
                        raise ContractError('Invalid inference score')
                elif score is not None or not isinstance(result['error_code'], str):
                    raise ContractError('Invalid abstention or error response')
                return result
            except HTTPError as exc:
                with exc:
                    epoch = exc.headers.get('X-IDS-History-Epoch')
                    if epoch:
                        self._observe_epoch(epoch)
                raise
            except (URLError, TimeoutError):
                if attempt:
                    raise
