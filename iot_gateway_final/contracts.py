"""Validated wire contract for Phase 7 gateway-to-IDS integration."""
import json
import math
import uuid
from feature_extractor import FEATURE_NAMES

COUNT_INDICES = set(range(12))


class ContractError(ValueError):
    pass


def validate_window(w):
    required = ('schema_version', 'feature_schema', 'window_id', 'gateway_id',
                'boot_id', 'capture_session_id', 'device_id', 'binding_revision',
                'sequence_number', 'window_start_ms', 'window_end_ms', 'observed_mode',
                'enforcement_revision', 'quality', 'values')
    missing = [name for name in required if name not in w]
    if missing:
        raise ContractError('missing window keys: ' + ', '.join(missing))
    if w['schema_version'] != '1.0' or w['feature_schema'] != 'device_window_v1':
        raise ContractError('SCHEMA_MISMATCH')
    if not all(isinstance(w[k], str) and 0 < len(w[k]) <= 128 for k in
               ('window_id', 'gateway_id', 'boot_id', 'capture_session_id', 'device_id')):
        raise ContractError('invalid identifier')
    if w['observed_mode'] not in ('live', 'offline'):
        raise ContractError('invalid observed_mode')
    for key in ('binding_revision', 'enforcement_revision', 'sequence_number',
                'window_start_ms', 'window_end_ms'):
        if type(w[key]) is not int or w[key] < 0:
            raise ContractError('invalid ' + key)
    if w['binding_revision'] < 1 or w['sequence_number'] < 1:
        raise ContractError('invalid revision/sequence')
    if w['window_end_ms'] - w['window_start_ms'] != 1000 or w['window_start_ms'] % 1000:
        raise ContractError('window must be aligned and 1000 ms')
    q = w['quality']
    if not isinstance(q, dict) or type(q.get('valid')) is not bool or not isinstance(q.get('reasons'), list):
        raise ContractError('invalid quality object')
    if not q['valid'] or q['reasons']:
        raise ContractError('invalid/unknown coverage')
    vals = w['values']
    if not isinstance(vals, list) or len(vals) != len(FEATURE_NAMES):
        raise ContractError('expected 16 numerical values')
    for i, value in enumerate(vals):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ContractError(f'invalid feature index {i}')
        if i in COUNT_INDICES and not float(value).is_integer():
            raise ContractError(f'non-integral count feature index {i}')
    return True


def validate_sequence(windows):
    if not isinstance(windows, list) or len(windows) != 8:
        raise ContractError('expected eight windows')
    for w in windows:
        validate_window(w)
    keys = ('device_id', 'gateway_id', 'boot_id', 'capture_session_id',
            'binding_revision', 'enforcement_revision', 'feature_schema', 'observed_mode')
    for earlier, later in zip(windows, windows[1:]):
        if any(earlier[k] != later[k] for k in keys):
            raise ContractError('inconsistent device/session/revisions')
        if earlier['window_end_ms'] != later['window_start_ms']:
            raise ContractError('noncontiguous timestamps')
        if earlier['sequence_number'] + 1 != later['sequence_number']:
            raise ContractError('noncontiguous sequence numbers')
    return True


def new_predict_request(model_id, windows, request_id=None):
    validate_sequence(windows)
    if not isinstance(model_id, str) or not model_id:
        raise ContractError('model_id is required')
    return {'schema_version': '1.0', 'request_id': request_id or str(uuid.uuid4()),
            'model_id': model_id, 'windows': windows}


def canonical_request(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False)
