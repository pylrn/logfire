"""Bounded first-failure evidence; observer errors never change pytest outcomes."""
import json
import os
from pathlib import Path
import sys

_controller = False
_saved = False
MAX_BYTES = 1024 * 1024


def clip(value, limit):
    text = str(value)
    if len(text) <= limit:
        return text
    marker = '\n[CONTRI: content truncated]\n'
    half = (limit - len(marker)) // 2
    return text[:half] + marker + text[-half:]


def emit(text):
    try:
        print(text, file=sys.__stderr__, flush=True)
    except Exception:
        pass


def pytest_configure(config):
    global _controller
    _controller = not hasattr(config, 'workerinput')


def pytest_runtest_logreport(report):
    global _saved
    if not _controller or _saved or not report.failed:
        return
    _saved = True
    try:
        original = report.longreprtext
        sections = report.sections
        payload = {
            'nodeid': clip(report.nodeid, 8192),
            'when': clip(report.when, 32),
            'outcome': clip(report.outcome, 32),
            'longreprtext': clip(original, 65536),
            'sections': [[clip(name, 128), clip(body, 2048)] for name, body in sections[:8]],
            'worker_id': clip(getattr(report, 'worker_id', None), 128),
            'truncated': len(original) > 65536 or len(report.nodeid) > 8192 or len(sections) > 8 or any(len(str(name)) > 128 or len(str(body)) > 2048 for name, body in sections[:8]),
            'evidence_byte_limit': MAX_BYTES,
        }
        encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + '\n').encode('utf-8', errors='replace')
        if len(encoded) > MAX_BYTES:
            payload.update(longreprtext=clip(original, 8192), sections=[], truncated=True)
            encoded = (json.dumps(payload, ensure_ascii=False) + '\n').encode('utf-8', errors='replace')
        if len(encoded) > MAX_BYTES:
            raise ValueError('failure receipt exceeds byte limit')
        emit('\nCONTRI_FIRST_FAILURE\n' + payload['longreprtext'])
        path = Path(os.environ['CONTRI_FAILURE_REPORT'])
        with path.open('xb') as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
    except Exception as error:
        emit('CONTRI_OBSERVER_ERROR: ' + clip(type(error).__name__ + ': ' + str(error), 2048))
