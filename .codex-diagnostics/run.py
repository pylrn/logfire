"""Operational native-CI evidence only; no product changes or remote writes.

Adapted from the reviewed run_linux_tests.py. Evidence stays outside source;
normal repository warning/coverage settings and every Docker case are retained.
"""

import datetime
import hashlib
import json
import os
import platform
import selectors
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

REFS = {
    'original': '060b741354bb7fd2204cd867ad2346068241e296',
    'patched': '41fe9a3feb66b1f90623f9be275b6e4bdb1d29e3',
}
BRANCH = 'refs/heads/codex/logfire-py310-diagnostics-20261019'
OBSERVER_SHA256 = '5cbdf3dcf8c98b1ad2535ffd0139474fd1c52d83ecedea52e798f0357d6ecf4a'
LOCK_SHA256 = 'c2bab013b5fd41fa9e812fe94941736c504f4046299bacbc43e85528822cbb5d'
# Canonical (normalized name, version) list from the reviewed 293-distribution
# CPython 3.10.20 frozen environment. No extra install/upgrade/seed step is allowed.
PACKAGES_SHA256 = 'dfdbd9331dd32b661e79c9b8be97199b72bcc381c29e5d3ae5ebde8673149057'
DISK_RESERVE = 2 * 1024**3
LOG_LIMIT = 64 * 1024**2
REPORT_LIMIT = 1024**2
HOSTS = ('logfire.dev', 'logfire-api.pydantic.dev', 'logfire.pydantic.dev')


def now():
    """Return an explicit UTC timestamp for the receipt."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    """Hash evidence using SHA-256."""
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    """Save a receipt outside the checkout under test."""
    path.write_text(json.dumps(value, indent=2) + '\n')


def git(source, *args):
    """Run a bounded local Git operation without optional index writes."""
    cp = subprocess.run(
        ['git', *args],
        cwd=source,
        capture_output=True,
        timeout=20,
        check=False,
        env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0'},
    )
    if cp.returncode:
        raise RuntimeError(f'git {args!r} exited {cp.returncode}: {cp.stderr[:2048]!r}')
    return cp.stdout


def source_snapshot(source, expected_ref):
    """Check every tracked blob and mode, HEAD, index, worktree, and lockfile."""
    entries = []
    mismatches = []
    for entry in git(source, 'ls-tree', '-rz', '--full-tree', expected_ref).split(b'\0'):
        if not entry:
            continue
        meta, raw_name = entry.split(b'\t', 1)
        mode, kind, oid = meta.split()
        name = os.fsdecode(raw_name)
        path = source / name
        try:
            if kind != b'blob':
                raise ValueError('unexpected non-blob tree entry')
            if mode == b'120000':
                data = os.fsencode(os.readlink(path))
                actual_mode = b'120000'
            else:
                if path.is_symlink():
                    raise ValueError('regular file replaced by symlink')
                data = path.read_bytes()
                actual_mode = b'100755' if path.stat().st_mode & 0o111 else b'100644'
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            entries.append([name, actual_mode.decode(), blob, digest(data)])
            if blob != oid.decode() or actual_mode != mode:
                mismatches.append(name)
        except (OSError, ValueError) as error:
            mismatches.append(f'{name}: {type(error).__name__}: {error}')
    head = git(source, 'rev-parse', 'HEAD').decode().strip()
    status = git(source, 'status', '--porcelain=v1', '--untracked-files=normal').decode(errors='replace')
    # Actual git diff exit codes plus bounded stat output, without dumping changed
    # cassettes or generating an unbounded binary patch into the Actions log.
    diffs = {}
    for name, args in [('worktree_and_index', ['HEAD']), ('index', ['--cached', 'HEAD'])]:
        quiet = subprocess.run(['git', 'diff', '--quiet', *args, '--'], cwd=source, timeout=20)
        diffs[name] = {
            'command': ['git', 'diff', '--quiet', *args, '--'],
            'exit_code': quiet.returncode,
            'stat': git(source, 'diff', '--stat', *args, '--')[:16384].decode(errors='replace'),
        }
    lock_hash = digest((source / 'uv.lock').read_bytes())
    return {
        'head': head,
        'expected_ref': expected_ref,
        'tree': git(source, 'rev-parse', expected_ref + '^{tree}').decode().strip(),
        'tracked_files': len(entries),
        'manifest_sha256': digest(json.dumps(entries, separators=(',', ':')).encode()),
        'mismatch_count': len(mismatches),
        'mismatches': mismatches[:50],
        'status': status[:16384],
        'status_bytes': len(status.encode()),
        'git_diff': diffs,
        'lock_sha256': lock_hash,
        'ok': head == expected_ref
        and not status
        and not mismatches
        and all(d['exit_code'] == 0 for d in diffs.values())
        and lock_hash == LOCK_SHA256,
    }


def cleanup_group(process):
    """Terminate the whole child session on normal completion and every failure."""
    for sig, grace in [(signal.SIGTERM, 2), (signal.SIGKILL, 0)]:
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
    process.wait(timeout=5)


def capture(name, command, source, evidence, env, timeout):
    """Bounded capture; never stream 64 MiB into the Actions log."""
    start = time.monotonic()
    receipt = {
        'start': now(),
        'command': command,
        'shell_command': shlex.join(command),
        'cwd': str(source),
        'timeout_seconds': timeout,
        'log_limit_bytes': LOG_LIMIT,
        'disk_reserve_bytes': DISK_RESERVE,
        'log_bytes': 0,
        'infrastructure_error': None,
        'exit_code': None,
    }
    process = None
    selector = selectors.DefaultSelector()
    try:
        if shutil.disk_usage(evidence).free < DISK_RESERVE:
            receipt['infrastructure_error'] = 'disk_reserve'
        else:
            process = subprocess.Popen(
                command,
                cwd=source,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            selector.register(process.stdout, selectors.EVENT_READ)
            with (evidence / f'{name}.log').open('xb') as log:
                while True:
                    if time.monotonic() - start > timeout:
                        receipt['infrastructure_error'] = 'wall_timeout'
                        break
                    if shutil.disk_usage(evidence).free < DISK_RESERVE:
                        receipt['infrastructure_error'] = 'disk_reserve'
                        break
                    events = selector.select(0.25)
                    if events:
                        data = os.read(process.stdout.fileno(), 65536)
                        if not data:
                            break
                        remaining = LOG_LIMIT - receipt['log_bytes']
                        log.write(data[:remaining])
                        receipt['log_bytes'] += min(len(data), remaining)
                        if len(data) > remaining:
                            receipt['infrastructure_error'] = 'log_limit'
                            break
                    elif process.poll() is not None:
                        break
    except BaseException as error:
        receipt['infrastructure_error'] = f'{type(error).__name__}: {str(error)[:2048]}'
        raise
    finally:
        selector.close()
        if process is not None:
            try:
                cleanup_group(process)
            except Exception as error:
                receipt['infrastructure_error'] = receipt['infrastructure_error'] or f'cleanup: {error}'
            finally:
                process.stdout.close()
            receipt['subprocess_returncode'] = process.returncode
        receipt['exit_code'] = 124 if receipt['infrastructure_error'] else process.returncode
        receipt.update(finish=now(), seconds=time.monotonic() - start)
        write_json(evidence / f'{name}.json', receipt)
    return receipt


def checked(name, command, source, evidence, env, timeout=20):
    """Capture a setup phase and reject any nonzero outcome."""
    receipt = capture(name, command, source, evidence, env, timeout)
    if receipt['exit_code']:
        raise RuntimeError(f'{name} failed: exit={receipt["exit_code"]}, cause={receipt["infrastructure_error"]}')
    return (evidence / f'{name}.log').read_text()


PROBE = r"""
import hashlib, importlib.metadata as m, inspect, json, os, platform, sys
from pathlib import Path
import logfire, logfire_api, logfire.integrations.logging as logging, contri_first_failure
import docker
source = Path.cwd().resolve()
distributions = sorted((d.metadata['Name'].lower().replace('_', '-').replace('.', '-'), d.version) for d in m.distributions())
paths = {name: str(Path(module.__file__).resolve()) for name, module in [('logfire', logfire), ('logging', logging), ('logfire_api', logfire_api), ('observer', contri_first_failure)]}
result = {'python': sys.version, 'implementation': platform.python_implementation(), 'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'machine': platform.machine(), 'platform': platform.platform(), 'imports': paths, 'source_version': logfire.__version__, 'packages': distributions, 'package_count': len(distributions), 'packages_sha256': hashlib.sha256(json.dumps(distributions, separators=(',', ':')).encode()).hexdigest(), 'coercion_present': '    msg = str(msg)' in inspect.getsource(logging._format_message)}
# Print actual identity before asserting, so mismatch evidence survives.
print(json.dumps(result), flush=True)
assert sys.version_info[:3] == (3, 10, 20) and platform.python_implementation() == 'CPython'
assert platform.machine() == 'x86_64' and sys.platform == 'linux'
assert Path(sys.prefix).resolve() == source / '.venv'
assert Path(paths['logfire']) == source / 'logfire-sdk/logfire/__init__.py'
assert Path(paths['logging']) == source / 'logfire-sdk/logfire/integrations/logging.py'
assert Path(paths['logfire_api']) == source / 'logfire-api/logfire_api/__init__.py'
assert Path(paths['observer']) == Path(os.environ['DIAGNOSTIC_HELPERS']) / 'contri_first_failure.py'
assert logfire.__version__ == m.version('logfire-sdk') == m.version('logfire-api') == '6.0.0b8'
assert result['coercion_present'] == (os.environ['DIAGNOSTIC_CASE'] == 'patched')
assert result['package_count'] == 293 and result['packages_sha256'] == os.environ['EXPECTED_PACKAGES_SHA256']
client = docker.from_env()
try:
    version = client.version()
    print(json.dumps({'docker_sdk_ping': client.ping(), 'docker_server_api': version.get('ApiVersion'), 'docker_server_version': version.get('Version'), 'docker_server_arch': version.get('Arch'), 'docker_server_os': version.get('Os')}), flush=True)
    assert client.ping() and version['Os'] == 'linux' and version['Arch'] in ('amd64', 'x86_64')
finally:
    client.close()
"""


LOGGING_PROBES = r"""
import json, logging, os, platform, sys, traceback
from pathlib import Path
import logfire
from logfire.integrations.logging import LogfireLoggingHandler

assert sys.version_info[:3] == (3, 10, 20) and platform.python_implementation() == 'CPython'
assert Path(logfire.__file__).resolve() == Path.cwd() / 'logfire-sdk/logfire/__init__.py'
logfire.configure(send_to_logfire=False, console=False, inspect_arguments=False)
cases = [
    ('positional', 'model %s finished', ('gemini',), 'model gemini finished'),
    ('mapping', 'model %(model)s finished', ({'model': 'gemini'},), 'model gemini finished'),
    ('positional-mapping', 'model %s finished', ({'model': 'gemini'},), "model {'model': 'gemini'} finished"),
]
observations = []
for name, template, args, expected in cases:
    class Message:
        def __str__(self):
            return template

    message = Message()
    received = []
    class CollectingHandler(logging.Handler):
        def emit(self, record):
            received.append({'formatted': record.getMessage(), 'message_object_unchanged': record.msg is message,
                             'arguments_unchanged': record.args is args[0] if isinstance(args[0], dict) else record.args == args})

    logger = logging.Logger('codex.native.message-object.' + name, level=logging.ERROR)
    logger.propagate = False
    first = LogfireLoggingHandler()
    second = CollectingHandler()
    logger.addHandler(first)
    logger.addHandler(second)
    error_type = None
    error_message = None
    genuine_type_error = False
    frames = []
    try:
        logger.error(message, *args)
    except Exception as error:
        error_type = type(error).__name__
        error_message = str(error)[:2048]
        frames = [{'file': frame.filename, 'function': frame.name, 'line': frame.lineno}
                  for frame in traceback.extract_tb(error.__traceback__)[-6:]]
        genuine_type_error = type(error) is TypeError and any(
            frame['function'] == '_format_message'
            and Path(frame['file']).resolve() == Path.cwd() / 'logfire-sdk/logfire/integrations/logging.py'
            for frame in frames)
    finally:
        logger.removeHandler(first)
        logger.removeHandler(second)
        first.close()
        second.close()
    expected_original = os.environ['DIAGNOSTIC_CASE'] == 'original'
    matches = (genuine_type_error and not received) if expected_original else (
        error_type is None and len(received) == 1 and received[0]['formatted'] == expected
        and received[0]['message_object_unchanged'] and received[0]['arguments_unchanged'])
    observation = {'case': name, 'source_case': os.environ['DIAGNOSTIC_CASE'], 'template': template,
                   'arguments': args, 'expected_formatted': expected, 'error_type': error_type,
                   'error_message': error_message, 'genuine_type_error_from_logfire_formatter': genuine_type_error,
                   'exception_frames': frames, 'subsequent_handler_count': len(received),
                   'subsequent_handler_records': received, 'expected_observation_matches': matches}
    observations.append(observation)
    print(json.dumps(observation), flush=True)
assert len(observations) == 3 and all(row['expected_observation_matches'] for row in observations), 'public Logger.error message-object observations did not match source ref'
"""


def probe_identity(text):
    """Select identity JSON even when imports emit preceding stderr output."""
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict) and 'packages_sha256' in value:
            return value
    raise ValueError('environment probe emitted no JSON identity with packages_sha256')


def print_report(evidence, source, expected_ref):
    """At most one MiB, with bounded tails and the entire observer JSON."""
    parts = []
    receipt = evidence / 'outcome.json'
    if receipt.exists():
        parts.append('CONTRI_OUTCOME\n' + receipt.read_text())
    else:
        fallback = {'first_cause': 'No completed runner receipt; inspect earlier checkout/setup/cancellation logs.'}
        try:
            fallback['source_after'] = source_snapshot(source, expected_ref)
        except Exception as error:
            fallback['source_after_error'] = f'{type(error).__name__}: {error}'
        parts.append(json.dumps(fallback, indent=2))
    for path in sorted(evidence.glob('*.json')):
        if path.name not in ('outcome.json', 'first-failure.json'):
            parts.append(f'CONTRI_RECEIPT {path.name}\n' + path.read_text())
    for path in sorted(evidence.glob('*.log')):
        with path.open('rb') as log:
            log.seek(max(0, path.stat().st_size - 8192))
            tail = log.read(8192).decode(errors='replace')
        parts.append(f'CONTRI_LOG_TAIL {path.name} (last <=8192 bytes)\n{tail}')
    failure = evidence / 'first-failure.json'
    if failure.exists():
        raw = failure.read_bytes()
        assert len(raw) <= REPORT_LIMIT, 'observer receipt exceeds reviewed byte bound'
        json.loads(raw)  # Print the whole valid JSON, never a tail of this file.
        parts.append('CONTRI_WHOLE_FIRST_FAILURE_JSON\n' + raw.decode())
    else:
        parts.append('CONTRI_FIRST_FAILURE_JSON absent; see outcome and setup/pytest tails for first cause.')
    payload = ('\n'.join(parts) + '\n').encode()
    # Reserve room for delimiters and the execution step's finally summary.
    budget = REPORT_LIMIT - 128 * 1024
    if len(payload) > budget:
        # Preserve the whole first-failure receipt and outcome; reduce ancillary
        # receipts/tails, never silently cut the observer JSON into invalid JSON.
        parts = [parts[0], parts[-1], 'CONTRI ancillary evidence omitted to enforce 1 MiB log bound.']
        payload = ('\n'.join(parts) + '\n').encode()
    assert len(payload) <= budget, 'mandatory evidence exceeds report budget'
    token = uuid.uuid4().hex
    print(f'::stop-commands::{token}', flush=True)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    print(f'::{token}::', flush=True)


def main():
    """Validate native CI, run the entire suite, and record source integrity."""
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    source = workspace / 'source'
    helpers = workspace / 'diagnostic/.codex-diagnostics'
    case = os.environ['DIAGNOSTIC_CASE']
    expected_ref = REFS[case]
    evidence = Path(os.environ['RUNNER_TEMP']).resolve() / (
        f'codex-py310-{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}-{case}'
    )
    assert evidence != source and source not in evidence.parents and workspace not in evidence.parents
    if sys.argv[1:] == ['--report-only']:
        print_report(evidence, source, expected_ref)
        return 0
    assert not sys.argv[1:]
    evidence.mkdir(exist_ok=False)
    env = dict(os.environ)
    removed = []
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        if key in env:
            removed.append(key)
            env.pop(key)
    # No inherited test selectors, warning overrides, or externally injected plugins.
    overrides = {
        key: env.pop(key)
        for key in (
            'PYTEST_ADDOPTS',
            'PYTHONWARNINGS',
            'PYTEST_PLUGINS',
            'PYTEST_DISABLE_PLUGIN_AUTOLOAD',
            'PYTEST_XDIST_AUTO_NUM_WORKERS',
            'COVERAGE_RCFILE',
            'COVERAGE_PROCESS_START',
        )
        if key in env
    }
    env.update(
        PYTHONPATH=os.pathsep.join(
            [str(helpers), str(source / 'logfire-sdk'), str(source / 'logfire-api'), str(source)]
        ),
        CI='true',
        PYTHONDONTWRITEBYTECODE='1',
        LOGFIRE_SEND_TO_LOGFIRE='false',
        PYTHONUNBUFFERED='1',
        COLUMNS='180',
        OPENAI_API_KEY='foo',
        ANTHROPIC_API_KEY='foo',
        COVERAGE_FILE=str(evidence / '.coverage'),
        CONTRI_FAILURE_REPORT=str(evidence / 'first-failure.json'),
        DIAGNOSTIC_HELPERS=str(helpers),
        EXPECTED_PACKAGES_SHA256=PACKAGES_SHA256,
        UV_PROJECT_ENVIRONMENT=str(source / '.venv'),
    )
    outcome = {
        'start': now(),
        'case': case,
        'expected_ref': expected_ref,
        'evidence': str(evidence),
        'environment': {
            key: env.get(key)
            for key in (
                'CI',
                'COLUMNS',
                'LOGFIRE_SEND_TO_LOGFIRE',
                'OPENAI_API_KEY',
                'ANTHROPIC_API_KEY',
                'GITHUB_REPOSITORY',
                'GITHUB_REF',
                'GITHUB_SHA',
                'GITHUB_RUN_ID',
                'GITHUB_RUN_ATTEMPT',
                'GITHUB_EVENT_NAME',
                'RUNNER_OS',
                'RUNNER_ARCH',
                'ImageOS',
                'ImageVersion',
                'PYTHONPATH',
                'COVERAGE_FILE',
                'CONTRI_FAILURE_REPORT',
                'UV_CACHE_DIR',
            )
        },
        'proxy_keys_removed_without_values': removed,
        'override_keys_removed_without_values': sorted(overrides),
        'warnings': 'unchanged repository policy; no added suppression',
        'scope': 'all default pytest cases including all eight Docker cases; no extra exclusions',
        'coverage': 'normal CI instrumentation; no combined-matrix 100% coverage claim',
        'cleanup': 'child process group TERM then KILL; Docker fixtures manage their own containers; no stop/prune commands',
        'first_cause': None,
        'pytest_exit_code': None,
    }
    exit_code = 1
    try:
        outcome['source_before'] = source_snapshot(source, expected_ref)
        assert outcome['source_before']['ok'], 'source-before integrity failed'
        assert os.environ['DIAGNOSTIC_SOURCE_REF'] == expected_ref
        assert os.environ['GITHUB_REPOSITORY'] == 'pylrn/logfire'
        assert os.environ['GITHUB_EVENT_NAME'] == 'push' and os.environ['GITHUB_REF'] == BRANCH
        outcome['diagnostic_head'] = git(helpers.parent, 'rev-parse', 'HEAD').decode().strip()
        assert outcome['diagnostic_head'] == os.environ['GITHUB_SHA'], 'helpers are not from workflow commit'
        outcome['observer_sha256'] = digest((helpers / 'contri_first_failure.py').read_bytes())
        assert outcome['observer_sha256'] == OBSERVER_SHA256
        assert sys.platform == 'linux' and platform.machine() == 'x86_64'
        outcome['host'] = {
            'platform': platform.platform(),
            'machine': platform.machine(),
            'logical_cpus': os.cpu_count(),
            'os_release': Path('/etc/os-release').read_text(),
            'free_bytes_before': shutil.disk_usage(evidence).free,
        }
        outcome['production_hosts'] = {
            host: sorted({info[4][0] for info in socket.getaddrinfo(host, None)}) for host in HOSTS
        }
        assert all(addresses == ['203.0.113.0'] for addresses in outcome['production_hosts'].values())
        # Local-only metadata parity with normal upstream CI; never pushes.
        git(source, 'remote', 'set-url', 'origin', 'https://github.com/pydantic/logfire.git')
        outcome['source_origin'] = git(source, 'remote', 'get-url', 'origin').decode().strip()
        uv_version = checked('uv-version', ['uv', '--version'], source, evidence, env).strip()
        outcome['uv_version'] = uv_version
        assert uv_version.split()[:2] == ['uv', '0.11.1']
        checked('docker-api', ['docker', 'version', '--format', '{{json .Server}}'], source, evidence, env)
        checked(
            'docker-host',
            ['docker', 'info', '--format', '{{json .ServerVersion}} {{json .OSType}} {{json .Architecture}}'],
            source,
            evidence,
            env,
        )
        checked('uv-sync', ['uv', 'sync', '--frozen', '--python', '3.10.20'], source, evidence, env, timeout=180)
        py = source / '.venv/bin/python'
        probe_output = checked('environment-imports', [str(py), '-c', PROBE], source, evidence, env, timeout=30)
        # Retain the complete actual 293-package manifest in Actions logs, not just
        # the bounded probe tail. Includes actual import paths and Python version.
        outcome['identity'] = probe_identity(probe_output)
        logging_probe_output = checked(
            'logging-probes', [str(py), '-c', LOGGING_PROBES], source, evidence, env, timeout=30
        )
        outcome['logging_probes'] = [
            json.loads(line) for line in logging_probe_output.splitlines() if line.startswith('{')
        ]
        outcome['source_pre_pytest'] = source_snapshot(source, expected_ref)
        assert outcome['source_pre_pytest']['ok'], 'setup changed source'
        command = [
            str(py),
            '-m',
            'coverage',
            'run',
            '-m',
            'pytest',
            '-p',
            'contri_first_failure',
            '-n',
            'logical',
            '--dist=loadgroup',
            '--record-mode=none',
            '--maxfail=1',
            '--tb=long',
            '-vv',
            '-rA',
        ]
        # Publish validated identity, all package versions, source checks and the
        # exact command before the long phase, in case the VM is forcibly stopped
        # before the always() report step has a chance to run.
        print(
            json.dumps({'CONTRI_PRE_PYTEST': outcome, 'pytest_command': command, 'test_timeout_seconds': 900}),
            flush=True,
        )
        result = capture('pytest', command, source, evidence, env, timeout=900)
        outcome['pytest'] = result
        outcome['pytest_exit_code'] = result.get('subprocess_returncode')
        exit_code = result['exit_code']
        if exit_code:
            outcome['first_cause'] = (
                result['infrastructure_error'] or 'pytest failed; see first-failure JSON and pytest tail'
            )
    except BaseException as error:
        outcome['first_cause'] = f'{type(error).__name__}: {str(error)[:4096]}'
        exit_code = 143 if isinstance(error, InterruptedError) else 1
    finally:
        # Always attempt source checks and first-cause evidence, even when frozen
        # sync/import/API preflight fails. Preserve a completed nonzero pytest exit.
        # Keep the full package/import identity even when the probe's assertions
        # reject it; an 8 KiB log tail alone would lose most of the manifest.
        logging_probe_log = evidence / 'logging-probes.log'
        if logging_probe_log.exists():
            try:
                outcome['logging_probes'] = [
                    json.loads(line) for line in logging_probe_log.read_text().splitlines() if line.startswith('{')
                ]
            except Exception as error:
                outcome['logging_probe_evidence_error'] = f'{type(error).__name__}: {str(error)[:2048]}'
        probe_log = evidence / 'environment-imports.log'
        if probe_log.exists():
            try:
                outcome['identity'] = probe_identity(probe_log.read_text())
            except Exception as error:
                outcome['probe_identity_error'] = f'{type(error).__name__}: {str(error)[:2048]}'
        try:
            outcome['source_after'] = source_snapshot(source, expected_ref)
            before = outcome.get('source_before', {})
            same = outcome['source_after']['manifest_sha256'] == before.get('manifest_sha256')
            outcome['source_manifest_unchanged'] = same
            if not outcome['source_after']['ok'] or not same:
                outcome['first_cause'] = outcome['first_cause'] or 'source-after integrity failed'
                exit_code = exit_code or 1
        except BaseException as error:
            outcome['source_after_error'] = f'{type(error).__name__}: {str(error)[:4096]}'
            outcome['first_cause'] = outcome['first_cause'] or outcome['source_after_error']
            exit_code = exit_code or 1
        # A capture interrupted before returning still has its own durable receipt.
        pytest_receipt = evidence / 'pytest.json'
        if 'pytest' not in outcome and pytest_receipt.exists():
            outcome['pytest'] = json.loads(pytest_receipt.read_text())
            outcome['pytest_exit_code'] = outcome['pytest'].get('subprocess_returncode')
        outcome.update(
            finish=now(), exit_code=exit_code, first_failure_report_exists=(evidence / 'first-failure.json').exists()
        )
        write_json(evidence / 'outcome.json', outcome)
        # The always() workflow step prints the full bounded evidence. This small
        # finally message survives an earlier step failure and records first cause.
        print(
            json.dumps(
                {
                    key: outcome.get(key)
                    for key in (
                        'case',
                        'first_cause',
                        'pytest_exit_code',
                        'exit_code',
                        'source_after',
                        'source_after_error',
                        'source_manifest_unchanged',
                        'first_failure_report_exists',
                    )
                }
            ),
            flush=True,
        )
    return exit_code


def interrupted(signum, frame):
    """Unwind through process cleanup and source evidence on cancellation."""
    raise InterruptedError(f'runner received signal {signum}')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main())
