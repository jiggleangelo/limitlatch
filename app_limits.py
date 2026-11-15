"""Resource-bounded application jobs. No request input is written to disk.

This is the only worker/process implementation. app_jobs.run_job delegates
here.
"""
import json
import multiprocessing
import shutil
import tempfile
import time
from pathlib import Path

# Limits and the strict policy cleaner live in app_jobs only. They are imported
# here so both modules always agree; nothing is monkeypatched at runtime.
from app_jobs import (  # noqa: F401  (re-exported for app.py)
    CPU_SECONDS,
    MAX_RESULT_BYTES,
    PROCESSING_SECONDS,
    RULE_KEYS,
    ProcessingLimit,
    check_stored_run,
    clean_policy,
    execute,
    silence_stderr,
)

PAGE_SIZE = 100
JOB_PREFIX = '.job-'
# A live job never exceeds PROCESSING_SECONDS, so anything this old is debris
# left by a killed server process and is safe to remove.
STALE_JOB_SECONDS = 600
ALL_AGENTS_LABEL = '(all agents)'


def sweep_stale_jobs(data_dir, max_age=STALE_JOB_SECONDS, now=None):
    """Remove orphaned job directories (worker output, run snapshots).

    Job directories live outside workspace accounting. A normal job removes
    its directory on exit, including on errors and timeouts; this sweep
    bounds disk use after a crash or hard kill of the HTTP process.
    """
    cutoff = (time.time() if now is None else now) - max_age
    removed = 0
    try:
        candidates = list(Path(data_dir).glob(JOB_PREFIX + '*'))
    except OSError:
        return 0
    for path in candidates:
        try:
            if path.is_symlink() or not path.is_dir() or path.stat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    return removed


def _page(records, query, name):
    try:
        number = max(1, int(query.get(name, ['1'])[-1]))
    except (ValueError, TypeError, IndexError):
        number = 1
    count = len(records)
    pages = max(1, (count + PAGE_SIZE - 1) // PAGE_SIZE)
    number = min(number, pages)
    return {'rows': records[(number - 1) * PAGE_SIZE:number * PAGE_SIZE],
            'count': count, 'page': number, 'pages': pages}


def _execute(operation, payload):
    if operation in {'verify', 'replay'}:
        # Replay: one parse, one save-time verification (inside replay), and
        # the kind/tool pair bound enforced by the engine itself.
        return execute(operation, payload)
    if operation not in {'stored', 'bundle'}:
        raise ValueError('unknown processing operation')
    filename, keys, query = payload
    path = Path(filename)
    if path.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError('stored run exceeds the 5 MB processing limit')
    with path.open(encoding='utf-8') as handle:
        run = json.load(handle)
    bundle = run['bundle']
    if operation == 'bundle':
        return bundle
    # Full stored-run check: bundle signature, policy digest, chain, anchors,
    # top-level copies and the derived_mac covering everything shown below.
    checked = check_stored_run(run, keys['sign'], keys['tsa'])
    totals = []
    for key, value in sorted(run['totals'].items()):
        agent, kind, day = key.split('|')
        if agent == '*':
            agent = ALL_AGENTS_LABEL
        totals.append({'agent': agent, 'kind': kind, 'day': day, 'committed': value.get('committed', 0)})
    report = dict(run['report'])
    # Runs saved by earlier versions may carry a numeric score. Never show it.
    report.pop('score', None)
    report['verification'] = checked
    return {'summary': run['summary'], 'verification': checked, 'report': report,
            'results': _page(run['results'], query, 'decisions'),
            'totals': _page(totals, query, 'totals'),
            'entries': _page(bundle['entries'], query, 'evidence'),
            'anchor_count': len(bundle['anchors'])}


def _write_output(output, encoded):
    """Write the result; on failure return False silently (no traceback)."""
    try:
        with open(output, 'wb') as handle:
            handle.write(encoded)
        return True
    except (OSError, ValueError):
        return False


def _worker(operation, payload, output):
    silence_stderr()
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT_BYTES, MAX_RESULT_BYTES))
        value = _execute(operation, payload)
        if operation == 'bundle':
            encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
        else:
            encoded = json.dumps({'result': value}, separators=(',', ':'), ensure_ascii=False).encode()
        if len(encoded) > MAX_RESULT_BYTES:
            raise ValueError('result exceeds the 5 MB workspace limit; use a smaller log')
    except (ValueError, TypeError, KeyError, RecursionError):
        # Replay errors are already safe, row-oriented diagnostics. Other
        # exceptions may contain stored or supplied text and stay generic.
        import sys
        error = sys.exc_info()[1]
        message = str(error) if operation == 'replay' and isinstance(error, ValueError) else 'input or stored run could not be processed'
        encoded = json.dumps({'error': message}).encode()
    except BaseException:
        encoded = b'{"error":"processing resource limit reached"}'
    if not _write_output(output, encoded):
        import os
        os._exit(1)


def run_job(data_dir, operation, payload, timeout=PROCESSING_SECONDS):
    """Only paginated views and bounded replay results enter the parent heap.

    Bundle downloads return an open file and never parse bundle JSON in the
    HTTP process. On Unix the open descriptor survives temporary-file cleanup;
    its space is released when the response handle is closed.
    """
    timeout = min(timeout, PROCESSING_SECONDS)
    if timeout <= 0:
        raise ProcessingLimit('processing deadline exceeded')
    sweep_stale_jobs(data_dir)
    with tempfile.TemporaryDirectory(prefix=JOB_PREFIX, dir=data_dir) as directory:
        output = Path(directory) / 'result.json'
        process = multiprocessing.get_context('spawn').Process(target=_worker, args=(operation, payload, str(output)))
        started = time.monotonic()
        try:
            process.start()
            process.join(max(0, timeout - (time.monotonic() - started)))
            if process.is_alive() or process.exitcode != 0 or not output.is_file():
                raise ProcessingLimit('processing resource limit reached; use a smaller input')
            if output.stat().st_size > MAX_RESULT_BYTES:
                raise ProcessingLimit('processing output limit reached')
            if operation == 'bundle':
                # An error response is tiny; inspect only that bounded case.
                if output.stat().st_size < 1024:
                    with output.open(encoding='utf-8') as handle:
                        value = json.load(handle)
                    if 'error' in value:
                        raise ValueError(value['error'])
                return output.open('rb')
            with output.open(encoding='utf-8') as handle:
                result = json.load(handle)
            if 'error' in result:
                raise ValueError(result['error'])
            return result['result']
        finally:
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                    process.join(.2)
                if process.is_alive():
                    process.kill()
                    process.join()
                process.close()
