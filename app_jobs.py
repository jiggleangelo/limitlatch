"""Policy cleaning, job operations and stored-run checks.

This module is the single source of worker limits and policy cleaning.
The one and only worker/process implementation lives in app_limits;
app_jobs.run_job is a thin alias for it so no caller can pick a
different, less-hardened path.
"""
import json
import os
import re
import sys
from dataclasses import asdict

from agentguard import Policy, PolicyError, verify_bundle
from agentguard.core import CURRENCIES, Signer, _verify_entries
from agentguard.replay import daily_scope, parse_log, parse_outages, replay, verify_stored_run

CPU_SECONDS = 5
PROCESSING_SECONDS = 6.0
MAX_RESULT_BYTES = 5 * 1024 * 1024
RULE_KEYS = {'risk', 'per_action_max', 'per_day_max', 'per_day_count_max', 'require_flag'}
POLICY_KEYS = {'policy_id', 'currency', 'rules', 'fail_mode', 'daily_scope'}
POLICY_ID = re.compile(r'[A-Za-z0-9_.:-]{1,64}')

# Top-level stored-run fields shown on the run page that are not part of the
# signed evidence bundle. They are covered by a separate HMAC (derived_mac)
# made with the workspace signing key, with domain separation from bundles.
DERIVED_FIELDS = ('storage_format', 'events', 'results', 'totals', 'summary', 'report', 'verification_at_save')
DERIVED_PURPOSE = 'limitlatch-run-derived/1'
DERIVED_MISMATCH = 'derived_data_mismatch: stored results, totals, summary or report do not match their signature'


class ProcessingLimit(ValueError):
    pass


def clean_policy(data):
    """Reject unsupported fields rather than silently changing a policy digest."""
    if not isinstance(data, dict) or set(data) - POLICY_KEYS:
        raise PolicyError('unsupported policy fields; nothing was saved')
    if data.get('currency') not in CURRENCIES:
        raise PolicyError('unsupported currency')
    if 'policy_id' in data:
        if not isinstance(data['policy_id'], str) or not POLICY_ID.fullmatch(data['policy_id']):
            raise PolicyError('policy_id must be a non-personal identifier of at most 64 characters')
    daily_scope(data)
    rules = data.get('rules')
    modes = data.get('fail_mode')
    if not isinstance(rules, dict) or not isinstance(modes, dict) or set(modes) - {'high', 'low'}:
        raise PolicyError('unsupported policy fields; nothing was saved')
    for rule in rules.values():
        if not isinstance(rule, dict) or set(rule) - RULE_KEYS:
            raise PolicyError('unsupported rule fields; nothing was saved')
        if 'require_flag' in rule and rule['require_flag'] != 'confirmed':
            raise PolicyError('only the confirmed flag is supported')
    return Policy.load(data)


def _key(value):
    return bytes.fromhex(value) if isinstance(value, str) else value


def derived_body(run):
    return {'purpose': DERIVED_PURPOSE, 'data': {name: run[name] for name in DERIVED_FIELDS if name in run}}


def sign_derived(run, signing_key):
    return Signer(_key(signing_key)).sign(derived_body(run))


def check_stored_run(run, signing_key, tsa_key):
    """Verify everything a run page displays.

    The signed bundle gets the full check (signature, policy digest, chain,
    anchors, top-level copies). Displayed derived data (results, totals,
    summary, report) must match derived_mac. A run that carries derived data
    without a valid derived_mac fails; nothing unsigned is shown as passed.
    """
    try:
        result = verify_stored_run(run, signing_key, tsa_key)
        if not result.ok:
            return asdict(result)
        if any(name in run for name in DERIVED_FIELDS):
            if not Signer.verify(derived_body(run), run.get('derived_mac'), _key(signing_key)):
                return {'ok': False, 'reason': DERIVED_MISMATCH, 'first_bad_seq': None}
        return asdict(result)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        return {'ok': False, 'reason': 'invalid stored run or keys', 'first_bad_seq': None}


def execute(operation, payload):
    if operation == 'replay':
        policy, text, outages, keys = payload
        validated = clean_policy(policy)
        # Parse exactly once. replay() enforces the kind/tool pair bound.
        run = replay(validated, parse_log(text), parse_outages(outages), keys)
        # replay() already verified stores, chain and anchors via risk_report
        # and signed the freshly built bundle. That is the save-time status.
        verification = dict(run.report['verification'])
        if not verification.get('ok'):
            raise ValueError('generated evidence failed verification')
        # Do not use asdict(run): that duplicates the entire evidence graph.
        stored = {'storage_format': 'limitlatch-run/1', 'events': run.events,
                  'results': run.results, 'totals': run.totals, 'summary': run.summary,
                  'report': run.report, 'bundle': run.bundle,
                  'verification_at_save': verification}
        stored['derived_mac'] = sign_derived(stored, keys['sign'])
        return stored
    if operation == 'stored':
        # Signature, policy digest, chain, anchors and derived data.
        run, sign, tsa = payload
        return check_stored_run(run, sign, tsa)
    if operation == 'verify':
        text, sign, tsa = payload
        if len(text.encode('utf-8')) > MAX_RESULT_BYTES:
            raise ValueError('bundle exceeds 5 MB; use verify.py')
        try:
            if not re.fullmatch('[0-9a-fA-F]{64}', sign) or not re.fullmatch('[0-9a-fA-F]{64}', tsa):
                raise ValueError
            bundle = json.loads(text)
            checked = verify_bundle(bundle, bytes.fromhex(sign), bytes.fromhex(tsa))
            result = asdict(checked)
            # A failed signature is still a failure. Inspect the chain only to
            # offer a location hint, never to upgrade authenticity to a pass.
            if not checked.ok and isinstance(bundle, dict) and isinstance(bundle.get('entries'), list):
                chain = _verify_entries(bundle['entries'])
                if not chain.ok:
                    result['first_bad_seq'] = chain.first_bad_seq
                    result['reason'] += '; ' + chain.reason
            return result
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            return {'ok': False, 'reason': 'invalid bundle or keys', 'first_bad_seq': None}
    raise ValueError('unknown processing operation')


def silence_stderr():
    """Worker processes must never print tracebacks that may quote input."""
    try:
        descriptor = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(descriptor, 2)
        finally:
            os.close(descriptor)
    except OSError:
        pass
    try:
        sys.stderr = open(os.devnull, 'w')
    except OSError:
        pass


def run_job(data_dir, operation, payload, timeout=None):
    """Alias for app_limits.run_job, the single worker implementation."""
    import app_limits
    return app_limits.run_job(data_dir, operation, payload,
                              timeout=PROCESSING_SECONDS if timeout is None else timeout)
