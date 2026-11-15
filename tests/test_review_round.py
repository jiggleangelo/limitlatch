import copy
import json
import os
import pathlib
import tempfile
import time
import unittest

import app_jobs
import app_limits
from agentguard import Policy, PolicyError
from agentguard.core import Signer
from agentguard.replay import ALL_AGENTS, ORDERING_NOTE, parse_log, replay, verify_stored_run

KEYS = {'tenant': b't' * 32, 'sign': b's' * 32, 'tsa': b'a' * 32}


def rows(*items):
    return json.dumps([{'ts': ts, 'agent_id': agent, 'tool': 'tool', 'kind': kind, 'amount_minor': amount, **extra}
                       for ts, agent, kind, amount, extra in items])


def refund_policy(**extra):
    data = {'currency': 'USD', 'rules': {'refund': {'risk': 'high', 'per_day_max': 50000},
                                         'spend': {'risk': 'high', 'per_day_max': 100000}},
            'fail_mode': {'high': 'closed'}}
    data.update(extra)
    return data


class DailyScopeTests(unittest.TestCase):
    # Issue: daily caps were silently per agent.
    LOG = rows(*[('2026-10-24T12:00:0%dZ' % i, 'agent%d' % i, 'refund', 25000, {}) for i in range(3)])

    def test_default_is_per_agent_and_says_so(self):
        run = replay(Policy.load(refund_policy()), parse_log(self.LOG), [], KEYS)
        self.assertEqual(['allowed'] * 3, [r['decision'] for r in run.results])
        self.assertEqual('per_agent', run.summary['daily_scope'])
        self.assertIn('separately to each agent_id', run.report['daily_scope_note'])

    def test_all_agents_scope_shares_one_cap(self):
        run = replay(Policy.load(refund_policy(daily_scope='all_agents')), parse_log(self.LOG), [], KEYS)
        self.assertEqual(['allowed', 'allowed', 'blocked'], [r['decision'] for r in run.results])
        self.assertEqual('daily_limit', run.results[2]['reason'])
        self.assertEqual(50000, run.totals[ALL_AGENTS + '|refund|2026-10-24']['committed'])
        self.assertEqual(50000, run.results[2]['running_committed'])

    def test_scope_is_validated_by_cleaner_and_engine(self):
        self.assertIsInstance(app_jobs.clean_policy(refund_policy(daily_scope='all_agents')), Policy)
        with self.assertRaises(PolicyError):
            app_jobs.clean_policy(refund_policy(daily_scope='global'))
        with self.assertRaises(PolicyError):
            replay(Policy.load(refund_policy(daily_scope='bogus')), [], [], KEYS)


class StoredVerificationTests(unittest.TestCase):
    # Issue: verify_stored_run checked only chain and anchors.
    def setUp(self):
        log = rows(('2026-10-24T12:00:00Z', 'a', 'refund', 100, {}))
        self.bundle = replay(Policy.load(refund_policy()), parse_log(log), [], KEYS).bundle

    def test_genuine_run_passes(self):
        self.assertTrue(verify_stored_run({'bundle': self.bundle}, KEYS['sign'], KEYS['tsa']).ok)
        self.assertTrue(verify_stored_run({'bundle': self.bundle}, KEYS['sign'].hex(), KEYS['tsa'].hex()).ok)

    def test_policy_swapped_and_resigned_run_fails(self):
        forged = copy.deepcopy(self.bundle)
        forged['policy']['rules']['refund']['per_day_max'] = 10 ** 9
        forged['policy_digest'] = Policy.load(forged['policy']).digest()
        body = {k: v for k, v in forged.items() if k != 'signature'}
        forged['signature'] = Signer(b'attacker-key').sign(body)
        result = verify_stored_run({'bundle': forged}, KEYS['sign'], KEYS['tsa'])
        self.assertFalse(result.ok)
        self.assertTrue(result.reason.startswith('bad_signature'))

    def test_tampered_entry_names_first_bad_seq(self):
        changed = copy.deepcopy(self.bundle)
        changed['entries'][0]['tool'] = 'changed'
        result = verify_stored_run({'bundle': changed}, KEYS['sign'], KEYS['tsa'])
        self.assertFalse(result.ok)
        self.assertEqual(0, result.first_bad_seq)

    def test_divergent_top_level_copy_fails(self):
        entries = copy.deepcopy(self.bundle['entries'])
        entries[0]['tool'] = 'other'
        result = verify_stored_run({'bundle': self.bundle, 'entries': entries}, KEYS['sign'], KEYS['tsa'])
        self.assertEqual(('stored_copy_mismatch', 0), (result.reason, result.first_bad_seq))

    def test_app_jobs_stored_operation_checks_signature(self):
        ok = app_jobs.execute('stored', ({'bundle': self.bundle}, KEYS['sign'].hex(), KEYS['tsa'].hex()))
        self.assertTrue(ok['ok'])
        bad = app_jobs.execute('stored', ({'bundle': self.bundle}, ('11' * 32), KEYS['tsa'].hex()))
        self.assertFalse(bad['ok'])


class ReportClarityTests(unittest.TestCase):
    # Issue: overrun rows lost their policy reason.
    def test_overrun_keeps_policy_reason(self):
        log = rows(('2026-10-24T12:00:00Z', 'a', 'spend', 1000, {'actual_minor': 1200}),
                   ('2026-10-24T12:00:01Z', 'a', 'refund', 60000, {}))
        run = replay(Policy.load(refund_policy()), parse_log(log), [], KEYS)
        overrun = next(r for r in run.results if r['kind'] == 'spend')
        self.assertEqual(('overrun', 'policy_allowed', True), (overrun['reason'], overrun['policy_reason'], overrun['overrun']))
        blocked = next(r for r in run.results if r['kind'] == 'refund')
        self.assertEqual(blocked['reason'], blocked['policy_reason'])

    # Issue: equal timestamps were replayed in input order without notice.
    def test_timestamp_ties_are_counted_and_disclosed(self):
        log = rows(*[('2026-10-24T12:00:00Z', 'a', 'refund', 1, {}) for _ in range(3)])
        run = replay(Policy.load(refund_policy()), parse_log(log), [], KEYS)
        self.assertEqual(2, run.summary['timestamp_ties'])
        self.assertEqual(ORDERING_NOTE, run.report['ordering_note'])
        self.assertEqual([1, 2, 3], [r['input_row'] for r in run.results])


class JobCleanupTests(unittest.TestCase):
    # High finding: job copies under DATA_DIR must not accumulate.
    def test_stale_job_directories_are_swept_and_live_ones_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stale, fresh, other = root / '.job-stale', root / '.job-fresh', root / 'w'
            for path in (stale, fresh, other):
                path.mkdir()
                (path / 'result.json').write_text('{}')
            old = time.time() - app_limits.STALE_JOB_SECONDS - 60
            os.utime(stale, (old, old))
            os.utime(other, (old, old))
            self.assertEqual(1, app_limits.sweep_stale_jobs(directory))
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())
            self.assertTrue(other.exists())

    def test_run_job_cleans_its_directory_and_sweeps(self):
        with tempfile.TemporaryDirectory() as directory:
            stale = pathlib.Path(directory) / '.job-left-by-crash'
            stale.mkdir()
            old = time.time() - app_limits.STALE_JOB_SECONDS - 60
            os.utime(stale, (old, old))
            result = app_limits.run_job(directory, 'verify', ('{}', '11' * 32, '22' * 32))
            self.assertFalse(result['ok'])
            self.assertEqual([], list(pathlib.Path(directory).glob('.job-*')))


class DocumentationTests(unittest.TestCase):
    # Issue: HARDENING.md claimed fixed modules were unchanged.
    def test_hardening_open_items_are_current(self):
        text = (pathlib.Path(__file__).resolve().parents[1] / 'HARDENING.md').read_text()
        self.assertNotIn('were not changed in this revision', text)
        self.assertIn('daily_scope', text)


if __name__ == '__main__':
    unittest.main()
