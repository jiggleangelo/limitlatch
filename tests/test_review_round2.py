import copy
import datetime as dt
import json
import pathlib
import secrets
import tempfile
import unittest
from unittest.mock import patch

import app_jobs
import app_limits
from agentguard import Policy, verify_bundle
from agentguard.replay import TIME_BASIS_NOTE, parse_log, parse_timestamp, replay

POLICY = {'currency': 'USD',
          'rules': {'refund': {'risk': 'high', 'per_action_max': 5000, 'per_day_max': 10000},
                    'spend': {'risk': 'high', 'per_action_max': 1000, 'per_day_max': 100000}},
          'fail_mode': {'high': 'closed', 'low': 'open'}}
BYTE_KEYS = {'tenant': b't' * 32, 'sign': b's' * 32, 'tsa': b'a' * 32}


def hex_keys():
    return {'tenant': secrets.token_hex(32), 'sign': secrets.token_hex(32), 'tsa': secrets.token_hex(32)}


def spend_events():
    rows = []
    for index, actual in enumerate([150, None, 300]):
        row = {'ts': f'2020-01-01T00:00:0{index}Z', 'agent_id': 'a', 'tool': 'pay', 'kind': 'spend', 'amount_minor': 100}
        if actual is not None:
            row['actual_minor'] = actual
        rows.append(row)
    return parse_log('\n'.join(json.dumps(row) for row in rows))


class ConnectorActualTests(unittest.TestCase):
    # Issue: replay mutated cached closures' __defaults__.
    def test_reused_tool_reconciles_each_rows_own_actual(self):
        run = replay(Policy.load(POLICY), spend_events(), [], BYTE_KEYS)
        self.assertEqual([True, False, True], [row['overrun'] for row in run.results])
        self.assertEqual(550, run.totals['a|spend|2020-01-01']['committed'])
        self.assertEqual([150, 250, 550], [row['running_committed'] for row in run.results])
        for entry in run.bundle['entries']:
            if entry['phase'] == 'decision':
                self.assertEqual({'amount', 'confirmed'}, set(entry['args']))


class TimeBasisTests(unittest.TestCase):
    # Issue: exported_at and anchor times read as contemporaneous.
    def test_bundle_has_wall_clock_export_time_and_labelled_replay_times(self):
        run = replay(Policy.load(POLICY), spend_events(), [], BYTE_KEYS)
        bundle = run.bundle
        exported = parse_timestamp(bundle['exported_at'])
        self.assertLess(abs(dt.datetime.now(dt.timezone.utc) - exported), dt.timedelta(minutes=1))
        self.assertEqual('2020-01-01T00:00:02Z', bundle['replay_clock_end'])
        self.assertEqual(TIME_BASIS_NOTE, bundle['time_basis'])
        self.assertEqual(TIME_BASIS_NOTE, run.report['time_basis'])
        self.assertEqual(bundle['exported_at'], run.report['generated_at'])
        self.assertTrue(all(anchor['time'].startswith('2020-01-01') for anchor in bundle['anchors']))
        self.assertTrue(verify_bundle(bundle, BYTE_KEYS['sign'], BYTE_KEYS['tsa']).ok)
        changed = copy.deepcopy(bundle)
        changed['time_basis'] = 'contemporaneous'
        self.assertFalse(verify_bundle(changed, BYTE_KEYS['sign'], BYTE_KEYS['tsa']).ok)


class StoredRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.keys = hex_keys()
        log = 'ts,agent_id,tool,kind,amount_minor\n2020-01-01T00:00:00Z,a,r,refund,6000\n2020-01-01T00:00:01Z,a,r,refund,100'
        self.run = app_jobs.execute('replay', (POLICY, log, [], self.keys))
        self.path = pathlib.Path(self.temp.name) / 'run.json'

    def tearDown(self):
        self.temp.cleanup()

    def view(self, run):
        self.path.write_text(json.dumps(run), encoding='utf-8')
        return app_limits._execute('stored', (str(self.path), self.keys, {}))['verification']

    # Issue: stored view verified only the bundle; displayed data was unsigned.
    def test_stored_view_detects_tampered_displayed_data(self):
        self.assertTrue(self.view(self.run)['ok'])
        for mutate in (lambda run: run['summary'].update(blocked=0),
                       lambda run: run['results'][0].update(decision='allowed'),
                       lambda run: run['totals'].clear(),
                       lambda run: run['report'].update(daily_scope_note='x'),
                       lambda run: run.pop('derived_mac')):
            damaged = copy.deepcopy(self.run)
            mutate(damaged)
            result = self.view(damaged)
            self.assertFalse(result['ok'])
            self.assertTrue(result['reason'].startswith('derived_data_mismatch'))

    def test_stored_view_uses_full_stored_run_check(self):
        damaged = copy.deepcopy(self.run)
        damaged['entries'] = []
        self.assertEqual('stored_copy_mismatch', self.view(damaged)['reason'])
        tampered = copy.deepcopy(self.run)
        tampered['bundle']['entries'][0]['tool'] = 'changed'
        result = self.view(tampered)
        self.assertFalse(result['ok'])
        self.assertEqual(0, result['first_bad_seq'])
        other = hex_keys()
        self.assertFalse(app_jobs.execute('stored', (self.run, other['sign'], other['tsa']))['ok'])
        self.assertTrue(app_jobs.execute('stored', (self.run, self.keys['sign'], self.keys['tsa']))['ok'])


class SingleWorkerTests(unittest.TestCase):
    # Issue: two divergent worker implementations.
    def test_app_jobs_run_job_delegates_to_app_limits(self):
        self.assertFalse(hasattr(app_jobs, '_worker'))
        with patch.object(app_limits, 'run_job', return_value='delegated') as worker:
            self.assertEqual('delegated', app_jobs.run_job('dir', 'verify', (), timeout=1))
            self.assertEqual('delegated', app_jobs.run_job('dir', 'verify', ()))
        worker.assert_any_call('dir', 'verify', (), timeout=1)
        worker.assert_any_call('dir', 'verify', (), timeout=app_jobs.PROCESSING_SECONDS)
        self.assertIs(app_jobs.ProcessingLimit, app_limits.ProcessingLimit)


class OperatorDocumentationTests(unittest.TestCase):
    # Issues: URL tokens in access logs; proxy trust depends on a firewall.
    def test_hardening_documents_token_logging_and_proxy_trust(self):
        text = (pathlib.Path(__file__).resolve().parents[1] / 'HARDENING.md').read_text(encoding='utf-8')
        self.assertIn('access logs', text)
        self.assertIn('Set APP_TRUSTED_PROXIES', text)
        self.assertIn('derived_mac', text)
        self.assertIn('replay_clock_end', text)


if __name__ == '__main__':
    unittest.main()
