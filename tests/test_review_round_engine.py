"""Regression tests for the engine/worker issues from the external review."""
import csv
import json
import pathlib
import secrets
import tempfile
import unittest
from unittest.mock import patch

import agentguard.replay as replay_module
import app
import app_jobs
import app_limits
from agentguard import Policy, PolicyError
from agentguard.replay import parse_log, replay

LOG = 'ts,agent_id,tool,kind,amount_minor\n2026-10-24T12:00:00Z,a0,tool,read,0'


def keys():
    return {name: secrets.token_hex(32) for name in ('tenant', 'sign', 'tsa')}


class EngineReviewTests(unittest.TestCase):
    # Issue: numeric score next to the report heading reads as a rating.
    def test_replay_report_has_no_numeric_score(self):
        run = replay(Policy.load(app.POLICY_DATA), parse_log(LOG), [], keys())
        self.assertNotIn('score', run.report)
        self.assertEqual('Operational control report', run.report['title'])
        self.assertIn('Not an insurance rating', run.report['disclaimer'])
        self.assertTrue(run.report['verification']['ok'])

    def test_stored_view_drops_legacy_score(self):
        supplied = keys()
        saved = app_limits._execute('replay', (app.POLICY_DATA, LOG, [], supplied))
        self.assertNotIn('score', saved['report'])
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'run.json'
            # The genuine, unmodified run views as passed and carries no score.
            path.write_text(json.dumps(saved), encoding='utf-8')
            genuine = app_limits._execute('stored', (str(path), supplied, {}))
            self.assertNotIn('score', genuine['report'])
            self.assertTrue(genuine['verification']['ok'])
            # A score key in the report (as written by earlier versions) must
            # never be displayed. The report is covered by derived_mac, so a
            # report that differs from what was signed at save time cannot be
            # shown as passed (see HARDENING.md, "Displayed derived data", and
            # test_stored_view_detects_tampered_displayed_data).
            saved['report']['score'] = 80
            path.write_text(json.dumps(saved), encoding='utf-8')
            view = app_limits._execute('stored', (str(path), supplied, {}))
        self.assertNotIn('score', view['report'])
        self.assertFalse(view['verification']['ok'])
        self.assertTrue(view['verification']['reason'].startswith('derived_data_mismatch'))

    # Issue: divergent app_jobs defaults patched at runtime by app_limits.
    def test_worker_limits_have_one_source(self):
        self.assertEqual(5, app_jobs.CPU_SECONDS)
        self.assertEqual(app_jobs.CPU_SECONDS, app_limits.CPU_SECONDS)
        self.assertEqual(app_jobs.PROCESSING_SECONDS, app_limits.PROCESSING_SECONDS)
        self.assertLessEqual(app_jobs.PROCESSING_SECONDS, 6)
        self.assertEqual(5 * 1024 * 1024, app_jobs.MAX_RESULT_BYTES)
        self.assertEqual(app_jobs.MAX_RESULT_BYTES, app_limits.MAX_RESULT_BYTES)
        self.assertIs(app_jobs.clean_policy, app_limits.clean_policy)
        self.assertEqual(5, replay_module.CPU_SECONDS)
        self.assertEqual(50, replay_module.MAX_TOOL_PAIRS)
        with self.assertRaises(app_jobs.ProcessingLimit):
            app_jobs.run_job(tempfile.gettempdir(), 'verify', (), timeout=0)

    def test_app_jobs_execute_is_strict_and_preserves_policy_id(self):
        loose = json.loads(json.dumps(app.POLICY_DATA))
        loose['extra'] = 'x'
        with self.assertRaises(PolicyError):
            app_jobs.execute('replay', (loose, LOG, [], keys()))
        policy = json.loads(json.dumps(app.POLICY_DATA))
        policy['policy_id'] = 'prod-v9'
        result = app_jobs.execute('replay', (policy, LOG, [], keys()))
        self.assertEqual(policy, result['bundle']['policy'])

    def test_engine_enforces_pair_limit_without_patching(self):
        rows = [{'ts': '2026-10-24T00:00:00Z', 'agent_id': 'a', 'tool': f't{i}', 'kind': 'read', 'amount_minor': 0} for i in range(51)]
        policy = Policy.load(app.POLICY_DATA)
        replay(policy, parse_log(json.dumps(rows[:50])), [], keys())
        with self.assertRaisesRegex(ValueError, '50 distinct kind/tool pairs'):
            replay(policy, parse_log(json.dumps(rows)), [], keys())

    # Issue: duplicate parse and duplicate post-replay verification.
    def test_replay_job_parses_once_and_does_not_reverify(self):
        calls = []
        real = replay_module.parse_log

        def counted(text):
            calls.append(1)
            return real(text)
        with patch.object(app_jobs, 'parse_log', counted), patch.object(replay_module, 'parse_log', counted), \
                patch.object(app_jobs, 'verify_bundle', side_effect=AssertionError('re-verified')):
            result = app_limits._execute('replay', (app.POLICY_DATA, LOG, [], keys()))
        self.assertEqual(1, len(calls))
        self.assertTrue(result['verification_at_save']['ok'])

    # Issue: csv.field_size_limit changed process-globally.
    def test_csv_field_limit_is_restored(self):
        before = csv.field_size_limit()
        parse_log(LOG)
        wide = 'ts,agent_id,tool,kind,amount_minor,discard\n2026-10-24T12:00:00Z,a0,tool,read,0,' + 'x' * 200000
        self.assertEqual(1, len(parse_log(wide)))
        self.assertEqual(before, csv.field_size_limit())

    # Issue: worker stderr on result-write failure.
    def test_worker_output_failure_is_silent(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(app_limits._write_output(directory, b'{}'))
            target = pathlib.Path(directory) / 'ok.json'
            self.assertTrue(app_limits._write_output(str(target), b'{}'))
            self.assertEqual(b'{}', target.read_bytes())


if __name__ == '__main__':
    unittest.main()
