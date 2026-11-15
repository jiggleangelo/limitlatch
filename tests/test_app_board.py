import http.client
import json
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlparse

import app
from agentguard.replay import parse_log


class BoardFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = app.make_server('127.0.0.1', 0, self.temp.name, public_base_url='')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.origin = f'http://127.0.0.1:{self.port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, values=None, headers=None):
        body = urlencode(values or {}).encode() if method == 'POST' else None
        supplied = {'Host': f'127.0.0.1:{self.port}'}
        if method == 'POST':
            supplied.update({'Origin': self.origin, 'Content-Type': 'application/x-www-form-urlencoded'})
        supplied.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        try:
            connection.request(method, path, body, supplied)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def create(self):
        status, body, headers = self.request('POST', '/start')
        self.assertEqual(303, status, body)
        return urlparse(headers['Location']).path

    @staticmethod
    def log(tool='tool'):
        return 'ts,agent_id,tool,kind,amount_minor\n2026-10-24T12:00:00Z,a0,' + tool + ',read,0'

    def run_log(self, url, text=None):
        status, page, headers = self.request('POST', url + '/replay', {'log_text': text or self.log()})
        self.assertEqual(303, status, page[:2000])
        return urlparse(headers['Location']).path

    def assert_notice(self, page):
        self.assertIn(app.NOTICE.encode(), page)
        self.assertIn(app.HONESTY.encode(), page)
        self.assertIn(b'https://manykiln.com/privacy', page)

    def test_home_offers_labelled_sample_button(self):
        status, page, _ = self.request('GET', '/')
        self.assertEqual(200, status)
        self.assertIn(b'Try with sample data', page)
        self.assertIn(b'made-up data', page)
        self.assert_notice(page)

    def test_sample_workspace_run_bundle_and_export_are_labelled_made_up(self):
        status, _, headers = self.request('POST', '/sample')
        self.assertEqual(303, status)
        url = urlparse(headers['Location']).path
        page = self.request('GET', url)[1]
        self.assertIn(app.SAMPLE_NOTICE.encode(), page)
        self.assertIn(b'SampleRefundBot', page)
        self.assert_notice(page)
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        run_path = next((workspace / 'runs').glob('*.json'))
        saved = json.loads(run_path.read_text())
        # 50,000 / 2,500 = 20 allowed refunds, 20 blocked refunds;
        # the one transfer is blocked by the inclusive outage window.
        self.assertEqual(41, len(saved['results']))
        self.assertEqual(20, saved['summary']['allowed'])
        self.assertEqual(21, saved['summary']['blocked'])
        self.assertEqual(51000, saved['summary']['prevented_minor'])
        run_page = self.request('GET', url + '/run/' + run_path.stem)[1]
        self.assertIn(app.SAMPLE_NOTICE.encode(), run_page)
        self.assertIn(b'Stored evidence verification passed', run_page)
        bundle = json.loads(self.request('GET', url + '/run/' + run_path.stem + '/bundle.json')[1])
        self.assertEqual(app.SAMPLE_POLICY_ID, bundle['policy']['policy_id'])
        exported = json.loads(self.request('GET', url + '/export')[1])
        self.assertIs(True, exported['sample_data'])
        self.assertEqual(app.SAMPLE_NOTICE, exported['data_label'])
        own = json.loads(self.request('GET', self.create() + '/export')[1])
        self.assertIs(False, own['sample_data'])
        self.assertNotIn(app.SAMPLE_NOTICE.encode(), self.request('GET', self.create())[1])

    def test_replay_form_states_contract_row_limit_and_resource_limits(self):
        url = self.create()
        page = self.request('GET', url)[1]
        # The brief specifies a 5,000-row input limit. A fixed 2,000-row
        # storage ceiling cannot be inferred from variable-size evidence.
        self.assertIn(b'up to 5,000 rows', page)
        self.assertIn(b'Processing and storage limits', page)
        self.assertIn(app.esc(app.ROW_NOTICE).encode(), page)
        self.assertIn(app.esc(app.STORAGE_NOTICE).encode(), page)
        self.assertIn(b'Storage used:', page)
        header = 'ts,agent_id,tool,kind,amount_minor\n'
        row = '2026-10-24T00:00:00Z,a,r,read,0'
        # ASCII header: 2 + 8 + 4 + 4 + 12 field bytes, four commas,
        # and one newline = 35 bytes. Row: 20 + 1 + 1 + 4 + 1
        # field bytes and four commas = 31 bytes. Joining 5,000 rows
        # adds 4,999 newlines: 35 + 5,000 * 31 + 4,999 = 160,034.
        self.assertEqual(35, len(header.encode()))
        self.assertEqual(31, len(row.encode()))
        text = header + '\n'.join([row] * 5000)
        self.assertEqual(160034, len(text.encode()))
        self.assertEqual(5000, len(parse_log(text)))
        with self.assertRaisesRegex(ValueError, '5,000 rows'):
            parse_log(text + '\n' + row)

    def test_every_workspace_page_offers_export_delete_and_notice(self):
        url = self.create()
        run_url = self.run_log(url)
        for path in (url, run_url):
            status, page, _ = self.request('GET', path)
            self.assertEqual(200, status)
            self.assertIn(b'Export everything', page)
            self.assertIn(b'Delete this workspace now', page)
            self.assertIn(b'Run deterministic replay' if path == url else b'Operational control report', page)
            self.assert_notice(page)
        for path in ('/verify', '/w/unknown-token'):
            self.assert_notice(self.request('GET', path)[1])
        self.assertEqual(303, self.request('POST', url + '/delete')[0])
        self.assertEqual(404, self.request('GET', run_url)[0])

    def test_destructive_form_hides_per_action_field(self):
        url = self.create()
        page = self.request('GET', url)[1]
        self.assertNotIn(b"name='destructive_per_action_max'", page)
        self.assertIn(b'counts as 1', page)
        values = {'editor': 'form', 'currency': 'USD', 'low_fail_mode': 'open', 'destructive_enabled': '1', 'destructive_risk': 'high', 'destructive_per_action_max': '0', 'destructive_per_day_count_max': '2'}
        self.assertIn(b'Policy saved.', self.request('POST', url + '/policy', values)[1])
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        saved = json.loads((workspace / 'policy.json').read_text())['rules']['destructive']
        self.assertNotIn('per_action_max', saved)
        self.assertEqual(2, saved['per_day_count_max'])
        policy = {'currency': 'USD', 'rules': {'destructive': {'risk': 'high', 'per_action_max': 0}}, 'fail_mode': {'high': 'closed'}}
        page = self.request('POST', url + '/policy', {'policy_json': json.dumps(policy)})[1]
        self.assertIn(b'Policy saved.', page)
        self.assertIn(app.esc(app.DESTRUCTIVE_ZERO_WARNING).encode(), page)

    def test_replace_link_revokes_old_token_and_keeps_runs(self):
        url = self.create()
        run_id = self.run_log(url).rsplit('/', 1)[-1]
        status, _, headers = self.request('POST', url + '/rotate')
        self.assertEqual(303, status)
        new_url = urlparse(headers['Location']).path
        self.assertNotEqual(url, new_url)
        self.assertEqual(404, self.request('GET', url)[0])
        self.assertEqual(404, self.request('GET', url + '/export')[0])
        status, page, _ = self.request('GET', new_url)
        self.assertEqual(200, status)
        self.assertIn(run_id.encode(), page)
        self.assertIn(b'Stored evidence verification passed', self.request('GET', new_url + '/run/' + run_id)[1])
        store = self.server.store
        self.assertEqual(1, store._count)
        self.assertEqual(app.directory_size(store.root), store._total)
        self.assertEqual(app.directory_size(store.root), app.WorkspaceStore(self.temp.name)._total)

    def test_busy_replay_waits_in_short_queue(self):
        url = self.create()
        slots = self.server.expensive_slots
        for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
            self.assertTrue(slots.acquire(timeout=2))
        held = True
        results = []
        try:
            with patch.object(app, 'QUEUE_SECONDS', 8):
                thread = threading.Thread(target=lambda: results.append(self.request('POST', url + '/replay', {'log_text': self.log()})[0]))
                thread.start()
                time.sleep(.4)
                for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
                    slots.release()
                held = False
                thread.join(15)
        finally:
            if held:
                for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
                    slots.release()
        self.assertEqual([303], results)

    def test_busy_replay_keeps_editor_content(self):
        url = self.create()
        slots = self.server.expensive_slots
        for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
            self.assertTrue(slots.acquire(timeout=2))
        try:
            with patch.object(app, 'QUEUE_SECONDS', .2), patch.object(app, 'run_job', side_effect=AssertionError('must not run')):
                status, page, _ = self.request('POST', url + '/replay', {'log_text': self.log('queued_marker')})
        finally:
            for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
                slots.release()
        self.assertEqual(429, status)
        self.assertIn(b'queued_marker', page)
        self.assertIn(app.esc(app.BUSY_MESSAGE).encode(), page)
        self.assert_notice(page)

    def test_processing_limit_keeps_editor_and_names_input_limit(self):
        url = self.create()
        with patch.object(app, 'run_job', side_effect=app.ProcessingLimit('processing resource limit reached')):
            status, page, _ = self.request('POST', url + '/replay', {'log_text': self.log('limit_marker')})
        self.assertEqual(200, status)
        self.assertIn(b'processing resource limit reached', page)
        self.assertIn(b'5,000 rows', page)
        self.assertIn(b'Processing and storage limits', page)
        self.assertIn(b'limit_marker', page)
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        self.assertEqual([], list((workspace / 'runs').iterdir()))


if __name__ == '__main__':
    unittest.main()
