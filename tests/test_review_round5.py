import copy
import http.client
import json
import tempfile
import threading
import unittest
from urllib.parse import urlencode, urlparse

import app


class ReviewRoundFiveTests(unittest.TestCase):
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
        status, _, headers = self.request('POST', '/start')
        self.assertEqual(303, status)
        return urlparse(headers['Location']).path

    def run_log(self, workspace):
        log = 'ts,agent_id,tool,kind,amount_minor\n2026-10-24T00:00:00Z,a,read,read,0'
        status, _, headers = self.request('POST', workspace + '/replay', {'log_text': log})
        self.assertEqual(303, status)
        return urlparse(headers['Location']).path

    def test_bundle_download_refuses_corrupt_stored_bundle(self):
        workspace = self.create()
        run_url = self.run_log(workspace)
        token = workspace.rsplit('/', 1)[-1]
        root = self.server.store.require(token)
        run_id = run_url.rsplit('/', 1)[-1]
        path = root / 'runs' / (run_id + '.json')
        damaged = json.loads(path.read_text())
        damaged['bundle']['entries'][0]['tool'] = 'changed'
        self.server.store.atomic(path, damaged)
        status, page, _ = self.request('GET', run_url + '/bundle.json')
        self.assertEqual(409, status)
        self.assertIn(b'verification failed', page.lower())
        self.assertIn(b'first bad sequence number: 0', page)

    def test_private_forwarding_is_fail_closed_but_loopback_https_proxy_is_supported(self):
        self.assertFalse(self.server.RequestHandlerClass.local_proxy_forwarding)
        self.assertEqual(303, self.request('POST', '/start', headers={'X-Forwarded-For': '198.51.100.9'})[0])
        workspace = self.server.store.require(next(iter(self.server.store.workspaces.iterdir())).name)
        self.assertIsNone(workspace)

    def test_policy_form_exposes_daily_scope(self):
        workspace = self.create()
        page = self.request('GET', workspace)[1]
        self.assertIn(b'name=daily_scope', page)
        self.assertIn(b'value=all_agents', page)

    def test_every_html_error_keeps_required_notices(self):
        status, page, _ = self.request('GET', '/missing')
        self.assertEqual(404, status)
        self.assertIn(app.NOTICE.encode(), page)
        self.assertIn(app.HONESTY.encode(), page)


if __name__ == '__main__':
    unittest.main()
