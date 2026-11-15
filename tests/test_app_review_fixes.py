import http.client
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlparse

import app


class Base(unittest.TestCase):
    host = None
    origin = None

    def start(self, **kwargs):
        self.temp = tempfile.TemporaryDirectory()
        self.server = app.make_server('127.0.0.1', 0, self.temp.name, **kwargs)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, values=None, headers=None, origin=True):
        body = urlencode(values or {}).encode() if method == 'POST' else None
        supplied = {'Host': self.host or f'127.0.0.1:{self.port}'}
        if method == 'POST':
            supplied['Content-Type'] = 'application/x-www-form-urlencoded'
            if origin:
                supplied['Origin'] = self.origin or f'http://127.0.0.1:{self.port}'
        supplied.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        try:
            connection.request(method, path, body, supplied)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def create(self, headers=None):
        status, body, result = self.request('POST', '/start', headers=headers)
        self.assertEqual(303, status, body[:500])
        return urlparse(result['Location']).path

    @staticmethod
    def log(currency=''):
        return 'ts,agent_id,tool,kind,amount_minor,currency\n2026-10-24T12:00:00Z,a0,tool,read,0,' + currency


class LocalFixTests(Base):
    def setUp(self):
        self.start(public_base_url='')

    # High finding: browser POSTs must not be rejected.
    def test_referrer_policy_allows_browser_origin_and_null_origin_fallback(self):
        headers = self.request('GET', '/')[2]
        self.assertEqual('same-origin', headers['Referrer-Policy'])
        self.assertEqual(303, self.request('POST', '/start', headers={'Origin': 'null', 'Sec-Fetch-Site': 'same-origin'}, origin=False)[0])
        self.assertEqual(303, self.request('POST', '/start', headers={'Sec-Fetch-Site': 'same-origin'}, origin=False)[0])
        self.assertEqual(403, self.request('POST', '/start', headers={'Origin': 'null'}, origin=False)[0])
        self.assertEqual(403, self.request('POST', '/start', headers={'Origin': 'null', 'Sec-Fetch-Site': 'cross-site'}, origin=False)[0])
        self.assertEqual(403, self.request('POST', '/start', headers={'Sec-Fetch-Site': 'same-site'}, origin=False)[0])

    def test_forwarded_for_ignored_without_https_proxy(self):
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 1):
            self.create({'X-Forwarded-For': '198.51.100.1'})
            self.assertEqual(429, self.request('POST', '/start', headers={'X-Forwarded-For': '198.51.100.2'})[0])

    # Issue: mixed currencies must not be summed.
    def test_currency_mismatch_rejected_and_nothing_saved(self):
        url = self.create()
        status, page, _ = self.request('POST', url + '/replay', {'log_text': self.log('EUR')})
        self.assertEqual(200, status)
        self.assertIn(b'currency does not match the policy currency (USD)', page)
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        self.assertEqual([], list((workspace / 'runs').iterdir()))
        self.assertEqual(303, self.request('POST', url + '/replay', {'log_text': self.log('USD')})[0])
        self.assertEqual(303, self.request('POST', url + '/replay', {'log_text': self.log('')})[0])
        jsonl = json.dumps({'ts': '2026-10-24T12:00:00Z', 'agent_id': 'a', 'tool': 't', 'kind': 'read', 'amount_minor': 0, 'currency': 'JPY'})
        with self.assertRaisesRegex(ValueError, 'row 1: currency'):
            app.check_currency(jsonl, 'USD')

    # Issue: slow uplinks need a size-scaled (still absolute) deadline.
    def test_upload_deadline_scales_with_declared_length(self):
        self.assertGreaterEqual(app.upload_deadline_for(5.0, app.MAX_BODY_BYTES), 30)
        self.assertLess(app.upload_deadline_for(5.0, 100), 5.1)
        url = self.create()
        body = urlencode({'log_text': self.log()}).encode()
        self.server.upload_deadline = .05
        with patch.object(app, 'MIN_UPLOAD_BYTES_PER_SECOND', len(body) / .6):
            client = socket.create_connection(('127.0.0.1', self.port), timeout=10)
            try:
                client.sendall((f'POST {url}/replay HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nOrigin: http://127.0.0.1:{self.port}\r\nContent-Length: {len(body)}\r\n\r\n').encode())
                client.sendall(body[:1])
                time.sleep(.2)
                client.sendall(body[1:])
                response = http.client.HTTPResponse(client)
                response.begin()
                response.read()
                self.assertEqual(303, response.status)
            finally:
                client.close()

    # Issue: result viewing should queue briefly instead of failing at once.
    def test_run_view_waits_for_read_slot(self):
        url = self.create()
        status, _, headers = self.request('POST', url + '/replay', {'log_text': self.log()})
        self.assertEqual(303, status)
        run_url = urlparse(headers['Location']).path
        slots = self.server.read_slots
        for _ in range(2):
            self.assertTrue(slots.acquire(timeout=2))
        releaser = threading.Timer(.4, lambda: [slots.release() for _ in range(2)])
        releaser.start()
        try:
            self.assertEqual(200, self.request('GET', run_url)[0])
        finally:
            releaser.join()

    # Issue: a leaked link must be able to rotate the forge-capable keys too.
    def test_replace_link_and_keys(self):
        url = self.create()
        self.assertEqual(303, self.request('POST', url + '/replay', {'log_text': self.log()})[0])
        store = self.server.store
        before = store.load_json(store.require(url.rsplit('/', 1)[-1]) / 'keys.json')
        status, _, headers = self.request('POST', url + '/rotate', {'replace_keys': '1', 'confirm': '1'})
        self.assertEqual(303, status)
        new_url = urlparse(headers['Location']).path
        self.assertEqual(404, self.request('GET', url)[0])
        workspace = store.require(new_url.rsplit('/', 1)[-1])
        after = store.load_json(workspace / 'keys.json')
        self.assertNotEqual(before['sign'], after['sign'])
        self.assertNotEqual(before['tsa'], after['tsa'])
        self.assertEqual([], list((workspace / 'runs').glob('*.json')))
        self.assertEqual(app.directory_size(store.root), store._total)
        self.assertEqual(303, self.request('POST', new_url + '/replay', {'log_text': self.log()})[0])

    # Issue: destructive actions need a confirmation step.
    def test_delete_controls_require_confirmation(self):
        url = self.create()
        status, _, headers = self.request('POST', url + '/replay', {'log_text': self.log()})
        run_url = urlparse(headers['Location']).path
        for path in (url, run_url):
            _, page, headers = self.request('GET', path)
            self.assertIn(b'class=confirm', page)
            self.assertIn(b'name=confirm value=1 required', page)
            self.assertIn(app.esc(app.DELETE_WORKSPACE_CONFIRM).encode(), page)
            self.assertIn(app.esc(app.DELETE_RUN_CONFIRM).encode(), page)
            self.assertIn(app.CONFIRM_SCRIPT.encode(), page)


class ProxyFixTests(Base):
    host = 'public.example'
    origin = 'https://public.example'

    def setUp(self):
        env = {key: value for key, value in os.environ.items() if key != 'APP_TRUSTED_PROXIES'}
        with patch.dict(os.environ, env, clear=True):
            self.start(public_base_url='https://public.example', https_terminated=True)

    # Issue: behind the HTTPS proxy, visitors must not share one quota.
    def test_https_proxy_separates_visitors_by_forwarded_for(self):
        self.assertTrue(self.server.RequestHandlerClass.local_proxy_forwarding)
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 1):
            self.create({'X-Forwarded-For': '198.51.100.1'})
            self.create({'X-Forwarded-For': '198.51.100.2'})
            # Client-prepended spoofed entries are ignored; the rightmost wins.
            self.assertEqual(429, self.request('POST', '/start', headers={'X-Forwarded-For': '203.0.113.9, 198.51.100.1'})[0])
            self.create()
            self.assertEqual(429, self.request('POST', '/start', headers={'X-Forwarded-For': 'not-an-ip'})[0])


if __name__ == '__main__':
    unittest.main()
