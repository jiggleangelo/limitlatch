"""Regression coverage for the latest external review.

Network tests use deliberately short receipt deadlines. No external services
or real customer records are used.
"""
import datetime as dt
import errno
import http.client
import ipaddress
import json
import pathlib
import re
import socket
import tempfile
import threading
import time
import unittest
from email.message import Message
from unittest.mock import patch
from urllib.parse import urlencode

import app
from agentguard.replay import parse_log


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = app.WorkspaceStore(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_ipv6_groups_and_ipv4_mapped_normalizes(self):
        self.assertEqual(self.store.owner('2001:db8:1:2::1'), self.store.owner('2001:db8:1:2::ffff'))
        self.assertNotEqual(self.store.owner('2001:db8:1:2::1'), self.store.owner('2001:db8:1:3::1'))
        self.assertEqual(self.store.owner('::ffff:192.0.2.1'), self.store.owner('192.0.2.1'))
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 1):
            self.store.create('2001:db8:1:2::1')
            with self.assertRaises(app.SourceLimited):
                self.store.create('2001:db8:1:2::2')
        restarted = app.WorkspaceStore(self.temp.name)
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 1):
            with self.assertRaises(app.SourceLimited):
                restarted.create('2001:db8:1:2::3')

    def test_source_normalizes_all_identity_paths(self):
        handler = object.__new__(app.Handler)
        handler.client_address = ('2001:db8::1', 1)
        handler.headers = Message()
        handler.trusted_proxies = ()
        handler.local_proxy_forwarding = False
        self.assertEqual('2001:db8::/64', handler.source())
        handler.client_address = ('127.0.0.1', 1)
        handler.trusted_proxies = (ipaddress.ip_network('127.0.0.1/32'),)
        handler.headers['X-Real-IP'] = '2001:db8::2'
        self.assertEqual('2001:db8::/64', handler.source())
        handler.headers['X-Real-IP'] = '2001:db8::3'
        with self.assertRaises(ValueError):
            handler.source()
        handler.headers = Message()
        handler.headers['X-Forwarded-For'] = '198.51.100.1, 2001:db8::4'
        handler.trusted_proxies = ()
        handler.local_proxy_forwarding = True
        self.assertEqual('2001:db8::/64', handler.source())

    def test_refused_sources_do_not_allocate_and_empty_owners_are_removed(self):
        with patch.object(app, 'MAX_WORKSPACES', 0):
            for number in range(1000):
                with self.assertRaises(app.WriteRefused):
                    self.store.create('source-' + str(number))
        self.assertEqual({}, self.store._creations)
        self.assertEqual({}, self.store._source_counts)
        self.assertEqual({}, self.store._source_bytes)
        workspace = self.store.require(self.store.create('one'))
        self.store.delete(workspace)
        self.assertEqual({}, self.store._source_counts)
        self.assertEqual({}, self.store._source_bytes)

    def test_histories_have_hard_bound_and_expire_without_quota_eviction(self):
        with patch.object(app, 'MAX_TRACKED_SOURCES', 2), patch.object(app.time, 'monotonic', return_value=100):
            for source in ('one', 'two'):
                self.store.delete(self.store.require(self.store.create(source)))
            with self.assertRaises(app.SourceLimited):
                self.store.create('three')
            self.assertEqual(2, len(self.store._creations))
        with patch.object(app.time, 'monotonic', return_value=100 + app.SOURCE_WINDOW):
            self.store.sweep()
            self.assertEqual({}, self.store._creations)
            self.store.create('three')
        self.assertEqual(1, len(self.store._creations))

    def test_failed_creation_leaves_no_admission_keys(self):
        with patch.object(self.store, '_atomic_raw', side_effect=OSError(errno.ENOSPC, 'private path')):
            with self.assertRaises(OSError):
                self.store.create('one')
        self.assertEqual({}, self.store._creations)
        self.assertEqual({}, self.store._source_counts)
        self.assertEqual({}, self.store._source_bytes)
        self.assertEqual([], list(self.store.workspaces.iterdir()))

    def test_rotation_missing_accounting_fails_before_rename(self):
        token = self.store.create('one')
        workspace = self.store.require(token)
        self.store._sizes.pop(workspace.name)
        with self.assertRaises(app.WriteRefused):
            self.store.rotate(workspace)
        self.assertEqual(workspace, self.store.require(token))
        self.assertEqual([workspace], list(self.store.workspaces.iterdir()))

    def test_activity_coalesces_without_atomic_write_or_global_guard(self):
        workspace = self.store.require(self.store.create('one'))
        meta_path = workspace / 'meta.json'
        meta = self.store.load_json(meta_path)
        meta['last_used'] = (app.utc_now() - dt.timedelta(days=91)).isoformat()
        self.store.atomic(meta_path, meta)
        before = meta_path.read_bytes()
        errors = []
        real_utime = app.os.utime
        def touch():
            try:
                self.store.touch(workspace)
            except Exception as error:
                errors.append(error)
        with patch.object(self.store, 'atomic', side_effect=AssertionError('read wrote JSON')), patch.object(app, 'fsync_directory', side_effect=AssertionError('read fsynced')), patch.object(app.os, 'utime', wraps=real_utime) as utime:
            with self.store._guard:
                thread = threading.Thread(target=touch, daemon=True)
                thread.start()
                thread.join(1)
                finished_without_guard = not thread.is_alive()
            thread.join(2)
            for _ in range(10):
                self.store.touch(workspace)
            self.assertTrue(finished_without_guard)
            self.assertEqual(1, utime.call_count)
        self.assertEqual([], errors)
        self.assertEqual(before, meta_path.read_bytes())
        restarted = app.WorkspaceStore(self.temp.name)
        restarted.sweep()
        self.assertTrue(workspace.exists())


class HttpReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = app.make_server('127.0.0.1', 0, self.temp.name, public_base_url='')
        self.port = self.server.server_address[1]
        self.origin = f'http://127.0.0.1:{self.port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, values=None, headers=None):
        supplied = {'Host': f'127.0.0.1:{self.port}'}
        body = None
        if method == 'POST':
            body = urlencode(values or {}).encode()
            supplied.update({'Origin': self.origin, 'Content-Type': 'application/x-www-form-urlencoded'})
        supplied.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            connection.request(method, path, body, supplied)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def create(self):
        status, _, headers = self.request('POST', '/start')
        self.assertEqual(303, status)
        return headers['Location']

    def test_drip_headers_hit_absolute_deadline_and_release_slot(self):
        self.server.header_deadline = .15
        client = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        try:
            client.sendall(b'GET / HTTP/1.1\r\nX-Test: ')
            for _ in range(12):
                time.sleep(.025)
                try:
                    client.sendall(b'x')
                except OSError:
                    break
            self.assertEqual(b'', client.recv(1))
        finally:
            client.close()
        acquired = 0
        try:
            for _ in range(app.MAX_CONNECTIONS):
                self.assertTrue(self.server._connections.acquire(timeout=1))
                acquired += 1
        finally:
            for _ in range(acquired):
                self.server._connections.release()
        self.assertEqual(200, self.request('GET', '/healthz')[0])

    def test_keep_alive_get_after_post_gets_fresh_header_timeout(self):
        self.server.header_deadline = .8
        self.server.upload_deadline = .04
        client = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        try:
            client.sendall((f'POST /start HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nOrigin: {self.origin}\r\nContent-Length: 3\r\n\r\nx=1').encode())
            response = http.client.HTTPResponse(client)
            response.begin()
            response.read()
            self.assertEqual(303, response.status)
            time.sleep(.15)
            client.sendall((f'GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n\r\n').encode())
            response = http.client.HTTPResponse(client)
            response.begin()
            self.assertEqual(200, response.status)
            self.assertEqual(b'ok', response.read())
        finally:
            client.close()

    def test_disk_failures_return_noticed_pages_without_private_exception(self):
        url = self.create()
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        before = (workspace / 'policy.json').read_bytes()
        for failure in (OSError(errno.ENOSPC, 'secret-filesystem-path'), FileNotFoundError('secret-filesystem-path')):
            with patch.object(self.server.store, '_atomic_raw', side_effect=failure):
                status, page, _ = self.request('POST', url + '/policy', {'policy_json': json.dumps(app.POLICY_DATA)})
            self.assertEqual(507, status)
            self.assertIn(app.NOTICE.encode(), page)
            self.assertIn(app.HONESTY.encode(), page)
            self.assertNotIn(b'secret-filesystem-path', page)
            self.assertEqual(before, (workspace / 'policy.json').read_bytes())
        with patch.object(self.server.store, 'rotate', side_effect=KeyError('secret-filesystem-path')):
            status, page, _ = self.request('POST', url + '/rotate')
        self.assertEqual(500, status)
        self.assertNotIn(b'secret-filesystem-path', page)
        self.assertIn(app.NOTICE.encode(), page)

    def test_replay_errors_and_busy_preserve_outage_editor_without_storage(self):
        url = self.create()
        values = {'log_text': 'rejected-log-marker', 'outages': '[{"start":"<unsafe-outage-marker>"}]'}
        for failure in (ValueError('invalid CSV'), OSError(errno.ENOSPC, 'private path')):
            with patch.object(app.Handler, '_save_run', side_effect=failure):
                status, page, _ = self.request('POST', url + '/replay', values)
            self.assertEqual(507 if isinstance(failure, OSError) else 200, status)
            self.assertIn(app.esc(values['outages']).encode(), page)
            self.assertIn(b'rejected-log-marker', page)
            self.assertNotIn(b'<unsafe-outage-marker>', page)
        for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
            self.server.expensive_slots.acquire()
        try:
            with patch.object(app, 'QUEUE_SECONDS', .01):
                status, page, _ = self.request('POST', url + '/replay', values)
        finally:
            for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
                self.server.expensive_slots.release()
        self.assertEqual(429, status)
        self.assertIn(app.esc(values['outages']).encode(), page)
        for path in pathlib.Path(self.temp.name).rglob('*'):
            if path.is_file():
                self.assertNotIn(b'unsafe-outage-marker', path.read_bytes())
                self.assertNotIn(b'rejected-log-marker', path.read_bytes())

    def test_browser_policy_save_redirects_and_validation_uses_fetch(self):
        url = self.create()
        status, _, headers = self.request('POST', url + '/policy', {'policy_json': json.dumps(app.POLICY_DATA)}, {'Accept': 'text/html'})
        self.assertEqual(303, status)
        self.assertEqual(url + '?saved=1', headers['Location'])
        status, page, headers = self.request('GET', headers['Location'])
        self.assertEqual(200, status)
        self.assertIn(b'Policy saved.', page)
        self.assertEqual(3, page.count(b'<form class=editor'))
        self.assertIn(app.EDITOR_SCRIPT.encode(), page)
        self.assertIn(b'e.preventDefault()', page)
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
        # The enhancement does not serialize editor data into browser URLs.
        self.assertNotIn('history.pushState', app.EDITOR_SCRIPT)
        self.assertNotIn('localStorage', app.EDITOR_SCRIPT)

    def test_risk_options_unique_and_low_fail_mode_round_trips(self):
        url = self.create()
        policy = json.loads(json.dumps(app.POLICY_DATA))
        policy['fail_mode']['low'] = 'closed'
        self.request('POST', url + '/policy', {'policy_json': json.dumps(policy)})
        page = self.request('GET', url)[1].decode()
        for kind in app.KINDS:
            options = re.search("<select name='" + kind + "_risk'>(.*?)</select>", page).group(1)
            self.assertEqual(2, options.count('<option '))
            self.assertEqual(1, options.count(' selected'))
            self.assertEqual(1, options.count("value='high'"))
            self.assertEqual(1, options.count("value='low'"))
        modes = re.search('<select name=low_fail_mode>(.*?)</select>', page).group(1)
        self.assertIn("value='closed' selected", modes)
        values = {'editor': 'form', 'currency': 'USD', 'read_enabled': '1', 'read_risk': 'low', 'low_fail_mode': 'closed'}
        self.request('POST', url + '/policy', values)
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        self.assertEqual('closed', self.server.store.load_json(workspace / 'policy.json')['fail_mode']['low'])

    def test_ui_discloses_actual_storage_and_conversion_contract(self):
        page = self.request('GET', self.create())[1]
        self.assertIn(b'about 2,000 rows', page)
        self.assertIn(b'parser accepts up to 5,000 rows', page)
        self.assertIn(b'shared 5 MiB', page)
        self.assertIn(b'25.00 dollars to 2500 cents', page)
        self.assertIn(b'Decimal amounts are rejected', page)
        with self.assertRaisesRegex(ValueError, 'non-negative integer'):
            parse_log('ts,agent_id,tool,kind,amount_minor\n2026-10-24T00:00:00Z,a,t,refund,25.00')
        event = parse_log('ts,agent_id,tool,kind,amount_minor\n1729771200,a,t, Refund ,2500')[0]
        self.assertEqual(('refund', 2500), (event.kind, event.amount_minor))


if __name__ == '__main__':
    unittest.main()
