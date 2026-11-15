import copy
import datetime as dt
import http.client
import ipaddress
import json
import os
import re
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

import app
import app_limits


class HardeningTests(unittest.TestCase):
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
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            connection.request(method, path, body, supplied)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def create(self, headers=None):
        status, body, result = self.request('POST', '/start', headers=headers)
        self.assertEqual(303, status, body)
        return result['Location']

    @staticmethod
    def log(count=1):
        return 'ts,agent_id,tool,kind,amount_minor\n' + '\n'.join(f'2026-10-24T00:00:00Z,a{i},read,read,0' for i in range(count))

    def test_all_post_bodies_reject_above_one_mb_before_worker(self):
        self.assertEqual(1048576, app.MAX_VERIFY_BODY_BYTES)
        self.assertEqual(app.MAX_BODY_BYTES, app.MAX_REPLAY_BODY_BYTES)
        url = self.create()
        for path in ('/verify', '/start', '/sample', url + '/replay'):
            with patch.object(app, 'run_job', side_effect=AssertionError('must not process')) as worker:
                status, page, _ = self.request('POST', path, headers={'Content-Length': str(1048577)})
                worker.assert_not_called()
            self.assertEqual(413, status)
            self.assertIn(app.NOTICE.encode(), page)
            self.assertIn(app.HONESTY.encode(), page)

    def test_busy_releases_slots_and_has_notice(self):
        acquired = 0
        try:
            for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
                self.assertTrue(self.server.expensive_slots.acquire(timeout=2))
                acquired += 1
            with patch.object(app, 'run_job', side_effect=AssertionError('must not process')):
                status, page, _ = self.request('POST', '/verify')
            self.assertEqual(429, status)
            self.assertIn(app.NOTICE.encode(), page)
            self.assertIn(app.HONESTY.encode(), page)
        finally:
            for _ in range(acquired):
                self.server.expensive_slots.release()

    def test_source_limit_cannot_be_bypassed_by_forwarded_headers(self):
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 2):
            self.create()
            self.create({'X-Real-IP': '198.51.100.2'})
            self.assertEqual(429, self.request('POST', '/start', headers={'X-Real-IP': '198.51.100.3'})[0])
            self.assertEqual(429, self.request('POST', '/sample')[0])
        self.assertEqual(2, self.server.store._count)
        restarted = app.WorkspaceStore(self.temp.name)
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 2):
            with self.assertRaises(app.SourceLimited):
                restarted.create('127.0.0.1')
            self.assertIsNotNone(restarted.create('198.51.100.4'))

    def test_trusted_proxy_separates_sources_and_rejects_missing_identity(self):
        self.server.RequestHandlerClass.trusted_proxies = (ipaddress.ip_network('127.0.0.1/32'),)
        with patch.object(app, 'MAX_SOURCE_WORKSPACES', 1):
            self.create({'X-Real-IP': '198.51.100.1'})
            self.create({'X-Real-IP': '198.51.100.2'})
            self.assertEqual(429, self.request('POST', '/start', headers={'X-Real-IP': '198.51.100.1'})[0])
            self.assertEqual(400, self.request('POST', '/start')[0])
            self.assertEqual(400, self.request('POST', '/start', headers={'X-Real-IP': 'a,b'})[0])

    def test_workspace_and_source_storage_limits_are_atomic(self):
        store = self.server.store
        first = store.require(store.create('one'))
        second = store.require(store.create('one'))
        self.assertEqual(5 * 1048576, app.MAX_WORKSPACE_BYTES)
        with self.assertRaises(app.WriteRefused):
            store.atomic(first / 'runs' / 'huge.json', {'data': 'x' * app.MAX_WORKSPACE_BYTES})
        source_bytes = next(iter(store._source_bytes.values()))
        with patch.object(app, 'MAX_SOURCE_BYTES', source_bytes + 100):
            with self.assertRaises(app.SourceLimited):
                store.atomic(second / 'runs' / 'large.json', {'data': 'x' * 1000})
        self.assertEqual([], list((first / 'runs').iterdir()))
        self.assertEqual([], list((second / 'runs').iterdir()))
        self.assertEqual(app.directory_size(store.root), store._total)

    def test_corrupt_metadata_does_not_prevent_startup(self):
        store = self.server.store
        bad = store.require(store.create('one'))
        good_token = store.create('two')
        (bad / 'meta.json').write_text('{truncated', encoding='utf-8')
        restarted = app.WorkspaceStore(self.temp.name)
        self.assertIsNotNone(restarted.require(good_token))
        self.assertEqual(2, restarted._count)
        self.assertEqual(app.directory_size(store.root), restarted._total)
        restarted.sweep()
        self.assertTrue(bad.exists())

    def test_source_accounting_is_pseudonymous_and_legacy_field_is_removed(self):
        store = self.server.store
        workspace = store.require(store.create('198.51.100.1'))
        meta = store.load_json(workspace / 'meta.json')
        self.assertRegex(meta['admission_owner'], '^[0-9a-f]{64}$')
        self.assertNotIn('198.51.100.1', json.dumps(meta))
        meta['source'] = 'legacy'
        store.atomic(workspace / 'meta.json', meta)
        (store.root / 'source.key').write_bytes(b'legacy')
        restarted = app.WorkspaceStore(self.temp.name)
        self.assertNotIn('source', restarted.load_json(workspace / 'meta.json'))
        self.assertFalse((store.root / 'source.key').exists())
        self.assertEqual(app.directory_size(store.root), restarted._total)

    def test_atomic_rename_is_followed_by_directory_fsync(self):
        store = self.server.store
        workspace = store.require(self.create().rsplit('/', 1)[-1])
        events = []
        real_replace, real_sync = app.os.replace, app.fsync_directory
        def replace(source, target):
            events.append(('replace', target))
            return real_replace(source, target)
        def sync(path):
            events.append(('sync', path))
            return real_sync(path)
        target = workspace / 'runs' / 'fixture.json'
        with patch.object(app.os, 'replace', side_effect=replace), patch.object(app, 'fsync_directory', side_effect=sync):
            store.atomic(target, {'saved': True})
        self.assertEqual([('replace', target), ('sync', target.parent)], events)

    def test_export_streams_and_releases_lock(self):
        url = self.create()
        store = self.server.store
        workspace = store.require(url.rsplit('/', 1)[-1])
        store.atomic(workspace / 'runs' / 'fixture.json', {'fixture': True})
        original_load, original_send = store.load_json, app.Handler.send_file
        acquired = []
        def load(path):
            if path.parent.name == 'runs':
                raise AssertionError('must not parse runs in parent')
            return original_load(path)
        def send(handler, handle, filename):
            def probe():
                lock = store.lock(workspace.name)
                ok = lock.acquire(timeout=1)
                acquired.append(ok)
                if ok:
                    lock.release()
            thread = threading.Thread(target=probe)
            thread.start()
            thread.join(2)
            return original_send(handler, handle, filename)
        with patch.object(store, 'load_json', side_effect=load), patch.object(app.Handler, 'send_file', send):
            status, body, _ = self.request('GET', url + '/export')
        self.assertEqual(200, status)
        self.assertEqual([True], acquired)
        self.assertTrue(json.loads(body)['runs'][0]['fixture'])

    def test_activity_survives_full_storage_and_restart(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'DATA_DIR is required'):
                app.make_server(port=0)
        store = self.server.store
        workspace = store.require(self.create().rsplit('/', 1)[-1])
        meta = store.load_json(workspace / 'meta.json')
        meta['last_used'] = (app.utc_now() - dt.timedelta(days=91)).isoformat()
        store.atomic(workspace / 'meta.json', meta)
        with patch.object(store, 'atomic', side_effect=app.WriteRefused('full')):
            store.touch(workspace)
        restarted = app.WorkspaceStore(self.temp.name)
        restarted.sweep()
        self.assertTrue(workspace.exists())

    def test_unknown_policy_fields_are_rejected_without_echo_or_persistence(self):
        url = self.create()
        workspace = self.server.store.require(url.rsplit('/', 1)[-1])
        before = (workspace / 'policy.json').read_bytes()
        for location in ('top', 'rule', 'mode'):
            policy = copy.deepcopy(app.POLICY_DATA)
            target = policy if location == 'top' else policy['rules']['read'] if location == 'rule' else policy['fail_mode']
            target['person@example.test'] = 'person@example.test'
            page = self.request('POST', url + '/policy', {'policy_json': json.dumps(policy)})[1]
            self.assertIn(b'Policy error:', page)
            self.assertNotIn(b'person@example.test', page)
            self.assertEqual(before, (workspace / 'policy.json').read_bytes())

    def test_worker_deadline_and_cleanup(self):
        self.assertEqual(5, app_limits.CPU_SECONDS)
        self.assertLessEqual(app_limits.PROCESSING_SECONDS, 6)
        for operation in ('replay', 'verify', 'stored', 'bundle'):
            with self.assertRaises(app_limits.ProcessingLimit):
                app_limits.run_job(self.temp.name, operation, (), timeout=0)
        result = app_limits.run_job(self.temp.name, 'verify', ('{}', '11' * 32, '22' * 32))
        self.assertFalse(result['ok'])
        self.assertEqual([], list(self.server.store.root.glob('.job-*')))

    def test_keys_warning_and_nonce(self):
        url = self.create()
        _, page, headers = self.request('GET', url)
        for filename in ('signing.key', 'tsa.key'):
            raw = self.request('GET', url + '/keys/' + filename)[1]
            self.assertIn(raw.hex().encode(), page)
        for path in ('/', '/verify', url):
            page = self.request('GET', path)[1]
            self.assertIn(app.EVIDENCE_NOTICE.encode(), page)
            self.assertIn(b'<strong>A key holder can forge bundles.', page)
        _, page, headers = self.request('GET', url)
        nonce = re.search(rb"<script nonce='([^']+)'", page).group(1).decode()
        self.assertIn("script-src 'nonce-" + nonce + "'", headers['Content-Security-Policy'])
        self.assertNotIn("script-src 'unsafe-inline'", headers['Content-Security-Policy'])

    def test_error_pages_have_notices(self):
        for method, path, headers, expected in [
            ('GET', '/', {'Host': 'bad.example'}, 421),
            ('POST', '/start', {'Origin': 'https://bad.example'}, 403),
            ('POST', '/start', {'Content-Length': '1048577'}, 413),
        ]:
            status, page, _ = self.request(method, path, headers=headers)
            self.assertEqual(expected, status)
            self.assertIn(app.NOTICE.encode(), page)
            self.assertIn(app.HONESTY.encode(), page)
        with patch.object(app.Handler, 'get_page', side_effect=RuntimeError):
            status, page, _ = self.request('GET', '/')
        self.assertEqual(500, status)
        self.assertIn(app.NOTICE.encode(), page)


if __name__ == '__main__':
    unittest.main()
