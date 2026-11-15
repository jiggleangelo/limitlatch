import copy
import datetime as dt
import http.client
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import urlencode, urlparse

import app
import app_limits
from agentguard import Policy, verify_bundle
from agentguard.replay import parse_log, replay


class ReviewTests(unittest.TestCase):
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
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
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

    def workspace(self, url):
        return self.server.store.require(url.rsplit('/', 1)[-1])

    @staticmethod
    def log(count=1, kind='refund', distinct_agents=False, padding=''):
        header = 'ts,agent_id,tool,kind,amount_minor,confirmed,discard\n'
        return header + '\n'.join(f'2026-10-24T12:00:00Z,a{i if distinct_agents else 0},tool,{kind},0,true,{padding}' for i in range(count))

    def run_log(self, url, text=None):
        status, page, headers = self.request('POST', url + '/replay', {'log_text': text or self.log()})
        self.assertEqual(303, status, page[:2000])
        return urlparse(headers['Location']).path

    def test_encoded_cap_applies_even_when_decoded_log_fits(self):
        url = self.create()
        text = self.log(5000, padding=':' * 100)
        self.assertLess(len(text.encode()), 1048576)
        self.assertGreater(len(urlencode({'log_text': text}).encode()), 1048576)
        # Declare the oversized body without sending it: rejection must precede receipt.
        with patch.object(app, 'run_job', side_effect=AssertionError('worker must not start')):
            status, _, _ = self.request('POST', url + '/replay', headers={'Content-Length': str(len(urlencode({'log_text': text}).encode()))})
        self.assertEqual(413, status)
        self.assertEqual([], list((self.workspace(url) / 'runs').iterdir()))
        self.assertEqual(5000, len(parse_log(self.log(5000))))
        with self.assertRaises(ValueError):
            parse_log(self.log(5001))

    def test_twenty_small_runs_and_storage_accounting(self):
        url = self.create()
        workspace = self.workspace(url)
        keys = self.server.store.load_json(workspace / 'keys.json')
        fixture = app_limits._execute('replay', (app.POLICY_DATA, self.log(), [], keys))
        with patch.object(app, 'run_job', side_effect=lambda *args: copy.deepcopy(fixture)):
            for _ in range(20):
                self.run_log(url)
            status, page, _ = self.request('POST', url + '/replay', {'log_text': self.log()})
        self.assertEqual(200, status)
        self.assertIn(b'20-run limit', page)
        self.assertEqual(20, len(list((workspace / 'runs').glob('*.json'))))
        self.assertEqual(app.directory_size(self.server.store.root), self.server.store._total)

    def test_fifty_pairs_are_accepted_and_fifty_one_rejected(self):
        url = self.create()
        rows = [{'ts': '2026-10-24T00:00:00Z', 'agent_id': 'a', 'tool': f'tool{i}', 'kind': 'read', 'amount_minor': 0} for i in range(51)]
        self.run_log(url, json.dumps(rows[:50]))
        status, page, _ = self.request('POST', url + '/replay', {'log_text': json.dumps(rows)})
        self.assertEqual(200, status)
        self.assertIn(b'50 distinct kind/tool pairs', page)
        self.assertEqual(1, len(list((self.workspace(url) / 'runs').iterdir())))
        self.assertIn(app.IDENTIFIER_NOTICE.encode(), self.request('GET', url)[1])

    def test_identical_invalid_ids_share_budget_without_colliding(self):
        rows = [{'ts': '2026-10-24T00:00:00Z', 'agent_id': agent, 'tool': 'bad tool', 'kind': 'refund', 'amount_minor': 6} for agent in ('person@example.test', 'person@example.test', 'agent_1', 'other@example.test')]
        events = parse_log(json.dumps(rows))
        self.assertEqual(events[0].agent_id, events[1].agent_id)
        self.assertNotEqual(events[0].agent_id, events[2].agent_id)
        self.assertNotEqual(events[0].agent_id, events[3].agent_id)
        policy = Policy.load({'currency': 'USD', 'rules': {'refund': {'risk': 'high', 'per_day_max': 10}}, 'fail_mode': {'high': 'closed'}})
        run = replay(policy, events, [], {'tenant': b't', 'sign': b's', 'tsa': b'a'})
        self.assertEqual(['allowed', 'blocked', 'allowed', 'allowed'], [row['decision'] for row in run.results])
        self.assertNotIn('@example.test', json.dumps(run.bundle))

    def test_run_and_bundle_reads_are_bounded_and_do_not_parse_in_parent(self):
        url = self.create()
        run_url = self.run_log(url, self.log(120, distinct_agents=True))
        store = self.server.store
        original = store.load_json
        def load(path):
            if path.parent.name == 'runs':
                raise AssertionError('main process parsed run')
            return original(path)
        for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
            self.server.expensive_slots.acquire()
        try:
            with patch.object(store, 'load_json', side_effect=load):
                status, page, _ = self.request('GET', run_url)
                self.assertEqual(200, status)
                self.assertEqual(303, page.count(b'<tr>'))
                status, page, _ = self.request('GET', run_url + '?decisions=2&evidence=3&totals=2')
                self.assertEqual(200, status)
                self.assertEqual(83, page.count(b'<tr>'))
                self.assertEqual(200, self.request('GET', run_url + '/bundle.json')[0])
        finally:
            for _ in range(app.MAX_EXPENSIVE_OPERATIONS):
                self.server.expensive_slots.release()
        for _ in range(2):
            self.server.read_slots.acquire()
        try:
            with patch.object(app, 'run_job', side_effect=AssertionError('busy read spawned worker')):
                self.assertEqual(429, self.request('GET', run_url)[0])
                self.assertEqual(429, self.request('GET', run_url + '/bundle.json')[0])
            self.assertEqual(200, self.request('GET', '/healthz')[0])
        finally:
            for _ in range(2):
                self.server.read_slots.release()

    def test_load_verifies_current_chain_and_anchors_not_save_status(self):
        url = self.create()
        run_url = self.run_log(url)
        path = self.workspace(url) / 'runs' / (run_url.rsplit('/', 1)[-1] + '.json')
        original = json.loads(path.read_text())
        for target in ('entry', 'anchor'):
            damaged = copy.deepcopy(original)
            if target == 'entry':
                damaged['bundle']['entries'][0]['tool'] = 'changed'
            else:
                damaged['bundle']['anchors'][0]['head_hash'] = '0' * 64
            self.server.store.atomic(path, damaged)
            status, page, _ = self.request('GET', run_url)
            self.assertEqual(200, status)
            self.assertIn(b'Stored evidence verification failed', page)
            self.assertNotIn(b'Stored evidence verification passed', page)
            if target == 'entry':
                self.assertIn(b'first bad sequence number: 0', page)
        self.server.store.atomic(path, original)
        self.assertIn(b'Stored evidence verification passed', self.request('GET', run_url)[1])

    def test_replay_releases_lock_and_delete_wins_without_resurrection(self):
        url = self.create()
        workspace = self.workspace(url)
        entered, release = threading.Event(), threading.Event()
        keys = self.server.store.load_json(workspace / 'keys.json')
        fixture = app_limits._execute('replay', (app.POLICY_DATA, self.log(), [], keys))
        results = []
        def blocked_job(*args):
            entered.set()
            if not release.wait(4):
                raise AssertionError('test did not release worker')
            return copy.deepcopy(fixture)
        def request_replay():
            results.append(self.request('POST', url + '/replay', {'log_text': self.log()})[0])
        with patch.object(app, 'run_job', side_effect=blocked_job):
            thread = threading.Thread(target=request_replay)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                lock = self.server.store.lock(workspace.name)
                self.assertTrue(lock.acquire(timeout=.5), 'replay held a shared stripe')
                lock.release()
                self.assertEqual(200, self.request('GET', url)[0])
                self.assertEqual(303, self.request('POST', url + '/delete')[0])
            finally:
                release.set()
                thread.join(5)
        self.assertEqual([404], results)
        self.assertFalse(workspace.exists())

    def test_policy_id_and_digest_survive_replay(self):
        url = self.create()
        policy = copy.deepcopy(app.POLICY_DATA)
        policy['policy_id'] = 'production-v7'
        self.assertIn(b'Policy saved.', self.request('POST', url + '/policy', {'policy_json': json.dumps(policy)})[1])
        run_url = self.run_log(url)
        bundle = json.loads(self.request('GET', run_url + '/bundle.json')[1])
        self.assertEqual(policy, bundle['policy'])
        self.assertEqual(Policy.load(policy).digest(), Policy.load(bundle['policy']).digest())
        keys = self.server.store.load_json(self.workspace(url) / 'keys.json')
        self.assertTrue(verify_bundle(bundle, bytes.fromhex(keys['sign']), bytes.fromhex(keys['tsa'])).ok)

    def test_disclosures_and_run_deletion_preserve_keys(self):
        url = self.create()
        run_url = self.run_log(url)
        workspace = self.workspace(url)
        keys = (workspace / 'keys.json').read_bytes()
        for path in (url, run_url):
            page = self.request('GET', path)[1]
            self.assertIn(app.REPLAY_NOTICE.encode(), page)
            self.assertIn(app.EVIDENCE_NOTICE.encode(), page)
        before = self.server.store._total
        self.assertEqual(403, self.request('POST', run_url + '/delete', headers={'Origin': 'https://evil.example'})[0])
        self.assertEqual(303, self.request('POST', run_url + '/delete')[0])
        self.assertLess(self.server.store._total, before)
        self.assertEqual(keys, (workspace / 'keys.json').read_bytes())
        self.assertEqual(404, self.request('GET', run_url)[0])

    def test_periodic_expiry_and_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            server = app.make_server('127.0.0.1', 0, directory, public_base_url='', sweep_interval=.02)
            try:
                workspace = server.store.require(server.store.create())
                # Store mutations acquire the accounting guard before the
                # workspace stripe; the fixture must follow the same order.
                with server.store._guard, server.store.lock(workspace.name):
                    meta = server.store.load_json(workspace / 'meta.json')
                    meta['last_used'] = (app.utc_now() - dt.timedelta(days=91)).isoformat()
                    server.store.atomic(workspace / 'meta.json', meta)
                deadline = time.monotonic() + 3
                while workspace.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(workspace.exists())
                self.assertEqual(0, server.store._count)
                self.assertEqual(app.directory_size(server.store.root), server.store._total)
            finally:
                server.server_close()
            self.assertFalse(server.sweeper.is_alive())

    def test_upload_and_processing_have_independent_deadlines(self):
        url = self.create()
        self.server.header_deadline = .08
        self.server.upload_deadline = .6
        original = app.Handler._save_run
        def slow_save(handler, *args):
            time.sleep(.15)
            return original(handler, *args)
        body = urlencode({'log_text': self.log()}).encode()
        client = socket.create_connection(('127.0.0.1', self.port), timeout=15)
        try:
            client.sendall((f'POST {url}/replay HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nOrigin: {self.origin}\r\nContent-Length: {len(body)}\r\n\r\n').encode())
            with patch.object(app.Handler, '_save_run', slow_save):
                client.sendall(body[:1])
                time.sleep(.15)
                client.sendall(body[1:])
                response = http.client.HTTPResponse(client)
                response.begin()
                response.read()
                self.assertEqual(303, response.status)
        finally:
            client.close()

    def test_upload_deadline_remains_absolute(self):
        self.server.upload_deadline = .1
        client = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        try:
            client.sendall((f'POST /start HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nOrigin: {self.origin}\r\nContent-Length: 100\r\n\r\nx').encode())
            time.sleep(.25)
            self.assertEqual(b'', client.recv(1))
        finally:
            client.close()
        self.assertEqual(0, self.server.store._count)

    def test_accounting_does_not_scan_on_requests(self):
        url = self.create()
        with patch.object(app, 'directory_size', side_effect=AssertionError('request scanned DATA_DIR')):
            self.assertEqual(200, self.request('GET', url)[0])
            run_url = self.run_log(url)
            self.assertEqual(303, self.request('POST', run_url + '/delete')[0])
        self.assertEqual(app.directory_size(self.server.store.root), self.server.store._total)
        self.assertEqual(self.server.store._total, app.WorkspaceStore(self.temp.name)._total)

    def test_health_bypasses_host_only_for_health(self):
        handler = self.server.RequestHandlerClass
        handler.allowed_hosts = {'public.example'}
        handler.public_base_url = 'https://public.example'
        self.assertEqual((200, b'ok'), self.request('GET', '/healthz', headers={'Host': 'internal-probe'})[:2])
        self.assertEqual(421, self.request('GET', '/', headers={'Host': 'internal-probe'})[0])
        self.assertEqual(403, self.request('POST', '/start', headers={'Host': 'internal-probe'})[0])

    def test_policy_form_errors_and_missing_kind_save_nothing(self):
        url = self.create()
        values = {'editor': 'form', 'currency': 'USD', 'low_fail_mode': 'closed', 'destructive_confirmed': '1'}
        for kind in app.KINDS:
            values[kind + '_enabled'] = '1'
            values[kind + '_risk'] = 'low' if kind == 'read' else 'high'
            values[kind + '_per_action_max'] = '10'
            values[kind + ('_per_day_count_max' if kind == 'destructive' else '_per_day_max')] = '20'
        self.assertIn(b'Policy saved.', self.request('POST', url + '/policy', values)[1])
        path = self.workspace(url) / 'policy.json'
        self.assertEqual(20, json.loads(path.read_text())['rules']['destructive']['per_day_count_max'])
        before = path.read_bytes()
        values['refund_per_action_max'] = '1.5'
        self.assertIn(b'Policy error:', self.request('POST', url + '/policy', values)[1])
        self.assertEqual(before, path.read_bytes())
        policy = {'currency': 'USD', 'rules': {'read': {'risk': 'low'}}, 'fail_mode': {'high': 'closed'}}
        self.request('POST', url + '/policy', {'policy_json': json.dumps(policy)})
        page = self.request('POST', url + '/replay', {'log_text': self.log(2)})[1]
        self.assertIn(b'row 1: kind is not defined in the policy', page)
        self.assertIn(b'row 2: kind is not defined in the policy', page)
        self.assertEqual([], list((self.workspace(url) / 'runs').iterdir()))

    def test_touch_waiting_on_delete_never_recreates_workspace(self):
        workspace = self.workspace(self.create())
        store = self.server.store
        started = threading.Event()
        errors = []
        def touch():
            started.set()
            try:
                store.touch(workspace)
            except Exception as exc:
                errors.append(exc)
        # Acquire locks in the store's order. Holding only the stripe lets
        # touch acquire _guard and wait for the stripe while delete waits
        # for _guard: a fixture-created deadlock, not an expiry failure.
        # Keep touch pending until deletion finishes, then verify it returns
        # without recreating the directory or raising an exception.
        thread = threading.Thread(target=touch, daemon=True)
        try:
            with store._guard, store.lock(workspace.name):
                thread.start()
                self.assertTrue(started.wait(1))
                self.assertTrue(store.delete(workspace))
                self.assertFalse(workspace.exists())
        finally:
            if thread.ident is not None:
                thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        self.assertFalse(workspace.exists())

    def test_import_does_not_import_demo_or_monkeypatch_html(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        source = "import html, sys; original = html.escape; import app; assert html.escape is original; assert 'demo' not in sys.modules; assert app.esc('<x>') == '&lt;x&gt;'"
        result = subprocess.run([sys.executable, '-B', '-c', source], cwd=root, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_concurrent_creation_count_and_lock_bounds(self):
        store = self.server.store
        def create(number):
            try:
                return store.create(str(number))
            except app.WriteRefused:
                return None
        with patch.object(app, 'MAX_WORKSPACES', 2), ThreadPoolExecutor(max_workers=12) as pool:
            tokens = list(pool.map(create, range(12)))
        self.assertEqual(2, sum(token is not None for token in tokens))
        for number in range(10000):
            store.lock(store.digest(str(number)))
        self.assertEqual(64, len(store._locks))
        for token in filter(None, tokens):
            store.delete(store.require(token))
        self.assertEqual(0, store._count)
        self.assertEqual(app.directory_size(store.root), store._total)

    def test_destructive_counts_and_decoded_log_limit(self):
        run = replay(Policy.load(app.POLICY_DATA), parse_log(self.log(4, kind='destructive')), [], {'tenant': b't', 'sign': b's', 'tsa': b'a'})
        self.assertEqual(['allowed', 'allowed', 'allowed', 'blocked'], [item['decision'] for item in run.results])
        self.assertEqual(3, run.totals['a0|destructive|2026-10-24']['committed'])
        with self.assertRaisesRegex(ValueError, '1 MB'):
            parse_log('x' * (1048576 + 1))


class AppHostingContractTests(unittest.TestCase):
    def test_entrypoint_public_origin_health_and_hsts(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            reservation = socket.socket()
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
            reservation.close()
            env = os.environ.copy()
            env.pop('APP_TRUSTED_PROXIES', None)
            env.update({'APP_HOST': '127.0.0.1', 'PORT': str(port), 'PUBLIC_BASE_URL': 'https://public.example', 'APP_HTTPS_TERMINATED': 'true', 'DATA_DIR': directory})
            process = subprocess.Popen([sys.executable, '-B', 'app.py'], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    self.assertIsNone(process.poll())
                    try:
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                        connection.request('GET', '/healthz', headers={'Host': 'internal-probe'})
                        response = connection.getresponse()
                        self.assertEqual(200, response.status)
                        self.assertEqual(b'ok', response.read())
                        connection.close()
                        break
                    except (ConnectionError, OSError):
                        time.sleep(.05)
                else:
                    self.fail('app did not become healthy')
                for _ in range(10):
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                    connection.request('POST', '/start', body=b'', headers={'Host': 'public.example', 'Origin': 'https://public.example'})
                    response = connection.getresponse()
                    response.read()
                    self.assertEqual(303, response.status)
                    self.assertTrue(response.getheader('Location').startswith('https://public.example/w/'))
                    self.assertEqual('max-age=31536000', response.getheader('Strict-Transport-Security'))
                    connection.close()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                process.stdout.close()
                process.stderr.close()


if __name__ == '__main__':
    unittest.main()
