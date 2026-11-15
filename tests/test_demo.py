import contextlib
import http.client
import io
import json
import socket
import threading
import time
import unittest
from urllib.parse import urlencode

from demo import BANNER, DEMO_MODE, DemoState, make_server


class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0, demo_mode=True)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.cookie = None

    def request(self, method, path, body=None, headers=None, remember=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        request_headers = {"Host": f"127.0.0.1:{self.port}"}
        if self.cookie:
            request_headers["Cookie"] = self.cookie
        request_headers.update(headers or {})
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        data = response.read()
        status = response.status
        returned_headers = dict(response.getheaders())
        if remember and "Set-Cookie" in returned_headers:
            self.cookie = returned_headers["Set-Cookie"].split(";", 1)[0]
        conn.close()
        return status, data, returned_headers

    def post(self, path, values=None, origin=None):
        body = urlencode(values or {}).encode()
        headers = {"Content-Type":"application/x-www-form-urlencoded", "Content-Length":str(len(body))}
        if origin:
            headers["Origin"] = origin
        return self.request("POST", path, body, headers)

    def test_full_flow_and_demo_controls_are_enabled_by_default(self):
        self.assertTrue(DEMO_MODE)
        status, body, _ = self.request("GET", "/")
        self.assertEqual(200, status)
        self.assertIn(b"Tamper with entry", body)
        self.assertIn(b"Export signed bundle", body)
        for path in ("/log", "/report"):
            status, body, headers = self.request("GET", path)
            self.assertEqual(200, status)
            self.assertIn(BANNER.encode(), body)
            self.assertEqual("DENY", headers["X-Frame-Options"])
        self.post("/reset")
        _, body, _ = self.post("/scenario/refund-loop")
        self.assertIn(b"20 allowed, 20 blocked", body)
        self.post("/outage", {"on":"1"})
        _, body, _ = self.post("/action", {"kind":"transfer","amount":"1000","note":"made up"})
        self.assertIn(b"Action blocked: enforcer_unavailable", body)
        _, body, _ = self.post("/action", {"kind":"read","amount":"0","note":"<script>alert(1)</script>"})
        self.assertNotIn(b"<script>", body)
        self.assertNotIn(b"alert(1)", body)
        self.post("/tamper", {"seq":"0"})
        _, body, _ = self.post("/verify")
        self.assertIn(b"Verification failed", body)
        self.post("/reset")
        status, bundle, _ = self.request("GET", "/export")
        self.assertEqual(200, status)
        self.assertEqual("agentguard-evidence/0.1", json.loads(bundle)["format"])
        _, body, _ = self.post("/verify-bundle")
        self.assertIn(b"verification passed", body.lower())

    def test_body_cap_origin_and_host(self):
        status, _, _ = self.request("POST", "/reset", b"x" * 70000, {"Content-Length":"70000"})
        self.assertEqual(413, status)
        status, _, _ = self.post("/reset", origin="https://evil.example")
        self.assertEqual(403, status)
        status, _, _ = self.request("GET", "/", headers={"Host":"evil.example"})
        self.assertEqual(421, status)

    def test_public_allowed_host_and_matching_origin_work_behind_proxy(self):
        server = make_server("127.0.0.1", 0, allowed_hosts="demo.example.com")
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            body = b""
            conn.request("POST", "/reset", body=body, headers={
                "Host": "demo.example.com:443",
                "Origin": "https://demo.example.com",
                "Content-Length": "0",
            })
            response = conn.getresponse()
            response.read()
            self.assertEqual(200, response.status)
            conn.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_sessions_isolate_outage_and_reset_controls(self):
        self.request("GET", "/")
        first_cookie = self.cookie
        self.post("/outage", {"on":"1"})
        self.cookie = None
        _, second_body, _ = self.request("GET", "/")
        self.assertIn(b"enforcer outage: false", second_body)
        second_cookie = self.cookie
        self.assertNotEqual(first_cookie, second_cookie)
        self.cookie = first_cookie
        _, first_body, _ = self.request("GET", "/")
        self.assertIn(b"enforcer outage: true", first_body)

    def test_state_auto_resets_before_bounded_capacity(self):
        state = DemoState(max_entries=2, max_vault_values=1)
        state.read(note="one@example.test")
        self.assertTrue(state.ensure_capacity(entries=1, vault_values=1))
        state.set_status("Action allowed.")
        self.assertEqual(0, state.log.seq)
        self.assertIn("automatically reset", state.last)

    def test_scenario_is_rate_limited_per_session(self):
        self.post("/scenario/refund-loop")
        status, body, _ = self.post("/scenario/refund-loop")
        self.assertEqual(429, status)
        self.assertIn(b"Please wait", body)

    def test_total_header_deadline_closes_slow_connection(self):
        server = make_server("127.0.0.1", 0, header_deadline=0.1, max_connections=2)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = socket.create_connection(("127.0.0.1", port), timeout=1)
        try:
            client.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1")
            time.sleep(0.25)
            client.settimeout(1)
            self.assertEqual(b"", client.recv(1))
            self.assertEqual(2, server.max_connections)
        finally:
            client.close()
            server.shutdown(); server.server_close(); thread.join()

    def test_server_handle_error_emits_no_client_metadata(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.server.handle_error(None, ("203.0.113.7", 1234))
        self.assertEqual("", output.getvalue())

    def test_tamper_and_export_are_disabled_outside_demo_mode(self):
        server = make_server("127.0.0.1", 0, demo_mode=False)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/export", headers={"Host":f"127.0.0.1:{port}"})
            response = conn.getresponse()
            response.read()
            self.assertEqual(404, response.status)
            conn.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__":
    unittest.main()
