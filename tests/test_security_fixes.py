import http.client
import socket
import threading
import time
import unittest
from urllib.parse import urlencode

from demo import MAX_BODY_BYTES, SessionCreationLimited, SessionPool, make_server


class RunningServer:
    def __init__(self, **kwargs):
        self.server = make_server("127.0.0.1", 0, demo_mode=True, **kwargs)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        request_headers = {"Host": f"127.0.0.1:{self.port}"}
        request_headers.update(headers or {})
        if cookie:
            request_headers["Cookie"] = cookie
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        data = response.read()
        result = response.status, data, dict(response.getheaders())
        conn.close()
        return result

    def post(self, path, values=None, cookie=None):
        body = urlencode(values or {}).encode()
        return self.request(
            "POST", path, body,
            {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))},
            cookie,
        )


class PublicDemoSecurityFixTests(unittest.TestCase):
    def test_body_has_small_cap_and_total_deadline(self):
        running = RunningServer(header_deadline=0.15, max_connections=1)
        try:
            status, _, _ = running.request(
                "POST", "/reset", b"x" * (MAX_BODY_BYTES + 1),
                {"Content-Length": str(MAX_BODY_BYTES + 1)},
            )
            self.assertEqual(413, status)

            client = socket.create_connection(("127.0.0.1", running.port), timeout=1)
            try:
                client.sendall(
                    f"POST /reset HTTP/1.1\r\nHost: 127.0.0.1:{running.port}\r\nContent-Length: 100\r\n\r\nx".encode()
                )
                time.sleep(0.3)
                client.settimeout(1)
                self.assertEqual(b"", client.recv(1))
            finally:
                client.close()

            deadline = time.monotonic() + 2
            while True:
                try:
                    status, _, _ = running.request("GET", "/healthz")
                    break
                except (ConnectionError, socket.timeout):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            self.assertEqual(200, status)
        finally:
            running.close()

    def test_health_and_stateful_gets_do_not_create_sessions(self):
        running = RunningServer()
        try:
            status, _, headers = running.request("GET", "/healthz")
            self.assertEqual(200, status)
            self.assertNotIn("Set-Cookie", headers)
            self.assertEqual(0, len(running.server.sessions.sessions))

            status, _, headers = running.request("GET", "/log")
            self.assertEqual(303, status)
            self.assertEqual("/", headers["Location"])
            self.assertNotIn("Set-Cookie", headers)
            self.assertEqual(0, len(running.server.sessions.sessions))

            status, _, headers = running.request("GET", "/")
            self.assertEqual(200, status)
            self.assertIn("Set-Cookie", headers)
            self.assertEqual(1, len(running.server.sessions.sessions))
        finally:
            running.close()

    def test_new_session_rate_limit_prevents_eviction_griefing(self):
        pool = SessionPool(True, max_sessions=2, new_session_limit=2, new_session_window=60)
        first, _, _ = pool.get(None, create=True, source="203.0.113.9")
        second, _, _ = pool.get(None, create=True, source="203.0.113.9")
        with self.assertRaises(SessionCreationLimited):
            pool.get(None, create=True, source="203.0.113.9")
        self.assertEqual([first, second], list(pool.sessions))

    def test_refund_loop_limit_survives_cookie_dropping(self):
        running = RunningServer(scenario_interval=30, new_session_limit=8)
        try:
            status, _, headers = running.post("/scenario/refund-loop")
            self.assertEqual(200, status)
            first_cookie = headers["Set-Cookie"].split(";", 1)[0]
            self.assertTrue(first_cookie.startswith("agentguard_session="))

            status, body, headers = running.post("/scenario/refund-loop", cookie=None)
            self.assertEqual(429, status)
            self.assertIn(b"Please wait", body)
            self.assertIn("Set-Cookie", headers)
        finally:
            running.close()

    def test_step_three_labels_minor_units_and_explains_default(self):
        running = RunningServer()
        try:
            status, body, _ = running.request("GET", "/")
            self.assertEqual(200, status)
            self.assertIn(b"Amount (cents)", body)
            self.assertIn(b"default 1,000 cents is $10", body)
            self.assertIn(b"50,000 cents ($500)", body)
        finally:
            running.close()

    def test_public_proxy_configuration_sets_secure_cookie(self):
        running = RunningServer(allowed_hosts="demo.example.com")
        try:
            conn = http.client.HTTPConnection("127.0.0.1", running.port, timeout=3)
            conn.request("GET", "/", headers={"Host": "demo.example.com"})
            response = conn.getresponse()
            response.read()
            cookie = response.getheader("Set-Cookie")
            conn.close()
            self.assertEqual(200, response.status)
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Lax", cookie)
            self.assertIn("Secure", cookie)
        finally:
            running.close()


if __name__ == "__main__":
    unittest.main()
