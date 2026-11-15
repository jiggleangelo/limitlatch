import copy
import datetime as dt
import http.client
import json
import pathlib
import tempfile
import threading
import unittest
from urllib.parse import urlencode, urlparse

from agentguard import verify_bundle
from app import NOTICE, esc, make_server


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.start_server()
        self.token = None

    def tearDown(self):
        self.stop_server()
        self.temp.cleanup()

    def start_server(self, data_cap_mb=200):
        self.server = make_server("127.0.0.1", 0, self.temp.name, data_cap_mb=data_cap_mb)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        supplied = {"Host": f"127.0.0.1:{self.port}"}
        supplied.update(headers or {})
        connection.request(method, path, body=body, headers=supplied)
        response = connection.getresponse()
        data = response.read()
        result = response.status, data, dict(response.getheaders())
        connection.close()
        return result

    def post(self, path, values=None, origin=True):
        body = urlencode(values or {}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))}
        if origin:
            headers["Origin"] = self.origin
        return self.request("POST", path, body, headers)

    def create(self):
        status, _, headers = self.post("/start")
        self.assertEqual(303, status)
        location = headers["Location"]
        self.token = location.rsplit("/", 1)[-1]
        return location

    def workspace_path(self):
        return pathlib.Path(self.temp.name) / "w" / self.server.store.digest(self.token)

    def test_start_notice_host_origin_health_and_token_secrecy(self):
        location = self.create()
        status, page, _ = self.request("GET", location)
        self.assertEqual(200, status)
        self.assertIn(b"this link is the only key; it cannot be recovered", page)
        self.assertIn(NOTICE.encode(), page)
        self.assertIn(b"https://manykiln.com/privacy", page)
        self.assertEqual(self.server.store.digest(self.token), self.workspace_path().name)
        for item in pathlib.Path(self.temp.name).rglob("*"):
            if item.is_file():
                self.assertNotIn(self.token.encode(), item.read_bytes())
        self.assertEqual(421, self.request("GET", "/", headers={"Host": "evil.example"})[0])
        self.assertEqual(403, self.post("/start", origin=False)[0])
        body = b""
        self.assertEqual(403, self.request("POST", "/start", body, {"Content-Length": "0", "Origin": "https://evil.example"})[0])
        self.assertEqual((200, b"ok"), self.request("GET", "/healthz")[:2])

    def test_core_flow_bundle_export_persistence_and_delete(self):
        self.create()
        policy = {
            "currency": "USD",
            "rules": {
                "refund": {"risk": "high", "per_action_max": 20000, "per_day_max": 50000},
                "transfer": {"risk": "high", "per_action_max": 50000, "per_day_max": 100000},
                "spend": {"risk": "high", "per_action_max": 5000, "per_day_max": 20000},
                "destructive": {"risk": "high", "per_day_count_max": 3, "require_flag": "confirmed"},
                "read": {"risk": "low"},
            },
            "fail_mode": {"high": "closed", "low": "open"},
        }
        self.assertEqual(200, self.post(f"/w/{self.token}/policy", {"policy_json": json.dumps(policy)})[0])
        header = "ts,agent_id,tool,kind,amount_minor,actual_minor,currency,confirmed,customer_email"
        rows = [header]
        base = dt.datetime(2026, 10, 24, 12, tzinfo=dt.timezone.utc)
        for number in range(40):
            rows.append(f"{(base + dt.timedelta(seconds=number)).isoformat()},a,refund,refund,2500,,USD,false,secret@example.test")
        outage_time = base + dt.timedelta(minutes=2)
        rows.extend([
            f"{(base + dt.timedelta(minutes=1)).isoformat()},a,transfer,transfer,60000,,USD,false,x@example.test",
            f"{outage_time.isoformat()},a,transfer2,transfer,1000,,USD,false,x@example.test",
            f"{outage_time.isoformat()},a,reader,read,0,,USD,false,x@example.test",
            f"{(base + dt.timedelta(minutes=3)).isoformat()},a,destroy,destructive,0,,USD,false,x@example.test",
            f"{(base + dt.timedelta(minutes=4)).isoformat()},a,spend,spend,1000,1200,USD,false,x@example.test",
        ])
        outages = [{"start": (outage_time - dt.timedelta(seconds=1)).isoformat(), "end": (outage_time + dt.timedelta(seconds=1)).isoformat()}]
        status, _, headers = self.post(f"/w/{self.token}/replay", {"log_text": "\n".join(rows), "outages": json.dumps(outages)})
        self.assertEqual(303, status)
        run_url = headers["Location"]
        run_id = run_url.split("/run/")[1]
        run = json.loads((self.workspace_path() / "runs" / f"{run_id}.json").read_text())
        refund_results = [item for item in run["results"] if item["kind"] == "refund"]
        self.assertEqual(20, sum(item["decision"] == "allowed" for item in refund_results))
        self.assertEqual(20, sum(item["reason"] == "daily_limit" for item in refund_results))
        self.assertIn("per_action_limit", [item["reason"] for item in run["results"]])
        self.assertIn("enforcer_unavailable", [item["reason"] for item in run["results"]])
        self.assertIn("missing_confirmation", [item["reason"] for item in run["results"]])
        self.assertTrue(any(item["overrun"] for item in run["results"]))
        self.assertEqual("allowed", next(item["decision"] for item in run["results"] if item["tool"] == "reader"))
        for item in pathlib.Path(self.temp.name).rglob("*"):
            if item.is_file():
                data = item.read_bytes()
                self.assertNotIn(b"customer_email", data)
                self.assertNotIn(b"secret@example.test", data)
        status, bundle_data, _ = self.request("GET", run_url + "/bundle.json")
        self.assertEqual(200, status)
        signing = self.request("GET", f"/w/{self.token}/keys/signing.key")[1]
        tsa = self.request("GET", f"/w/{self.token}/keys/tsa.key")[1]
        bundle = json.loads(bundle_data)
        self.assertTrue(verify_bundle(bundle, signing, tsa).ok)
        changed = copy.deepcopy(bundle)
        changed["entries"][0]["tool"] = "changed"
        status, page, _ = self.post("/verify", {"bundle": json.dumps(changed), "signing_key": signing.hex(), "tsa_key": tsa.hex()})
        self.assertEqual(200, status)
        self.assertIn(b"first bad sequence number: 0", page)
        status, exported, _ = self.request("GET", f"/w/{self.token}/export")
        self.assertEqual(200, status)
        self.assertIn("keys", json.loads(exported))
        self.stop_server()
        self.start_server()
        status, page, _ = self.request("GET", f"/w/{self.token}")
        self.assertEqual(200, status)
        self.assertIn(run_id.encode(), page)
        self.assertEqual(303, self.post(f"/w/{self.token}/delete")[0])
        self.assertFalse(self.workspace_path().exists())
        self.assertEqual(404, self.request("GET", f"/w/{self.token}")[0])

    def test_jsonl_errors_expiry_caps_and_sample(self):
        self.create()
        bad = json.dumps({"ts": "2026-10-24T00:00:00Z", "agent_id": "a", "tool": "r", "kind": "refund", "amount_minor": "secret-value"})
        status, page, _ = self.post(f"/w/{self.token}/replay", {"log_text": bad})
        self.assertEqual(200, status)
        self.assertIn(b"Replay error: row 1: amount must be a non-negative integer", page)
        # Returning escaped input to its editor is not persistence. The brief
        # does not require discarding it on validation failure. Keep checking
        # that diagnostics omit raw values and rejected input is never saved.
        editor_start = page.index(b'<textarea id=logtext')
        content_start = page.index(b'>', editor_start) + 1
        content_end = page.index(b'</textarea>', content_start)
        self.assertEqual(esc(bad).encode(), page[content_start:content_end])
        self.assertNotIn(b"secret-value", page[:content_start] + page[content_end:])
        self.assertEqual([], list((self.workspace_path() / "runs").iterdir()))
        for item in pathlib.Path(self.temp.name).rglob("*"):
            if item.is_file():
                self.assertNotIn(b"secret-value", item.read_bytes())
        self.assertNotIn(b"secret-value", self.request("GET", f"/w/{self.token}")[1])
        # Declare an oversized body without sending it. The server must reject
        # on the declared length before receipt and close the connection, so
        # actually streaming 1 MiB here races the close and raises
        # BrokenPipeError in the client instead of exercising the cap.
        oversized_length = 1024 * 1024 + 1
        self.assertEqual(413, self.request("POST", "/start", None, {"Content-Length": str(oversized_length), "Origin": self.origin})[0])
        too_many = "ts,agent_id,tool,kind,amount_minor\n" + "\n".join("2026-10-24T00:00:00Z,a,r,read,0" for _ in range(5001))
        status, page, _ = self.post(f"/w/{self.token}/replay", {"log_text": too_many})
        self.assertEqual(200, status)
        self.assertIn(b"5,000", page)
        meta_path = self.workspace_path() / "meta.json"
        meta = json.loads(meta_path.read_text())
        meta["last_used"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=91)).isoformat()
        meta_path.write_text(json.dumps(meta))
        self.server.store.sweep()
        self.assertFalse(self.workspace_path().exists())
        status, _, headers = self.post("/sample")
        self.assertEqual(303, status)
        sample_token = headers["Location"].rsplit("/", 1)[-1]
        sample_path = pathlib.Path(self.temp.name) / "w" / self.server.store.digest(sample_token)
        self.assertEqual(1, len(list((sample_path / "runs").glob("*.json"))))


if __name__ == "__main__":
    unittest.main()
