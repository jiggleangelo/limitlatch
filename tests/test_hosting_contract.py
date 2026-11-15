import http.client
import os
import pathlib
import socket
import subprocess
import sys
import time
import unittest


class HostingContractTests(unittest.TestCase):
    def test_contract_environment_starts_and_accepts_public_host(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        public_host = "try-limitlatch.manykiln.com"

        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()

        env = os.environ.copy()
        env.update({
            "DEMO_HOST": "127.0.0.1",
            "PORT": str(port),
            "PUBLIC_BASE_URL": f"https://{public_host}",
            "DEMO_HTTPS_TERMINATED": "true",
        })
        env.pop("HOST", None)
        env.pop("ALLOWED_HOSTS", None)
        env.pop("SESSION_COOKIE_SECURE", None)

        process = subprocess.Popen(
            [sys.executable, "demo.py"],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 8
            last_error = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=1)
                    self.fail(
                        f"demo exited with {process.returncode}; stdout={stdout!r}; stderr={stderr!r}"
                    )
                try:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                    connection.request("GET", "/healthz", headers={"Host": public_host})
                    response = connection.getresponse()
                    body = response.read()
                    connection.close()
                    self.assertEqual(200, response.status)
                    self.assertEqual(b"ok", body)
                    break
                except (ConnectionError, OSError, http.client.HTTPException) as exc:
                    last_error = exc
                    time.sleep(0.05)
            else:
                self.fail(f"demo did not become healthy: {last_error!r}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
