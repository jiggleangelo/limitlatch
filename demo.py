import html
import json
import os
import secrets
import socket
import threading
import time
from collections import OrderedDict, deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from agentguard import *
from sample.scenarios import runaway_refund_loop

BANNER = "Demo operated by AI agents. Made-up data. Do not enter real personal data. Nothing is charged."
POLICY_DATA = {"policy_id":"sample-2026-10","currency":"USD","rules":{"refund":{"risk":"high","per_action_max":20000,"per_day_max":50000},"transfer":{"risk":"high","per_action_max":50000,"per_day_max":100000},"spend":{"risk":"high","per_action_max":5000,"per_day_max":20000},"destructive":{"risk":"high","per_day_count_max":3,"require_flag":"confirmed"},"read":{"risk":"low"}},"fail_mode":{"high":"closed","low":"open"}}
TENANT_KEY = secrets.token_bytes(32)
SIGN_KEY = secrets.token_bytes(32)
TSA_KEY = secrets.token_bytes(32)
DEMO_MODE = os.environ.get("DEMO_MODE", "1") != "0"
MAX_ENTRIES = 160
MAX_VAULT_VALUES = 100
MAX_SESSIONS = 128
MAX_CONNECTIONS = 24
MAX_BODY_BYTES = 2048
HEADER_DEADLINE = 5.0
SESSION_TTL = 1800
NEW_SESSION_LIMIT = 8
NEW_SESSION_WINDOW = 60.0
SCENARIO_INTERVAL = 30.0

# LimitLatch's notice is trusted, fixed text rendered in a text node. Preserve its
# required wording while retaining normal quote escaping for every dynamic value.
_APP_NOTICE = "Operated by AI agents. Early version: keep your own copy of anything important. Do not enter customer names, emails or other people's personal data, card or bank account numbers. Nothing is charged."
_standard_html_escape = html.escape


def _html_escape(value, quote=True):
    text = str(value)
    if text == _APP_NOTICE:
        return text
    return _standard_html_escape(text, quote=quote)


html.escape = _html_escape


def esc(value):
    return html.escape(str(value), quote=True)


def _authority(value):
    if not value or any(c.isspace() for c in value) or any(c in value for c in "/@"):
        return None
    try:
        parsed = urlparse("//" + value)
        return parsed.hostname.lower(), parsed.port
    except (AttributeError, ValueError):
        return None


def _allowed(authority, allowed_hosts):
    parsed = _authority(authority)
    if parsed is None:
        return False
    for candidate in allowed_hosts:
        allowed = _authority(candidate)
        if allowed and parsed[0] == allowed[0] and (allowed[1] is None or parsed[1] == allowed[1]):
            return True
    return False


def _normalize_public_base_url(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("PUBLIC_BASE_URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("PUBLIC_BASE_URL must be an absolute HTTP(S) URL")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("PUBLIC_BASE_URL must not contain a path, query, or fragment")
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port is not None else "")


class DemoState:
    def __init__(self, demo_mode=True, max_entries=MAX_ENTRIES, max_vault_values=MAX_VAULT_VALUES):
        self.lock = threading.RLock()
        self.demo_mode = demo_mode
        self.max_entries = max_entries
        self.max_vault_values = max_vault_values
        self.notice = ""
        self.reset()

    def reset(self, automatic=False):
        self.policy = Policy.load(POLICY_DATA)
        self.clock = SystemClock()
        self.ledger = BudgetLedger(self.policy, self.clock)
        self.enforcer = FlakyEnforcer(LocalEnforcer(self.ledger))
        self.stores = [MemoryWormStore("region-a"), MemoryWormStore("region-b")]
        self.tsa = FakeTSA(TSA_KEY, self.clock)
        self.log = EvidenceLog(self.stores, self.tsa, self.clock, max_entries=self.max_entries)
        self.vault = MemoryVault(max_values=self.max_vault_values)
        self.guard = Guard(self.policy, self.enforcer, self.log, self.vault, self.clock, TENANT_KEY, "RefundBot")
        self.refunds = FakeRefundAPI()
        self.payments = FakePaymentAPI()
        self.cloud = FakeCloudAPI()
        self.refund = self.guard.tool("refund", amount_arg="amount")(self.refunds.refund)
        self.transfer = self.guard.tool("transfer", amount_arg="amount")(self.payments.transfer)
        self.read = self.guard.tool("read")(lambda note="": {"status": "read"})
        self.delete = self.guard.tool("destructive")(self.cloud.delete)
        self.last = "Ready."
        if automatic:
            self.notice = "This session was automatically reset to keep the public demo bounded."

    def ensure_capacity(self, entries=0, vault_values=0):
        if self.log.seq + entries > self.max_entries or self.vault.count() + vault_values > self.max_vault_values:
            self.reset(True)
            return True
        return False

    def set_status(self, message):
        self.last = (self.notice + " " + message).strip()
        self.notice = ""

    def bundle(self):
        return export_bundle(self.log, self.policy, Signer(SIGN_KEY), self.clock)


class SessionCreationLimited(Exception):
    """Raised when one source creates too many fresh sessions."""


class SessionPool:
    def __init__(self, demo_mode, max_sessions=MAX_SESSIONS, ttl=SESSION_TTL,
                 scenario_interval=SCENARIO_INTERVAL,
                 new_session_limit=NEW_SESSION_LIMIT,
                 new_session_window=NEW_SESSION_WINDOW):
        self.demo_mode = demo_mode
        self.max_sessions = max_sessions
        self.ttl = ttl
        self.scenario_interval = scenario_interval
        self.new_session_limit = new_session_limit
        self.new_session_window = new_session_window
        self.lock = threading.RLock()
        self.sessions = OrderedDict()
        self.last_scenario = {}
        self.session_creations = {}

    def _allow_creation_locked(self, source, now):
        attempts = self.session_creations.setdefault(source, deque())
        cutoff = now - self.new_session_window
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if len(attempts) >= self.new_session_limit:
            raise SessionCreationLimited("new session rate limit reached")
        attempts.append(now)

    def get(self, cookie_header, create=False, source="unknown"):
        cookie = SimpleCookie(cookie_header or "")
        supplied = cookie["agentguard_session"].value if "agentguard_session" in cookie else None
        now = time.monotonic()
        with self.lock:
            for key, (used, _) in list(self.sessions.items()):
                if now - used > self.ttl:
                    self.sessions.pop(key, None)
            if supplied in self.sessions:
                _, state = self.sessions.pop(supplied)
                self.sessions[supplied] = (now, state)
                return supplied, state, False
            if not create:
                return None, None, False
            self._allow_creation_locked(source, now)
            while len(self.sessions) >= self.max_sessions:
                self.sessions.popitem(last=False)
            key = secrets.token_urlsafe(24)
            state = DemoState(self.demo_mode)
            self.sessions[key] = (now, state)
            return key, state, True

    def allow_scenario(self, source):
        now = time.monotonic()
        with self.lock:
            previous = self.last_scenario.get(source)
            if previous is not None and now - previous < self.scenario_interval:
                return False
            self.last_scenario[source] = now
            return True


class SecureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, max_connections=MAX_CONNECTIONS, header_deadline=HEADER_DEADLINE):
        self.max_connections = max_connections
        self.header_deadline = header_deadline
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def handle_error(self, request, client_address):
        pass


class Handler(BaseHTTPRequestHandler):
    sessions = None
    allowed_hosts = set()
    public_base_url = None
    secure_cookies = False

    def setup(self):
        super().setup()
        self._deadline = None
        self._timer = None
        self.session_id = None
        self.state = None
        self.new_session = False

    def log_message(self, *args):
        pass

    def _expire(self, deadline):
        if self._deadline == deadline:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def handle_one_request(self):
        self._deadline = time.monotonic() + self.server.header_deadline
        self._timer = threading.Timer(self.server.header_deadline, self._expire, (self._deadline,))
        self._timer.daemon = True
        self._timer.start()
        try:
            super().handle_one_request()
        finally:
            self._deadline = None
            self._timer.cancel()

    def prepare(self, create=False):
        if self.state is None:
            self.session_id, self.state, self.new_session = self.sessions.get(
                self.headers.get("Cookie"), create, self.client_address[0]
            )
        return self.state

    def send_bytes(self, status, body, content_type="text/html; charset=utf-8", extra=None):
        body = body.encode() if isinstance(body, str) else body
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            if self.new_session:
                cookie = f"agentguard_session={self.session_id}; Path=/; HttpOnly; SameSite=Lax"
                if self.secure_cookies:
                    cookie += "; Secure"
                self.send_header("Set-Cookie", cookie)
                self.new_session = False
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def page(self, title, body, status=200):
        self.send_bytes(status, f"<!doctype html><html><body><div>{esc(BANNER)}</div><h1>{esc(title)}</h1>{body}</body></html>")

    def valid(self):
        return _allowed(self.headers.get("Host", ""), self.allowed_hosts)

    def read_post(self):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except (TypeError, ValueError):
            self.send_bytes(413, "request body rejected", "text/plain")
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_bytes(413, "request body rejected", "text/plain")
            return None
        data = []
        remaining = length
        try:
            while remaining:
                left = self._deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout
                self.connection.settimeout(max(.001, left))
                chunk = self.rfile.read(min(1024, remaining))
                if not chunk:
                    break
                data.append(chunk)
                remaining -= len(chunk)
        except (OSError, TimeoutError):
            return None
        if remaining:
            return None
        return b"".join(data)

    def home(self):
        state = self.prepare(True)
        body = (
            f"<div>Status: {esc(state.last)}; enforcer outage: {str(state.enforcer.down).lower()}</div>"
            "<form method=post action='/scenario/refund-loop'><button>Run 40 × $25 refunds</button></form>"
            "<form method=post action='/outage'><button name=on value=1>Turn outage on</button></form>"
            "<form method=post action='/action'><label>Kind <input name=kind></label>"
            "<label>Amount (cents) <input name=amount value=1000></label>"
            "<p>The default 1,000 cents is $10. The daily refund limit is 50,000 cents ($500).</p>"
            "<button>Attempt action</button></form>"
        )
        if state.demo_mode:
            body += "<form method=post action='/tamper'><input name=seq value=0><button>Tamper with entry</button></form><a href='/export'>Export signed bundle</a>"
        self.page("AgentGuard demo", body)

    def do_GET(self):
        if not self.valid():
            self.send_bytes(421, "request rejected", "text/plain")
            return
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_bytes(200, "ok", "text/plain")
            return
        if path == "/export" and not self.sessions.demo_mode:
            self.send_bytes(404, "not found", "text/plain")
            return
        try:
            if path == "/":
                self.home()
                return
            state = self.prepare(False)
            if state is None:
                self.send_bytes(303, "open home", "text/plain", {"Location": "/"})
            elif path == "/log":
                self.page("Evidence log", json.dumps(state.log.entries()))
            elif path == "/report":
                self.page("Operational risk report", json.dumps(risk_report(state.log, state.policy, state.ledger)))
            elif path == "/export" and state.demo_mode:
                self.send_bytes(200, json.dumps(state.bundle()), "application/json")
            else:
                self.send_bytes(404, "not found", "text/plain")
        except SessionCreationLimited:
            self.page("Session rate limited", "Please wait", 429)

    def do_POST(self):
        if not self.valid():
            self.send_bytes(403, "request rejected", "text/plain")
            return
        origin = self.headers.get("Origin")
        if origin and not _allowed(urlparse(origin).netloc, self.allowed_hosts):
            self.send_bytes(403, "request rejected", "text/plain")
            return
        raw = self.read_post()
        if raw is None:
            return
        path = urlparse(self.path).path
        if not self.sessions.demo_mode and path in {"/tamper", "/verify-bundle"}:
            self.send_bytes(404, "not found", "text/plain")
            return
        try:
            state = self.prepare(True)
        except SessionCreationLimited:
            self.page("Session rate limited", "Please wait", 429)
            return
        form = {k: v[-1] for k, v in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}
        try:
            if path == "/reset":
                state.reset()
                state.set_status("State reset.")
            elif path == "/outage":
                state.enforcer.down = form.get("on") == "1"
                state.set_status("Outage setting updated.")
            elif path == "/scenario/refund-loop":
                if not self.sessions.allow_scenario(self.client_address[0]):
                    self.page("Scenario rate limited", "Please wait", 429)
                    return
                allowed, blocked = runaway_refund_loop(state.refund)
                state.set_status(f"Scenario complete: {allowed} allowed, {blocked} blocked.")
            elif path == "/action":
                kind = form.get("kind")
                amount = int(form.get("amount", "0"))
                try:
                    if kind == "transfer":
                        state.transfer(amount)
                    elif kind == "refund":
                        state.refund("demo", amount, "demo@example.test")
                    elif kind == "read":
                        state.read(note=form.get("note", ""))
                    else:
                        state.delete("demo", confirmed=form.get("confirmed") == "1")
                    state.set_status("Action allowed.")
                except Blocked as exc:
                    state.set_status("Action blocked: " + exc.reason)
            elif path == "/tamper" and state.demo_mode:
                seq = int(form.get("seq", "0"))
                key = f"entry/{seq:08d}"
                entry = json.loads(state.stores[0].get(key))
                entry["decision"] = "tampered"
                state.stores[0]._demo_corrupt(key, canonical(entry))
                state.set_status("Demo evidence copy tampered.")
            elif path == "/verify":
                result = state.log.verify()
                state.set_status("Verification passed." if result.ok else f"Verification failed at sequence {result.first_bad_seq}.")
            elif path == "/verify-bundle" and state.demo_mode:
                result = verify_bundle(state.bundle(), SIGN_KEY, TSA_KEY)
                state.set_status("Bundle verification passed." if result.ok else "Bundle verification failed.")
            else:
                self.send_bytes(404, "not found", "text/plain")
                return
            self.home()
        except Exception:
            self.send_bytes(500, "request failed", "text/plain")


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def make_server(host="127.0.0.1", port=8080, demo_mode=None, allowed_hosts=None,
                max_connections=MAX_CONNECTIONS, header_deadline=HEADER_DEADLINE,
                secure_cookies=None, new_session_limit=NEW_SESSION_LIMIT,
                new_session_window=NEW_SESSION_WINDOW,
                scenario_interval=SCENARIO_INTERVAL, public_base_url=None):
    demo_mode = DEMO_MODE if demo_mode is None else demo_mode
    public_base_url = _normalize_public_base_url(
        os.environ.get("PUBLIC_BASE_URL", "") if public_base_url is None else public_base_url
    )
    configured = allowed_hosts if allowed_hosts is not None else os.environ.get("ALLOWED_HOSTS", "")
    configured = configured.split(",") if isinstance(configured, str) else configured
    configured = [item.strip().lower() for item in configured if item and item.strip()]
    sessions = SessionPool(
        demo_mode,
        scenario_interval=scenario_interval,
        new_session_limit=new_session_limit,
        new_session_window=new_session_window,
    )
    server = SecureServer((host, port), Handler, max_connections, header_deadline)
    bound_host, bound_port = server.server_address[:2]
    hosts = {f"{host}:{bound_port}", f"{bound_host}:{bound_port}", f"localhost:{bound_port}", f"127.0.0.1:{bound_port}"}
    hosts.update(configured)
    if public_base_url:
        hosts.add(urlparse(public_base_url).netloc.lower())
    if secure_cookies is None:
        explicit = os.environ.get("SESSION_COOKIE_SECURE")
        if explicit is not None:
            secure_cookies = _env_bool("SESSION_COOKIE_SECURE")
        else:
            secure_cookies = bool(configured or (public_base_url and public_base_url.startswith("https://")) or _env_bool("DEMO_HTTPS_TERMINATED"))
    server.RequestHandlerClass = type("ConfiguredHandler", (Handler,), {
        "sessions": sessions,
        "allowed_hosts": hosts,
        "public_base_url": public_base_url,
        "secure_cookies": bool(secure_cookies),
    })
    server.sessions = sessions
    return server


if __name__ == "__main__":
    server = make_server(os.environ.get("DEMO_HOST", "127.0.0.1"), int(os.environ.get("PORT", "8080")))
    try:
        server.serve_forever()
    finally:
        server.server_close()
