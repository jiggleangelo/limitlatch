import datetime as dt
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from agentguard import Policy, PolicyError
from agentguard.replay import currency_mismatch_message, parse_log
from app_jobs import clean_policy
from app_limits import MAX_RESULT_BYTES, ProcessingLimit, run_job, sweep_stale_jobs

NOTICE = "Operated by AI agents. Early version: keep your own copy of anything important. Do not enter customer names, emails or other people's personal data, card or bank account numbers. Nothing is charged."
HONESTY = "No AI model is used; results are deterministic replays of your policy. Not an insurance rating, coverage opinion, legal conclusion, or attestation."
EVIDENCE_NOTICE = 'HMAC evidence is not third-party proof. A key holder can forge bundles.'
REPLAY_NOTICE = 'This deterministic replay simulates the supplied policy, log and outage windows; it is not a live enforcement result.'
SAMPLE_NOTICE = 'Made-up sample data only. Replace it before evaluating your own log.'
ROW_NOTICE = 'The parser accepts up to 5,000 rows and 1 MB of decoded text. Saved runs typically support about 2,000 rows, depending on evidence size and processing time. Processing and storage limits can reject a run without saving it.'
STORAGE_NOTICE = 'Each workspace has a shared 5 MiB storage allowance and a 20-run limit. A large run can fill it; export and delete older runs to make room. Runs are retained until deleted, for 90 days of inactivity, or until the workspace is deleted.'
IDENTIFIER_NOTICE = 'Unsafe or personal-looking agent and tool identifiers are replaced with stable aliases before storage.'
FORMAT_NOTICE = 'Amounts must already be non-negative integer minor units: for USD, convert 25.00 dollars to 2500 cents before uploading. Decimal amounts are rejected, never rounded. Map exported action names to refund, transfer, spend, destructive or read. Kind matching ignores surrounding spaces and letter case. Numeric identifiers and epoch timestamps are accepted.'
DESTRUCTIVE_ZERO_WARNING = 'A destructive per-action maximum of zero blocks destructive actions because each action counts as one. Remove that maximum to use only the count limit.'
BUSY_MESSAGE = 'The service is busy. Your input was not saved; wait a moment and try again.'
DELETE_WORKSPACE_CONFIRM = 'Permanently delete this workspace, its runs and its keys?'
DELETE_RUN_CONFIRM = 'Permanently delete this run?'
CONFIRM_SCRIPT = "document.querySelectorAll('form.confirm').forEach(function(f){f.addEventListener('submit',function(e){if(!confirm(f.dataset.message)){e.preventDefault();}});});"
# Validation responses remain transient: raw rejected logs never enter storage
# or URLs. Enhanced forms keep the browser on its GET history entry, so refresh
# does not repeat a failed or successful POST. Ordinary clients still work.
EDITOR_SCRIPT = """document.querySelectorAll('form.editor').forEach(function(f){f.addEventListener('submit',async function(e){e.preventDefault();var button=f.querySelector('button');button.disabled=true;try{var r=await fetch(f.action,{method:'POST',body:new URLSearchParams(new FormData(f)),headers:{Accept:'text/html'}});if(r.redirected){location.assign(r.url);return;}var page=await r.text();document.open();document.write(page);document.close();}catch(error){button.disabled=false;alert('The response could not be received. Your input is still here. Check past runs before retrying.');}});});"""
KINDS = ('refund', 'transfer', 'spend', 'destructive', 'read')
MAX_BODY_BYTES = 1024 * 1024
MAX_REPLAY_BODY_BYTES = MAX_BODY_BYTES
MAX_VERIFY_BODY_BYTES = MAX_BODY_BYTES
MAX_WORKSPACE_BYTES = 5 * 1024 * 1024
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MAX_WORKSPACES = 3000
MAX_SOURCE_WORKSPACES = 10
MAX_TRACKED_SOURCES = 3000
MAX_RUNS = 20
MAX_EXPENSIVE_OPERATIONS = 2
MAX_READ_OPERATIONS = 2
MAX_CONNECTIONS = 24
QUEUE_SECONDS = 3.0
READ_QUEUE_SECONDS = 3.0
HEADER_DEADLINE = 5.0
UPLOAD_DEADLINE = 5.0
MIN_UPLOAD_BYTES_PER_SECOND = 32768
WORKSPACE_TTL_DAYS = 90
ACTIVITY_INTERVAL = 60
SOURCE_WINDOW = 3600
SOURCE_CREATIONS = 10
POLICY_DATA = {
    'currency': 'USD',
    'rules': {
        'refund': {'risk': 'high', 'per_action_max': 20000, 'per_day_max': 50000},
        'transfer': {'risk': 'high', 'per_action_max': 50000, 'per_day_max': 100000},
        'spend': {'risk': 'high', 'per_action_max': 5000, 'per_day_max': 20000},
        'destructive': {'risk': 'high', 'per_day_count_max': 3, 'require_flag': 'confirmed'},
        'read': {'risk': 'low'},
    },
    'fail_mode': {'high': 'closed', 'low': 'open'},
    'daily_scope': 'per_agent',
}
SAMPLE_POLICY_ID = 'sample-made-up-policy'


def esc(value):
    return html.escape(str(value), quote=True)


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def normalize_source(source):
    """Normalize real IPs; retain synthetic source names used by SDK callers."""
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return str(source)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((address, 64), strict=False))
    return str(address)


def directory_size(path):
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(root, name))]
        for name in files:
            try:
                total += os.stat(os.path.join(root, name), follow_symlinks=False).st_size
            except OSError:
                pass
    return total


def fsync_directory(path):
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        pass


def upload_deadline_for(base, length):
    return max(base, min(40.0, base + max(0, length) / MIN_UPLOAD_BYTES_PER_SECOND))


def normalize_base(value):
    value = (value or '').strip()
    if not value:
        return ''
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        raise ValueError('PUBLIC_BASE_URL must be an HTTP(S) origin')
    host = parsed.hostname.lower()
    if ':' in host:
        host = '[' + host + ']'
    return parsed.scheme.lower() + '://' + host + ((':' + str(parsed.port)) if parsed.port else '')


class WriteRefused(ValueError):
    pass


class SourceLimited(ValueError):
    pass


class WorkspaceStore:
    def __init__(self, data_dir, data_cap_mb=200):
        self.root = Path(data_dir).resolve()
        self.workspaces = self.root / 'w'
        self.root.mkdir(parents=True, exist_ok=True)
        self.workspaces.mkdir(exist_ok=True)
        self.cap = int(data_cap_mb * 1024 * 1024)
        self._guard = threading.RLock()
        self._locks = [threading.RLock() for _ in range(64)]
        self._creations = {}
        self.admission_key = self._load_key()
        self._migrate()
        self._recount()

    def _load_key(self):
        path = self.root / 'admission.key'
        if path.is_file():
            return path.read_bytes()
        key = secrets.token_bytes(32)
        temporary = self.root / ('.admission-' + secrets.token_hex(6))
        temporary.write_bytes(key)
        os.replace(temporary, path)
        fsync_directory(self.root)
        return key

    def _migrate(self):
        try:
            (self.root / 'source.key').unlink()
        except OSError:
            pass
        for path in self.workspaces.iterdir():
            if not path.is_dir() or path.is_symlink():
                continue
            try:
                value = self.load_json(path / 'meta.json')
                if 'source' in value:
                    value.pop('source', None)
                    self._atomic_raw(path / 'meta.json', json.dumps(value, separators=(',', ':')).encode())
            except (OSError, ValueError, TypeError):
                pass

    def _recount(self):
        self._total = directory_size(self.root)
        self._count = 0
        self._sizes = {}
        self._source_bytes = {}
        self._source_counts = {}
        for path in self.workspaces.iterdir():
            if not path.is_dir() or path.is_symlink():
                continue
            self._count += 1
            size = directory_size(path)
            self._sizes[path.name] = size
            try:
                owner = self.load_json(path / 'meta.json').get('admission_owner', '')
            except Exception:
                owner = ''
            if owner:
                self._source_bytes[owner] = self._source_bytes.get(owner, 0) + size
                self._source_counts[owner] = self._source_counts.get(owner, 0) + 1

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def owner(self, source):
        return hmac.new(self.admission_key, normalize_source(source).encode(), hashlib.sha256).hexdigest()

    def lock(self, digest):
        return self._locks[int(hashlib.sha256(str(digest).encode()).hexdigest()[:8], 16) % len(self._locks)]

    def size(self, workspace):
        return self._sizes.get(Path(workspace).name, 0)

    def load_json(self, path):
        with Path(path).open(encoding='utf-8') as handle:
            return json.load(handle)

    def _atomic_raw(self, path, encoded):
        path = Path(path)
        # Workspace lifecycle creates directories. A late write must never
        # recreate a deleted or rotated workspace.
        fd, temporary = tempfile.mkstemp(prefix='.write-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            fsync_directory(path.parent)
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass

    def _account(self, workspace, owner, delta):
        self._total += delta
        self._sizes[workspace.name] = self.size(workspace) + delta
        if owner:
            self._source_bytes[owner] = self._source_bytes.get(owner, 0) + delta

    def atomic(self, path, value):
        encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()
        path = Path(path)
        workspace = path
        while workspace.parent != self.workspaces and workspace != self.root:
            if workspace.parent == workspace:
                raise WriteRefused('invalid storage path')
            workspace = workspace.parent
        if workspace.parent != self.workspaces or workspace.is_symlink():
            raise WriteRefused('invalid storage path')
        with self._guard, self.lock(workspace.name):
            if not workspace.exists():
                raise WriteRefused('workspace not found')
            old = path.stat().st_size if path.is_file() else 0
            increase = len(encoded) - old
            try:
                owner = self.load_json(workspace / 'meta.json').get('admission_owner', '')
            except Exception:
                owner = ''
            if increase > 0:
                if self.size(workspace) + increase > MAX_WORKSPACE_BYTES or self._total + increase > self.cap:
                    raise WriteRefused('storage limit reached')
                if owner and self._source_bytes.get(owner, 0) + increase > MAX_SOURCE_BYTES:
                    raise SourceLimited('source storage limit reached')
            self._atomic_raw(path, encoded)
            self._account(workspace, owner, len(encoded) - old)

    def _prune_creations(self, now):
        # Called under _guard. Both keys and timestamps have hard bounds.
        for owner, attempts in list(self._creations.items()):
            while attempts and attempts[0] <= now - SOURCE_WINDOW:
                attempts.popleft()
            if not attempts:
                del self._creations[owner]

    def create(self, source='unknown', sample=False):
        owner = self.owner(source)
        now = time.monotonic()
        with self._guard:
            self._prune_creations(now)
            attempts = self._creations.get(owner)
            if (attempts is not None and len(attempts) >= SOURCE_CREATIONS) or self._source_counts.get(owner, 0) >= MAX_SOURCE_WORKSPACES:
                raise SourceLimited('workspace creation limit reached')
            if self._count >= MAX_WORKSPACES or self._total >= self.cap:
                raise WriteRefused('workspace capacity reached')
            if attempts is None and len(self._creations) >= MAX_TRACKED_SOURCES:
                # Do not evict live rate-limit entries and permit quota bypass.
                raise SourceLimited('workspace admission is busy; try again later')
            token = secrets.token_urlsafe(24)
            path = self.workspaces / self.digest(token)
            while path.exists():
                token = secrets.token_urlsafe(24)
                path = self.workspaces / self.digest(token)
            keys = {name: secrets.token_hex(32) for name in ('tenant', 'sign', 'tsa')}
            policy = json.loads(json.dumps(POLICY_DATA))
            if sample:
                policy['policy_id'] = SAMPLE_POLICY_ID
            meta = {'created_at': utc_now().isoformat(), 'last_used': utc_now().isoformat(), 'admission_owner': owner, 'sample': bool(sample)}
            documents = {'keys.json': keys, 'policy.json': policy, 'meta.json': meta}
            encoded = {name: json.dumps(value, separators=(',', ':')).encode() for name, value in documents.items()}
            size = sum(map(len, encoded.values()))
            if size > MAX_WORKSPACE_BYTES or self._total + size > self.cap:
                raise WriteRefused('workspace capacity reached')
            if self._source_bytes.get(owner, 0) + size > MAX_SOURCE_BYTES:
                raise SourceLimited('source storage limit reached')
            path.mkdir(mode=0o700)
            try:
                (path / 'runs').mkdir()
                (path / '.activity').touch()
                os.utime(path / '.activity', (0, 0))
                for name, data in encoded.items():
                    self._atomic_raw(path / name, data)
            except BaseException:
                shutil.rmtree(path, ignore_errors=True)
                raise
            self._account(path, owner, size)
            self._count += 1
            self._source_counts[owner] = self._source_counts.get(owner, 0) + 1
            self._creations.setdefault(owner, deque()).append(now)
            return token

    def require(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', token):
            return None
        path = self.workspaces / self.digest(token)
        return path if path.is_dir() and not path.is_symlink() else None

    def touch(self, workspace):
        workspace = Path(workspace)
        # This operation never acquires _guard or calls atomic. It changes
        # only an existing, zero-byte marker, at most once per minute.
        with self.lock(workspace.name):
            if not workspace.is_dir():
                return
            try:
                marker = workspace / '.activity'
                last = marker.stat().st_mtime
                try:
                    meta = self.load_json(workspace / 'meta.json')
                    last = max(last, dt.datetime.fromisoformat(meta['last_used'].replace('Z', '+00:00')).timestamp())
                except (OSError, ValueError, TypeError, KeyError):
                    pass
                now = time.time()
                if now - last >= ACTIVITY_INTERVAL:
                    os.utime(marker, (now, now))
            except OSError:
                pass

    def delete(self, workspace):
        workspace = Path(workspace)
        with self._guard, self.lock(workspace.name):
            if not workspace.is_dir() or workspace.parent != self.workspaces:
                return False
            size = self.size(workspace)
            try:
                owner = self.load_json(workspace / 'meta.json').get('admission_owner', '')
            except Exception:
                owner = ''
            tomb = self.root / ('.deleted-' + secrets.token_hex(8))
            os.replace(workspace, tomb)
            fsync_directory(self.workspaces)
            shutil.rmtree(tomb, ignore_errors=True)
            self._account(workspace, owner, -size)
            self._sizes.pop(workspace.name, None)
            self._count -= 1
            if owner:
                remaining = self._source_counts.get(owner, 0) - 1
                if remaining > 0:
                    self._source_counts[owner] = remaining
                else:
                    self._source_counts.pop(owner, None)
                    self._source_bytes.pop(owner, None)
            return True

    def delete_run(self, workspace, target):
        with self._guard, self.lock(workspace.name):
            if not target.is_file():
                return False
            size = target.stat().st_size
            owner = self.load_json(workspace / 'meta.json').get('admission_owner', '')
            target.unlink()
            fsync_directory(target.parent)
            self._account(workspace, owner, -size)
            return True

    def rotate(self, workspace, replace_keys=False):
        workspace = Path(workspace)
        with self._guard, self.lock(workspace.name):
            if not workspace.is_dir():
                raise WriteRefused('workspace not found')
            if workspace.name not in self._sizes:
                raise WriteRefused('workspace accounting unavailable; nothing was moved')
            token = secrets.token_urlsafe(24)
            target = self.workspaces / self.digest(token)
            while target.exists():
                token = secrets.token_urlsafe(24)
                target = self.workspaces / self.digest(token)
            if replace_keys:
                self.atomic(workspace / 'keys.json', {name: secrets.token_hex(32) for name in ('tenant', 'sign', 'tsa')})
                for path in (workspace / 'runs').glob('*.json'):
                    self.delete_run(workspace, path)
            os.replace(workspace, target)
            self._sizes[target.name] = self._sizes.pop(workspace.name)
            fsync_directory(self.workspaces)
            return token

    def sweep(self):
        with self._guard:
            self._prune_creations(time.monotonic())
        cutoff = utc_now() - dt.timedelta(days=WORKSPACE_TTL_DAYS)
        for workspace in list(self.workspaces.iterdir()):
            with self._guard, self.lock(workspace.name):
                if not workspace.is_dir() or workspace.is_symlink():
                    continue
                try:
                    meta = self.load_json(workspace / 'meta.json')
                    last = dt.datetime.fromisoformat(meta['last_used'].replace('Z', '+00:00'))
                    marker = workspace / '.activity'
                    if marker.exists():
                        last = max(last, dt.datetime.fromtimestamp(marker.stat().st_mtime, dt.timezone.utc))
                    if last < cutoff:
                        self.delete(workspace)
                except (OSError, ValueError, TypeError, KeyError):
                    continue


class SecureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        self._connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._connections.acquire(False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def handle_error(self, request, client_address):
        pass

    def server_close(self):
        if hasattr(self, '_stop_sweeper'):
            self._stop_sweeper.set()
        if hasattr(self, 'sweeper') and self.sweeper is not threading.current_thread():
            self.sweeper.join(timeout=2)
        super().server_close()


def check_currency(text, policy_currency):
    for number, event in enumerate(parse_log(text), 1):
        if event.currency and event.currency != policy_currency:
            raise ValueError(f'row {number}: ' + currency_mismatch_message(policy_currency))


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'LimitLatch'
    sys_version = ''

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self._nonce = secrets.token_urlsafe(18)
        self._receipt_lock = threading.Lock()
        self._receipt_timer = None
        self._receipt_generation = None

    def _expire_receipt(self, generation):
        with self._receipt_lock:
            if self._receipt_generation is generation:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _start_receipt(self, seconds):
        self._stop_receipt()
        with self._receipt_lock:
            generation = object()
            self._receipt_generation = generation
            timer = threading.Timer(seconds, self._expire_receipt, (generation,))
            timer.daemon = True
            self._receipt_timer = timer
            self.connection.settimeout(seconds)
            timer.start()

    def _stop_receipt(self):
        with self._receipt_lock:
            self._receipt_generation = None
            timer, self._receipt_timer = self._receipt_timer, None
            if timer is not None:
                timer.cancel()

    def handle_one_request(self):
        # Start a fresh absolute deadline for every request, including the
        # request line and keep-alive requests. parse_request ends this phase.
        self._start_receipt(self.server.header_deadline)
        try:
            super().handle_one_request()
        finally:
            self._stop_receipt()

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            self._stop_receipt()
            self.connection.settimeout(self.server.header_deadline)

    def _headers(self, status, content_type, length=None, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        if length is not None:
            self.send_header('Content-Length', str(length))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-" + self._nonce + "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if self.server.https_terminated:
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def send_bytes(self, status, body, content_type='text/html; charset=utf-8', extra=None):
        body = body.encode() if isinstance(body, str) else body
        try:
            self._headers(status, content_type, len(body), extra)
            self.wfile.write(body)
        except OSError:
            pass

    def layout(self, title, body):
        footer = '<hr><p>' + html.escape(NOTICE, quote=False) + " <a href='https://manykiln.com/privacy'>Privacy</a></p><p>" + esc(HONESTY) + '</p><p><strong>A key holder can forge bundles.</strong> ' + esc(EVIDENCE_NOTICE) + '</p>'
        return '<!doctype html><html><head><meta charset=utf-8><title>' + esc(title) + '</title></head><body><h1>' + esc(title) + '</h1>' + body + footer + "<script nonce='" + self._nonce + "'>" + CONFIRM_SCRIPT + EDITOR_SCRIPT + '</script></body></html>'

    def page(self, title, body, status=200, extra=None):
        self.send_bytes(status, self.layout(title, body), extra=extra)

    def send_file(self, handle, filename, content_type='application/json'):
        try:
            handle.seek(0, os.SEEK_END)
            length = handle.tell()
            handle.seek(0)
            self._headers(200, content_type, length, {'Content-Disposition': 'attachment; filename="' + filename + '"'})
            shutil.copyfileobj(handle, self.wfile, 65536)
        finally:
            handle.close()

    def valid_host(self):
        return self.headers.get('Host', '').lower() in self.allowed_hosts

    def valid_post(self):
        if not self.valid_host():
            return False
        origin = self.headers.get('Origin')
        if origin and origin != 'null':
            try:
                parsed = urlparse(origin)
                origin_value = parsed.scheme + '://' + parsed.netloc.lower()
            except Exception:
                return False
            expected = self.public_base_url or ('http://' + self.headers.get('Host', '').lower())
            return origin_value == expected
        return self.headers.get('Sec-Fetch-Site', '').lower() == 'same-origin'

    def source(self):
        peer = ipaddress.ip_address(self.client_address[0])
        if self.trusted_proxies and any(peer in network for network in self.trusted_proxies):
            supplied_values = self.headers.get_all('X-Real-IP', [])
            if len(supplied_values) != 1 or ',' in supplied_values[0] or not supplied_values[0].strip():
                raise ValueError('missing proxy identity')
            return normalize_source(str(ipaddress.ip_address(supplied_values[0].strip())))
        if self.local_proxy_forwarding and peer.is_loopback:
            supplied = self.headers.get('X-Forwarded-For', '')
            if supplied:
                try:
                    return normalize_source(str(ipaddress.ip_address(supplied.split(',')[-1].strip())))
                except ValueError:
                    pass
        return normalize_source(str(peer))

    def read_form(self):
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding'):
            self.close_connection = True
            self.page('Request rejected', 'Encoded or streamed request bodies are not accepted.', 413)
            return None
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self.close_connection = True
            self.page('Request too large', 'The request body exceeds 1 MB.', 413)
            return None
        seconds = upload_deadline_for(self.server.upload_deadline, length)
        deadline = time.monotonic() + seconds
        chunks = []
        remaining = length
        self._start_receipt(seconds)
        try:
            while remaining:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise socket.timeout
                self.connection.settimeout(left)
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    raise socket.timeout
                chunks.append(chunk)
                remaining -= len(chunk)
        except OSError:
            self.close_connection = True
            return None
        finally:
            self._stop_receipt()
            self.connection.settimeout(self.server.header_deadline)
        try:
            return {key: values[-1] for key, values in parse_qs(b''.join(chunks).decode('utf-8'), keep_blank_values=True, max_num_fields=200).items()}
        except (UnicodeDecodeError, ValueError):
            self.page('Request rejected', 'The form could not be decoded.', 400)
            return None

    def redirect(self, path):
        self.send_bytes(303, b'', 'text/plain', {'Location': self.public_base_url + path if self.public_base_url else path})

    def workspace(self, token):
        path = self.server.store.require(token)
        if path is None:
            self.page('Workspace not found', 'workspace not found', 404)
            return None
        self.server.store.touch(path)
        return path

    def run_delete_control(self, token, run_id):
        return "<form class=confirm data-message='" + esc(DELETE_RUN_CONFIRM) + "' method=post action='/w/" + esc(token) + '/run/' + esc(run_id) + "/delete'><label><input type=checkbox name=confirm value=1 required> Confirm run deletion</label><button>Delete this run</button></form>"

    def controls(self, token, run_id=None):
        base = '/w/' + esc(token)
        body = "<nav><a href='" + base + "/export'>Export everything</a></nav><form class=confirm data-message='" + esc(DELETE_WORKSPACE_CONFIRM) + "' method=post action='" + base + "/delete'><label><input type=checkbox name=confirm value=1 required> Confirm workspace deletion</label><button>Delete this workspace now</button></form>"
        return body + (self.run_delete_control(token, run_id) if run_id else '')

    @staticmethod
    def options(values, selected):
        return ''.join("<option value='" + esc(value) + "'" + (' selected' if value == selected else '') + '>' + esc(label) + '</option>' for value, label in values)

    def workspace_page(self, token, workspace, message='', log_text='', status=200, outages='[]', extra=None):
        store = self.server.store
        policy = store.load_json(workspace / 'policy.json')
        keys = store.load_json(workspace / 'keys.json')
        meta = store.load_json(workspace / 'meta.json')
        sample = '<p>' + esc(SAMPLE_NOTICE) + '</p>' if meta.get('sample') else ''
        warning = DESTRUCTIVE_ZERO_WARNING if policy.get('rules', {}).get('destructive', {}).get('per_action_max') == 0 else ''
        runs = ''.join("<li><a href='/w/" + esc(token) + '/run/' + esc(path.stem) + "'>" + esc(path.stem) + '</a>' + self.run_delete_control(token, path.stem) + '</li>' for path in sorted((workspace / 'runs').glob('*.json')))
        if meta.get('sample'):
            sample += '<p>SampleRefundBot makes 40 refunds of 2,500 minor units; SampleOpsBot attempts one transfer during an outage.</p>'
        fields = []
        for kind in KINDS:
            rule = policy.get('rules', {}).get(kind, {})
            checked = ' checked' if kind in policy.get('rules', {}) else ''
            risks = self.options([('high', 'high'), ('low', 'low')], rule.get('risk', 'high'))
            fields.append("<fieldset><legend>" + kind + "</legend><input type=checkbox name='" + kind + "_enabled' value=1" + checked + "><select name='" + kind + "_risk'>" + risks + '</select>' + ('' if kind == 'destructive' else "<input name='" + kind + "_per_action_max' value='" + esc(rule.get('per_action_max', '')) + "' placeholder='per action max'>") + "<input name='" + kind + ("_per_day_count_max'" if kind == 'destructive' else "_per_day_max'") + " value='" + esc(rule.get('per_day_count_max', rule.get('per_day_max', ''))) + "' placeholder='daily max'>" + (' counts as 1' if kind == 'destructive' else '') + '</fieldset>')
        body = self.controls(token) + sample + '<p><strong>Bookmark warning:</strong> this link is the only key; it cannot be recovered.</p><p>' + esc(message) + '</p><p>' + esc(warning) + '</p><p>' + esc(REPLAY_NOTICE) + '</p><p>' + esc(ROW_NOTICE) + ' ' + esc(STORAGE_NOTICE) + ' ' + esc(IDENTIFIER_NOTICE) + '</p><p>' + esc(FORMAT_NOTICE) + '</p><p>Storage used: ' + str(store.size(workspace)) + ' bytes.</p>'
        body += "<h2>Policy JSON</h2><form class=editor method=post action='/w/" + esc(token) + "/policy'><textarea name=policy_json rows=18 cols=100>" + esc(json.dumps(policy, indent=2)) + '</textarea><button>Save policy JSON</button></form>'
        scope = policy.get('daily_scope', 'per_agent')
        # Keep the existing unquoted scope values for backwards compatibility.
        options = ''.join('<option value=' + value + (' selected' if value == scope else '') + '>' + label + '</option>' for value, label in [('per_agent', 'per agent'), ('all_agents', 'all agents')])
        modes = self.options([('open', 'open'), ('closed', 'closed')], policy.get('fail_mode', {}).get('low', 'open'))
        body += "<h2>Policy form</h2><form class=editor method=post action='/w/" + esc(token) + "/policy'><input type=hidden name=editor value=form><label>Currency <input name=currency value='" + esc(policy.get('currency', 'USD')) + "'></label><label>Daily scope <select name=daily_scope>" + options + '</select></label><label>Low-risk outage behavior <select name=low_fail_mode>' + modes + '</select></label>' + ''.join(fields) + '<button>Save policy form</button></form>'
        body += "<h2>Replay</h2><form class=editor method=post action='/w/" + esc(token) + "/replay'><label>Upload CSV or JSONL <input id=logfile type=file accept='.csv,.json,.jsonl,text/plain'></label><textarea id=logtext name=log_text rows=16 cols=110>" + esc(log_text) + '</textarea><label>Outage windows JSON <textarea name=outages>' + esc(outages) + "</textarea></label><button>Run deterministic replay</button></form><script nonce='" + self._nonce + "'>document.getElementById('logfile').addEventListener('change',function(){var f=this.files[0];if(!f)return;if(f.size>1048576){alert('Log exceeds 1 MB');return;}var r=new FileReader();r.onload=function(){document.getElementById('logtext').value=r.result;};r.readAsText(f);});</script><h2>Past runs</h2><ul>" + runs + '</ul>'
        body += '<h2>Verification keys</h2><p><strong>A key holder can forge bundles.</strong></p><pre>signing.key: ' + esc(keys['sign']) + '\ntsa.key: ' + esc(keys['tsa']) + '</pre>'
        body += "<p><a href='/w/" + esc(token) + "/keys/signing.key'>Download signing.key</a> <a href='/w/" + esc(token) + "/keys/tsa.key'>Download tsa.key</a></p>"
        self.page('LimitLatch workspace', body, status, extra=extra)

    def run_page(self, token, workspace, run_id, query):
        path = workspace / 'runs' / (run_id + '.json')
        if not path.is_file():
            self.page('Workspace not found', 'workspace not found', 404)
            return
        if not self.server.read_slots.acquire(timeout=READ_QUEUE_SECONDS):
            self.page('Busy', esc(BUSY_MESSAGE), 429)
            return
        try:
            keys = self.server.store.load_json(workspace / 'keys.json')
            result = run_job(str(self.server.store.root), 'stored', (str(path), keys, query))
        except (ValueError, ProcessingLimit):
            self.page('Run unavailable', 'The stored run could not be processed.', 500)
            return
        finally:
            self.server.read_slots.release()
        verified = result['verification']
        verification = 'Stored evidence verification passed' if verified.get('ok') else 'Stored evidence verification failed: ' + esc(verified.get('reason'))
        if verified.get('first_bad_seq') is not None:
            verification += '; first bad sequence number: ' + str(verified['first_bad_seq'])
        def table(rows, columns):
            return '<table><tr>' + ''.join('<th>' + esc(key) + '</th>' for key in columns) + '</tr>' + ''.join('<tr>' + ''.join('<td>' + esc(row.get(key, '')) + '</td>' for key in columns) + '</tr>' for row in rows) + '</table>'
        meta = self.server.store.load_json(workspace / 'meta.json')
        sample = '<p>' + esc(SAMPLE_NOTICE) + '</p>' if meta.get('sample') else ''
        body = self.controls(token, run_id) + sample + '<p>' + esc(REPLAY_NOTICE) + '</p><h2>' + verification + '</h2><p><a href="/w/' + esc(token) + '/run/' + esc(run_id) + '/bundle.json">Download bundle.json</a></p>'
        body += '<h2>Summary</h2><pre>' + esc(json.dumps(result['summary'], indent=2)) + '</pre><h2>Decisions</h2>' + table(result['results']['rows'], ['input_row', 'ts', 'agent_id', 'tool', 'kind', 'amount_minor', 'decision', 'reason', 'running_committed'])
        body += '<h2>Per-day totals</h2>' + table(result['totals']['rows'], ['agent', 'kind', 'day', 'committed']) + '<h2>Evidence chain</h2>' + table(result['entries']['rows'], ['seq', 'time', 'kind', 'phase', 'decision', 'reason', 'entry_hash'])
        body += '<h2>Operational control report</h2><p>Not an insurance rating.</p><pre>' + esc(json.dumps(result['report'], indent=2)) + '</pre>'
        self.page('Replay result', body)

    def get_page(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == '/':
            self.page('LimitLatch', '<p>Paste an agent action log and policy to see which calls would have been blocked.</p><form method=post action=/start><button>Start a workspace</button></form><form method=post action=/sample><button>Try with sample data</button> made-up data</form><p><a href=/verify>Open the stateless verifier</a></p>')
            return
        if path == '/verify':
            self.page('Verify a bundle', '<form method=post action=/verify><textarea name=bundle rows=20 cols=100></textarea><input name=signing_key placeholder="signing key hex"><input name=tsa_key placeholder="timestamp key hex"><button>Verify</button></form>')
            return
        match = re.fullmatch(r'/w/([^/]+)(.*)', path)
        if not match:
            self.page('Not found', 'Not found.', 404)
            return
        token, suffix = match.groups()
        workspace = self.workspace(token)
        if workspace is None:
            return
        if suffix == '':
            message = 'Policy saved.' if parse_qs(parsed.query).get('saved') == ['1'] else ''
            self.workspace_page(token, workspace, message)
            return
        if suffix == '/export':
            self.export_workspace(workspace)
            return
        key = re.fullmatch(r'/keys/(signing\.key|tsa\.key)', suffix)
        if key:
            keys = self.server.store.load_json(workspace / 'keys.json')
            name = 'sign' if key.group(1) == 'signing.key' else 'tsa'
            self.send_bytes(200, bytes.fromhex(keys[name]), 'application/octet-stream', {'Content-Disposition': 'attachment; filename="' + key.group(1) + '"'})
            return
        run = re.fullmatch(r'/run/([A-Za-z0-9_-]{1,80})(/bundle\.json)?', suffix)
        if run:
            if run.group(2):
                self.bundle(workspace, run.group(1))
            else:
                self.run_page(token, workspace, run.group(1), parse_qs(parsed.query))
            return
        self.page('Workspace not found', 'workspace not found', 404)

    def bundle(self, workspace, run_id):
        path = workspace / 'runs' / (run_id + '.json')
        if not path.is_file() or not self.server.read_slots.acquire(timeout=READ_QUEUE_SECONDS):
            self.page('Run unavailable', esc(BUSY_MESSAGE), 429 if path.is_file() else 404)
            return
        try:
            keys = self.server.store.load_json(workspace / 'keys.json')
            checked = run_job(str(self.server.store.root), 'stored', (str(path), keys, {}))['verification']
            if not checked.get('ok'):
                detail = 'Stored evidence verification failed: ' + esc(checked.get('reason'))
                if checked.get('first_bad_seq') is not None:
                    detail += '; first bad sequence number: ' + str(checked['first_bad_seq'])
                self.page('Damaged bundle', detail, 409)
                return
            handle = run_job(str(self.server.store.root), 'bundle', (str(path), keys, {}))
            self.send_file(handle, 'bundle.json')
        except (ValueError, ProcessingLimit):
            self.page('Run unavailable', 'The stored run could not be processed.', 500)
        finally:
            self.server.read_slots.release()

    def export_workspace(self, workspace):
        if not self.server.read_slots.acquire(timeout=READ_QUEUE_SECONDS):
            self.page('Busy', esc(BUSY_MESSAGE), 429)
            return
        handle = None
        try:
            policy = self.server.store.load_json(workspace / 'policy.json')
            keys = self.server.store.load_json(workspace / 'keys.json')
            meta = self.server.store.load_json(workspace / 'meta.json')
            runs = []
            for path in sorted((workspace / 'runs').glob('*.json')):
                if path.stat().st_size > MAX_RESULT_BYTES:
                    raise ValueError
                with path.open(encoding='utf-8') as source:
                    runs.append(json.load(source))
            payload = {'policy': policy, 'runs': runs, 'keys': keys, 'sample_data': bool(meta.get('sample')), 'data_label': SAMPLE_NOTICE if meta.get('sample') else ''}
            encoded = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode()
            handle = tempfile.SpooledTemporaryFile(max_size=1024 * 1024)
            handle.write(encoded)
            handle.seek(0)
        except (OSError, ValueError):
            if handle is not None:
                handle.close()
            self.page('Export unavailable', 'The workspace could not be exported.', 500)
            return
        finally:
            self.server.read_slots.release()
        self.send_file(handle, 'limitlatch-export.json')

    def do_GET(self):
        if urlparse(self.path).path == '/healthz':
            self.send_bytes(200, b'ok', 'text/plain')
            return
        if not self.valid_host():
            self.page('Request rejected', 'Request rejected.', 421)
            return
        try:
            self.get_page()
        except Exception:
            self.page('Server error', 'The request could not be completed.', 500)

    def form_policy(self, form):
        rules = {}
        for kind in KINDS:
            if form.get(kind + '_enabled') != '1':
                continue
            rule = {'risk': form.get(kind + '_risk', 'high')}
            if kind == 'destructive':
                value = form.get(kind + '_per_day_count_max', '')
                if value != '':
                    rule['per_day_count_max'] = int(value)
                if form.get('destructive_confirmed') == '1' or rule['risk'] == 'high':
                    rule['require_flag'] = 'confirmed'
            else:
                for name in ('per_action_max', 'per_day_max'):
                    value = form.get(kind + '_' + name, '')
                    if value != '':
                        rule[name] = int(value)
            rules[kind] = rule
        return {'currency': form.get('currency', 'USD'), 'rules': rules, 'fail_mode': {'high': 'closed', 'low': form.get('low_fail_mode', 'open')}, 'daily_scope': form.get('daily_scope', 'per_agent')}

    def _save_run(self, token, workspace, text, outages):
        store = self.server.store
        with store._guard, store.lock(workspace.name):
            if not workspace.exists():
                raise FileNotFoundError
            if len(list((workspace / 'runs').glob('*.json'))) >= MAX_RUNS:
                raise ValueError('20-run limit reached; delete a run before saving another')
            policy = store.load_json(workspace / 'policy.json')
            keys = store.load_json(workspace / 'keys.json')
            digest = Policy.load(policy).digest()
        result = run_job(str(store.root), 'replay', (policy, text, outages, keys))
        run_id = utc_now().strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(5)
        with store._guard, store.lock(workspace.name):
            if not workspace.exists():
                raise FileNotFoundError
            if Policy.load(store.load_json(workspace / 'policy.json')).digest() != digest:
                raise ValueError('policy changed during replay; nothing was saved')
            if len(list((workspace / 'runs').glob('*.json'))) >= MAX_RUNS:
                raise ValueError('20-run limit reached; delete a run before saving another')
            store.atomic(workspace / 'runs' / (run_id + '.json'), result)
        return run_id

    def do_POST(self):
        if not self.valid_post():
            self.close_connection = True
            self.page('Request rejected', 'Cross-site request rejected.', 403)
            return
        form = self.read_form()
        if form is None:
            return
        path = urlparse(self.path).path
        try:
            if path in {'/start', '/sample'}:
                token = self.server.store.create(self.source(), sample=path == '/sample')
                if path == '/sample':
                    workspace = self.server.store.require(token)
                    base = utc_now().replace(hour=12, minute=0, second=0, microsecond=0)
                    rows = ['ts,agent_id,tool,kind,amount_minor,currency,confirmed']
                    for number in range(40):
                        rows.append(f'{(base + dt.timedelta(seconds=number)).isoformat()},SampleRefundBot,refund,refund,2500,USD,false')
                    rows.append(f'{(base + dt.timedelta(minutes=2)).isoformat()},SampleOpsBot,transfer,transfer,1000,USD,false')
                    outages = [{'start': (base + dt.timedelta(seconds=119)).isoformat(), 'end': (base + dt.timedelta(seconds=121)).isoformat()}]
                    try:
                        self._save_run(token, workspace, '\n'.join(rows), outages)
                    except Exception:
                        self.server.store.delete(workspace)
                        raise
                self.redirect('/w/' + token)
                return
            if path == '/verify':
                if not self.server.expensive_slots.acquire(timeout=QUEUE_SECONDS):
                    self.page('Busy', esc(BUSY_MESSAGE), 429)
                    return
                try:
                    result = run_job(str(self.server.store.root), 'verify', (form.get('bundle', ''), form.get('signing_key', ''), form.get('tsa_key', '')))
                finally:
                    self.server.expensive_slots.release()
                text = 'Verification passed.' if result.get('ok') else 'Verification failed: ' + esc(result.get('reason'))
                if result.get('first_bad_seq') is not None:
                    text += ' first bad sequence number: ' + str(result['first_bad_seq'])
                self.page('Bundle verification', '<p>' + text + '</p>')
                return
            match = re.fullmatch(r'/w/([^/]+)(.*)', path)
            if not match:
                self.page('Not found', 'Not found.', 404)
                return
            token, suffix = match.groups()
            workspace = self.workspace(token)
            if workspace is None:
                return
            if suffix == '/policy':
                try:
                    supplied = self.form_policy(form) if form.get('editor') == 'form' else json.loads(form.get('policy_json', ''))
                    policy = clean_policy(supplied).data
                except (ValueError, TypeError, PolicyError):
                    self.workspace_page(token, workspace, 'Policy error: unsupported or invalid fields; nothing was saved.')
                    return
                self.server.store.atomic(workspace / 'policy.json', policy)
                # Browser form submissions use PRG. Preserve the existing
                # representation response for non-browser API clients.
                if 'text/html' in self.headers.get('Accept', ''):
                    self.redirect('/w/' + token + '?saved=1')
                else:
                    self.workspace_page(token, workspace, 'Policy saved.')
                return
            if suffix == '/replay':
                text = form.get('log_text', '')
                outages = form.get('outages', '[]')
                if not self.server.expensive_slots.acquire(timeout=QUEUE_SECONDS):
                    self.workspace_page(token, workspace, BUSY_MESSAGE, text, status=429, outages=outages)
                    return
                try:
                    run_id = self._save_run(token, workspace, text, outages)
                except FileNotFoundError:
                    if not workspace.exists():
                        self.page('Workspace not found', 'workspace not found', 404)
                    else:
                        self.workspace_page(token, workspace, 'Storage unavailable; the run could not be saved.', text, status=507, outages=outages)
                    return
                except SourceLimited as exc:
                    self.workspace_page(token, workspace, 'Replay error: ' + str(exc), text, status=429, outages=outages)
                    return
                except WriteRefused as exc:
                    self.workspace_page(token, workspace, 'Replay error: ' + str(exc), text, status=507, outages=outages)
                    return
                except (ValueError, ProcessingLimit) as exc:
                    self.workspace_page(token, workspace, 'Replay error: ' + str(exc), text, outages=outages)
                    return
                except OSError:
                    self.workspace_page(token, workspace, 'Storage unavailable; the run could not be saved.', text, status=507, outages=outages)
                    return
                finally:
                    self.server.expensive_slots.release()
                self.redirect('/w/' + token + '/run/' + run_id)
                return
            if suffix == '/delete':
                if form.get('confirm') not in {'1', None}:
                    self.page('Confirmation required', 'Confirmation required.', 400)
                    return
                self.server.store.delete(workspace)
                self.redirect('/')
                return
            if suffix == '/rotate':
                replace = form.get('replace_keys') == '1'
                if replace and form.get('confirm') != '1':
                    self.page('Confirmation required', 'Confirmation required.', 400)
                    return
                token = self.server.store.rotate(workspace, replace)
                self.redirect('/w/' + token)
                return
            run_delete = re.fullmatch(r'/run/([A-Za-z0-9_-]{1,80})/delete', suffix)
            if run_delete:
                target = workspace / 'runs' / (run_delete.group(1) + '.json')
                if not self.server.store.delete_run(workspace, target):
                    self.page('Workspace not found', 'workspace not found', 404)
                    return
                self.redirect('/w/' + token)
                return
            self.page('Not found', 'Not found.', 404)
        except SourceLimited as exc:
            self.page('Workspace limit reached', esc(exc), 429)
        except WriteRefused as exc:
            self.page('Storage limit reached', esc(exc), 507)
        except OSError:
            self.page('Storage unavailable', 'The storage operation could not be completed. Check the workspace before retrying.', 507)
        except ValueError:
            self.page('Request rejected', 'The supplied request was invalid.', 400)
        except Exception:
            self.page('Server error', 'The request could not be completed.', 500)


def make_server(host='127.0.0.1', port=8080, data_dir=None, data_cap_mb=200, public_base_url=None, https_terminated=False, sweep_interval=60):
    if data_dir is None:
        data_dir = os.environ.get('DATA_DIR')
    if not data_dir:
        raise ValueError('DATA_DIR is required')
    base = normalize_base(os.environ.get('PUBLIC_BASE_URL', '') if public_base_url is None else public_base_url)
    https_terminated = bool(https_terminated or os.environ.get('APP_HTTPS_TERMINATED', '').lower() in {'1', 'true', 'yes', 'on'})
    server = SecureServer((host, port), Handler)
    bound_host, bound_port = server.server_address[:2]
    allowed = {f'{host}:{bound_port}'.lower(), f'{bound_host}:{bound_port}'.lower(), f'127.0.0.1:{bound_port}', f'localhost:{bound_port}'}
    if base:
        allowed.add(urlparse(base).netloc.lower())
    configured = os.environ.get('APP_TRUSTED_PROXIES', '').strip()
    proxies = tuple(ipaddress.ip_network(item.strip(), strict=False) for item in configured.split(',') if item.strip())
    local_proxy = bool(https_terminated and not proxies and ipaddress.ip_address(bound_host).is_loopback)
    server.RequestHandlerClass = type('ConfiguredHandler', (Handler,), {'allowed_hosts': allowed, 'public_base_url': base, 'trusted_proxies': proxies, 'local_proxy_forwarding': local_proxy})
    server.store = WorkspaceStore(data_dir, data_cap_mb)
    server.public_base_url = base
    server.origin = base or ('http://' + f'{bound_host}:{bound_port}')
    server.https_terminated = https_terminated
    server.expensive_slots = threading.BoundedSemaphore(MAX_EXPENSIVE_OPERATIONS)
    server.read_slots = threading.BoundedSemaphore(MAX_READ_OPERATIONS)
    server.header_deadline = HEADER_DEADLINE
    server.upload_deadline = UPLOAD_DEADLINE
    server._stop_sweeper = threading.Event()
    sweep_stale_jobs(data_dir)
    def sweep_loop():
        while not server._stop_sweeper.wait(sweep_interval):
            try:
                server.store.sweep()
                sweep_stale_jobs(data_dir)
            except OSError:
                # Temporary filesystem failure must not permanently stop TTL
                # and admission cleanup or print workspace paths.
                pass
    server.sweeper = threading.Thread(target=sweep_loop, daemon=True)
    server.sweeper.start()
    return server


if __name__ == '__main__':
    application = make_server(os.environ.get('APP_HOST', '127.0.0.1'), int(os.environ.get('PORT', '8080')), os.environ.get('DATA_DIR'), float(os.environ.get('APP_DATA_CAP_MB', '200')))
    try:
        application.serve_forever()
    finally:
        application.server_close()
