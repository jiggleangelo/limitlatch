import datetime as dt
import hashlib
import hmac
import inspect
import json
import re
import secrets
import threading
from dataclasses import dataclass
from functools import wraps


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class PolicyError(ValueError):
    pass


class LimitExceeded(Exception):
    pass


class EnforcerUnavailable(Exception):
    pass


class EvidenceUnavailable(Exception):
    pass


class WormViolation(Exception):
    pass


class Blocked(Exception):
    def __init__(self, reason, seq=None):
        super().__init__(reason)
        self.reason = reason
        self.seq = seq


class Policy:
    KINDS = {"refund", "transfer", "spend", "destructive", "read"}

    def __init__(self, data):
        self.data = data

    @classmethod
    def load(cls, data):
        try:
            data = json.loads(json.dumps(data))
        except (TypeError, ValueError) as exc:
            raise PolicyError("policy must be JSON-compatible") from exc
        if not isinstance(data, dict) or not isinstance(data.get("currency"), str) or not data["currency"]:
            raise PolicyError("missing currency")
        rules = data.get("rules")
        if not isinstance(rules, dict) or not rules:
            raise PolicyError("missing rules")
        if set(rules) - cls.KINDS:
            raise PolicyError("unknown kind")
        fail_mode = data.get("fail_mode", {})
        # Direct SDK callers and the public verifier must get PolicyError, not
        # AttributeError, when fail_mode is not an object.
        if not isinstance(fail_mode, dict):
            raise PolicyError("fail_mode must be an object")
        if fail_mode.get("high") != "closed":
            raise PolicyError("high risk must fail closed")
        if fail_mode.get("low", "open") not in {"open", "closed"}:
            raise PolicyError("invalid low-risk fail mode")
        for kind, rule in rules.items():
            if not isinstance(rule, dict) or rule.get("risk") not in {"high", "low"}:
                raise PolicyError("invalid risk")
            for key, value in rule.items():
                if key.endswith("max") and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                    raise PolicyError("limits must be non-negative integers")
            if kind == "destructive" and "per_day_max" in rule:
                raise PolicyError("destructive actions use a count limit")
        return cls(data)

    @property
    def currency(self):
        return self.data["currency"]

    def rule(self, kind):
        if kind not in self.data["rules"]:
            raise PolicyError("unknown kind")
        return self.data["rules"][kind]

    def digest(self):
        return hashlib.sha256(canonical(self.data)).hexdigest()


class SystemClock:
    def now(self):
        return dt.datetime.now(dt.timezone.utc)


class FixedClock:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value

    def set(self, value):
        self.value = value


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _utc_iso(value):
    return _aware(value).isoformat().replace("+00:00", "Z")


@dataclass
class Reservation:
    reservation_id: str
    key: tuple
    amount: int
    created_at: dt.datetime
    state: str = "reserved"
    overrun: bool = False
    anomaly: bool = False
    anomaly_reason: str | None = None


class BudgetLedger:
    """Track daily budgets; Guard enforces the limit on each tool action."""

    def __init__(self, policy, clock, reservation_ttl=dt.timedelta(minutes=5)):
        self.policy = policy
        self.clock = clock
        self.reservation_ttl = reservation_ttl
        self._lock = threading.RLock()
        self._totals = {}
        self._reservations = {}
        self.anomalies = 0
        self.anomaly_counts = {"unknown": 0, "already_final": 0, "expired": 0}

    def _sweep_locked(self, now):
        if self.reservation_ttl is None:
            return 0
        expired = 0
        for reservation in self._reservations.values():
            if reservation.state == "reserved" and now - reservation.created_at >= self.reservation_ttl:
                total = self._totals[reservation.key]
                total["reserved"] -= reservation.amount
                total["committed"] += reservation.amount
                reservation.state = "expired"
                reservation.anomaly = True
                reservation.anomaly_reason = "expired"
                self.anomalies += 1
                self.anomaly_counts["expired"] += 1
                expired += 1
        return expired

    def sweep_expired(self):
        with self._lock:
            return self._sweep_locked(_aware(self.clock.now()))

    def reserve(self, agent_id, kind, amount):
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError("invalid amount")
        rule = self.policy.rule(kind)
        cap = rule.get("per_day_count_max") if kind == "destructive" else rule.get("per_day_max")
        now = _aware(self.clock.now())
        key = (str(agent_id), kind, now.date().isoformat())
        with self._lock:
            self._sweep_locked(now)
            total = self._totals.setdefault(key, {"committed": 0, "reserved": 0})
            if cap is not None and total["committed"] + total["reserved"] + amount > cap:
                raise LimitExceeded("daily_limit")
            total["reserved"] += amount
            reservation = Reservation(secrets.token_hex(16), key, amount, now)
            self._reservations[reservation.reservation_id] = reservation
            return reservation

    def _anomaly(self, supplied, reason):
        supplied.anomaly = True
        supplied.anomaly_reason = reason
        self.anomalies += 1
        self.anomaly_counts[reason] += 1
        return supplied

    def reconcile(self, reservation, actual):
        if isinstance(actual, bool) or not isinstance(actual, int) or actual < 0:
            raise ValueError("invalid actual")
        with self._lock:
            self._sweep_locked(_aware(self.clock.now()))
            saved = self._reservations.get(reservation.reservation_id)
            if saved is None:
                return self._anomaly(reservation, "unknown")
            total = self._totals[saved.key]
            if saved.state == "expired":
                total["committed"] += max(actual, saved.amount) - saved.amount
                saved.state = "committed"
                saved.overrun = actual > saved.amount
                reservation.state = saved.state
                reservation.overrun = saved.overrun
                reservation.anomaly = saved.anomaly
                reservation.anomaly_reason = saved.anomaly_reason
                return reservation
            if saved.state != "reserved":
                return self._anomaly(reservation, "already_final")
            total["reserved"] -= saved.amount
            total["committed"] += actual
            saved.state = "committed"
            saved.overrun = actual > saved.amount
            reservation.state = saved.state
            reservation.overrun = saved.overrun
            return reservation

    def release(self, reservation):
        with self._lock:
            self._sweep_locked(_aware(self.clock.now()))
            saved = self._reservations.get(reservation.reservation_id)
            if saved is None:
                self._anomaly(reservation, "unknown")
                return False
            if saved.state != "reserved":
                self._anomaly(reservation, "already_final")
                return False
            self._totals[saved.key]["reserved"] -= saved.amount
            saved.state = "released"
            reservation.state = "released"
            return True

    def totals(self):
        with self._lock:
            self._sweep_locked(_aware(self.clock.now()))
            return json.loads(json.dumps({"|".join(key): value for key, value in self._totals.items()}))


class LocalEnforcer:
    def __init__(self, ledger):
        self.ledger = ledger

    def reserve(self, agent_id, kind, amount):
        return self.ledger.reserve(agent_id, kind, amount)

    def reconcile(self, reservation, actual):
        return self.ledger.reconcile(reservation, actual)

    def release(self, reservation):
        return self.ledger.release(reservation)


class FlakyEnforcer:
    def __init__(self, inner):
        self.inner = inner
        self.down = False

    def _check(self):
        if self.down:
            raise EnforcerUnavailable("enforcer unavailable")

    def reserve(self, *args):
        self._check()
        return self.inner.reserve(*args)

    def reconcile(self, *args):
        self._check()
        return self.inner.reconcile(*args)

    def release(self, *args):
        self._check()
        return self.inner.release(*args)


class MemoryVault:
    def __init__(self):
        self.__values = {}
        self.__lock = threading.Lock()

    def put(self, value):
        ref = "v_" + secrets.token_hex(16)
        with self.__lock:
            self.__values[ref] = value
        return ref

    def count(self):
        with self.__lock:
            return len(self.__values)


EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE = re.compile(r"^\+?[\d\s()-]{7,}$")
CONTACT_KEYS = {"email", "phone", "name", "address", "contact", "customer_email"}
CLEAR_KEYS = {"amount", "currency", "confirmed"}
CURRENCIES = frozenset({"USD", "EUR", "GBP", "JPY", "CAD", "AUD", "NZD", "CHF", "CNY", "INR"})


def redact_args(values, vault, tenant_key):
    refs = []

    def sensitive_key(key):
        return key in CONTACT_KEYS or any(part in key for part in ("email", "phone", "contact", "address", "name", "account"))

    def walk(value, key=""):
        key = key.lower()
        # Validate clear fields before contact detection or container traversal.
        if key in CLEAR_KEYS:
            if key == "amount" and isinstance(value, int) and not isinstance(value, bool):
                return value
            if key == "confirmed" and isinstance(value, bool):
                return value
            if key == "currency" and isinstance(value, str) and value in CURRENCIES:
                return value
            return "[redacted]"
        if isinstance(value, dict):
            return {str(k): walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [walk(item, key) for item in value]
        if isinstance(value, str) and (sensitive_key(key) or EMAIL.fullmatch(value) or PHONE.fullmatch(value)):
            ref = vault.put(value)
            refs.append(ref)
            return ref
        if value is None:
            return None
        return "[redacted]"

    redacted = walk(values)
    nonce = secrets.token_hex(16)
    digest = hmac.new(tenant_key, canonical({"nonce": nonce, "args": redacted}), hashlib.sha256).hexdigest()
    return {"args": redacted, "vault_refs": refs, "args_digest": digest, "digest_nonce": nonce}


class MemoryWormStore:
    def __init__(self, name="memory"):
        self.name = name
        self._values = {}
        self._lock = threading.RLock()
        self.fail_next_put = False

    def put(self, key, value):
        if not isinstance(value, bytes):
            raise TypeError("WORM values must be bytes")
        with self._lock:
            if self.fail_next_put:
                self.fail_next_put = False
                raise OSError("store unavailable")
            existing = self._values.get(key)
            if existing is not None:
                if hmac.compare_digest(existing, value):
                    return False
                raise WormViolation("immutable key already exists")
            self._values[key] = value
            return True

    def get(self, key):
        with self._lock:
            return self._values[key]

    def keys(self):
        with self._lock:
            return sorted(self._values)

    def _demo_corrupt(self, key, value):
        with self._lock:
            if key not in self._values:
                raise KeyError(key)
            self._values[key] = value


class FakeTSA:
    def __init__(self, key, clock):
        self.key = key
        self.clock = clock
        self.down = False

    def issue(self, seq, digest):
        if self.down:
            raise OSError("timestamp authority unavailable")
        token = {"seq": seq, "digest": digest, "time": _utc_iso(self.clock.now())}
        token["mac"] = hmac.new(self.key, canonical(token), hashlib.sha256).hexdigest()
        return token

    @staticmethod
    def verify(token, key):
        if not isinstance(token, dict) or not isinstance(token.get("mac"), str):
            return False
        unsigned = {k: token[k] for k in ("seq", "digest", "time") if k in token}
        expected = hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, token["mac"])


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    first_bad_seq: int | None = None


class EvidenceLog:
    def __init__(self, stores, tsa, clock):
        if len(stores) < 2:
            raise ValueError("at least two evidence stores are required")
        self.stores = list(stores)
        self.tsa = tsa
        self.clock = clock
        self._entries = []
        self._anchors = []
        self._pending = None
        self._lock = threading.RLock()

    @property
    def seq(self):
        with self._lock:
            return len(self._entries)

    def _replicate(self, entry):
        key = f"entry/{entry['seq']:08d}"
        encoded = canonical(entry)
        for store in self.stores:
            store.put(key, encoded)

    def _commit_pending(self):
        if self._pending is None:
            return
        entry = self._pending
        self._replicate(entry)
        self._entries.append(entry)
        self._pending = None
        try:
            self._anchors.append(self.tsa.issue(entry["seq"], entry["entry_hash"]))
        except Exception as exc:
            raise EvidenceUnavailable("timestamp authority unavailable") from exc

    def append(self, payload):
        with self._lock:
            try:
                self._commit_pending()
            except (OSError, WormViolation) as exc:
                raise EvidenceUnavailable("evidence replication unavailable") from exc
            seq = len(self._entries)
            prev_hash = self._entries[-1]["entry_hash"] if self._entries else "0" * 64
            entry = dict(payload)
            entry.update({"seq": seq, "time": _utc_iso(self.clock.now()), "prev_hash": prev_hash})
            entry["entry_hash"] = hashlib.sha256(canonical(entry)).hexdigest()
            self._pending = entry
            try:
                self._commit_pending()
            except EvidenceUnavailable:
                raise
            except (OSError, WormViolation) as exc:
                raise EvidenceUnavailable("evidence replication unavailable") from exc
            return json.loads(json.dumps(entry))

    def entries(self):
        with self._lock:
            return json.loads(json.dumps(self._entries))

    def anchors(self):
        with self._lock:
            return json.loads(json.dumps(self._anchors))

    def verify(self):
        with self._lock:
            try:
                key_sets = [store.keys() for store in self.stores]
                if any(keys != key_sets[0] for keys in key_sets[1:]):
                    return VerifyResult(False, "store_mismatch", 0)
                expected_keys = [f"entry/{i:08d}" for i in range(len(key_sets[0]))]
                if key_sets[0] != expected_keys:
                    return VerifyResult(False, "sequence_gap", _first_gap(key_sets[0]))
                entries = []
                for index, key in enumerate(expected_keys):
                    blobs = [store.get(key) for store in self.stores]
                    if any(blob != blobs[0] for blob in blobs[1:]):
                        return VerifyResult(False, "store_mismatch", index)
                    entries.append(json.loads(blobs[0]))
            except Exception:
                return VerifyResult(False, "store_read_failure", None)
            result = _verify_entries(entries)
            if not result.ok:
                return result
            if entries != self._entries:
                return VerifyResult(False, "memory_store_mismatch", _first_difference(entries, self._entries))
            anchors = {anchor.get("seq"): anchor for anchor in self._anchors}
            for entry in entries:
                anchor = anchors.get(entry["seq"])
                if anchor is None:
                    return VerifyResult(False, "missing_anchor", entry["seq"])
                if anchor.get("digest") != entry["entry_hash"] or not FakeTSA.verify(anchor, self.tsa.key):
                    return VerifyResult(False, "bad_anchor", entry["seq"])
            return VerifyResult(True, "verification passed", None)


class Signer:
    def __init__(self, key):
        self.key = key

    def sign(self, value):
        return hmac.new(self.key, canonical(value), hashlib.sha256).hexdigest()

    @staticmethod
    def verify(value, signature, key):
        if not isinstance(signature, str):
            return False
        expected = hmac.new(key, canonical(value), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def export_bundle(log, policy, signer, clock):
    verification = log.verify()
    if not verification.ok:
        raise EvidenceUnavailable("evidence verification failed")
    body = {
        "format": "agentguard-evidence/0.1",
        "exported_at": _utc_iso(clock.now()),
        "policy": policy.data,
        "policy_digest": policy.digest(),
        "entries": log.entries(),
        "anchors": log.anchors(),
    }
    bundle = dict(body)
    bundle["signature"] = signer.sign(body)
    return bundle


def verify_bundle(bundle, signing_key, tsa_key):
    if not isinstance(bundle, dict):
        return VerifyResult(False, "invalid_bundle", None)
    if not signing_key:
        return VerifyResult(False, "bad_signature", None)
    if not tsa_key:
        return VerifyResult(False, "bad_tsa_key", None)
    signature = bundle.get("signature")
    body = {key: value for key, value in bundle.items() if key != "signature"}
    if not Signer.verify(body, signature, signing_key):
        return VerifyResult(False, "bad_signature", None)
    if body.get("format") != "agentguard-evidence/0.1":
        return VerifyResult(False, "invalid_format", None)
    try:
        policy = Policy.load(body["policy"])
    except (KeyError, PolicyError):
        return VerifyResult(False, "invalid_policy", None)
    if not hmac.compare_digest(policy.digest(), str(body.get("policy_digest", ""))):
        return VerifyResult(False, "policy_digest_mismatch", None)
    entries = body.get("entries")
    if not isinstance(entries, list):
        return VerifyResult(False, "invalid_entries", None)
    result = _verify_entries(entries)
    if not result.ok:
        return result
    anchors = body.get("anchors")
    if not isinstance(anchors, list):
        return VerifyResult(False, "invalid_anchors", None)
    by_seq = {anchor.get("seq"): anchor for anchor in anchors if isinstance(anchor, dict)}
    for entry in entries:
        seq = entry["seq"]
        anchor = by_seq.get(seq)
        if anchor is None:
            return VerifyResult(False, "missing_anchor", seq)
        if anchor.get("digest") != entry["entry_hash"] or not FakeTSA.verify(anchor, tsa_key):
            return VerifyResult(False, "bad_anchor", seq)
    return VerifyResult(True, "verification passed", None)


def _verify_entries(entries):
    previous = "0" * 64
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("seq") != index:
            return VerifyResult(False, "sequence_gap", index)
        if entry.get("prev_hash") != previous:
            return VerifyResult(False, "chain_mismatch", index)
        unsigned = {key: value for key, value in entry.items() if key != "entry_hash"}
        digest = hashlib.sha256(canonical(unsigned)).hexdigest()
        if not hmac.compare_digest(digest, str(entry.get("entry_hash", ""))):
            return VerifyResult(False, "bad_entry_hash", index)
        previous = digest
    return VerifyResult(True, "verification passed", None)


def _first_gap(keys):
    for index, key in enumerate(keys):
        if key != f"entry/{index:08d}":
            return index
    return len(keys)


def _first_difference(left, right):
    for index, pair in enumerate(zip(left, right)):
        if pair[0] != pair[1]:
            return index
    return min(len(left), len(right))


class Guard:
    def __init__(self, policy, enforcer, evidence, vault, clock, tenant_key, agent_id="agent"):
        self.policy = policy
        self.enforcer = enforcer
        self.evidence = evidence
        self.vault = vault
        self.clock = clock
        self.tenant_key = tenant_key
        self.agent_id = agent_id
        self.final_evidence_failures = 0
        self._reconciliation_lock = threading.RLock()
        self._pending_reconciliations = {}

    def _event(self, fn, kind, phase, decision, reason, redaction):
        return {
            "agent_id": self.agent_id,
            "tool": fn.__name__,
            "kind": kind,
            "phase": phase,
            "decision": decision,
            "reason": reason,
            "args": redaction["args"],
            "vault_refs": redaction["vault_refs"],
            "args_digest": redaction["args_digest"],
            "digest_nonce": redaction["digest_nonce"],
            "policy_digest": self.policy.digest(),
        }

    def _retry_pending_reconciliations(self):
        with self._reconciliation_lock:
            for reservation_id, (reservation, actual) in list(self._pending_reconciliations.items()):
                try:
                    self.enforcer.reconcile(reservation, actual)
                except EnforcerUnavailable:
                    return
                else:
                    self._pending_reconciliations.pop(reservation_id, None)

    def _reconcile_or_queue(self, reservation, actual):
        with self._reconciliation_lock:
            for _ in range(2):
                try:
                    self.enforcer.reconcile(reservation, actual)
                except EnforcerUnavailable:
                    continue
                else:
                    return
            self._pending_reconciliations[reservation.reservation_id] = (reservation, actual)
            self.final_evidence_failures += 1

    def tool(self, kind, amount_arg=None):
        rule = self.policy.rule(kind)

        def decorate(fn):
            signature = inspect.signature(fn)

            @wraps(fn)
            def wrapped(*args, **kwargs):
                try:
                    bound = signature.bind(*args, **kwargs)
                    bound.apply_defaults()
                except TypeError:
                    raise
                values = dict(bound.arguments)
                redaction = redact_args(values, self.vault, self.tenant_key)
                risk = rule["risk"]
                required = rule.get("require_flag")
                if required and values.get(required) is not True:
                    self._append_block(fn, kind, "missing_confirmation", redaction, risk)
                    raise Blocked("missing_confirmation")
                self._retry_pending_reconciliations()
                amount = 1 if kind == "destructive" else values.get(amount_arg, 0) if amount_arg else 0
                if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
                    raise ValueError("invalid amount")
                per_action = rule.get("per_action_max")
                if per_action is not None and amount > per_action:
                    self._append_block(fn, kind, "per_action_limit", redaction, risk)
                    raise Blocked("per_action_limit")
                reservation = None
                try:
                    reservation = self.enforcer.reserve(self.agent_id, kind, amount)
                except LimitExceeded as exc:
                    reason = str(exc)
                    self._append_block(fn, kind, reason, redaction, risk)
                    raise Blocked(reason) from None
                except EnforcerUnavailable:
                    if risk == "high" or self.policy.data.get("fail_mode", {}).get("low") == "closed":
                        self._append_block(fn, kind, "enforcer_unavailable", redaction, risk)
                        raise Blocked("enforcer_unavailable") from None
                if risk == "high":
                    try:
                        entry = self.evidence.append(self._event(fn, kind, "decision", "allow", "policy_allowed", redaction))
                    except EvidenceUnavailable:
                        if reservation is not None:
                            try:
                                self.enforcer.release(reservation)
                            except EnforcerUnavailable:
                                pass
                        raise Blocked("evidence_unavailable") from None
                else:
                    entry = None
                    try:
                        entry = self.evidence.append(self._event(fn, kind, "decision", "allow", "policy_allowed", redaction))
                    except EvidenceUnavailable:
                        if self.policy.data.get("fail_mode", {}).get("low") == "closed":
                            if reservation is not None:
                                try:
                                    self.enforcer.release(reservation)
                                except EnforcerUnavailable:
                                    pass
                            raise Blocked("evidence_unavailable") from None
                try:
                    result = fn(*args, **kwargs)
                except Exception:
                    # Invocation may have completed its side effect before failing.
                    # Without proof of non-execution, consume the reserved budget.
                    if reservation is not None:
                        self._reconcile_or_queue(reservation, amount)
                    self._outcome(fn, kind, "anomaly", "tool_error", redaction)
                    raise
                if reservation is not None:
                    actual = amount
                    if isinstance(result, dict) and isinstance(result.get("amount"), int) and not isinstance(result["amount"], bool):
                        actual = result["amount"]
                    self._reconcile_or_queue(reservation, actual)
                self._outcome(fn, kind, "success", "tool_completed", redaction)
                return result

            return wrapped

        return decorate

    def _append_block(self, fn, kind, reason, redaction, risk):
        try:
            self.evidence.append(self._event(fn, kind, "decision", "block", reason, redaction))
        except EvidenceUnavailable:
            if risk == "high":
                self.final_evidence_failures += 1

    def _outcome(self, fn, kind, decision, reason, redaction):
        try:
            self.evidence.append(self._event(fn, kind, "outcome", decision, reason, redaction))
        except EvidenceUnavailable:
            self.final_evidence_failures += 1


class FakeRefundAPI:
    def __init__(self):
        self.calls = []

    def refund(self, order_id, amount, customer_email=None):
        self.calls.append({"order_id": order_id, "amount": amount})
        return {"status": "refunded", "amount": amount}


class FakePaymentAPI:
    def __init__(self):
        self.calls = []

    def transfer(self, amount, **kwargs):
        self.calls.append({"amount": amount})
        return {"status": "transferred", "amount": amount}


class FakeCloudAPI:
    def __init__(self):
        self.calls = []

    def delete(self, resource="sample", confirmed=False):
        self.calls.append(resource)
        return {"status": "deleted"}


class FakeLLM:
    def complete(self, prompt):
        return "fake response"


DISCLAIMER = "Not an insurance rating, coverage opinion, legal conclusion, or attestation."


def risk_report(log, policy, ledger, anomalies=0):
    verification = log.verify()
    entries = log.entries()
    allowed = sum(1 for entry in entries if entry.get("phase") == "decision" and entry.get("decision") == "allow")
    blocked = sum(1 for entry in entries if entry.get("phase") == "decision" and entry.get("decision") == "block")
    evidence_failures = anomalies + (0 if verification.ok else 1)
    return {
        "title": "Operational control report",
        "generated_at": _utc_iso(log.clock.now()),
        "policy_digest": policy.digest(),
        "score": None if not verification.ok else max(0, 100 - evidence_failures * 20),
        "metrics": {
            "allowed": allowed,
            "blocked": blocked,
            "evidence_entries": len(entries),
            "evidence_failures": evidence_failures,
            "budget_anomalies": ledger.anomalies,
        },
        "verification": {"ok": verification.ok, "reason": verification.reason, "first_bad_seq": verification.first_bad_seq},
        "disclaimer": DISCLAIMER,
    }
