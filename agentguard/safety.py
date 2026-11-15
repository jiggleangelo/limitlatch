import hashlib
import hmac
import secrets

from .core import (
    CLEAR_KEYS,
    CONTACT_KEYS,
    CURRENCIES,
    EMAIL,
    PHONE,
    EvidenceLog as _EvidenceLog,
    EvidenceUnavailable,
    MemoryVault as _MemoryVault,
    WormViolation,
    canonical,
)

SAFE_KEYS = frozenset({
    *CLEAR_KEYS,
    *CONTACT_KEYS,
    "agent_id",
    "kind",
    "note",
    "order_id",
    "resource",
    "status",
})


class MemoryVault(_MemoryVault):
    """Write-only vault with an optional hard bound on retained values."""

    def __init__(self, max_values=None):
        super().__init__()
        if max_values is not None and (isinstance(max_values, bool) or not isinstance(max_values, int) or max_values < 0):
            raise ValueError("max_values must be a non-negative integer or None")
        self.max_values = max_values

    def put(self, value):
        # The parent deliberately exposes neither values nor a read method. Its
        # lock makes this count-and-put sequence safe when called concurrently.
        with self._MemoryVault__lock:
            if self.max_values is not None and len(self._MemoryVault__values) >= self.max_values:
                return "v_capacity_redacted"
            ref = "v_" + secrets.token_hex(16)
            self._MemoryVault__values[ref] = value
            return ref


class EvidenceLog(_EvidenceLog):
    """Evidence log with an optional maximum committed-entry count."""

    def __init__(self, stores, tsa, clock, max_entries=None):
        super().__init__(stores, tsa, clock)
        if max_entries is not None and (isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 0):
            raise ValueError("max_entries must be a non-negative integer or None")
        self.max_entries = max_entries

    def append(self, payload):
        with self._lock:
            if self.max_entries is not None:
                projected = len(self._entries) + (1 if self._pending is not None else 0)
                if projected >= self.max_entries:
                    if self._pending is not None:
                        try:
                            self._commit_pending()
                        except EvidenceUnavailable:
                            raise
                        except (OSError, WormViolation) as exc:
                            raise EvidenceUnavailable("evidence replication unavailable") from exc
                    raise EvidenceUnavailable("evidence capacity reached")
            return super().append(payload)


def redact_args(values, vault, tenant_key):
    """Redact values and prevent attacker-controlled mapping keys entering WORM."""
    refs = []

    def sensitive_key(key):
        return key in CONTACT_KEYS or any(
            part in key for part in ("email", "phone", "contact", "address", "name", "account")
        )

    def walk(value, key=""):
        lowered = key.lower()
        if lowered in CLEAR_KEYS:
            if lowered == "amount" and isinstance(value, int) and not isinstance(value, bool):
                return value
            if lowered == "confirmed" and isinstance(value, bool):
                return value
            if lowered == "currency" and isinstance(value, str) and value in CURRENCIES:
                return value
            return "[redacted]"
        if isinstance(value, dict):
            result = {}
            for position, (raw_key, item) in enumerate(value.items()):
                original = str(raw_key)
                output_key = original if original.lower() in SAFE_KEYS else f"[key:{position}]"
                result[output_key] = walk(item, original)
            return result
        if isinstance(value, (list, tuple)):
            return [walk(item, lowered) for item in value]
        if isinstance(value, str) and (
            sensitive_key(lowered) or EMAIL.fullmatch(value) or PHONE.fullmatch(value)
        ):
            ref = vault.put(value)
            refs.append(ref)
            return ref
        if value is None:
            return None
        return "[redacted]"

    redacted = walk(values)
    nonce = secrets.token_hex(16)
    digest = hmac.new(
        tenant_key,
        canonical({"nonce": nonce, "args": redacted}),
        hashlib.sha256,
    ).hexdigest()
    return {
        "args": redacted,
        "vault_refs": refs,
        "args_digest": digest,
        "digest_nonce": nonce,
    }
