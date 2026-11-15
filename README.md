# limitlatch

Prototype: Stop runaway AI agent actions: limitlatch

**Use it free, no account:** https://app-limitlatch.manykiln.com/  
**Try the demo (made-up data):** https://try-limitlatch.manykiln.com/  
**Product page:** https://limitlatch.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. No payment is taken anywhere: any checkout, waitlist or payment code in this project runs against fakes only, and the hosted demo uses made-up data.

- Status: prototype; run the 44 automated tests yourself with `python3 -m unittest discover`
- Runs on the Python 3.12 standard library; run the usable app with `python3 app.py` (see below)
- Licence: MIT. Free to use, fork and improve.
- Issues and pull requests are not monitored yet.

---

# AgentGuard MVP

AgentGuard is a Python SDK and public-demo sample for race-safe action limits, fail-closed high-risk actions, and tamper-evident evidence. It is operational-control software. It does not quote, rate, recommend, bind, or attest to insurance coverage.

## Quick start

Requires Python 3.12 and no third-party packages.

```sh
python3 demo.py
```

Open `http://localhost:8080`. `HOST` and `PORT` configure the bind address and port. The default bind address is `127.0.0.1`. When a TLS-terminating reverse proxy exposes the demo, set its public hostnames as a comma-separated allow-list, for example:

```sh
HOST=0.0.0.0 ALLOWED_HOSTS=demo.example.com python3 demo.py
```

Configuring a public `ALLOWED_HOSTS` value also enables the session cookie's `Secure` attribute. Set `SESSION_COOKIE_SECURE=1` to enable it explicitly, or `SESSION_COOKIE_SECURE=0` only for a deliberately plain-HTTP deployment such as local development.

The complete seven-step flow, including tampering, export, and bundle verification, is enabled by default because all demo data and integrations are synthetic and memory-only. Set `DEMO_MODE=0` to hide destructive demo controls.

Each browser gets isolated state in an HttpOnly, SameSite session cookie. Sessions are created only by the home page or a valid state-changing POST; health checks and other cookieless reads do not allocate state. Sessions expire, session creation is rate-limited per source, and the number of sessions and connections is capped. Evidence and vault storage are bounded, and a session automatically resets with a visible notice before reaching its limits. The expensive refund-loop scenario is rate-limited by source rather than cookie, so discarding a cookie does not reset its cooldown.

The server enforces one total deadline across request-line, header, and POST-body receipt, limits form bodies to 2 KiB, validates Host and Origin, and suppresses request and exception logging. The body deadline is absolute: sending occasional bytes does not extend it.

Run tests:

```sh
python3 -m unittest discover -s tests
```

## SDK example

```python
import datetime as dt
import secrets
from agentguard import (
    BudgetLedger, EvidenceLog, FakeTSA, FixedClock, Guard,
    LocalEnforcer, MemoryVault, MemoryWormStore, Policy,
)

policy = Policy.load({
    "currency": "USD",
    "rules": {"refund": {"risk": "high", "per_action_max": 20000, "per_day_max": 50000}},
    "fail_mode": {"high": "closed", "low": "open"},
})
clock = FixedClock(dt.datetime.now(dt.timezone.utc))
ledger = BudgetLedger(policy, clock)
log = EvidenceLog(
    [MemoryWormStore("region-a"), MemoryWormStore("region-b")],
    FakeTSA(secrets.token_bytes(32), clock),
    clock,
)
guard = Guard(policy, LocalEnforcer(ledger), log, MemoryVault(), clock, secrets.token_bytes(32))

@guard.tool(kind="refund", amount_arg="amount")
def issue_refund(order_id: str, amount: int, customer_email: str):
    return {"status": "refunded", "amount": amount}

issue_refund("ord_1", 2500, "buyer@example.test")
```

Amounts are integer minor currency units. High-risk tools reserve budget before execution and reconcile after execution. The tool runs only after an allow decision has been replicated to both evidence stores.

`EvidenceLog(..., max_entries=N)` and `MemoryVault(max_values=N)` provide optional hard memory bounds. Once a vault reaches its bound, additional sensitive values are represented by a non-readable capacity marker and are not retained.

## Verify an export

The demo generates distinct signing, timestamp, and tenant keys for each process. Embedded deployments should persist and distribute verification keys through a secret manager. The CLI reads exact binary key contents without trimming:

```sh
python3 verify.py bundle.json --key-file signing.key --tsa-key-file tsa.key
```

The command exits 0 for a valid bundle and 1 otherwise.

## Known limitations

The MVP uses HMAC-SHA256 signatures. Anyone holding the signing secret could forge a bundle. Production must use asymmetric Ed25519 signatures with keys held in a KMS and an RFC 3161 timestamp authority. The timestamp authority, two-region WORM stores, connectors, and outages are in-memory fakes.

Budget counters and reservations reset whenever a session or process resets. Unreconciled reservations expire after five minutes. Production deployments need a durable, distributed ledger and an expiration policy suited to tool duration.

The demo has no accounts, billing, persistence, or real integrations. Session cookies provide isolation, not authentication.

## Security notes

The banner appears on every HTML page. The server serves no files, escapes interpolated HTML, prevents framing, and emits a restrictive content security policy.

Tool arguments are never logged raw. Contact values go into a write-only bounded vault. Attacker-controlled dictionary keys are replaced by positional placeholders unless the key belongs to a small schema allow-list, so an email address or phone number used as a key cannot reach WORM evidence or exports. Evidence contains opaque references, a nonce-hardened HMAC digest, and only type-checked numeric, boolean, or recognized currency values. Other free text is replaced with `[redacted]`.

## Usable app

LimitLatch is the persistent, account-free replay application. It uses the existing AgentGuard policy, guard, ledger, evidence, timestamp and signing modules. No AI model is called: policy validation, chronological replay, counters, hash chaining and HMAC verification are deterministic.

Start it with:

```sh
DATA_DIR=./limitlatch-data python3 app.py
```

The default address is `http://127.0.0.1:8080`. Deployment configuration is provided through `APP_HOST`, `PORT`, `PUBLIC_BASE_URL`, `APP_HTTPS_TERMINATED`, `DATA_DIR` and `APP_DATA_CAP_MB`. `DATA_DIR` is the only application data location. Each private workspace is addressed by an unrecorded random URL token; only its SHA-256 digest is used on disk. Before a public deployment, complete the deployment checklist in HARDENING.md (proxy identity, token logging, disk headroom).

Logs may be CSV, JSON arrays or JSONL. They can contain only `ts`, `agent_id`, `tool`, `kind`, `amount_minor`, optional `actual_minor`, `currency` and `confirmed`. Unknown columns are dropped before persistence. Amounts are non-negative integer minor units. The supported size for a saved run is about 2,000 rows; see HARDENING.md. A CSV example is:

```csv
ts,agent_id,tool,kind,amount_minor,actual_minor,currency,confirmed
2026-10-24T12:00:00Z,RefundBot,issue_refund,refund,2500,,USD,false
2026-10-24T12:01:00Z,OpsBot,send_transfer,transfer,60000,,USD,false
2026-10-24T12:02:00Z,OpsBot,delete_resource,destructive,0,,USD,true
```

The results page provides replay decisions, reasons, per-agent UTC-day totals, prevented amounts, the evidence chain, timestamp anchors and an operational control report. Download `bundle.json`, `signing.key` and `tsa.key`, then verify them without the server:

```sh
python3 verify.py bundle.json --key-file signing.key --tsa-key-file tsa.key
```

The verifier proves consistency only to a holder of the shared HMAC secrets. Anyone holding the signing and timestamp keys can forge a bundle. A signed bundle is therefore not third-party proof. The displayed-results check (`derived_mac`) uses the same downloadable signing key, so it does not protect results against the workspace holder. This early version is not an insurance rating, compliance attestation, legal attestation, coverage opinion or substitute for independently managed asymmetric signing keys.
