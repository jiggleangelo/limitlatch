import csv
import datetime as dt
import io
import json
import re
import threading
import time
from dataclasses import asdict, dataclass

from .core import (
    Blocked, BudgetLedger, FakeTSA, FixedClock, FlakyEnforcer, Guard,
    LocalEnforcer, MemoryWormStore, Policy, PolicyError, Signer, VerifyResult,
    _first_difference, _verify_entries, risk_report, verify_bundle,
)
from .safety import EvidenceLog, MemoryVault

ALLOWED_KEYS = frozenset({'ts', 'agent_id', 'tool', 'kind', 'amount_minor', 'actual_minor', 'currency', 'confirmed'})
IDENTIFIER = re.compile(r'^[A-Za-z0-9_.:-]{1,64}$')
# Identifiers with more digits than this are aliased. Card numbers, bank
# account numbers and phone numbers all exceed it, so they never persist in
# runs, bundles or exports even when they otherwise match IDENTIFIER.
MAX_IDENTIFIER_DIGITS = 6
MAX_EVENTS = 5000
MAX_LOG_BYTES = 1024 * 1024
# The app admits at most fifty distinct sanitized kind/tool pairs per replay.
# The engine enforces the same bound, so no caller has to patch it at runtime.
MAX_TOOL_PAIRS = 50
# Matches the worker CPU rlimit in app_jobs/app_limits.
CPU_SECONDS = 5.0
# Guard writes at most two evidence entries per event (decision + outcome).
ENTRIES_PER_EVENT = 2
EVIDENCE_CAPACITY_ERROR = 'evidence capacity reached during replay; nothing was saved'

# Daily caps are per agent_id by default (the AgentGuard ledger key). A policy
# may set "daily_scope": "all_agents" to apply one cap across the whole log.
# '*' can never collide with a sanitized agent id, which must match IDENTIFIER.
DAILY_SCOPES = ('per_agent', 'all_agents')
ALL_AGENTS = '*'
DAILY_SCOPE_NOTES = {
    'per_agent': 'Daily limits were applied separately to each agent_id. Several agents together can exceed one daily limit without being blocked. Set "daily_scope": "all_agents" in the policy to apply one cap across the whole log.',
    'all_agents': 'Daily limits were applied once across all agents in the log.',
}
ORDERING_NOTE = ('Events are replayed in timestamp order. Rows with identical timestamps keep their input '
                 'order, which may differ from the order a live enforcer would have seen.')
# Entry and anchor times come from the replay FixedClock, i.e. the logged event
# timestamps. They are not the time anything was anchored. exported_at and the
# report's generated_at are the real wall-clock time the replay ran.
TIME_BASIS_NOTE = ('Evidence entry "time" and timestamp anchor "time" values are the replayed log timestamps '
                   '(a fixed replay clock), not the time of anchoring. exported_at is the wall-clock UTC time '
                   'the replay was generated. The timestamp authority is a local HMAC stand-in, not an '
                   'independent RFC 3161 service.')

# csv.field_size_limit is process-global. Change it only under this lock and
# always restore the previous value, so other csv users are not affected.
_CSV_LIMIT_LOCK = threading.Lock()
_EPOCH_TEXT = re.compile(r'[0-9]{9,13}(\.[0-9]+)?')


@dataclass
class Event:
    ts: str
    agent_id: str
    tool: str
    kind: str
    amount_minor: int
    actual_minor: int | None = None
    currency: str | None = None
    confirmed: bool = False

    @property
    def instant(self):
        return parse_timestamp(self.ts)


@dataclass
class Run:
    events: list
    results: list
    entries: list
    anchors: list
    totals: dict
    summary: dict
    report: dict
    bundle: dict


def daily_scope(policy):
    data = policy.data if isinstance(policy, Policy) else policy
    scope = data.get('daily_scope', 'per_agent') if isinstance(data, dict) else None
    if scope not in DAILY_SCOPES:
        raise PolicyError('daily_scope must be per_agent or all_agents')
    return scope


def currency_mismatch_message(policy_currency):
    """Row-level message for a currency that differs from the policy.

    Only the policy currency is named, so the message never echoes input.
    """
    return f'currency does not match the policy currency ({policy_currency})'


class _ScopedEnforcer:
    """Maps the ledger key to one shared agent when the policy scope is global."""

    def __init__(self, inner, scope):
        self.inner = inner
        self.scope = scope

    def ledger_agent(self, agent_id):
        return ALL_AGENTS if self.scope == 'all_agents' else agent_id

    def reserve(self, agent_id, kind, amount):
        return self.inner.reserve(self.ledger_agent(agent_id), kind, amount)

    def reconcile(self, reservation, actual):
        return self.inner.reconcile(reservation, actual)

    def release(self, reservation):
        return self.inner.release(reservation)


class _ReplayConnector:
    """Holds the logged actual amount for the row currently being replayed.

    Connectors read the value from here at call time. Nothing mutates function
    defaults, so a change to the connector signature cannot silently pick up a
    stale amount from an earlier row.
    """

    def __init__(self):
        self.actual = 0

    def make(self, name):
        state = self

        def connector(amount=0, confirmed=False):
            return {'amount': state.actual}
        connector.__name__ = name
        return connector


def _epoch(number):
    # Values of 1e11 or more are milliseconds; smaller values are seconds.
    if number != number or number in (float('inf'), float('-inf')) or number < 0:
        raise ValueError('invalid timestamp')
    if number >= 1e11:
        number = number / 1000
    return dt.datetime.fromtimestamp(number, dt.timezone.utc)


def parse_timestamp(value):
    try:
        if isinstance(value, bool):
            raise ValueError('invalid timestamp')
        if isinstance(value, (int, float)):
            return _epoch(float(value))
        if not isinstance(value, str) or not value.strip():
            raise ValueError('invalid timestamp')
        text = value.strip()
        if _EPOCH_TEXT.fullmatch(text):
            return _epoch(float(text))
        parsed = dt.datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise ValueError('invalid timestamp') from None


def _iso(value):
    return value.astimezone(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def _integer(value, csv_mode, optional=False):
    if optional and (value is None or value == ''):
        return None
    if csv_mode and isinstance(value, str) and re.fullmatch(r'[0-9]+', value.strip()):
        try:
            value = int(value.strip())
        except ValueError:
            raise ValueError('amount must be a non-negative integer') from None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError('amount must be a non-negative integer')
    return value


def _boolean(value, csv_mode):
    if value is None or value == '':
        return False
    if isinstance(value, bool):
        return value
    if csv_mode and isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {'true', '1'}:
            return True
        if lowered in {'false', '0'}:
            return False
    raise ValueError('confirmed must be true or false')


def _csv_rows(text):
    # csv's default 128 KB field limit is smaller than the 1 MB log contract.
    # Raise it only for this parse and restore the previous process value.
    with _CSV_LIMIT_LOCK:
        previous = csv.field_size_limit(MAX_LOG_BYTES)
        try:
            return list(csv.DictReader(io.StringIO(text)))
        finally:
            csv.field_size_limit(previous)


def _rows(text):
    stripped = text.lstrip('\ufeff \t\r\n')
    if not stripped:
        return [], False
    if stripped[0] not in '[{':
        try:
            return _csv_rows(stripped), True
        except csv.Error:
            raise ValueError('invalid CSV') from None
    try:
        decoded = json.loads(stripped)
    except json.JSONDecodeError:
        rows = []
        for line_number, line in enumerate(stripped.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                raise ValueError(f'row {line_number}: invalid JSON') from None
        return rows, False
    return (decoded if isinstance(decoded, list) else [decoded]), False


def safe_identifier(value):
    """True when an identifier may be stored as-is.

    It must match IDENTIFIER and contain at most MAX_IDENTIFIER_DIGITS digits,
    so card, account and phone numbers are always aliased.
    """
    return (isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None
            and sum(character.isdigit() for character in value) <= MAX_IDENTIFIER_DIGITS)


def _identifier_text(value, field):
    # Numeric ids from JSON exports are accepted as text and then go through
    # the same safety check as any other identifier.
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return value
    raise ValueError(field + ' must be a string')


def _aliases(rows, field, prefix):
    # Reserve all safe input identifiers, including ones appearing later. An
    # alias must never merge a redacted agent with a different, valid agent.
    used = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            text = _identifier_text(row.get(field), field)
        except ValueError:
            continue
        if safe_identifier(text):
            used.add(text)
    mapping = {}
    sequence = 0

    def alias(value):
        nonlocal sequence
        text = _identifier_text(value, field)
        if safe_identifier(text):
            return text
        if text not in mapping:
            while True:
                sequence += 1
                candidate = f'{prefix}_{sequence}'
                if candidate not in used:
                    break
            mapping[text] = candidate
            used.add(candidate)
        return mapping[text]
    return alias


def parse_log(text):
    if not isinstance(text, str):
        raise ValueError('log must be text')
    if len(text.encode('utf-8')) > MAX_LOG_BYTES:
        raise ValueError('log exceeds 1 MB')
    rows, csv_mode = _rows(text)
    if len(rows) > MAX_EVENTS:
        raise ValueError('log exceeds 5,000 rows')
    agent_alias = _aliases(rows, 'agent_id', 'agent')
    tool_alias = _aliases(rows, 'tool', 'tool')
    events, errors = [], []
    for number, original in enumerate(rows, 1):
        try:
            if not isinstance(original, dict):
                raise ValueError('row must be an object')
            row = {key: original.get(key) for key in ALLOWED_KEYS}
            instant = parse_timestamp(row['ts'])
            kind = row['kind']
            if isinstance(kind, str):
                kind = kind.strip().lower()
            if not isinstance(kind, str) or kind not in Policy.KINDS:
                raise ValueError('unknown kind')
            amount = _integer(row['amount_minor'], csv_mode)
            actual = _integer(row['actual_minor'], csv_mode, optional=True)
            confirmed = _boolean(row['confirmed'], csv_mode)
            agent, tool = agent_alias(row['agent_id']), tool_alias(row['tool'])
            currency = row['currency']
            if currency in (None, ''):
                currency = None
            elif not isinstance(currency, str) or not re.fullmatch(r'[A-Z]{3}', currency):
                raise ValueError('invalid currency')
            events.append(Event(_iso(instant), agent, tool, kind, amount, actual, currency, confirmed))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"row {number}: {str(exc) or 'invalid row'}")
    if errors:
        raise ValueError('; '.join(errors))
    return events


def parse_outages(value):
    if value in (None, '', []):
        return []
    if isinstance(value, str):
        if len(value.encode('utf-8')) > 16384:
            raise ValueError('outage windows exceed 16 KB')
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise ValueError('outage windows must be JSON') from None
    if not isinstance(value, list):
        raise ValueError('outage windows must be a list')
    if len(value) > 100:
        raise ValueError('at most 100 outage windows are supported')
    result = []
    for number, window in enumerate(value, 1):
        try:
            start = parse_timestamp(window['start'])
            end = parse_timestamp(window['end'])
        except (KeyError, TypeError, ValueError):
            raise ValueError(f'outage window {number} is invalid') from None
        if end < start:
            raise ValueError(f'outage window {number} ends before it starts')
        result.append({'start': _iso(start), 'end': _iso(end)})
    return result


def _evidence_capacity(event_count):
    """Entries needed for the worst case: every event allowed (two entries)."""
    return max(ENTRIES_PER_EVENT, event_count * ENTRIES_PER_EVENT)


def _policy_row_errors(policy, events):
    """Rows the policy cannot replay: undefined kinds and foreign currencies.

    The currency check lives in the engine, not only in the web app, so SDK
    callers can never have mixed currencies summed into one daily total.
    """
    errors = []
    rules = policy.data['rules']
    for number, event in enumerate(events, 1):
        if event.kind not in rules:
            errors.append(f'row {number}: kind is not defined in the policy')
        if event.currency is not None and event.currency != policy.currency:
            errors.append(f'row {number}: ' + currency_mismatch_message(policy.currency))
    return errors


def replay(policy, events, outages, keys):
    if not isinstance(policy, Policy):
        policy = Policy.load(policy)
    scope = daily_scope(policy)
    if len(events) > MAX_EVENTS:
        raise ValueError('log exceeds 5,000 rows')
    errors = _policy_row_errors(policy, events)
    if errors:
        raise ValueError('; '.join(errors))
    if len({(event.kind, event.tool) for event in events}) > MAX_TOOL_PAIRS:
        raise ValueError(f'log exceeds {MAX_TOOL_PAIRS} distinct kind/tool pairs')
    outages = parse_outages(outages)
    windows = []
    for start, end in sorted((parse_timestamp(x['start']), parse_timestamp(x['end'])) for x in outages):
        if windows and start <= windows[-1][1]:
            windows[-1] = (windows[-1][0], max(end, windows[-1][1]))
        else:
            windows.append((start, end))
    window_index = 0
    tenant_key, signing_key, tsa_key = (keys[name] for name in ('tenant', 'sign', 'tsa'))
    if isinstance(tenant_key, str):
        tenant_key, signing_key, tsa_key = (bytes.fromhex(key) for key in (tenant_key, signing_key, tsa_key))
    generated_at = _iso(dt.datetime.now(dt.timezone.utc))
    ordered = sorted(enumerate(events), key=lambda pair: pair[1].instant)
    initial = ordered[0][1].instant if ordered else dt.datetime.now(dt.timezone.utc)
    clock = FixedClock(initial)
    ledger = BudgetLedger(policy, clock, reservation_ttl=None)
    scoped = _ScopedEnforcer(LocalEnforcer(ledger), scope)
    enforcer = FlakyEnforcer(scoped)
    # Capacity is sized to the worst case for this log, so the cap can never
    # turn a policy-allowed row into an evidence_unavailable block.
    evidence = EvidenceLog([MemoryWormStore('region-a'), MemoryWormStore('region-b')], FakeTSA(tsa_key, clock), clock, max_entries=_evidence_capacity(len(events)))
    vault = MemoryVault(max_values=0)
    connectors = _ReplayConnector()
    guards, tools, results = {}, {}, []
    ties, previous_instant = 0, None
    deadline = time.process_time() + CPU_SECONDS
    for original_index, event in ordered:
        if time.process_time() > deadline:
            raise ValueError('replay exceeded its processing CPU limit')
        instant = event.instant
        if previous_instant is not None and instant == previous_instant:
            ties += 1
        previous_instant = instant
        clock.set(instant)
        while window_index < len(windows) and windows[window_index][1] < instant:
            window_index += 1
        enforcer.down = window_index < len(windows) and windows[window_index][0] <= instant
        guard = guards.get(event.agent_id)
        if guard is None:
            guard = Guard(policy, enforcer, evidence, vault, clock, tenant_key, event.agent_id)
            guards[event.agent_id] = guard
        cache_key = (event.agent_id, event.kind, event.tool)
        action = tools.get(cache_key)
        if action is None:
            action = guard.tool(event.kind, amount_arg='amount')(connectors.make(event.tool))
            tools[cache_key] = action
        actual = event.actual_minor if event.actual_minor is not None else event.amount_minor
        # Set the logged amount for this row immediately before the call.
        connectors.actual = 1 if event.kind == 'destructive' else actual
        allowed, reason = True, 'policy_allowed'
        try:
            action(amount=event.amount_minor, confirmed=event.confirmed)
        except Blocked as exc:
            allowed, reason = False, exc.reason
        # Keep the policy decision even when the row is flagged as an overrun.
        policy_reason = reason
        overrun = allowed and event.kind != 'destructive' and actual > event.amount_minor
        if overrun:
            reason = 'overrun'
        day = instant.date().isoformat()
        with ledger._lock:
            committed = ledger._totals.get((scoped.ledger_agent(event.agent_id), event.kind, day), {}).get('committed', 0)
        results.append({'input_row': original_index + 1, 'ts': event.ts, 'agent_id': event.agent_id,
                        'tool': event.tool, 'kind': event.kind, 'amount_minor': event.amount_minor,
                        'actual_minor': event.actual_minor, 'currency': event.currency or policy.currency,
                        'confirmed': event.confirmed, 'decision': 'allowed' if allowed else 'blocked',
                        'reason': reason, 'policy_reason': policy_reason, 'overrun': overrun,
                        'running_committed': committed, 'utc_day': day})
    # An evidence failure is an artefact of the replay, not a policy decision.
    # Refuse to produce a run rather than show such rows as blocked.
    if any(item['reason'] == 'evidence_unavailable' for item in results) or any(guard.final_evidence_failures for guard in guards.values()):
        raise ValueError(EVIDENCE_CAPACITY_ERROR)
    totals = ledger.totals()
    blocked_by_kind = {kind: 0 for kind in Policy.KINDS}
    for result in results:
        if result['decision'] == 'blocked':
            blocked_by_kind[result['kind']] += result['amount_minor']
    summary = {'allowed': sum(item['decision'] == 'allowed' for item in results),
               'blocked': sum(item['decision'] == 'blocked' for item in results),
               'overrun': sum(item['overrun'] for item in results),
               'blocked_minor_by_kind': blocked_by_kind,
               'prevented_minor': sum(item['amount_minor'] for item in results if item['decision'] == 'blocked'),
               'daily_scope': scope,
               'timestamp_ties': ties}
    # risk_report runs the full store/chain/anchor verification once. That is
    # the save-time check; callers must not re-verify the bundle afterwards.
    report = risk_report(evidence, policy, ledger, anomalies=sum(guard.final_evidence_failures for guard in guards.values()))
    # The brief excludes any score that could be read as a rating or premium
    # input. The operational control report carries counts only.
    report.pop('score', None)
    report['generated_at'] = generated_at
    report['time_basis'] = TIME_BASIS_NOTE
    report['daily_scope'] = scope
    report['daily_scope_note'] = DAILY_SCOPE_NOTES[scope]
    report['ordering_note'] = ORDERING_NOTE
    report['timestamp_ties'] = ties
    entries, anchors = evidence.entries(), evidence.anchors()
    body = {'format': 'agentguard-evidence/0.1', 'exported_at': generated_at,
            'replay_clock_end': _iso(clock.now()), 'time_basis': TIME_BASIS_NOTE,
            'policy': policy.data, 'policy_digest': policy.digest(), 'entries': entries, 'anchors': anchors}
    bundle = dict(body)
    bundle['signature'] = Signer(signing_key).sign(body)
    return Run([asdict(event) for event in events], results, entries, anchors, totals, summary, report, bundle)


def _key_bytes(value):
    if isinstance(value, str):
        return bytes.fromhex(value)
    return value


def verify_stored_run(run, signing_key, tsa_key):
    """Full check of a stored run: signature, policy digest, chain and anchors.

    Any top-level entries/anchors copies must equal the signed bundle's, so a
    caller can never get 'passed' for a re-signed or policy-swapped run.
    """
    if not isinstance(run, dict) or not isinstance(run.get('bundle'), dict):
        return VerifyResult(False, 'invalid_bundle', None)
    bundle = run['bundle']
    for name in ('entries', 'anchors'):
        if name in run and run[name] != bundle.get(name):
            stored, signed = run[name], bundle.get(name)
            seq = _first_difference(stored, signed) if isinstance(stored, list) and isinstance(signed, list) else None
            return VerifyResult(False, 'stored_copy_mismatch', seq)
    try:
        signing_key, tsa_key = _key_bytes(signing_key), _key_bytes(tsa_key)
    except ValueError:
        return VerifyResult(False, 'invalid_keys', None)
    result = verify_bundle(bundle, signing_key, tsa_key)
    if not result.ok and result.first_bad_seq is None and isinstance(bundle.get('entries'), list):
        # Location hint only; never upgrades a failure to a pass.
        chain = _verify_entries(bundle['entries'])
        if not chain.ok:
            return VerifyResult(False, result.reason + '; ' + chain.reason, chain.first_bad_seq)
    return result
