import json
import unittest
from unittest.mock import patch

from agentguard import Policy
from agentguard import replay as replay_module
from agentguard.replay import parse_log, parse_timestamp, replay, safe_identifier

KEYS = {'tenant': b't' * 32, 'sign': b's' * 32, 'tsa': b'a' * 32}
POLICY = {
    'currency': 'USD',
    'rules': {
        'refund': {'risk': 'high', 'per_action_max': 20000, 'per_day_max': 50000},
        'read': {'risk': 'low'},
    },
    'fail_mode': {'high': 'closed', 'low': 'open'},
}


class ForbiddenIdentifierTests(unittest.TestCase):
    # Issue: card, account and phone numbers matched IDENTIFIER and persisted.
    def test_digit_heavy_identifiers_are_aliased_and_never_stored(self):
        card, phone = '4111111111111111', '555-123-4567'
        text = ('ts,agent_id,tool,kind,amount_minor\n'
                f'2026-10-24T12:00:00Z,{card},refund,refund,100\n'
                f'2026-10-24T12:00:01Z,{card},{phone},refund,100\n'
                '2026-10-24T12:00:02Z,a119,tool50,refund,100\n')
        events = parse_log(text)
        self.assertEqual(events[0].agent_id, events[1].agent_id)
        self.assertTrue(events[0].agent_id.startswith('agent_'))
        self.assertTrue(events[1].tool.startswith('tool_'))
        self.assertEqual(('a119', 'tool50'), (events[2].agent_id, events[2].tool))
        run = replay(Policy.load(POLICY), events, [], KEYS)
        stored = json.dumps([run.events, run.results, run.totals, run.bundle])
        self.assertNotIn(card, stored)
        self.assertNotIn(phone, stored)
        self.assertFalse(safe_identifier('4111-1111-1111-1111'))
        self.assertTrue(safe_identifier('SampleRefundBot'))

    def test_numeric_json_identifiers_are_text_and_checked(self):
        rows = [{'ts': '2026-10-24T12:00:00Z', 'agent_id': 42, 'tool': 7, 'kind': 'read', 'amount_minor': 0},
                {'ts': '2026-10-24T12:00:00Z', 'agent_id': 4111111111111111, 'tool': 't', 'kind': 'read', 'amount_minor': 0}]
        events = parse_log(json.dumps(rows))
        self.assertEqual(('42', '7'), (events[0].agent_id, events[0].tool))
        self.assertTrue(events[1].agent_id.startswith('agent_'))
        with self.assertRaisesRegex(ValueError, 'agent_id must be a string'):
            parse_log(json.dumps([dict(rows[0], agent_id=True)]))


class LogErgonomicsTests(unittest.TestCase):
    # Issue: epoch timestamps and capitalised kinds were rejected.
    def test_epoch_seconds_and_milliseconds(self):
        self.assertEqual('2024-10-24T12:00:00+00:00', parse_timestamp(1729771200).isoformat())
        self.assertEqual(parse_timestamp(1729771200), parse_timestamp('1729771200000'))
        events = parse_log('ts,agent_id,tool,kind,amount_minor\n1729771200,a,t,Refund ,5\n')
        self.assertEqual('2024-10-24T12:00:00Z', events[0].ts)
        self.assertEqual('refund', events[0].kind)
        for bad in (True, -1, float('nan'), 'yesterday'):
            with self.assertRaises(ValueError):
                parse_timestamp(bad)

    def test_decimal_amounts_still_rejected_per_brief(self):
        with self.assertRaisesRegex(ValueError, 'amount must be a non-negative integer'):
            parse_log('ts,agent_id,tool,kind,amount_minor\n2026-10-24T12:00:00Z,a,t,refund,25.00\n')


class EvidenceCapacityTests(unittest.TestCase):
    # Issue: hitting the evidence cap showed rows as blocked (evidence_unavailable).
    def test_capacity_covers_all_allowed_rows(self):
        text = 'ts,agent_id,tool,kind,amount_minor\n' + '\n'.join(f'2026-10-24T12:00:{i:02d}Z,a,t,refund,1' for i in range(30))
        run = replay(Policy.load(POLICY), parse_log(text), [], KEYS)
        self.assertEqual(30, run.summary['allowed'])
        self.assertNotIn('evidence_unavailable', [row['reason'] for row in run.results])

    def test_capacity_artefact_raises_instead_of_blocking(self):
        text = 'ts,agent_id,tool,kind,amount_minor\n2026-10-24T12:00:00Z,a,t,read,0\n2026-10-24T12:00:01Z,a,t,refund,1\n'
        with patch.object(replay_module, '_evidence_capacity', return_value=1):
            with self.assertRaisesRegex(ValueError, 'evidence capacity'):
                replay(Policy.load(POLICY), parse_log(text), [], KEYS)


if __name__ == '__main__':
    unittest.main()
