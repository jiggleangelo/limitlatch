"""Review issue: the currency-mismatch check must live in the engine.

Previously only app.check_currency rejected mixed currencies, so SDK callers
of agentguard.replay.replay could sum EUR and USD into one daily total.
"""
import json
import unittest

from agentguard import Policy
from agentguard.replay import currency_mismatch_message, parse_log, replay

KEYS = {'tenant': b't' * 32, 'sign': b's' * 32, 'tsa': b'a' * 32}
POLICY = {
    'currency': 'USD',
    'rules': {'refund': {'risk': 'high', 'per_day_max': 10000}, 'read': {'risk': 'low'}},
    'fail_mode': {'high': 'closed', 'low': 'open'},
}


def log(*currencies, kind='refund'):
    rows = []
    for currency in currencies:
        row = {'ts': '2026-10-24T12:00:00Z', 'agent_id': 'a', 'tool': 't', 'kind': kind, 'amount_minor': 100}
        if currency is not None:
            row['currency'] = currency
        rows.append(json.dumps(row))
    return '\n'.join(rows)


class ReplayCurrencyTests(unittest.TestCase):
    def test_mixed_currency_is_rejected_by_engine(self):
        events = parse_log(log('USD', 'EUR', None))
        with self.assertRaises(ValueError) as caught:
            replay(Policy.load(POLICY), events, [], KEYS)
        message = str(caught.exception)
        self.assertEqual('row 2: ' + currency_mismatch_message('USD'), message)
        self.assertIn('currency does not match the policy currency (USD)', message)

    def test_dict_policy_is_checked_too(self):
        with self.assertRaisesRegex(ValueError, r'row 1: currency does not match'):
            replay(POLICY, parse_log(log('JPY')), [], KEYS)

    def test_matching_and_blank_currency_replay(self):
        run = replay(Policy.load(POLICY), parse_log(log('USD', None, '')), [], KEYS)
        self.assertEqual(['allowed'] * 3, [row['decision'] for row in run.results])
        self.assertEqual({'USD'}, {row['currency'] for row in run.results})

    def test_kind_and_currency_errors_reported_together_in_row_order(self):
        text = log('EUR', kind='transfer')
        with self.assertRaises(ValueError) as caught:
            replay(Policy.load(POLICY), parse_log(text), [], KEYS)
        self.assertEqual(
            'row 1: kind is not defined in the policy; row 1: ' + currency_mismatch_message('USD'),
            str(caught.exception),
        )


if __name__ == '__main__':
    unittest.main()
