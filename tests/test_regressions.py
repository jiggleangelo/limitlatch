import datetime as dt
import unittest

from agentguard import (
    Blocked,
    BudgetLedger,
    EvidenceLog,
    FakeTSA,
    FixedClock,
    FlakyEnforcer,
    Guard,
    LimitExceeded,
    LocalEnforcer,
    MemoryVault,
    MemoryWormStore,
    Policy,
    redact_args,
)


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(dt.datetime(2026, 10, 24, 12, tzinfo=dt.timezone.utc))
        self.policy = Policy.load({
            "currency": "USD",
            "fail_mode": {"high": "closed", "low": "open"},
            "rules": {
                "refund": {
                    "risk": "high",
                    "per_action_max": 1000,
                    "per_day_max": 2000,
                },
            },
        })
        self.ledger = BudgetLedger(self.policy, self.clock)
        self.enforcer = FlakyEnforcer(LocalEnforcer(self.ledger))
        self.stores = [MemoryWormStore(), MemoryWormStore()]
        self.log = EvidenceLog(self.stores, FakeTSA(b"tsa", self.clock), self.clock)
        self.guard = Guard(
            self.policy, self.enforcer, self.log, MemoryVault(),
            self.clock, b"tenant", agent_id="a",
        )

    def test_f2_exception_after_side_effect_consumes_daily_budget(self):
        effects = []
        failure = TimeoutError("response lost after refund")

        @self.guard.tool("refund", amount_arg="amount")
        def refund(amount):
            effects.append(amount)
            raise failure

        for expected in (1000, 2000):
            with self.assertRaises(TimeoutError) as caught:
                refund(1000)
            self.assertIs(failure, caught.exception)
            self.assertEqual(
                {"committed": expected, "reserved": 0},
                self.ledger.totals()["a|refund|2026-10-24"],
            )
            outcome = self.log.entries()[-1]
            self.assertEqual("outcome", outcome["phase"])
            self.assertEqual("anomaly", outcome["decision"])
            self.assertEqual("tool_error", outcome["reason"])

        with self.assertRaises(Blocked) as caught:
            refund(1)
        self.assertEqual("daily_limit", caught.exception.reason)
        self.assertEqual([1000, 1000], effects)
        self.assertTrue(self.log.verify().ok)

    def test_f2_exception_reconciliation_survives_outage_and_expiry(self):
        effects = []

        @self.guard.tool("refund", amount_arg="amount")
        def refund(amount):
            effects.append(amount)
            self.enforcer.down = True
            raise TimeoutError("refund accepted")

        with self.assertRaises(TimeoutError):
            refund(1000)
        self.assertEqual(
            {"committed": 0, "reserved": 1000},
            self.ledger.totals()["a|refund|2026-10-24"],
        )
        self.assertEqual(1, self.guard.final_evidence_failures)
        self.enforcer.down = False
        self.clock.set(self.clock.now() + dt.timedelta(minutes=6))

        @self.guard.tool("refund", amount_arg="amount")
        def another_refund(amount):
            effects.append(amount)
            return {"amount": amount}

        another_refund(1000)
        self.assertEqual(
            {"committed": 2000, "reserved": 0},
            self.ledger.totals()["a|refund|2026-10-24"],
        )
        with self.assertRaises(Blocked) as caught:
            another_refund(1)
        self.assertEqual("daily_limit", caught.exception.reason)
        self.assertEqual([1000, 1000], effects)
        self.assertTrue(self.log.verify().ok)

    def test_f2_outcome_evidence_failure_does_not_release_spend(self):
        failure = TimeoutError("refund accepted")

        @self.guard.tool("refund", amount_arg="amount")
        def refund(amount):
            self.stores[0].fail_next_put = True
            raise failure

        with self.assertRaises(TimeoutError) as caught:
            refund(1000)
        self.assertIs(failure, caught.exception)
        self.assertEqual(
            {"committed": 1000, "reserved": 0},
            self.ledger.totals()["a|refund|2026-10-24"],
        )
        self.assertEqual(1, self.guard.final_evidence_failures)

    def test_guard_enforces_action_limit_before_execution(self):
        calls = []

        @self.guard.tool("refund", amount_arg="amount")
        def refund(amount):
            calls.append(amount)
            return {"amount": amount}

        for unavailable in (False, True):
            with self.subTest(enforcer_unavailable=unavailable):
                self.enforcer.down = unavailable
                with self.assertRaises(Blocked) as caught:
                    refund(1001)
                self.assertEqual("per_action_limit", caught.exception.reason)
                self.assertEqual("block", self.log.entries()[-1]["decision"])
                self.assertEqual("per_action_limit", self.log.entries()[-1]["reason"])
        self.assertEqual([], calls)
        self.assertEqual({}, self.ledger.totals())
        self.enforcer.down = False
        refund(1000)
        self.assertEqual([1000], calls)
        self.assertEqual(
            {"committed": 1000, "reserved": 0},
            self.ledger.totals()["a|refund|2026-10-24"],
        )

    def test_daily_ledger_accepts_full_budget_and_preserves_expired_spend(self):
        reservation = self.ledger.reserve("a", "refund", 2000)
        self.clock.set(self.clock.now() + dt.timedelta(minutes=6))
        self.assertEqual(1, self.ledger.sweep_expired())
        self.assertEqual("expired", reservation.state)
        self.assertEqual(
            {"committed": 2000, "reserved": 0},
            self.ledger.totals()["a|refund|2026-10-24"],
        )
        with self.assertRaisesRegex(LimitExceeded, "daily_limit"):
            self.ledger.reserve("a", "refund", 1)
        self.clock.set(dt.datetime(2026, 10, 25, tzinfo=dt.timezone.utc))
        self.ledger.reconcile(reservation, 2000)
        self.ledger.reserve("a", "refund", 2000)
        self.assertEqual(
            {
                "a|refund|2026-10-24": {"committed": 2000, "reserved": 0},
                "a|refund|2026-10-25": {"committed": 0, "reserved": 2000},
            },
            self.ledger.totals(),
        )

    def test_invalid_clear_fields_do_not_become_vault_references(self):
        invalid = {
            "amount": ["4111111111111111", "a@example.test", True, None, [1], {"email": "a@example.test"}],
            "currency": ["a@example.test", "1234567890", 1, None, ["USD"]],
            "confirmed": ["a@example.test", "1234567890", 1, None, [True]],
        }
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    vault = MemoryVault()
                    result = redact_args({key.upper(): value}, vault, b"tenant")
                    self.assertEqual({key.upper(): "[redacted]"}, result["args"])
                    self.assertEqual([], result["vault_refs"])
                    self.assertEqual(0, vault.count())


if __name__ == "__main__":
    unittest.main()
