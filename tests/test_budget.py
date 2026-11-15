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
)
from demo import POLICY_DATA, TENANT_KEY, TSA_KEY


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(dt.datetime(2026, 10, 24, 23, 59, tzinfo=dt.timezone.utc))
        self.ledger = BudgetLedger(Policy.load(POLICY_DATA), self.clock)

    def test_overrun_blocks_next_reservation(self):
        reservation = self.ledger.reserve("a", "refund", 1000)
        self.ledger.reconcile(reservation, 50001)
        with self.assertRaises(LimitExceeded):
            self.ledger.reserve("a", "refund", 1)

    def test_destructive_count_and_confirmation_policy(self):
        reservations = [self.ledger.reserve("a", "destructive", 1) for _ in range(3)]
        for reservation in reservations:
            self.ledger.reconcile(reservation, 1)
        with self.assertRaises(LimitExceeded):
            self.ledger.reserve("a", "destructive", 1)

    def test_reservation_keeps_original_day(self):
        reservation = self.ledger.reserve("a", "refund", 1000)
        self.clock.set(dt.datetime(2026, 10, 25, 0, 1, tzinfo=dt.timezone.utc))
        self.ledger.reconcile(reservation, 1000)
        totals = self.ledger.totals()
        self.assertEqual(1000, totals["a|refund|2026-10-24"]["committed"])
        self.ledger.reserve("a", "refund", 50000)

    def test_expired_reservation_is_released(self):
        reservation = self.ledger.reserve("a", "refund", 50000)
        self.clock.set(self.clock.now() + dt.timedelta(minutes=6))
        self.assertEqual(1, self.ledger.sweep_expired())
        self.assertEqual("expired", reservation.state)
        totals = self.ledger.totals()["a|refund|2026-10-24"]
        self.assertEqual({"committed": 50000, "reserved": 0}, totals)
        self.clock.set(dt.datetime(2026, 10, 24, 12, 6, tzinfo=dt.timezone.utc))
        with self.assertRaises(LimitExceeded):
            self.ledger.reserve("a", "refund", 1)

    def test_late_reconcile_after_expiry_counts_actual_on_original_day(self):
        reservation = self.ledger.reserve("a", "refund", 1000)
        self.clock.set(self.clock.now() + dt.timedelta(minutes=6))
        self.assertEqual(1, self.ledger.sweep_expired())

        self.ledger.reconcile(reservation, 50000)

        totals = self.ledger.totals()["a|refund|2026-10-24"]
        self.assertEqual({"committed": 50000, "reserved": 0}, totals)
        self.assertEqual("committed", reservation.state)
        self.assertTrue(reservation.overrun)
        self.assertTrue(reservation.anomaly)
        self.assertEqual("expired", reservation.anomaly_reason)

    def test_guard_retries_failed_reconcile_and_prevents_daily_limit_bypass(self):
        self.clock.set(dt.datetime(2026, 10, 24, 12, 0, tzinfo=dt.timezone.utc))
        enforcer = FlakyEnforcer(LocalEnforcer(self.ledger))
        evidence = EvidenceLog(
            [MemoryWormStore(), MemoryWormStore()],
            FakeTSA(TSA_KEY, self.clock),
            self.clock,
        )
        guard = Guard(
            Policy.load(POLICY_DATA),
            enforcer,
            evidence,
            MemoryVault(),
            self.clock,
            TENANT_KEY,
            agent_id="a",
        )

        @guard.tool("refund", amount_arg="amount")
        def spend(amount):
            enforcer.down = True
            return {"status": "refunded", "amount": 50000}

        self.assertEqual(50000, spend(1000)["amount"])
        self.assertEqual(1, guard.final_evidence_failures)

        enforcer.down = False
        self.clock.set(self.clock.now() + dt.timedelta(minutes=6))

        @guard.tool("refund", amount_arg="amount")
        def another_spend(amount):
            return {"status": "refunded", "amount": amount}

        with self.assertRaises(Blocked) as caught:
            another_spend(1)
        self.assertEqual("daily_limit", caught.exception.reason)
        totals = self.ledger.totals()["a|refund|2026-10-24"]
        self.assertEqual({"committed": 50000, "reserved": 0}, totals)


if __name__ == "__main__":
    unittest.main()
