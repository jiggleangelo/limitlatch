import datetime as dt
import json
import threading
import unittest
from agentguard import *
from demo import POLICY_DATA, SIGN_KEY, TSA_KEY, TENANT_KEY


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc))
        self.policy = Policy.load(POLICY_DATA)
        self.ledger = BudgetLedger(self.policy, self.clock)
        self.enforcer = FlakyEnforcer(LocalEnforcer(self.ledger))
        self.stores = [MemoryWormStore(), MemoryWormStore()]
        self.log = EvidenceLog(self.stores, FakeTSA(TSA_KEY, self.clock), self.clock)
        self.guard = Guard(self.policy, self.enforcer, self.log, MemoryVault(), self.clock, TENANT_KEY)

    def test_policy_validation_and_digest(self):
        bad = json.loads(json.dumps(POLICY_DATA)); bad["fail_mode"]["high"] = "open"
        with self.assertRaises(PolicyError): Policy.load(bad)
        bad = json.loads(json.dumps(POLICY_DATA)); bad["rules"]["refund"]["per_day_max"] = 1.2
        with self.assertRaises(PolicyError): Policy.load(bad)
        self.assertEqual(self.policy.digest(), Policy.load(dict(reversed(list(POLICY_DATA.items())))).digest())

    def test_concurrent_budget_never_exceeds_limit(self):
        successes = []
        def worker():
            for _ in range(20):
                try:
                    res = self.ledger.reserve("a", "refund", 1000); self.ledger.reconcile(res, 1000); successes.append(1)
                except LimitExceeded: pass
        threads = [threading.Thread(target=worker) for _ in range(50)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(50, len(successes))
        self.assertEqual(50000, next(iter(self.ledger.totals().values()))["committed"])

    def test_reconcile_release_idempotence_and_rollover(self):
        res = self.ledger.reserve("a", "refund", 2000); self.ledger.reconcile(res, 1000)
        self.assertFalse(res.overrun)
        res2 = self.ledger.reserve("a", "refund", 1000); self.ledger.reconcile(res2, 1500)
        self.assertTrue(res2.overrun); self.ledger.reconcile(res2, 1500); self.assertTrue(res2.anomaly)
        res3 = self.ledger.reserve("a", "refund", 1000); self.assertTrue(self.ledger.release(res3))
        self.clock.set(dt.datetime(2026, 10, 25, tzinfo=dt.timezone.utc))
        self.ledger.reserve("a", "refund", 50000)

    def test_guard_loop_outage_failure_and_redaction(self):
        calls = []
        refund = self.guard.tool("refund", amount_arg="amount")(lambda order_id, amount, customer_email: calls.append(order_id))
        allowed = blocked = 0
        for i in range(40):
            try: refund(str(i), 2500, "buyer@example.test"); allowed += 1
            except Blocked: blocked += 1
        self.assertEqual((20, 20), (allowed, blocked))
        self.assertNotIn("buyer@example.test", json.dumps(self.log.entries()))
        self.enforcer.down = True
        transfer = self.guard.tool("transfer", amount_arg="amount")(lambda amount: calls.append("transfer"))
        with self.assertRaises(Blocked): transfer(1000)
        read = self.guard.tool("read")(lambda: "ok")
        self.assertEqual("ok", read())

    def test_evidence_tamper_export_and_report(self):
        read = self.guard.tool("read")(lambda: "ok"); read()
        self.assertTrue(self.log.verify().ok)
        bundle = export_bundle(self.log, self.policy, Signer(SIGN_KEY), self.clock)
        self.assertTrue(verify_bundle(bundle, SIGN_KEY, TSA_KEY).ok)
        bundle["entries"][0]["tool"] = "changed"
        self.assertFalse(verify_bundle(bundle, SIGN_KEY, TSA_KEY).ok)
        key = "entry/00000000"; entry = json.loads(self.stores[0].get(key)); entry["kind"] = "transfer"
        self.stores[0]._demo_corrupt(key, canonical(entry))
        result = self.log.verify(); self.assertFalse(result.ok); self.assertEqual(0, result.first_bad_seq)
        report = risk_report(self.log, self.policy, self.ledger)
        self.assertIsNone(report["score"]); self.assertIn("Not an insurance rating", report["disclaimer"])

    def test_write_failure_blocks_and_releases(self):
        action = self.guard.tool("refund", amount_arg="amount")(lambda amount: self.fail("must not run"))
        self.stores[0].fail_next_put = True
        with self.assertRaises(Blocked) as caught: action(1000)
        self.assertEqual("evidence_unavailable", caught.exception.reason)
        self.assertEqual(0, next(iter(self.ledger.totals().values()))["reserved"])

    def test_vault_has_no_read_method(self):
        vault = MemoryVault(); vault.put("a@example.test")
        self.assertEqual(1, vault.count()); self.assertFalse(hasattr(vault, "get"))


if __name__ == "__main__": unittest.main()
