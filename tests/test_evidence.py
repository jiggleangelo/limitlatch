import datetime as dt
import unittest
from agentguard import EvidenceLog, EvidenceUnavailable, FakeTSA, FixedClock, MemoryWormStore


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc))
        self.stores = [MemoryWormStore("a"), MemoryWormStore("b")]
        self.tsa = FakeTSA(b"tsa", self.clock)
        self.log = EvidenceLog(self.stores, self.tsa, self.clock)

    def test_partial_replication_is_resumed(self):
        self.stores[1].fail_next_put = True
        with self.assertRaises(EvidenceUnavailable):
            self.log.append({"kind": "read"})
        self.log.append({"kind": "read-2"})
        self.assertEqual(2, self.log.seq)
        self.assertTrue(self.log.verify().ok)

    def test_tsa_failure_advances_chain(self):
        self.tsa.down = True
        with self.assertRaises(EvidenceUnavailable):
            self.log.append({"kind": "read"})
        self.assertEqual(1, self.log.seq)
        self.assertEqual("missing_anchor", self.log.verify().reason)
        self.tsa.down = False
        self.log.append({"kind": "read-2"})
        self.assertEqual(2, self.log.seq)


if __name__ == "__main__":
    unittest.main()
