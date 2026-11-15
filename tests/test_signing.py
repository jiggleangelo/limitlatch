import copy
import datetime as dt
import unittest
from agentguard import EvidenceLog, FakeTSA, FixedClock, MemoryWormStore, Policy, Signer, export_bundle, verify_bundle
from demo import POLICY_DATA


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc))
        self.policy = Policy.load(POLICY_DATA)
        self.log = EvidenceLog([MemoryWormStore(), MemoryWormStore()], FakeTSA(b"tsa", self.clock), self.clock)
        self.log.append({"kind": "read"})
        self.bundle = export_bundle(self.log, self.policy, Signer(b"sign"), self.clock)

    def test_bad_signing_and_tsa_keys(self):
        self.assertEqual("bad_signature", verify_bundle(self.bundle, b"wrong", b"tsa").reason)
        self.assertEqual("bad_anchor", verify_bundle(self.bundle, b"sign", b"wrong").reason)

    def test_tamper_truncate_reorder_and_gap(self):
        changed = copy.deepcopy(self.bundle)
        changed["entries"][0]["kind"] = "changed"
        self.assertEqual("bad_signature", verify_bundle(changed, b"sign", b"tsa").reason)

        log = EvidenceLog([MemoryWormStore(), MemoryWormStore()], FakeTSA(b"tsa", self.clock), self.clock)
        log.append({"kind": "one"}); log.append({"kind": "two"})
        bundle = export_bundle(log, self.policy, Signer(b"sign"), self.clock)
        reordered = copy.deepcopy(bundle)
        reordered["entries"].reverse()
        body = {k: v for k, v in reordered.items() if k != "signature"}
        reordered["signature"] = Signer(b"sign").sign(body)
        self.assertEqual(0, verify_bundle(reordered, b"sign", b"tsa").first_bad_seq)

        gap = copy.deepcopy(bundle)
        gap["entries"][1]["seq"] = 2
        body = {k: v for k, v in gap.items() if k != "signature"}
        gap["signature"] = Signer(b"sign").sign(body)
        result = verify_bundle(gap, b"sign", b"tsa")
        self.assertEqual(("sequence_gap", 1), (result.reason, result.first_bad_seq))


if __name__ == "__main__":
    unittest.main()
