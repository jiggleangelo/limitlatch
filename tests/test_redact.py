import json
import unittest
from agentguard import MemoryVault, redact_args


class RedactionTests(unittest.TestCase):
    def test_clear_fields_are_allow_listed_by_type(self):
        vault = MemoryVault()
        result = redact_args({"amount": "4111111111111111", "currency": "secret", "confirmed": "yes"}, vault, b"k")
        self.assertEqual("[redacted]", result["args"]["amount"])
        self.assertEqual("[redacted]", result["args"]["currency"])
        self.assertEqual("[redacted]", result["args"]["confirmed"])

    def test_contact_values_use_vault_and_digests_are_salted(self):
        vault = MemoryVault()
        first = redact_args({"email": "a@example.test", "amount": 10, "currency": "USD", "confirmed": True}, vault, b"k")
        second = redact_args({"email": "a@example.test", "amount": 10, "currency": "USD", "confirmed": True}, vault, b"k")
        self.assertEqual(2, vault.count())
        self.assertNotEqual(first["args_digest"], second["args_digest"])
        self.assertEqual(10, first["args"]["amount"])
        self.assertEqual("USD", first["args"]["currency"])
        self.assertIs(True, first["args"]["confirmed"])

    def test_pii_dictionary_key_never_reaches_evidence_arguments(self):
        vault = MemoryVault()
        result = redact_args({"note": {"jane@corp.com": 2500, "+1 212 555 0100": True}}, vault, b"k")
        encoded = json.dumps(result)
        self.assertNotIn("jane@corp.com", encoded)
        self.assertNotIn("212 555", encoded)
        self.assertEqual({"[key:0]", "[key:1]"}, set(result["args"]["note"]))

    def test_vault_capacity_does_not_retain_unbounded_contact_values(self):
        vault = MemoryVault(max_values=1)
        first = vault.put("first@example.test")
        second = vault.put("second@example.test")
        self.assertTrue(first.startswith("v_"))
        self.assertEqual("v_capacity_redacted", second)
        self.assertEqual(1, vault.count())


if __name__ == "__main__":
    unittest.main()
