"""Regression coverage for repository-root unittest discovery."""

import pathlib
import unittest


class DiscoveryTests(unittest.TestCase):
    def test_root_discovery_includes_existing_test_modules(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        loader = unittest.TestLoader()
        suite = loader.discover(
            start_dir=str(root),
            pattern="test*.py",
            top_level_dir=str(root),
        )
        self.assertEqual([], loader.errors)

        def test_ids(tests):
            for test in tests:
                if isinstance(test, unittest.TestSuite):
                    yield from test_ids(test)
                else:
                    yield test.id()

        discovered_modules = {
            test_id.rsplit(".", 2)[0] for test_id in test_ids(suite)
        }
        expected_modules = {
            "tests.test_budget",
            "tests.test_constraints",
            "tests.test_core",
            "tests.test_demo",
            "tests.test_evidence",
            "tests.test_redact",
            "tests.test_signing",
        }
        self.assertTrue(
            expected_modules.issubset(discovered_modules),
            f"Missing test modules: {sorted(expected_modules - discovered_modules)}",
        )


if __name__ == "__main__":
    unittest.main()
