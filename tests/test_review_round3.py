"""Operator and user disclosure regressions, updated for current behavior."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(name):
    return (ROOT / name).read_text(encoding='utf-8')


class DisclosureTests(unittest.TestCase):
    def test_deployment_checklist_covers_proxy_tokens_and_headroom(self):
        text = read('HARDENING.md')
        start = text.index('## Deployment checklist')
        section = text[start:text.index('\n## ', start + 1)]
        self.assertIn('APP_HOST=127.0.0.1', section)
        self.assertIn('APP_TRUSTED_PROXIES', section)
        self.assertIn('`/w/`', section)
        self.assertIn('30 MiB', section)
        self.assertIn('deployment checklist', read('README.md'))

    def test_job_headroom_is_quantified_and_listed(self):
        text = read('HARDENING.md')
        self.assertIn('x 5 MiB = 30 MiB', text)
        self.assertIn('`.job-*` directories are outside the APP_DATA_CAP_MB accounting', text)

    def test_bundle_verification_disclosure_matches_current_behavior(self):
        text = read('HARDENING.md')
        self.assertIn('Bundle downloads are re-verified before serving', text)
        self.assertIn('409', text)
        self.assertNotIn('Bundle downloads are not re-verified', text)

    def test_derived_mac_limitation_is_documented(self):
        self.assertIn('derived_mac is not an integrity guarantee against the workspace holder', read('HARDENING.md'))
        self.assertIn('does not protect results against the workspace holder', read('README.md'))

    def test_signed_bundle_is_not_third_party_proof(self):
        for name in ('README.md', 'HARDENING.md'):
            with self.subTest(document=name):
                self.assertIn('not third-party proof', read(name))

    def test_log_format_limits_match_current_parser(self):
        text = read('HARDENING.md')
        self.assertIn('Decimal amounts are rejected without rounding', text)
        self.assertIn('Numeric identifiers and epoch seconds/milliseconds are accepted', text)
        self.assertIn('refund, transfer, spend, destructive or read', text)
        self.assertNotIn('Epoch timestamps and decimal amounts are rejected', text)

    def test_row_ceiling_is_stated_in_readme_and_hardening(self):
        self.assertIn('about 2,000 rows', read('README.md'))
        self.assertIn('about 2,000 rows', read('HARDENING.md'))


if __name__ == '__main__':
    unittest.main()
