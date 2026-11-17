"""Immunefi governed manual intake and scanner resilience tests; no external requests."""
import unittest
from datetime import datetime, timezone

import bounty_discovery_service as svc
from immunefi_review import REQUIRED_CHECKS, evaluate_program, public_policy

NOW = datetime(2026, 11, 17, 18, 0, tzinfo=timezone.utc)


def record(**updates):
    result = {
        "program_url": "https://immunefi.com/bug-bounty/ens/information/",
        "scope_url": "https://immunefi.com/bug-bounty/ens/scope/",
        "reviewed_at": "2026-11-17T17:00:00Z",
        "source_mode": "operator_manual",
        "checks": {key: True for key in REQUIRED_CHECKS},
    }
    result.update(updates)
    return result


class TestImmunefiManualReview(unittest.TestCase):
    def test_review_checklist_never_authorizes_security_action(self):
        output = evaluate_program(record(), now=NOW)
        self.assertEqual(output["review_status"], "human_checklist_recorded")
        self.assertTrue(output["human_review_checklist_complete"])
        self.assertFalse(output["security_testing_enabled"])
        self.assertFalse(output["scope_authorization_verified"])
        self.assertFalse(output["automatic_submission_enabled"])
        self.assertFalse(output["payout_verified"])
        self.assertFalse(output["program_information_authenticated"])

    def test_reject_program_scope_mismatch(self):
        output = evaluate_program(record(
            scope_url="https://immunefi.com/bug-bounty/0x/scope/"), now=NOW)
        self.assertEqual(output["review_status"], "blocked")
        self.assertIn("canonical_program_scope_url_mismatch",
                      output["blocking_reasons"])

    def test_reject_impersonation_and_urls_with_query_or_credentials(self):
        bad_urls = (
            "https://immunefi.com.attacker.test/bug-bounty/ens/information/",
            "http://immunefi.com/bug-bounty/ens/information/",
            "https://immunefi.com/bug-bounty/ens/information/?key=secret",
            "https://a:b@immunefi.com/bug-bounty/ens/information/",
            "https://immunefi.com/bug-bounty/ens/information/#disclosure",
        )
        for url in bad_urls:
            with self.subTest(url=url):
                self.assertEqual(evaluate_program(
                    record(program_url=url), now=NOW)["review_status"], "blocked")

    def test_reject_automated_source_collection(self):
        self.assertIn("automatic_or_unattributed_collection_not_allowed",
                      evaluate_program(record(source_mode="scraper"), now=NOW)["blocking_reasons"])

    def test_reject_missing_or_unchecked_scope_checks(self):
        missing = {key: True for key in REQUIRED_CHECKS}
        missing.pop("asset_ownership_reviewed")
        self.assertEqual(evaluate_program(record(checks=missing), now=NOW)["review_status"], "blocked")
        unchecked = {key: True for key in REQUIRED_CHECKS}
        unchecked["research_method_allowed"] = False
        self.assertEqual(evaluate_program(record(checks=unchecked), now=NOW)["review_status"], "blocked")

    def test_reject_stale_and_future_review(self):
        for stamp in ("2026-11-01T00:00:00Z", "2026-11-18T00:00:00Z",
                      "2026-11-17T17:00:00"):
            with self.subTest(stamp=stamp):
                self.assertIn("review_timestamp_missing_or_stale",
                              evaluate_program(record(reviewed_at=stamp),
                                               now=NOW)["blocking_reasons"])

    def test_reject_sensitive_extra_fields(self):
        for field in ("private_key", "raw_vulnerability", "payout_amount"):
            with self.subTest(field=field):
                self.assertIn("unexpected_fields_rejected",
                              evaluate_program({**record(), field: "untrusted"},
                                               now=NOW)["blocking_reasons"])

    def test_policy_explicitly_disables_automated_access(self):
        policy = public_policy()
        self.assertFalse(policy["automated_website_access"])
        self.assertFalse(policy["security_testing_enabled"])
        self.assertFalse(policy["automatic_submission_enabled"])
        self.assertEqual(policy["programs_imported"], 0)
        self.assertEqual(policy["official_links"]["rules"], "https://immunefi.com/rules/")


class TestScannerHardening(unittest.TestCase):
    def test_canonical_github_issues_only(self):
        accepted = "https://github.com/example/repo/issues/123"
        self.assertTrue(svc.public_issue_url(accepted))
        for bad in (accepted + "?token=x", accepted + "#secret",
                    accepted + "/comments", accepted.replace("github.com",
                    "github.com.evil.example"), "https://github.com/a/b/issues/0"):
            with self.subTest(bad=bad):
                self.assertFalse(svc.public_issue_url(bad))

    def test_malformed_rows_are_skipped_not_crash(self):
        items = [None, 10, "malformed",
                 {"state": "open", "html_url": "https://github.com/a/b/issues/9",
                  "labels": "invalid", "title": "Safe"}]
        rows = svc.parse_items({"items": items})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["labels"], [])

    def test_unexpected_source_exception_fails_closed(self):
        def broken(query):
            raise RuntimeError("unexpected adapter defect")
        idx = svc.BountyIndex(search=broken)
        idx.scan_once()
        state = idx.snapshot()
        self.assertEqual(state["scan_state"], "unavailable")
        self.assertEqual(len(state["source_errors"]), len(svc.QUERIES))
        self.assertIsNone(state["last_success_at"])


if __name__ == "__main__":
    unittest.main()
