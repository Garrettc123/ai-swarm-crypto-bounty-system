"""Offline regression tests: an open or funded GitHub label is not claimability."""
import unittest
from datetime import datetime, timezone

from bounty_discovery_service import parse_items
from bounty_intelligence import enrich_candidate

NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)


def issue(*, repo="example/project", labels=None, body="", title="Bounty: $500"):
    return {
        "id": 99,
        "state": "open",
        "html_url": f"https://github.com/{repo}/issues/99",
        "title": title,
        "body": body,
        "updated_at": "2026-11-17T00:00:00Z",
        "labels": [{"name": label} for label in (labels or ["bounty"])],
    }


def triage(item):
    parsed = parse_items({"items": [item]})
    assert len(parsed) == 1
    return enrich_candidate(parsed[0], now=NOW)


class TestBountyEligibilityGates(unittest.TestCase):
    def test_funded_but_verification_unavailable_is_blocked(self):
        row = triage(issue(
            labels=["bounty", "funded-live", "verification-unavailable"]
        ))
        self.assertEqual(row["status"], "blocked_for_review")
        self.assertEqual(row["priority_score"], 0)
        self.assertIn("label:verification-unavailable", row["risk_flags"])
        self.assertFalse(row["reward_terms_verified"])
        self.assertFalse(row["payout_confirmed"])

    def test_funding_needed_is_blocked_despite_reward_title(self):
        row = triage(issue(labels=["bounty", "funding-needed"]))
        self.assertEqual(row["status"], "blocked_for_review")
        self.assertEqual(row["priority_score"], 0)
        self.assertIn("label:funding-needed", row["risk_flags"])

    def test_no_longer_claimable_in_body_is_blocked(self):
        row = triage(issue(
            body="The delivery cutoff has passed. This issue is closed to new work."
        ))
        self.assertEqual(row["status"], "blocked_for_review")
        self.assertEqual(row["priority_score"], 0)

    def test_positive_funding_label_is_not_funding_evidence(self):
        row = triage(issue(labels=["bounty", "funded-live"]))
        self.assertEqual(row["status"], "candidate_unverified")
        self.assertFalse(row["sponsor_verified"])
        self.assertFalse(row["reward_terms_verified"])
        self.assertIsNone(row["reward_amount"])
        self.assertTrue(row["approval_required"])

    def test_mirror_is_deprioritized_and_not_verified(self):
        mirrored = triage(issue(repo="mirror/bounty-plaza"))
        original = triage(issue(repo="example/original"))
        self.assertTrue(mirrored["possibly_mirrored"])
        self.assertLess(mirrored["priority_score"], original["priority_score"])
        self.assertFalse(mirrored["reward_terms_verified"])


if __name__ == "__main__":
    unittest.main()
