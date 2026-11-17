"""Hermetic governance and idempotency tests; no real opportunity data."""
import unittest
from bounty_work_queue import build_work_queue, safe_issue_url, MAX_CANDIDATES


def candidate(n=3, **fields):
    row = {
        "url": f"https://github.com/verified/repo/issues/{n}",
        "title": "Python code task — fixture, not a funded bounty",
        "status": "candidate_unverified",
        "source_verified": True,
        "source_stale": False,
        "priority_score": 75,
        "risk_flags": [],
        "possibly_mirrored": False,
        "labels": ["bounty"],
        "reward_amount": None,
    }
    row.update(fields)
    return row


class TestGovernedQueue(unittest.TestCase):
    def test_research_candidate_creates_no_external_action(self):
        q = build_work_queue([candidate()], "ok")
        self.assertEqual(q["counts"]["research_ready"], 1)
        work = q["work_orders"][0]
        self.assertEqual(work["task_type"], "canonical_source_qualification")
        self.assertEqual(work["mode"], "read_only_research")
        self.assertFalse(work["external_execution_enabled"])
        self.assertFalse(work["reward_funding_verified"])
        self.assertFalse(work["payout_verified"])
        self.assertTrue(work["approval_required"])
        self.assertIn("wallet_sign", work["forbidden_actions"])
        self.assertIn("submit_claim", work["forbidden_actions"])

    def test_unavailable_source_fails_closed(self):
        q = build_work_queue([candidate()], "unavailable")
        self.assertEqual(q["counts"]["research_ready"], 0)
        self.assertEqual(q["held_reasons"]["source_scan_not_ok"], 1)

    def test_partial_source_fails_closed(self):
        q = build_work_queue([candidate()], "partial")
        self.assertEqual(q["counts"]["research_ready"], 0)

    def test_untrusted_source_fails_closed(self):
        q = build_work_queue([candidate(source_verified=False)], "ok")
        self.assertEqual(q["counts"]["research_ready"], 0)

    def test_stale_source_fails_closed(self):
        q = build_work_queue([candidate(source_stale=True)], "ok")
        self.assertEqual(q["held_reasons"]["source_observation_stale_or_unknown"], 1)

    def test_funded_label_cannot_override_block(self):
        q = build_work_queue([candidate(status="blocked_for_review",
            risk_flags=["label:verification-unavailable"],
            labels=["bounty","funded-live"])], "ok")
        self.assertEqual(q["counts"]["research_ready"], 0)
        self.assertEqual(q["held_reasons"]["risk_flags_present"], 1)

    def test_mirror_fails_closed(self):
        q = build_work_queue([candidate(possibly_mirrored=True)], "ok")
        self.assertEqual(q["counts"]["research_ready"], 0)

    def test_score_does_not_prove_funding(self):
        q = build_work_queue([candidate(priority_score=100)], "ok")
        self.assertFalse(q["work_orders"][0]["reward_funding_verified"])

    def test_dedup_preserves_first_issue(self):
        q = build_work_queue([candidate(), candidate()], "ok")
        self.assertEqual(q["counts"]["observed_unique"], 1)

    def test_determinism_and_priority(self):
        rows = [candidate(11, priority_score=40), candidate(22, priority_score=95)]
        q = build_work_queue(rows, "ok", limit=1)
        same = build_work_queue(list(reversed(rows)), "ok", limit=1)
        self.assertEqual(q["queue_digest"], same["queue_digest"])
        self.assertEqual(q["work_orders"][0]["source_url"], rows[1]["url"])
        self.assertEqual(q["counts"]["truncated"], 1)

    def test_bad_urls_are_not_agent_instructions(self):
        invalid = [
            "https://github.com.evil.invalid/o/r/issues/3",
            "https://github.com/o/r/issues/4?token=secret",
            "http://github.com/o/r/issues/3",
            "https://user:pass@github.com/o/r/issues/3",
            "https://github.com/o/r/pull/3",
            "https://github.com/o/r/issues/0",
        ]
        for url in invalid:
            with self.subTest(url=url):
                self.assertFalse(safe_issue_url(url))
        q = build_work_queue([candidate(url=invalid[0])], "ok")
        self.assertEqual(q["counts"]["observed_unique"], 0)

    def test_bounded_input_and_output(self):
        with self.assertRaises(ValueError):
            build_work_queue([candidate()], "ok", limit=26)
        with self.assertRaises(ValueError):
            build_work_queue([candidate()]* (MAX_CANDIDATES + 1), "ok")
        with self.assertRaises(ValueError):
            build_work_queue([candidate()], "ok", limit=True)

    def test_no_floating_score_or_null_status_allowed(self):
        q = build_work_queue([candidate(priority_score=100.0),candidate(4,status=None)], "ok")
        self.assertEqual(q["counts"]["research_ready"], 0)


if __name__ == "__main__":
    unittest.main()
