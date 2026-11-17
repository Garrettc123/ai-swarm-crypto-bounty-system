"""Offline regression tests for the read-only public bounty discovery service."""
import io
import json
import unittest
from urllib.error import URLError

import bounty_discovery_service as svc


class FakeResponse:
    def __init__(self, payload):
        self.body = io.BytesIO(json.dumps(payload).encode("utf-8"))

    def __enter__(self):
        return self.body

    def __exit__(self, *args):
        self.body.close()


class TestBountyDiscovery(unittest.TestCase):
    def test_candidates_exclude_closed_pr_and_untrusted_host(self):
        rows = svc.parse_items({"items": [
            {"id": 42, "state": "open", "title": "Solidity bounty",
             "html_url": "https://github.com/real/project/issues/42",
             "updated_at": "2026-11-17T10:00:00Z",
             "labels": [{"name": "bounty"}]},
            {"id": 43, "state": "closed",
             "html_url": "https://github.com/real/project/issues/43"},
            {"id": 44, "state": "open",
             "html_url": "https://evil.invalid/issue/44"},
            {"id": 45, "state": "open",
             "html_url": "https://github.com/real/project/pull/45"},
            {"id": 46, "state": "open", "pull_request": {"url": "x"},
             "html_url": "https://github.com/real/project/issues/46"},
        ]})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["repository"], "real/project")
        self.assertEqual(rows[0]["status"], "candidate_unverified")
        self.assertIsNone(rows[0]["reward_amount"])
        self.assertFalse(rows[0]["payout_confirmed"])
        self.assertFalse(rows[0]["authorization_to_test"])

    def test_github_request_is_read_only_and_fixed_host(self):
        seen = []
        def opener(request, timeout):
            seen.append((request.full_url, request.get_method(), timeout))
            return FakeResponse({"items": []})
        self.assertEqual(svc.github_search(
            "is:issue is:open label:bounty crypto", opener=opener), [])
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][0].startswith("https://api.github.com/search/issues?"))
        self.assertEqual(seen[0][1], "GET")
        self.assertEqual(seen[0][2], 12)

    def test_no_money_or_submission_powers(self):
        index = svc.BountyIndex(search=lambda query: [])
        index.scan_once()
        state = index.snapshot()
        self.assertEqual(state["scan_state"], "ok")
        self.assertEqual(state["candidate_count"], 0)
        self.assertTrue(all(value is False for value in state["actions_enabled"].values()))

    def test_error_state_not_faked_as_success(self):
        def fail(_query):
            raise URLError("offline")
        index = svc.BountyIndex(search=fail)
        index.scan_once()
        state = index.snapshot()
        self.assertEqual(state["scan_state"], "unavailable")
        self.assertEqual(len(state["source_errors"]), len(svc.QUERIES))
        self.assertIsNone(state["last_success_at"])

    def test_deduplicates_same_issue_across_queries(self):
        candidate = {"url": "https://github.com/real/project/issues/42",
                     "title": "one", "updated_at": "2026-11-17T00:00:00Z"}
        index = svc.BountyIndex(search=lambda query: [candidate])
        index.scan_once()
        self.assertEqual(index.snapshot()["candidate_count"], 1)

    def test_reject_non_issue_url(self):
        self.assertFalse(svc.public_issue_url(
            "https://github.com.attacker.test/repo/issues/3"))
        self.assertFalse(svc.public_issue_url(
            "http://github.com/a/b/issues/3"))
        self.assertFalse(svc.public_issue_url(
            "https://github.com/a/b/pull/3"))


if __name__ == "__main__":
    unittest.main()
