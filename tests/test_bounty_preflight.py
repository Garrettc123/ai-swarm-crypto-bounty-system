"""Offline behavioral tests for canonical issue verification."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import bounty_preflight as preflight


class Response:
    def __init__(self, payload):
        self.body = io.BytesIO(json.dumps(payload).encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.body.close()

    def read(self, amount=-1):
        return self.body.read(amount)


URL = "https://github.com/example/repo/issues/42"


def payload(**updates):
    issue = {
        "html_url": URL, "title": "Improve Python API",
        "state": "open", "body": "Documentation and tests",
        "labels": [{"name": "bounty"}], "assignees": [],
        "updated_at": "2026-11-17T19:00:00Z",
    }
    issue.update(updates)
    return issue


def reader(issue):
    def open_request(request, timeout):
        assert request.get_method() == "GET"
        assert request.full_url == "https://api.github.com/repos/example/repo/issues/42"
        assert timeout == 10
        return Response(issue)
    return open_request


class TestCanonicalPreflight(unittest.TestCase):
    def test_only_canonical_github_issue_urls(self):
        src, api = preflight.canonical_source(URL)
        self.assertEqual(src, URL)
        self.assertEqual(api, "https://api.github.com/repos/example/repo/issues/42")
        for bad in (
            "http://github.com/example/repo/issues/42",
            "https://github.com.evil.com/example/repo/issues/42",
            "https://github.com/example/repo/pull/42",
            "https://github.com/example/repo/issues/42?redirect=evil",
            "https://github.com/example/repo/issues/42#fragment",
            "https://github.com/@evil.example/repo/issues/42",
            "https://github.com/../repo/issues/42",
            "https://github.com/example/repo/issues/42/attachments",
        ):
            with self.subTest(url=bad):
                with self.assertRaises(ValueError):
                    preflight.canonical_source(bad)

    def test_unassigned_open_issue_still_not_payable(self):
        res = preflight.inspect_issue(URL, opener=reader(payload()))
        self.assertEqual(res["status"], "manual_review")
        self.assertEqual(res["source_issue_state"], "open")
        self.assertFalse(res["funding_verified"])
        self.assertFalse(res["reward_terms_verified"])
        self.assertFalse(res["authorization_to_test"])
        self.assertFalse(res["external_action_allowed"])
        self.assertFalse(res["payout_verified"])

    def test_closed_issue_is_held(self):
        res = preflight.inspect_issue(URL, opener=reader(payload(state="closed")))
        self.assertEqual(res["status"], "hold")
        self.assertIn("issue_closed_at_canonical_source", res["reasons"])

    def test_assignment_or_in_progress_blocks_claimability(self):
        for issue in (
            payload(assignees=[{"login": "someone-else"}]),
            payload(labels=[{"name": "in-progress"}, {"name": "bounty"}]),
            payload(body="This bounty is currently unavailable; do not claim."),
        ):
            with self.subTest(issue=issue):
                res = preflight.inspect_issue(URL, opener=reader(issue))
                self.assertEqual(res["status"], "hold")
                self.assertFalse(res["external_action_allowed"])

    def test_rejects_redirected_or_wrong_canonical_response(self):
        bad = preflight.inspect_issue(
            URL, opener=reader(payload(html_url="https://github.com/else/r/issues/1"))
        )
        self.assertEqual(bad["status"], "hold")
        self.assertIn("canonical_url_mismatch", bad["reasons"])
        no_pr = preflight.inspect_issue(URL, opener=reader(payload(pull_request={})))
        self.assertEqual(no_pr["status"], "hold")
        self.assertIn("not_a_verifiable_issue", no_pr["reasons"])
        self.assertIsNone(preflight._NoRedirect().redirect_request(None, None, 302, "", {}, URL))

    def test_source_failure_does_not_mean_closed_or_available(self):
        def fail(request, timeout):
            raise HTTPError(request.full_url, 404, "Not found", {}, None)
        result = preflight.inspect_issue(URL, opener=fail)
        self.assertEqual(result["status"], "source_unavailable")
        self.assertEqual(result["source_issue_state"], "unknown")
        self.assertIn("canonical_source_http_404", result["reasons"])

    def test_oversize_payload_is_blocked_for_network_reliability(self):
        class Oversized(Response):
            def read(self, amount=-1):
                return b"x" * (preflight.MAX_BYTES + 1)
        result = preflight.inspect_issue(URL, opener=lambda request, timeout: Oversized({}))
        self.assertEqual(result["status"], "source_unavailable")

    def test_batch_url_validation_before_any_requests(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "urls.json"
            path.write_text(json.dumps([URL, "https://evil.invalid/path"]))
            with patch.object(preflight, "inspect_issue") as mocked:
                with self.assertRaises(ValueError):
                    preflight.main(["--file", str(path)])
                mocked.assert_not_called()

    def test_cli_never_submits_or_reports_real_rewards(self):
        with patch.object(preflight, "inspect_issue") as mocked:
            mocked.return_value = preflight._baseline(URL)
            with patch("builtins.print") as printed:
                self.assertEqual(preflight.main(["--url", URL]), 0)
            doc = json.loads(printed.call_args.args[0])
            self.assertEqual(doc["checked"], 1)
            self.assertEqual(doc["funded_bounties_verified"], 0)
            self.assertFalse(doc["claim_or_submission_performed"])


if __name__ == "__main__":
    unittest.main()
