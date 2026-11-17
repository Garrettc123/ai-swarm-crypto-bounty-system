"""Loopback-only HTTP contract tests for the bounded staging dashboard."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import bounty_discovery_service as svc

ROOT = Path(__file__).resolve().parents[1]


class TestReadOnlyDashboard(unittest.TestCase):
    def setUp(self):
        self.previous = svc.INDEX
        item = {
            "url": "https://github.com/sample/repo/issues/12",
            "title": "Python crypto bounty task",
            "labels": ["bounty", "help wanted"],
            "updated_at": "2026-11-17T13:00:00Z",
        }
        svc.INDEX = svc.BountyIndex(search=lambda _query: [item])
        svc.INDEX.scan_once()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), svc.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.root = "http://127.0.0.1:" + str(self.server.server_address[1])

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=3)
        self.server.server_close()
        svc.INDEX = self.previous

    def test_homepage_serves_protected_assets(self):
        with urlopen(self.root + "/", timeout=3) as response:
            html = response.read().decode("utf-8")
            policy = response.headers.get("Content-Security-Policy")
            self.assertEqual(response.status, 200)
            self.assertIn("Bounty Intelligence", html)
            self.assertIn("script-src 'self'", policy)
            self.assertIn("frame-ancestors 'none'", policy)
            self.assertEqual(response.headers.get("X-Content-Type-Options"),
                             "nosniff")
        for path, expected in (("/dashboard.css", "text/css"),
                               ("/dashboard.js", "text/javascript")):
            with urlopen(self.root + path, timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(expected, response.headers["Content-Type"])
                self.assertGreater(len(response.read()), 100)

    def test_read_only_json_contracts(self):
        for path in ("/health", "/ready", "/bounties?limit=1&skill=python",
                     "/sources", "/receipts", "/digest"):
            with urlopen(self.root + path, timeout=3) as response:
                self.assertEqual(response.status, 200, path)
                self.assertIsInstance(json.load(response), dict)
        with urlopen(self.root + "/bounties?limit=1", timeout=3) as response:
            value = json.load(response)
            self.assertEqual(value["returned"], 1)
            self.assertFalse(value["items"][0]["authorization_to_test"])

    def test_rhns_governance_route_is_read_only_and_research_only(self):
        with urlopen(self.root + "/governance", timeout=3) as response:
            self.assertEqual(response.status, 200)
            value = json.load(response)
        self.assertEqual(value["governance_version"], "rhns-governance-0.1")
        self.assertFalse(value["external_execution_enabled"])
        self.assertFalse(value["wallet_actions_enabled"])
        self.assertTrue(value["review_queue_admissible"])
        with urlopen(self.root + "/work-queue?limit=2", timeout=3) as response:
            self.assertEqual(response.status, 200)
            work_queue = json.load(response)
        self.assertTrue(work_queue["formal_governance"]["passed"])
        self.assertFalse(work_queue["formal_governance"]["external_dispatch_enabled"])
        with urlopen(self.root + "/", timeout=3) as response:
            html = response.read().decode("utf-8")
        self.assertIn('id="governance-status"', html)

    def test_governance_queue_fails_closed_during_outage(self):
        from urllib.error import URLError
        svc.INDEX = svc.BountyIndex(search=lambda _q: (_ for _ in ()).throw(URLError("offline")))
        svc.INDEX.scan_once()
        with self.assertRaises(HTTPError) as failure:
            urlopen(self.root + "/work-queue", timeout=3)
        self.assertEqual(failure.exception.code, 503)

    def test_immunefi_policy_is_reachable_and_never_enables_automation(self):
        with urlopen(self.root + "/immunefi-policy", timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("application/json", response.headers["Content-Type"])
            value = json.load(response)
        self.assertEqual(value["integration"], "manual_review_only")
        self.assertFalse(value["automated_website_access"])
        self.assertFalse(value["security_testing_enabled"])
        self.assertFalse(value["automatic_submission_enabled"])
        self.assertEqual(value["programs_imported"], 0)
        self.assertEqual(value["official_links"]["terms"],
                         "https://immunefi.com/terms-of-use/")

        with urlopen(self.root + "/", timeout=3) as response:
            html = response.read().decode("utf-8")
        self.assertIn('id="immunefi-status"', html)
        self.assertIn('href="https://immunefi.com/rules/"', html)

    def test_immunefi_policy_unhandled_http_methods_fail_closed(self):
        from urllib.request import Request
        request = Request(self.root + "/immunefi-policy",
                          data=b'{"program":"untrusted"}', method="POST")
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=3)
        self.assertEqual(error.exception.code, 501)

    def test_invalid_query_does_not_execute_search(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(self.root + "/bounties?limit=invalid", timeout=3)
        self.assertEqual(error.exception.code, 400)

    def test_frontend_uses_text_content_not_html_sink(self):
        script = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        self.assertIn(".textContent", script)
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("eval(", script)


if __name__ == "__main__":
    unittest.main()
