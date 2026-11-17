"""Independent regression coverage for ranked, governed bounty review."""
import unittest
from datetime import datetime, timezone
from urllib.error import URLError

import bounty_discovery_service as svc
from bounty_intelligence import ReceiptLog, enrich_candidate

NOW = datetime(2026, 11, 17, 15, 0, tzinfo=timezone.utc)


def candidate():
    return {
        "id": "100", "url": "https://github.com/real/project/issues/100",
        "title": "Fix Python web3 RPC issue", "labels": ["bounty", "help wanted"],
        "updated_at": "2026-11-15T15:00:00Z",
        "status": "candidate_unverified",
    }


class TestIntelligence(unittest.TestCase):
    def test_priority_is_explainable_not_revenue_forecast(self):
        result = enrich_candidate(candidate(), now=NOW)
        self.assertGreater(result["priority_score"], 20)
        self.assertEqual(result["priority_label"], "review_priority_not_profitability")
        self.assertIn("python", result["matched_keywords"])
        self.assertGreater(len(result["priority_reasons"]), 1)
        self.assertIsNone(result["reward_amount"])
        self.assertFalse(result["payout_confirmed"])
        self.assertFalse(result["authorization_to_test"])
        self.assertTrue(result["approval_required"])

    def test_candidate_id_stable_across_title_edits(self):
        first = candidate()
        second = dict(first, title="different title")
        self.assertEqual(
            enrich_candidate(first, now=NOW)["candidate_id"],
            enrich_candidate(second, now=NOW)["candidate_id"]
        )

    def test_candidate_source_is_restricted(self):
        attack = dict(candidate(), url="https://attacker.example.com/")
        with self.assertRaises(ValueError):
            enrich_candidate(attack, now=NOW)

    def test_missing_update_timestamp_does_not_get_freshness_bonus(self):
        one = candidate()
        one["updated_at"] = "no timestamp"
        result = enrich_candidate(one, now=NOW)
        self.assertIsNone(result["last_updated_days_ago"])
        self.assertFalse(any("updated within" in reason
                             for reason in result["priority_reasons"]))

    def test_receipts_chain_and_tamper_detection(self):
        ledger = ReceiptLog()
        first = ledger.append(
            time_utc="2026-11-17T15:00:00Z", scan_state="ok",
            observed_urls=["https://github.com/a/b/issues/1"],
            query_outcomes=[{"query": "label:bounty", "status": "ok", "count": 1}],
            count=1
        )
        second = ledger.append(
            time_utc="2026-11-17T16:00:00Z", scan_state="partial",
            observed_urls=[], query_outcomes=[],
            count=0
        )
        self.assertEqual(second["prev_hash"], first["event_hash"])
        self.assertTrue(ledger.verify())
        self.assertEqual(ledger.snapshot()["storage"], "process_memory_only")
        ledger._entries[0]["candidate_count"] = 100000
        self.assertFalse(ledger.verify())

    def test_receipts_are_bounded_and_volatile(self):
        ledger = ReceiptLog()
        for hour in range(100):
            ledger.append(time_utc=f"2026-11-17T15:00:{hour % 60:02d}Z",
                          scan_state="ok", observed_urls=[],
                          query_outcomes=[], count=0)
        self.assertEqual(len(ledger.snapshot()["entries"]), 64)
        self.assertTrue(ledger.verify())

    def test_partial_failure_keeps_last_observed_result_as_stale(self):
        state = {"fail_second": False}
        target = svc.QUERIES[1]

        def search(query):
            if query == target and state["fail_second"]:
                raise URLError("offline")
            return [candidate()] if query == target else []

        index = svc.BountyIndex(search=search)
        index.scan_once()
        self.assertEqual(index.snapshot()["scan_state"], "ok")
        self.assertEqual(index.snapshot()["candidate_count"], 1)
        self.assertFalse(index.candidates()[0]["source_stale"])

        state["fail_second"] = True
        index.scan_once()
        snapshot = index.snapshot()
        self.assertEqual(snapshot["scan_state"], "partial")
        self.assertEqual(snapshot["candidate_count"], 1)
        self.assertEqual(snapshot["last_changes"]["no_longer_listed"], 0)
        self.assertTrue(index.candidates()[0]["source_stale"])
        self.assertEqual(len(index.receipts_snapshot()["entries"]), 2)
        self.assertTrue(snapshot["receipt_chain_valid"])

    def test_total_source_outage_not_misreported_as_ready(self):
        state = {"down": False}

        def search(_query):
            if state["down"]:
                raise URLError("offline")
            return [candidate()]

        index = svc.BountyIndex(search=search)
        index.scan_once()
        self.assertTrue(index.ready())
        state["down"] = True
        index.scan_once()
        self.assertFalse(index.ready())
        self.assertEqual(index.snapshot()["scan_state"], "unavailable")
        self.assertGreater(index.snapshot()["candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()
