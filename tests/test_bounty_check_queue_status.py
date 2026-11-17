import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest

p=Path(__file__).resolve().parents[1]/"crypto"/"check_queue_status.py"
s=importlib.util.spec_from_file_location("queue_health",p)
module=importlib.util.module_from_spec(s)
s.loader.exec_module(module)


def sample(now):
    t=now.isoformat(timespec="seconds")
    return {"storage":"redis_with_existing_disk_snapshots",
            "observed_unique":277,
            "feeds":{"github_actions:count":"246","github_actions:at":t,
                     "railway_public_scout:count":"55","railway_public_scout:at":t},
            "verified_earnings_usd":0,"external_actions_enabled":False}


class TestQueueHealth(unittest.TestCase):
    def test_both_feeds_and_overlapping_rows(self):
        now=datetime.now(timezone.utc)
        self.assertEqual(module.verify(sample(now),now=now)["stored_unique_candidates"],277)

    def test_stale_feed_rejected(self):
        now=datetime.now(timezone.utc)
        data=sample(now)
        data["feeds"]["github_actions:at"]=(now-timedelta(days=3)).isoformat()
        with self.assertRaisesRegex(ValueError,"stale feed"):
            module.verify(data,now=now)

    def test_financial_or_external_execution_claim_rejected(self):
        now=datetime.now(timezone.utc)
        data=sample(now)
        data["verified_earnings_usd"]=13
        with self.assertRaises(ValueError):
            module.verify(data,now=now)

    def test_historical_rows_may_exceed_today_feeds(self):
        now=datetime.now(timezone.utc)
        data=sample(now)
        data["observed_unique"]=900
        self.assertEqual(module.verify(data,now=now)["stored_unique_candidates"],900)
