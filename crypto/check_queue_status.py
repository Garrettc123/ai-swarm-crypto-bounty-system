#!/usr/bin/env python3
"""Verify both live discovery feeds are present in the existing durable queue."""
import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen

URL = "https://garcar-crypto-bounty-discovery-canary-staging.up.railway.app/queue-status"
FEEDS = ("github_actions", "railway_public_scout")


def verify(status, *, now=None):
    if not isinstance(status, dict):
        raise ValueError("missing queue status")
    feeds = status.get("feeds")
    if status.get("storage") != "redis_with_existing_disk_snapshots" or not isinstance(feeds, dict):
        raise ValueError("durable queue backend not confirmed")
    counts = []
    current = now or datetime.now(timezone.utc)
    for feed in FEEDS:
        try:
            count = int(feeds[feed + ":count"])
            timestamp = datetime.fromisoformat(feeds[feed + ":at"])
            if timestamp.tzinfo is None:
                raise ValueError("timestamp lacks timezone")
            age = (current - timestamp).total_seconds()
            if not 0 <= age <= 172800:
                raise ValueError("feed is stale")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("missing or stale feed: " + feed) from exc
        if count <= 0:
            raise ValueError("zero listings from feed " + feed)
        counts.append(count)
    unique = status.get("observed_unique")
    if type(unique) is not int or not max(counts) <= unique <= 25000:
        raise ValueError("unexpected deduplicated queue size")
    if status.get("verified_earnings_usd") != 0 or status.get("external_actions_enabled") is not False:
        raise ValueError("financial or execution gate violation")
    return {
        "result": "verified_two_live_feeds",
        "feed_counts": dict(zip(FEEDS, counts)),
        "stored_unique_candidates": unique,
        "verified_earnings_usd": 0,
        "external_actions_enabled": False,
        "persistence_level": "Redis with existing RDB snapshots; backups and independent payout verification not proven",
    }


def main():
    req = Request(URL, headers={"Accept": "application/json", "User-Agent": "Garcar-Queue-Health/1.0"})
    with urlopen(req, timeout=15) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("status payload exceeds limit")
    print(json.dumps(verify(json.loads(raw)), indent=2))


if __name__ == "__main__":
    main()
