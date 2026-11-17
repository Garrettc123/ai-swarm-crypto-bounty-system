"""Durable, metadata-only bounty review queue backed by existing Redis.

Discovery never grants authority to test targets, submit claims, or move money.
The Redis instance MUST have persistence enabled for restart durability.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import re
from urllib.parse import urlsplit

MAX_LISTINGS = 1200
STATES = frozenset({
    "unreviewed", "assigned", "researching", "submission_reported",
    "acceptance_reported", "payout_reported", "archived",
})
TRANSITIONS = {
    "unreviewed": frozenset({"assigned", "archived"}),
    "assigned": frozenset({"researching", "archived"}),
    "researching": frozenset({"submission_reported", "archived"}),
    "submission_reported": frozenset({"acceptance_reported", "archived"}),
    "acceptance_reported": frozenset({"payout_reported", "archived"}),
    "payout_reported": frozenset({"archived"}),
    "archived": frozenset(),
}
EVIDENCE_KINDS = frozenset({
    "terms", "funding", "eligibility", "authorization", "submission",
    "acceptance", "payout", "other",
})
GITHUB_PATH = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*$")
IMMUNEFI_PATH = re.compile(r"^/bug-bounty/[A-Za-z0-9_-]+/information/$")


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_url(value):
    if not isinstance(value, str) or len(value) > 350:
        raise ValueError("invalid opportunity URL")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or parsed.username is not None
                or parsed.password is not None or parsed.port is not None
                or parsed.query or parsed.fragment):
            raise ValueError("unsafe URL")
        if parsed.netloc == "github.com" and GITHUB_PATH.fullmatch(parsed.path):
            return parsed.geturl()
        if parsed.netloc == "immunefi.com" and IMMUNEFI_PATH.fullmatch(parsed.path):
            return parsed.geturl()
    except ValueError as exc:
        raise ValueError("invalid opportunity URL") from exc
    raise ValueError("source host or path not permitted")


def evidence_url(value):
    if not isinstance(value, str) or len(value) > 500:
        raise ValueError("invalid evidence URL")
    try:
        p = urlsplit(value)
        if (p.scheme != "https" or not p.hostname
                or p.username is not None or p.password is not None
                or p.port not in (None, 443) or p.fragment):
            raise ValueError("unsafe evidence URL")
        if p.hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
            raise ValueError("local evidence URL disallowed")
        return value
    except ValueError as exc:
        raise ValueError("invalid evidence URL") from exc


def normalized_rows(payload, feed):
    if feed not in {"github_actions", "railway_public_scout"}:
        raise ValueError("unrecognized discovery feed")
    if not isinstance(payload, dict):
        raise ValueError("discovery payload must be an object")
    key = "top" if feed == "github_actions" else "items"
    rows = payload.get(key)
    if not isinstance(rows, list) or len(rows) > MAX_LISTINGS:
        raise ValueError("invalid listing count")
    if feed == "github_actions" and payload.get("discovered") != len(rows):
        raise ValueError("scan export incomplete")
    if feed == "railway_public_scout" and payload.get("scan_state") != "ok":
        raise ValueError("railway scout not fully fresh")
    normalized = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid listing object")
        url = canonical_url(row.get("url"))
        if url in seen:
            # Source may repeat an issue but must not double-count it.
            continue
        seen.add(url)
        if feed == "github_actions":
            expected = "github.com" if row.get("platform") == "github" else "immunefi.com"
            if row.get("platform") not in ("github", "immunefi") or urlsplit(url).hostname != expected:
                raise ValueError("platform/URL mismatch")
        elif urlsplit(url).hostname != "github.com":
            raise ValueError("railway scout may only supply GitHub issues")
        reward = row.get("reward_max_usd") if feed == "github_actions" else None
        if type(reward) not in (int, float) or not math.isfinite(reward) or not 0 <= reward < 1e12:
            reward = None
        normalized.append({
            "id": hashlib.sha256(url.encode("utf-8")).hexdigest()[:32],
            "url": url, "title": str(row.get("title") or "")[:240],
            "platform": "github" if urlsplit(url).hostname == "github.com" else "immunefi",
            "advertised_max_usd": "" if reward is None else str(reward),
        })
    return normalized


class QueueStore:
    """Persist observations separately from manual, evidentiary workflow status."""

    def __init__(self, client, namespace="garcar:bounties:v1"):
        self.client = client
        self.prefix = namespace

    def _key(self, item_id):
        if not isinstance(item_id, str) or not re.fullmatch(r"[0-9a-f]{32}", item_id):
            raise ValueError("invalid item identifier")
        return self.prefix + ":item:" + item_id

    def ingest(self, payload, feed):
        rows = normalized_rows(payload, feed)  # validate whole batch first
        at = utc()
        pipe = self.client.pipeline(transaction=True)
        for row in rows:
            key = self._key(row["id"])
            pipe.hsetnx(key, "workflow_state", "unreviewed")
            pipe.hsetnx(key, "first_seen_at", at)
            pipe.hset(key, mapping={
                "url": row["url"], "title": row["title"], "platform": row["platform"],
                "last_seen_at": at,
            })
            # A source without a reward must not erase a previously observed
            # advertised amount from another discovery feed.
            if row["advertised_max_usd"] != "":
                pipe.hset(key, "advertised_max_usd", row["advertised_max_usd"])
            else:
                pipe.hsetnx(key, "advertised_max_usd", "")
            pipe.sadd(self.prefix + ":index", row["id"])
            pipe.sadd(key + ":feeds", feed)
        pipe.hset(self.prefix + ":feed_status", mapping={
            feed + ":at": at, feed + ":count": str(len(rows)),
            feed + ":errors": str(len(payload.get("source_errors") or [])),
        })
        pipe.xadd(self.prefix + ":events", {
            "action": "observation_batch", "feed": feed, "count": str(len(rows)),
            "observed_at": at,
        }, maxlen=5000, approximate=True)
        pipe.execute()
        return {"feed": feed, "accepted": len(rows), "received": len(payload["top" if feed == "github_actions" else "items"])}

    def summary(self):
        ids = list(self.client.smembers(self.prefix + ":index"))
        if len(ids) > 25000:
            raise ValueError("review queue exceeds safety cap")
        states = Counter()
        for item_id in ids:
            item = self.client.hgetall(self._key(item_id))
            if item:
                states[item.get("workflow_state", "unreviewed")] += 1
        return {
            "storage": "redis_with_existing_disk_snapshots",
            "observed_unique": sum(states.values()),
            "states": dict(states),
            "feeds": self.client.hgetall(self.prefix + ":feed_status"),
            "verified_earnings_usd": 0,
            "payment_reconciliation": "not_connected",
            "external_actions_enabled": False,
        }

    def items(self, limit=30):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        ids = sorted(self.client.smembers(self.prefix + ":index"))
        results = []
        for item_id in ids[:limit]:
            data = self.client.hgetall(self._key(item_id))
            if data:
                results.append(dict(item_id=item_id, **data))
        return results

    def get(self, item_id):
        data = self.client.hgetall(self._key(item_id))
        if not data:
            raise KeyError("unknown opportunity")
        return dict(item_id=item_id, **data)

    def assign(self, item_id, operator, assignee):
        if not all(isinstance(s, str) and 1 <= len(s) <= 120 for s in (operator, assignee)):
            raise ValueError("operator and assignee required")
        key = self._key(item_id)
        with self.client.pipeline() as p:
            while True:
                try:
                    p.watch(key)
                    if p.hget(key, "workflow_state") != "unreviewed":
                        raise ValueError("only unreviewed opportunities can be assigned")
                    p.multi()
                    p.hset(key, mapping={"workflow_state": "assigned", "assignee": assignee,
                                         "assigned_by": operator, "updated_at": utc()})
                    p.xadd(self.prefix + ":events", {
                        "action": "assigned", "item_id": item_id, "operator": operator,
                        "recorded_at": utc(),
                    }, maxlen=5000, approximate=True)
                    p.execute()
                    return self.get(item_id)
                except __import__("redis").WatchError:
                    continue

    def evidence(self, item_id, kind, reference, digest, operator):
        if kind not in EVIDENCE_KINDS:
            raise ValueError("invalid evidence kind")
        if not isinstance(operator, str) or not 1 <= len(operator) <= 120:
            raise ValueError("operator required")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("evidence content SHA256 required")
        url = evidence_url(reference)
        self.get(item_id)
        at = utc()
        evidence_id = hashlib.sha256(
            (item_id + ":" + kind + ":" + url + ":" + digest.lower()).encode()
        ).hexdigest()[:32]
        p = self.client.pipeline(transaction=True)
        p.hset(self.prefix + ":evidence:" + evidence_id, mapping={
            "item_id": item_id, "kind": kind, "reference": url,
            "content_sha256": digest.lower(), "recorded_by": operator,
            "recorded_at": at, "verification": "operator_supplied_not_independently_verified",
        })
        p.sadd(self._key(item_id) + ":evidence", evidence_id)
        p.xadd(self.prefix + ":events", {
            "action": "evidence_recorded", "item_id": item_id, "evidence_id": evidence_id,
            "recorded_at": at,
        }, maxlen=5000, approximate=True)
        p.execute()
        return {"evidence_id": evidence_id, "verification": "operator_supplied_not_independently_verified"}

    def transition(self, item_id, state, operator, evidence_id=None):
        if state not in STATES:
            raise ValueError("invalid workflow state")
        if not isinstance(operator, str) or not 1 <= len(operator) <= 120:
            raise ValueError("operator required")
        key = self._key(item_id)
        if state in {"submission_reported", "acceptance_reported", "payout_reported"}:
            if not isinstance(evidence_id, str) or evidence_id not in self.client.smembers(key + ":evidence"):
                raise ValueError("supporting evidence ID is required")
            evidence = self.client.hgetall(self.prefix + ":evidence:" + evidence_id)
            needed = {"submission_reported": "submission", "acceptance_reported": "acceptance",
                      "payout_reported": "payout"}[state]
            if evidence.get("kind") != needed:
                raise ValueError("wrong evidence kind for claimed transition")
        with self.client.pipeline() as p:
            while True:
                try:
                    p.watch(key)
                    old = p.hget(key, "workflow_state")
                    if state not in TRANSITIONS.get(old, set()):
                        raise ValueError("invalid state transition")
                    p.multi()
                    p.hset(key, mapping={
                        "workflow_state": state, "updated_at": utc(),
                        "last_recorded_by": operator,
                        "last_evidence_id": evidence_id or "",
                    })
                    p.xadd(self.prefix + ":events", {
                        "action": "state_recorded", "item_id": item_id, "from": old,
                        "to": state, "operator": operator, "evidence_id": evidence_id or "",
                        "recorded_at": utc(),
                    }, maxlen=5000, approximate=True)
                    p.execute()
                    return self.get(item_id)
                except __import__("redis").WatchError:
                    continue


def from_environment():
    url = os.environ.get("BOUNTY_QUEUE_REDIS_URL")
    if not url:
        return None
    import redis
    return QueueStore(redis.Redis.from_url(
        url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3,
    ))
