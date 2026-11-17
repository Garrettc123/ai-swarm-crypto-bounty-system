"""Deterministic evidence-first triage and ephemeral hash-chained scan receipts.

These functions explain *why to inspect* a public issue. A score is not an
estimated success probability, verified bounty reward, or permission to test.
No untrusted issue content is used as instructions.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

SKILL_TERMS = {
    "python": ("python", "fastapi", "django", "flask"),
    "typescript": ("typescript", "react", "nextjs", "next.js"),
    "rust": ("rust", "solana"),
    "solidity": ("solidity", "evm", "smart contract"),
}
DECISION_GATES = (
    "Confirm sponsor and funded reward terms at original source",
    "Confirm issue is still open and contributor acceptance is available",
    "Review eligibility, jurisdiction, KYC and submission conditions",
    "For any security research, verify explicit written scope and rules",
    "Get operator approval before external action or submitting work",
)
MAX_RECEIPTS = 64


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(obj: object) -> str:
    return hashlib.sha256(_canonical(obj)).hexdigest()


def _updated_days(value: object, *, now: datetime) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return max(0, int((now - dt.astimezone(timezone.utc)).total_seconds() // 86400))
    except (ValueError, OverflowError):
        return None


def enrich_candidate(item: dict, *, now: datetime | None = None) -> dict:
    """Explain deterministic review priority without fabricating money or eligibility."""
    if not isinstance(item, dict) or not isinstance(item.get("url"), str):
        raise ValueError("Invalid candidate")
    if not item["url"].startswith("https://github.com/"):
        raise ValueError("Invalid candidate source")
    current = now or datetime.now(timezone.utc)
    title = str(item.get("title") or "")[:240]
    labels = [str(x)[:80] for x in (item.get("labels") or []) if isinstance(x, str)]
    haystack = " ".join([title, *labels]).casefold()
    matched = sorted([
        skill for skill, terms in SKILL_TERMS.items()
        if any(term in haystack for term in terms)
    ])
    reasons = ["Public GitHub issue; sponsor, payment and acceptance unverified"]
    score = 20  # The issue can be reviewed, not paid.
    label_set = {x.casefold() for x in labels}
    if "bounty" in label_set:
        score += 20
        reasons.append("Issue carries a 'bounty' label (not payment proof)")
    if matched:
        score += min(20, len(matched) * 10)
        reasons.append("Technical keyword match: " + ", ".join(matched))
    age_days = _updated_days(item.get("updated_at"), now=current)
    if age_days is not None and age_days <= 7:
        score += 15
        reasons.append("Issue metadata updated within seven days")
    elif age_days is not None and age_days <= 30:
        score += 7
        reasons.append("Issue metadata updated within thirty days")
    if any(x in label_set for x in ("help wanted", "good first issue", "up-for-grabs")):
        score += 10
        reasons.append("Repository label suggests contributor availability")
    result = dict(item)
    result.update({
        "candidate_id": digest({"source": "github", "url": item["url"]})[:20],
        "source": "github_public_issue_search",
        "source_verified": True,  # Only provenance of fetched public metadata.
        "sponsor_verified": False,
        "reward_terms_verified": False,
        "payout_confirmed": False,
        "authorization_to_test": False,
        "status": "candidate_unverified",
        "priority_score": min(score, 100),
        "priority_label": "review_priority_not_profitability",
        "priority_reasons": reasons,
        "matched_keywords": matched,
        "last_updated_days_ago": age_days,
        "approval_required": True,
        "review_gates": list(DECISION_GATES),
    })
    # Never infer or copy alleged reward figures from an unverified GitHub issue.
    result["reward_amount"] = None
    return result


class ReceiptLog:
    """Bounded volatile receipts, not a durable, signed or externally anchored ledger."""

    def __init__(self):
        self._entries: list[dict] = []
        self._tip = "0" * 64
        self._counter = 0

    def append(self, *, time_utc: str, scan_state: str,
               observed_urls: list[str], query_outcomes: list[dict],
               count: int) -> dict:
        self._counter += 1
        payload = {
            "sequence": self._counter,
            "observed_at": time_utc,
            "prev_hash": self._tip,
            "state": scan_state,
            "candidate_count": count,
            "dataset_digest": digest(sorted(set(observed_urls))),
            "queries": [
                {
                    "query": str(x["query"]),
                    "status": str(x["status"]),
                    "count": int(x["count"]),
                }
                for x in query_outcomes
            ],
        }
        entry = dict(payload, event_hash=digest(payload))
        self._tip = entry["event_hash"]
        self._entries.append(entry)
        if len(self._entries) > MAX_RECEIPTS:
            self._entries.pop(0)
        return dict(entry)

    def verify(self) -> bool:
        for i, entry in enumerate(self._entries):
            payload = {k: v for k, v in entry.items() if k != "event_hash"}
            if digest(payload) != entry.get("event_hash"):
                return False
            if i and entry["prev_hash"] != self._entries[i - 1]["event_hash"]:
                return False
        return True

    def snapshot(self) -> dict:
        return {
            "storage": "process_memory_only",
            "cryptographic_signature": False,
            "external_anchor": False,
            "entries": [dict(e) for e in self._entries],
            "chain_valid_for_retained_entries": self.verify(),
            "latest_hash": self._tip,
        }
