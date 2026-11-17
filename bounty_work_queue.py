"""RHNS-aligned, read-only bounty task planning.

Produces deterministic candidate review work orders, not execution. No external
requests, wallet keys, security scans, claims, payouts or outbound messages.
Candidate strings are untrusted data; never pass them as agent instructions.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

MAX_WORK_ORDERS = 25
MAX_CANDIDATES = 250
ISSUE_PATH = re.compile(r"^/[^/]+/[^/]+/issues/[1-9][0-9]*$")
REVIEW_GATES = (
    "Verify canonical sponsor identity and current program terms",
    "Verify available funding or escrow from a trusted authoritative source",
    "Confirm open submission or claim eligibility and payment conditions",
    "Confirm permitted scope; no security testing without written authorization",
    "Confirm acceptance, beneficiary, and payout evidence separately",
)
FORBIDDEN_ACTIONS = (
    "wallet_sign", "trade", "swap", "bridge", "submit_claim",
    "publish_pr", "send_message", "test_third_party_target",
    "withdraw_funds", "pay_fee", "merge", "deploy_production",
)


def safe_issue_url(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 320:
        return False
    try:
        x = urlsplit(value)
        return (x.scheme == "https" and x.hostname == "github.com"
                and x.netloc == "github.com" and not x.query and not x.fragment
                and bool(ISSUE_PATH.fullmatch(x.path)))
    except ValueError:
        return False


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False
    ).encode("utf-8")).hexdigest()


def build_work_queue(candidates: list[dict], scan_state: str, *,
                     limit: int = 15) -> dict:
    """Build an inspect-only queue from a snapshot of the existing scout.

    An item cannot become executable just because the GitHub issue has a
    'bounty' or 'funded-live' label, a high score, or a transaction.
    """
    if type(limit) is not int or not 1 <= limit <= MAX_WORK_ORDERS:
        raise ValueError("limit must be 1..25")
    if not isinstance(candidates, list):
        raise ValueError("candidates must be a list")
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError("candidate input exceeds bounded evaluation budget")

    permitted = scan_state == "ok"
    seen = set()
    ready = []
    held = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        url = candidate.get("url")
        if not safe_issue_url(url) or url in seen:
            continue
        seen.add(url)
        risk = [str(x)[:80] for x in (candidate.get("risk_flags") or [])
                if isinstance(x, str)]
        score = candidate.get("priority_score")
        if type(score) is not int or not 0 <= score <= 100:
            score = 0
        reasons = []
        if not permitted:
            reasons.append("source_scan_not_ok")
        if candidate.get("source_stale") is not False:
            reasons.append("source_observation_stale_or_unknown")
        if candidate.get("source_verified") is not True:
            reasons.append("source_provenance_unverified")
        if candidate.get("status") != "candidate_unverified":
            reasons.append("candidate_status_requires_review")
        if candidate.get("possibly_mirrored") is True:
            reasons.append("possible_mirror")
        if risk:
            reasons.append("risk_flags_present")
        if score < 35:
            reasons.append("insufficient_technical_review_priority")
        work_id = _sha({"v": 1, "source": "github_public_issue_search", "url": url})[:24]
        work = {
            "work_id": work_id,
            "source_url": url,
            "title": str(candidate.get("title") or "")[:160],
            "priority_score": score,
            "mode": "read_only_research",
            "task_type": "canonical_source_qualification",
            "instructions": (
                "Inspect canonical issue and authoritative sponsor terms. "
                "Record evidence; do not claim, message, scan, submit, or transact."
            ),
            "approval_required": True,
            "review_gates": list(REVIEW_GATES),
            "allowed_actions": ["read_public_source", "prepare_private_review_notes"],
            "forbidden_actions": list(FORBIDDEN_ACTIONS),
            "risk_reasons": reasons,
            "external_execution_enabled": False,
            "payout_verified": False,
            "reward_funding_verified": False,
        }
        (held if reasons else ready).append(work)

    ready.sort(key=lambda w: (-w["priority_score"], w["work_id"]))
    held.sort(key=lambda w: (w["work_id"],))
    selected = ready[:limit]
    return {
        "mode": "read_only",
        "policy": "RHNS_propose_verify_hold_no_automatic_dispatch",
        "scan_state": scan_state,
        "work_orders": selected,
        "counts": {
            "observed_unique": len(seen),
            "research_ready": len(ready),
            "held_for_review": len(held),
            "returned": len(selected),
            "truncated": max(0, len(ready) - len(selected)),
        },
        "held_reasons": {
            key: sum(key in x["risk_reasons"] for x in held)
            for key in sorted({reason for x in held for reason in x["risk_reasons"]})
        },
        "queue_digest": _sha([x["work_id"] for x in selected]),
        "note": (
            "Research-ready means candidate review only, not a funded, claimable "
            "or executable bounty. No external actions are performed."
        ),
    }
