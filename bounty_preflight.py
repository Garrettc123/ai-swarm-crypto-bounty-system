#!/usr/bin/env python3
"""Bounded, read-only canonical GitHub issue verification for bounty candidates.

A search hit is not proof an issue is still open, unclaimed, funded,
authorized for testing, or payable. This tool issues at most five GET requests
to fixed github.com API endpoints per explicit CLI invocation. No secrets,
submissions, wallet operations, target probes, or outbound messages.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

SOURCE_PATH = re.compile(
    r"^/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})/issues/([1-9][0-9]{0,12})$"
)
API_ROOT = "https://api.github.com/repos"
MAX_BYTES = 350_000
MAX_CHECKS = 5
BLOCKED_LABELS = frozenset({
    "in-progress", "claimed", "assigned", "closed-to-contributors",
    "quarantined", "unfunded", "not-claimable", "funding-needed",
    "verification-unavailable",
})
BLOCKED_TERMS = (
    "do not claim", "unfunded", "not claimable", "currently unavailable",
    "quarantined", "not accepting claims", "claims paused",
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical_source(value: object) -> tuple[str, str]:
    """Return canonical display/API URLs; reject userinfo, redirects and extras."""
    if not isinstance(value, str) or len(value) > 320:
        raise ValueError("invalid source URL")
    try:
        p = urlsplit(value)
    except ValueError as exc:
        raise ValueError("invalid source URL") from exc
    if (p.scheme != "https" or p.netloc != "github.com" or p.query
            or p.fragment or p.username is not None or p.password is not None):
        raise ValueError("source must be a canonical GitHub issue URL")
    match = SOURCE_PATH.fullmatch(p.path)
    if not match or any(piece in (".", "..") for piece in match.groups()[:2]):
        raise ValueError("not a canonical GitHub issue URL")
    owner, repo, issue = match.groups()
    source = "https://github.com/" + owner + "/" + repo + "/issues/" + issue
    api = API_ROOT + "/" + owner + "/" + repo + "/issues/" + issue
    return source, api


def _baseline(url: str) -> dict:
    return {
        "source_url": url,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "source_unavailable",
        "source_issue_state": "unknown",
        "availability_for_contribution": "not_verified",
        "reward_terms_verified": False,
        "funding_verified": False,
        "authorization_to_test": False,
        "payout_verified": False,
        "external_action_allowed": False,
        "reasons": [],
    }


def inspect_issue(url: str, *, opener=None) -> dict:
    source, api = canonical_source(url)
    out = _baseline(source)
    req = Request(api, method="GET", headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Garcar-Canonical-Preflight/1.0",
    })
    open_request = opener if opener is not None else build_opener(_NoRedirect).open
    try:
        with open_request(req, timeout=10) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("source payload size limit exceeded")
        issue = json.loads(raw)
    except HTTPError as exc:
        out["reasons"].append("canonical_source_http_" + str(exc.code))
        return out
    except (URLError, OSError, TimeoutError, ValueError, TypeError) as exc:
        out["reasons"].append("canonical_source_read_error_" + type(exc).__name__)
        return out
    if not isinstance(issue, dict) or issue.get("pull_request") is not None:
        out["status"] = "hold"
        out["reasons"].append("not_a_verifiable_issue")
        return out
    observed_url = issue.get("html_url")
    if not isinstance(observed_url, str) or observed_url.casefold() != source.casefold():
        out["status"] = "hold"
        out["reasons"].append("canonical_url_mismatch")
        return out
    state = issue.get("state")
    if state not in ("open", "closed"):
        out["status"] = "hold"
        out["reasons"].append("unknown_canonical_issue_state")
        return out
    out["source_issue_state"] = state
    out["source_updated_at"] = issue.get("updated_at")
    out["title"] = str(issue.get("title") or "")[:240]
    labels = issue.get("labels") if isinstance(issue.get("labels"), list) else []
    label_names = [label.get("name", "").casefold() for label in labels
                   if isinstance(label, dict) and isinstance(label.get("name"), str)]
    assignees = issue.get("assignees")
    has_assignees = isinstance(assignees, list) and len(assignees) > 0
    out["has_assignees"] = has_assignees
    out["labels"] = label_names[:30]
    if state == "closed":
        out["status"] = "hold"
        out["reasons"].append("issue_closed_at_canonical_source")
        return out
    suspicious = [label for label in label_names if label in BLOCKED_LABELS]
    body_text = str(issue.get("body") or "")[:2500].casefold()
    text = (out["title"].casefold() + "\n" + body_text)
    suspicious.extend(term for term in BLOCKED_TERMS if term in text)
    if has_assignees:
        suspicious.append("already_assigned")
    if suspicious:
        out["status"] = "hold"
        out["reasons"].extend(sorted(set(suspicious)))
    else:
        out["status"] = "manual_review"
        out["reasons"].append("open_issue_but_terms_and_availability_unverified")
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="One canonical public GitHub issue URL")
    source.add_argument("--file", type=Path, help="JSON list of at most five issue URLs")
    opts = p.parse_args(argv)
    if opts.url:
        urls = [opts.url]
    else:
        if opts.file.stat().st_size > 64 * 1024:
            p.error("input too large")
        data = json.loads(opts.file.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            p.error("file must contain a JSON list of canonical issue URLs")
        urls = data
    if not 1 <= len(urls) <= MAX_CHECKS:
        p.error("1..5 canonical URLs required")
    # Entire batch is validated before any HTTP request; no partial unsafe fetch.
    for url in urls:
        canonical_source(url)
    results = [inspect_issue(url) for url in urls]
    print(json.dumps({
        "mode": "read_only_preflight", "checked": len(results),
        "results": results,
        "funded_bounties_verified": 0,
        "claim_or_submission_performed": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
