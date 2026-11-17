#!/usr/bin/env python3
"""Read-only crypto/software bounty discovery service.

Discovers candidate public GitHub issues. Never claims payment eligibility,
runs scans of third-party targets, signs transactions, or submits work.
The only outbound requests are HTTPS GETs to a fixed GitHub API hostname.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from bounty_intelligence import ReceiptLog, enrich_candidate

LOG = logging.getLogger("garcar.bounty.discovery")
API_ROOT = "https://api.github.com/search/issues"
QUERIES = (
    "is:issue is:open label:bounty blockchain",
    "is:issue is:open label:bounty solidity",
    "is:issue is:open label:bounty crypto",
)
MAX_ITEMS_PER_QUERY = 20
POLL_SECONDS = 1800
REQUEST_TIMEOUT_SECONDS = 12
MAX_RESPONSE_BYTES = 2_000_000
STALE_AFTER_SECONDS = 3600
ASSET_ROOT = Path(__file__).resolve().parent
DASHBOARD_ASSETS = {
    "/": ("dashboard.html", "text/html; charset=utf-8"),
    "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
}


def iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def public_issue_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    p = urlparse(value)
    return (
        p.scheme == "https" and p.hostname == "github.com"
        and p.username is None and p.password is None
        and p.port is None and p.path.startswith("/")
        and len(p.path.split("/")) >= 5
        and p.path.split("/")[3] == "issues"
    )


def parse_items(payload: dict) -> list[dict]:
    output = []
    for item in payload.get("items", []):
        if not isinstance(item, dict) or item.get("state") != "open":
            continue
        if item.get("pull_request") is not None:
            continue
        url = item.get("html_url")
        if not public_issue_url(url):
            continue
        parts = urlparse(url).path.strip("/").split("/")
        labels = item.get("labels") or []
        names = [label.get("name", "")[:80] for label in labels
                 if isinstance(label, dict) and isinstance(label.get("name"), str)]
        # Classification only: never execute instructions from issue bodies.
        title = str(item.get("title") or "")[:240]
        body_head = str(item.get("body") or "")[:1800]
        metadata_text = (title + "\n" + body_head).casefold()
        blocked_terms = (
            "do not claim", "currently unavailable", "quarantined",
            "unfunded precommit", "unfunded", "not claimable",
            "not open for claims", "bounty cancelled", "bounty canceled",
        )
        risk_flags = [
            term for term in blocked_terms if term in metadata_text
        ]
        mirror_hint = (
            parts[1].casefold() in ("bounty-plaza", "bounty-bot")
            or "original link / source url" in metadata_text
            or "原始链接" in metadata_text
        )
        output.append({
            "id": str(item.get("id", ""))[:80],
            "title": title,
            "url": url,
            "repository": "/".join(parts[:2]),
            "updated_at": str(item.get("updated_at", ""))[:40],
            "labels": names[:20],
            "status": "candidate_unverified",
            "risk_flags": risk_flags,
            "possibly_mirrored": mirror_hint,
            "reward_amount": None,
            "payout_confirmed": False,
            "authorization_to_test": False,
        })
    return output


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def github_search(query: str, opener=None) -> list[dict]:
    # Fixed URL, fixed hostname, bounded parameters. No user-supplied URLs.
    params = urlencode({"q": query, "per_page": MAX_ITEMS_PER_QUERY, "sort": "updated"})
    url = API_ROOT + "?" + params
    req = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "Garcar-ReadOnly-BountyScout/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }, method="GET")
    # Prevent automatic redirects to unapproved destinations and cap size.
    safe_open = opener if opener is not None else build_opener(_NoRedirect).open
    with safe_open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("GitHub response exceeds configured size cap")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("GitHub returned an unexpected response")
    if payload.get("incomplete_results") is True:
        raise ValueError("GitHub search reported incomplete results")
    return parse_items(payload)


class BountyIndex:
    """Read-only collector, deterministic review triage and verifiable volatile receipts."""

    def __init__(self, search=github_search):
        self._lock = threading.Lock()
        self._search = search
        self._cache: dict[str, tuple[list[dict], str]] = {}
        self.receipts = ReceiptLog()
        self.items: list[dict] = []
        self.last_scan_at: str | None = None
        self.last_success_at: str | None = None
        self.source_errors: list[str] = []
        self.source_outcomes: list[dict] = []
        self.scan_state = "not_started"
        self.scans = 0
        self.last_changes = {"new_candidates": 0, "no_longer_listed": 0,
                             "still_listed": 0}

    def scan_once(self):
        with self._lock:
            self.scan_state = "scanning"
            previous_urls = {x["url"] for x in self.items}
            cached = dict(self._cache)
        scanned_at = iso_utc()
        results: dict[str, dict] = {}
        errors: list[str] = []
        outcomes: list[dict] = []
        successes = 0
        for query in QUERIES:
            try:
                rows = self._search(query)
                if not isinstance(rows, list):
                    raise ValueError("Unexpected source results")
                accepted = [enrich_candidate(row) for row in rows
                            if isinstance(row, dict) and isinstance(row.get("url"), str)]
                successes += 1
                cached[query] = (accepted, scanned_at)
                outcomes.append({"query": query, "status": "ok", "count": len(accepted)})
                for row in accepted:
                    row["source_stale"] = False
                    row["source_observed_at"] = scanned_at
                    results[row["url"]] = row
            except (HTTPError, URLError, TimeoutError, OSError,
                    ValueError, TypeError) as exc:
                # Errors never turn into "zero opportunities" or "all closed".
                errors.append(f"source_error for query {query}: {type(exc).__name__}")
                LOG.warning("Bounty source query failed: %s (%s)",
                            query, type(exc).__name__)
                last = cached.get(query)
                retained = last[0] if last else []
                outcomes.append({"query": query, "status": "stale" if last else "error",
                                 "count": len(retained)})
                for old_row in retained:
                    row = dict(old_row, source_stale=True,
                               source_observed_at=last[1])
                    if row["url"] not in results:
                        results[row["url"]] = row
        items = sorted(results.values(), key=lambda row: (
            row.get("source_stale", True),
            -(row.get("priority_score") or 0),
            row.get("updated_at") or ""
        ))
        state = "ok" if not errors else ("partial" if successes else "unavailable")
        urls = {row["url"] for row in items}
        changes = {
            "new_candidates": len(urls - previous_urls),
            "no_longer_listed": len(previous_urls - urls) if successes == len(QUERIES) else 0,
            "still_listed": len(urls & previous_urls),
        }
        with self._lock:
            self._cache = cached
            self.scans += 1
            self.last_scan_at = scanned_at
            self.source_errors = errors
            self.source_outcomes = outcomes
            self.scan_state = state
            self.last_changes = changes
            self.items = items
            if successes:
                self.last_success_at = scanned_at
            receipt = self.receipts.append(
                time_utc=scanned_at,
                scan_state=state,
                observed_urls=sorted(urls),
                query_outcomes=outcomes,
                count=len(items)
            )
        LOG.info(
            "Bounty scan: state=%s candidates=%d source_errors=%d receipt=%s",
            state, len(items), len(errors), receipt["event_hash"][:16]
        )

    def snapshot(self):
        with self._lock:
            return {
                "mode": "read_only",
                "scanner": "github_public_issues",
                "scan_state": self.scan_state,
                "last_scan_at": self.last_scan_at,
                "last_success_at": self.last_success_at,
                "scans_completed": self.scans,
                "candidate_count": len(self.items),
                "blocked_for_review_count": sum(
                    x.get("status") == "blocked_for_review" for x in self.items
                ),
                "mirrored_listing_count": sum(
                    x.get("possibly_mirrored", False) for x in self.items
                ),
                "source_errors": list(self.source_errors),
                "source_outcomes": list(self.source_outcomes),
                "last_changes": dict(self.last_changes),
                "receipt_chain_valid": self.receipts.verify(),
                "receipt_storage": "process_memory_only",
                "actions_enabled": {
                    "wallet": False, "trading": False, "exploitation": False,
                    "submissions": False, "payments": False, "external_messages": False,
                },
            }

    def ready(self):
        with self._lock:
            last_success = self.last_success_at
            state = self.scan_state
        if not last_success or state == "unavailable":
            return False
        try:
            dt = datetime.fromisoformat(last_success)
            age = (datetime.now(timezone.utc) - dt).total_seconds()
            return age >= 0 and age <= STALE_AFTER_SECONDS
        except ValueError:
            return False

    def candidates(self):
        with self._lock:
            return [dict(x) for x in self.items]

    def receipts_snapshot(self):
        with self._lock:
            return self.receipts.snapshot()


INDEX = BountyIndex()


class Handler(BaseHTTPRequestHandler):
    server_version = "GarcarBountyScout/1.0"

    def send_json(self, status: int, value: dict):
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_asset(self, path):
        filename, content_type = DASHBOARD_ASSETS[path]
        try:
            data = (ASSET_ROOT / filename).read_bytes()
        except OSError:
            self.send_json(503, {"error": "dashboard_asset_unavailable"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'none'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'"
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlsplit(self.path)
        route = parsed.path
        if route in DASHBOARD_ASSETS:
            self.send_asset(route)
        elif route in ("/health", "/status"):
            state = INDEX.snapshot()
            state["service"] = "garcar-crypto-bounty-discovery"
            state["alive"] = True
            self.send_json(200, state)
        elif route == "/ready":
            ready = INDEX.ready()
            self.send_json(200 if ready else 503, {
                "ready": ready,
                "source_freshness_max_seconds": STALE_AFTER_SECONDS,
                "scan_state": INDEX.snapshot()["scan_state"],
                "note": "Readiness requires at least one recent source success",
            })
        elif route == "/bounties":
            params = parse_qs(parsed.query, keep_blank_values=False)
            try:
                limit = max(1, min(100, int(params.get("limit", ["25"])[0])))
                min_score = max(0, min(100, int(params.get("min_score", ["0"])[0])))
            except ValueError:
                self.send_json(400, {"error": "invalid_limit_or_min_score"})
                return
            skill = params.get("skill", [""])[0][:40].casefold()
            rows = INDEX.candidates()
            if skill:
                rows = [x for x in rows if skill in x.get("matched_keywords", [])]
            rows = [x for x in rows if x.get("priority_score", 0) >= min_score]
            state = INDEX.snapshot()
            self.send_json(200, {
                "candidate_count": len(rows),
                "returned": min(len(rows), limit),
                "scan_state": state["scan_state"],
                "last_success_at": state["last_success_at"],
                "classification": "unverified_public_issue_candidates",
                "ranking": "explainable_review_priority_not_profitability",
                "note": "Issue metadata is not proof of funding, permission, or payout.",
                "items": rows[:limit],
            })
        elif route == "/sources":
            state = INDEX.snapshot()
            self.send_json(200, {
                "source": "GitHub public issues REST API",
                "queries": state["source_outcomes"],
                "errors": state["source_errors"],
                "last_success_at": state["last_success_at"],
                "automated_immunefi_collection": False,
                "note": "External program websites require separate terms and authorization review.",
            })
        elif route == "/digest":
            state = INDEX.snapshot()
            self.send_json(200, {
                "last_scan_at": state["last_scan_at"],
                "scan_state": state["scan_state"],
                "candidate_count": state["candidate_count"],
                "blocked_for_review_count": state["blocked_for_review_count"],
                "mirrored_listing_count": state["mirrored_listing_count"],
                "change_summary": state["last_changes"],
                "receipts_chain_valid": state["receipt_chain_valid"],
                "actual_revenue": None,
                "payouts_verified": 0,
                "note": "Payouts not tracked; zero verified payouts is not a claim about external accounts.",
            })
        elif route == "/receipts":
            self.send_json(200, INDEX.receipts_snapshot())
        else:
            self.send_json(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.client_address[0], fmt % args)


def scanner_loop(stop: threading.Event, index: BountyIndex):
    while not stop.is_set():
        index.scan_once()
        stop.wait(POLL_SECONDS)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(os.environ.get("PORT", "8080"))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid PORT")
    stop = threading.Event()
    worker = threading.Thread(target=scanner_loop, args=(stop, INDEX), daemon=True)
    worker.start()
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    LOG.info("Read-only bounty discovery listening on port %s", port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()


if __name__ == "__main__":
    main()
