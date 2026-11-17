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
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

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
        output.append({
            "id": str(item.get("id", ""))[:80],
            "title": str(item.get("title", ""))[:240],
            "url": url,
            "repository": "/".join(parts[:2]),
            "updated_at": str(item.get("updated_at", ""))[:40],
            "labels": names[:20],
            "status": "candidate_unverified",
            "reward_amount": None,
            "payout_confirmed": False,
            "authorization_to_test": False,
        })
    return output


def github_search(query: str, opener=urlopen) -> list[dict]:
    # Fixed URL, fixed hostname, bounded parameters. No user-supplied URLs.
    params = urlencode({"q": query, "per_page": MAX_ITEMS_PER_QUERY, "sort": "updated"})
    url = API_ROOT + "?" + params
    req = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "Garcar-ReadOnly-BountyScout/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }, method="GET")
    with opener(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("GitHub returned an unexpected response")
    return parse_items(payload)


class BountyIndex:
    def __init__(self, search=github_search):
        self._lock = threading.Lock()
        self._search = search
        self.items: list[dict] = []
        self.last_scan_at: str | None = None
        self.last_success_at: str | None = None
        self.source_errors: list[str] = []
        self.scan_state = "not_started"
        self.scans = 0

    def scan_once(self):
        with self._lock:
            self.scan_state = "scanning"
        results: dict[str, dict] = {}
        errors: list[str] = []
        successes = 0
        for query in QUERIES:
            try:
                rows = self._search(query)
                successes += 1
                for row in rows:
                    if isinstance(row, dict) and row.get("url"):
                        results[row["url"]] = row
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError) as exc:
                errors.append(f"source_error for query {query}: {type(exc).__name__}")
                LOG.warning("Bounty source query failed: %s (%s)", query, type(exc).__name__)
        items = sorted(
            results.values(),
            key=lambda row: row.get("updated_at") or "",
            reverse=True,
        )
        with self._lock:
            self.scans += 1
            self.last_scan_at = iso_utc()
            self.source_errors = errors
            self.scan_state = "ok" if not errors else ("partial" if successes else "unavailable")
            # Preserve previously retrieved results during a transient total outage,
            # but do not represent them as fresh or currently verified.
            if successes:
                self.items = items
                self.last_success_at = self.last_scan_at

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
                "source_errors": list(self.source_errors),
                "actions_enabled": {
                    "wallet": False, "trading": False, "exploitation": False,
                    "submissions": False, "payments": False, "external_messages": False,
                },
            }

    def candidates(self):
        with self._lock:
            return list(self.items)


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

    def do_GET(self):
        route = self.path.partition("?")[0]
        if route in ("/", "/health", "/status"):
            state = INDEX.snapshot()
            state["service"] = "garcar-crypto-bounty-discovery"
            state["alive"] = True
            self.send_json(200, state)
        elif route == "/bounties":
            state = INDEX.snapshot()
            self.send_json(200, {
                "candidate_count": state["candidate_count"],
                "scan_state": state["scan_state"],
                "last_success_at": state["last_success_at"],
                "classification": "unverified_public_issue_candidates",
                "note": "Listings are not verified paid bounties. Check current sponsor terms, scope, and authorization.",
                "items": INDEX.candidates(),
            })
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
