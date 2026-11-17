#!/usr/bin/env python3
"""Push public discovery metadata to the governed staging queue with GitHub OIDC.

Requires a GitHub Actions job with id-token: write. Never submits claims,
executes security tests, or transmits wallet/payment information.
"""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


AUDIENCE = "garcar-bounty-queue-staging"
DESTINATION = (
    "https://garcar-crypto-bounty-discovery-canary-staging."
    "up.railway.app/internal/ingest"
)
MAX_BYTES = 4 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_token(opener, request_url, request_token):
    if not request_url.startswith("https://") or not request_token:
        raise RuntimeError("GitHub Actions OIDC unavailable")
    if not (urlsplit(request_url).hostname or "").endswith(".actions.githubusercontent.com"):
        raise RuntimeError("Unexpected GitHub OIDC token endpoint")
    sep = "&" if "?" in request_url else "?"
    request = Request(
        request_url + sep + "audience=" + AUDIENCE,
        headers={"Authorization": "Bearer " + request_token},
        method="GET",
    )
    with opener.open(request, timeout=15) as resp:
        data = json.load(resp)
    token = data.get("value")
    if not isinstance(token, str) or len(token) < 100:
        raise RuntimeError("GitHub OIDC endpoint gave no token")
    return token


def push(path):
    data = Path(path).read_bytes()
    if not 0 < len(data) <= MAX_BYTES:
        raise ValueError("Queue metadata exceeds size limit")
    doc = json.loads(data)
    if not isinstance(doc, dict) or doc.get("discovered") != len(doc.get("top", [])):
        raise ValueError("Refusing incomplete scanner export")
    opener = build_opener(NoRedirect)
    token = fetch_token(
        opener,
        os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", ""),
        os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""),
    )
    request = Request(
        DESTINATION, data=data,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with opener.open(request, timeout=30) as resp:
        result = json.load(resp)
    if result.get("status") != "ingested" or result.get("accepted") != doc["discovered"]:
        raise RuntimeError("Queue did not acknowledge complete discovery")
    print(json.dumps({
        "queue_ingest_status": "confirmed_by_staging",
        "discovered": doc["discovered"], "accepted": result["accepted"],
        "submission_enabled": False, "payments_enabled": False,
    }, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    args = p.parse_args()
    push(args.input)
