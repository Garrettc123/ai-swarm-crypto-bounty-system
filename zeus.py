#!/usr/bin/env python3
"""ZEUS Base Everest: reproducible pinned-source research pass.

Runs static source inspection only. Never attacks an endpoint, attempts
proof-of-concept exploitation, sends reports, or represents hashes of
source material as proof of a vulnerability.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

COMMIT = "689054ee14933cb2ee5bd54eadcd8dacbe1cc517"
REPO = "immunefi-team/audit-comp-base-everest-base"
RAW = "https://raw.githubusercontent.com/" + REPO + "/" + COMMIT + "/"
INTENT = "Base Everest bounty hunt organ"
MAX_FILE = 1024 * 1024
TARGETS = {
    "crates/consensus/service/src/follow/proof_gate.rs": {
        "blob": "b1c9af658d92830dbf9c7c3c22181d11e4dd885e",
        "focus": "Proof-follow progression and retry boundary",
        "patterns": (r"wait_til_ready", r"proofs_latest", r"max_blocks_ahead", r"refresh"),
    },
    "crates/proof/contracts/src/aggregate_verifier.rs": {
        "blob": "67b811a6ccdebe3b5fbd3dd328cad0047d6b32bd",
        "focus": "AggregateVerifier ABI and challenge/nullify binding",
        "patterns": (r"aggregate", r"challenge", r"nullify", r"interval"),
    },
    "crates/execution/base-tx-rpc/src/everest_gate.rs": {
        "blob": "4c756cfc8ab549aaa48281c19b7c5e81408a6f53",
        "focus": "Everest fork activation checks",
        "patterns": (r"timestamp", r"TxBase", r"resolve_timestamp", r"is_feature_active"),
    },
    "crates/consensus/protocol/src/batch/validity.rs": {
        "blob": "dbc88782419cb9ee46ea29cfe2e18873352fd494",
        "focus": "Batch validation rejection reasons",
        "patterns": (r"TxBasePreEverest", r"Timestamp", r"Invalid", r"Epoch"),
    },
    "crates/proof/challenge/src/validator.rs": {
        "blob": "f0bfb9af00b4f77c5e2262acb74873f2c3dd4d99",
        "focus": "Candidate output-root validation",
        "patterns": (r"verify_proof", r"output_root", r"checkpoint", r"header.*hash"),
    },
}


def blob_sha1(content: bytes) -> str:
    prefix = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return sha1(prefix + content).hexdigest()


def require_pinned_path(path: str) -> None:
    if path not in TARGETS or path.startswith("/") or ".." in path.split("/"):
        raise ValueError("Path not present in the explicitly pinned audit scope")


def fetch_pinned(path: str) -> bytes:
    require_pinned_path(path)
    url = RAW + path
    req = Request(url, headers={"User-Agent": "Garcar-ZEUS-Research/1.0", "Accept": "text/plain"}, method="GET")
    with urlopen(req, timeout=30) as response:
        resolved = urlparse(response.geturl())
        if resolved.scheme != "https" or resolved.netloc != "raw.githubusercontent.com":
            raise ValueError("Unexpected source redirect")
        result = response.read(MAX_FILE + 1)
    if len(result) > MAX_FILE:
        raise ValueError("Oversize source file: " + path)
    return result


def review_bytes(path: str, content: bytes, expected_blob: str, focus: str, patterns: tuple[str, ...]) -> dict:
    require_pinned_path(path)
    if blob_sha1(content) != expected_blob:
        raise ValueError("Git blob mismatch for immutable competition source " + path)
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Non-UTF8 source file " + path) from exc
    anchors = []
    counts = {}
    lines = source.splitlines()
    for pattern in patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        locations = [n for n, line in enumerate(lines, 1) if regex.search(line)]
        counts[pattern] = len(locations)
        anchors.extend({"pattern": pattern, "line": line} for line in locations[:6])
    anchors.sort(key=lambda item: (item["line"], item["pattern"]))
    return {
        "path": path,
        "pinned_raw_url": RAW + path,
        "expected_git_blob_sha1": expected_blob,
        "observed_git_blob_sha1": blob_sha1(content),
        "content_sha256": sha256(content).hexdigest(),
        "bytes": len(content),
        "lines": len(lines),
        "review_focus": focus,
        "match_counts": counts,
        "anchors": anchors[:24],
        "classification": "static_review_anchor_not_a_vulnerability",
    }


def run_once(fetcher=fetch_pinned, targets=TARGETS) -> dict:
    reports = []
    for path, settings in sorted(targets.items()):
        reports.append(review_bytes(
            path, fetcher(path), settings["blob"], settings["focus"], settings["patterns"]
        ))
    digest_inputs = [{"path": row["path"], "sha256": row["content_sha256"],
                      "git_blob_sha1": row["observed_git_blob_sha1"]} for row in reports]
    evidence = sha256(json.dumps(digest_inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema_version": 1,
        "run_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "organ": "base-everest-hunter",
        "intent": INTENT,
        "upstream_repository": REPO,
        "upstream_pinned_commit": COMMIT,
        "source_evidence_sha256": evidence,
        "evidence_kind": "authenticated_immutable_source_inspection_only",
        "reviewed_source_files": len(reports),
        "files": reports,
        "known_issue_review": "still_required_before_any_submission",
        "source_review_status": "completed_not_exploit_validation",
        "devnet_status": "not_executed",
        "vulnerability_finding": None,
        "poc_reproduced": False,
        "proof_hash": None,
        "srr_hash": None,
        "seal_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
        "submission": "none",
        "safety": "Source files fetched over HTTPS only. No public network probing or exploit executed.",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["run-once"])
    p.add_argument("--intent", default=INTENT)
    p.add_argument("--estimated-value-usd", type=int, default=250000)
    p.add_argument("--output", default="artifacts/base-everest-source-review.json")
    args = p.parse_args()
    if args.intent != INTENT:
        p.error("Only the scoped Base Everest research intent is supported")
    if args.estimated_value_usd != 250000:
        p.error("Expected contest pool context $250000; this is not a projected payout")
    try:
        result = run_once()
    except (HTTPError, URLError, ValueError, TimeoutError, OSError) as exc:
        print("ZEUS source review failed closed: " + str(exc), file=sys.stderr)
        return 2
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "source_review_status": result["source_review_status"],
        "reviewed_source_files": result["reviewed_source_files"],
        "source_evidence_sha256": result["source_evidence_sha256"],
        "devnet_status": result["devnet_status"],
        "poc_reproduced": False,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
        "output": str(destination)
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
