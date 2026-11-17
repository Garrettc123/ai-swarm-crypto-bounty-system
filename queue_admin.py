#!/usr/bin/env python3
"""Operator-only local commands. Never sends bounty submissions or payments.

Requires an authenticated Redis connection from the existing trusted network.
Do not expose this CLI to HTTP or autonomous tool execution.
"""
import argparse
import json
import sys

from bounty_queue_persistence import from_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    list_cmd = sub.add_parser("list")
    list_cmd.add_argument("--limit", type=int, default=30)
    ingest = sub.add_parser("ingest-file")
    ingest.add_argument("--path", required=True)
    ingest.add_argument("--feed", choices=("github_actions", "railway_public_scout"), required=True)
    assign = sub.add_parser("assign")
    assign.add_argument("--item-id", required=True)
    assign.add_argument("--operator", required=True)
    assign.add_argument("--assignee", required=True)
    evidence = sub.add_parser("evidence")
    evidence.add_argument("--item-id", required=True)
    evidence.add_argument("--operator", required=True)
    evidence.add_argument("--kind", required=True)
    evidence.add_argument("--reference", required=True)
    evidence.add_argument("--sha256", required=True)
    move = sub.add_parser("record-state")
    move.add_argument("--item-id", required=True)
    move.add_argument("--operator", required=True)
    move.add_argument("--state", required=True)
    move.add_argument("--evidence-id")
    args = parser.parse_args()
    store = from_environment()
    if store is None:
        parser.error("BOUNTY_QUEUE_REDIS_URL not configured; no changes performed")
    if args.command == "status":
        result = store.summary()
    elif args.command == "list":
        result = store.items(args.limit)
    elif args.command == "ingest-file":
        from pathlib import Path
        raw = Path(args.path).read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            parser.error("input exceeds the size cap")
        result = store.ingest(json.loads(raw), args.feed)
    elif args.command == "assign":
        result = store.assign(args.item_id, args.operator, args.assignee)
    elif args.command == "evidence":
        result = store.evidence(
            args.item_id, args.kind, args.reference, args.sha256, args.operator)
    else:
        result = store.transition(
            args.item_id, args.state, args.operator, args.evidence_id)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        raise SystemExit(2)
