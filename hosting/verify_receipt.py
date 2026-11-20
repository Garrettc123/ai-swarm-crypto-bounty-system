#!/usr/bin/env python3
"""Independent integrity verification for Garcar host mesh dispatch receipts.

SHA-256 checks protect *file consistency*, not author identity. This verifier
does not authenticate a host or prove an exploit; it rejects unauthorized
routing and edited receipts under the current checked-in operator policy.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mesh_dispatch import load_policy, digest, EXPECTED_LANES


def verify(receipt: dict, policy: dict, observation: dict | None) -> dict:
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise ValueError("Unsupported receipt")
    claimed_digest = receipt.get("receipt_sha256")
    payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if not isinstance(claimed_digest, str) or digest(payload) != claimed_digest:
        raise ValueError("Receipt integrity failure")
    if receipt.get("policy_sha256") != digest(policy):
        raise ValueError("Receipt policy revision mismatch")
    if receipt.get("observation_sha256") != (
        digest(observation) if observation is not None else None
    ):
        raise ValueError("Observation hash mismatch")
    job = receipt.get("requested_job")
    if job not in EXPECTED_LANES or receipt.get("planned_lane") != EXPECTED_LANES[job]:
        raise ValueError("Unexpected job/lane")
    if receipt.get("decision") == "routed_read_only":
        if job == "everest_devnet" or receipt.get("target_lane") != "github_actions_ephemeral":
            raise ValueError("Unapproved execution lane")
        if receipt.get("blockers") != []:
            raise ValueError("Contradictory route blockers")
    elif receipt.get("decision") == "blocked":
        if receipt.get("target_lane") is not None or not receipt.get("blockers"):
            raise ValueError("Blocked request missing reasons")
    else:
        raise ValueError("Unknown routing decision")
    required = {
        "execute_requested": False,
        "actual_execution": False,
        "new_cloud_resources": 0,
        "new_charges_usd": 0,
        "vulnerability_submitted": False,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
    }
    for name, expected in required.items():
        if receipt.get(name, object()) != expected or type(receipt.get(name)) is not type(expected):
            raise ValueError("Receipt contains prohibited execution/economic assertion: " + name)
    return {
        "result": "verified_integrity_only",
        "job": job,
        "decision": receipt["decision"],
        "receipt_sha256": claimed_digest,
        "authenticated_operator": False,
        "authorized_actual_execution": False,
        "confirmed_vulnerability": False,
        "verified_payout_usd": 0,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--observation", type=Path,
                   default=Path("artifacts/burst-host-health.json"))
    args = p.parse_args()
    policy = load_policy()
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    obs = (json.loads(args.observation.read_text(encoding="utf-8"))
           if args.observation.is_file() else None)
    print(json.dumps(verify(receipt, policy, obs), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
