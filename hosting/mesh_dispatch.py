#!/usr/bin/env python3
"""Deterministic, deny-by-default routing for existing Garcar hosting lanes.

Plans jobs; never executes commands or provisions a cloud resource.
Receipts are plain SHA-256 integrity digests, NOT signatures, PoC hashes,
host attestation, or payout proof.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "dispatch_policy.json"
MESH_FILE = HERE / "burst_host_mesh.json"
REPORT_FILE = Path("artifacts/burst-host-health.json")

EXPECTED_JOBS = frozenset({
    "source_review", "staging_health", "devnet_preflight", "everest_devnet"
})
EXPECTED_LANES = {
    "source_review": "github_actions_ephemeral",
    "staging_health": "github_actions_ephemeral",
    "devnet_preflight": "github_actions_ephemeral",
    "everest_devnet": "isolated_self_hosted_linux",
}
EXPECTED_HEALTH = (
    "https://garcar-crypto-bounty-discovery-canary-staging.up.railway.app/health"
)


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return sha256(encoded(value)).hexdigest()


def load_policy(path: Path = POLICY_FILE) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema_version") != 2 or doc.get("default_deny") is not True:
        raise ValueError("Unrecognized or permissive dispatch policy")
    if doc.get("spend_limit_usd") != 0:
        raise ValueError("No billable infrastructure is authorized")
    if doc.get("paid_provisioning_enabled") is not False:
        raise ValueError("Provisioning must remain disabled")
    if doc.get("outbound_vulnerability_reports_enabled") is not False:
        raise ValueError("Automated vulnerability submissions are prohibited")
    if doc.get("metadata_host") != EXPECTED_HEALTH:
        raise ValueError("Unrecognized Railway health endpoint")
    jobs = doc.get("allowed_jobs")
    if not isinstance(jobs, dict) or set(jobs) != EXPECTED_JOBS:
        raise ValueError("Unrecognized allowed jobs")
    for name, cfg in jobs.items():
        if not isinstance(cfg, dict) or cfg.get("lane") != EXPECTED_LANES[name]:
            raise ValueError("Unsafe lane change: " + name)
        if type(cfg.get("max_runtime_seconds")) is not int or not 1 <= cfg["max_runtime_seconds"] <= 1800:
            raise ValueError("Job timeout missing or exceeds policy limit")
    heavy = jobs["everest_devnet"]
    if heavy.get("automatic_dispatch") is not False or heavy.get("requires_host") is not True:
        raise ValueError("Local Everest execution must never auto-route")
    if doc.get("dedicated_runner_labels") != ["self-hosted", "linux", "x64", "zeus-everest-isolated"]:
        raise ValueError("Do not route Everest jobs to generic/self-hosted runner pools")
    return doc


def plan(job: str, observation: dict | None, policy: dict, *, at: datetime | None = None) -> dict:
    if job not in EXPECTED_JOBS:
        raise ValueError("Unknown job type")
    if policy.get("schema_version") != 2 or policy.get("default_deny") is not True:
        raise ValueError("Unsafe policy")
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")
    reasons = []
    route = policy["allowed_jobs"][job]["lane"]
    if job == "everest_devnet":
        reasons.append("dedicated Linux runner not verified by this workflow; manual enrollment and opt-in required")
        reasons.append("full devnet Production config and current scope review are not validated")
    else:
        observed = (observation or {}).get("source_research", {}).get("runner", {})
        if observed.get("github_actions") is not True or observed.get("platform") != "Linux":
            reasons.append("Linux GitHub Actions runner not verified")
        if job == "staging_health":
            railway = (observation or {}).get("railway_staging", {})
            if railway.get("result") != "connected_health_verified" or railway.get("alive") is not True:
                reasons.append("Railway live health identity not verified")
    decision = "blocked" if reasons else "routed_read_only"
    payload = {
        "schema_version": 1,
        "created_at_utc": now,
        "requested_job": job,
        "decision": decision,
        "target_lane": route if not reasons else None,
        "planned_lane": route,
        "blockers": reasons,
        "policy_sha256": digest(policy),
        "observation_sha256": digest(observation) if observation is not None else None,
        "execute_requested": False,
        "actual_execution": False,
        "new_cloud_resources": 0,
        "new_charges_usd": 0,
        "vulnerability_submitted": False,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
        "note": "Routing decision only; hash is unsigned metadata integrity evidence, not a proof.",
    }
    payload["receipt_sha256"] = digest(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", choices=sorted(EXPECTED_JOBS), required=True)
    parser.add_argument("--observation", type=Path, default=REPORT_FILE)
    parser.add_argument("--output", type=Path, default=Path("artifacts/dispatch-receipt.json"))
    parser.add_argument("--require-route", action="store_true")
    args = parser.parse_args()
    policy = load_policy()
    observation = None
    if args.observation.is_file():
        observation = json.loads(args.observation.read_text(encoding="utf-8"))
    receipt = plan(args.job, observation, policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "requested_job": receipt["requested_job"],
        "decision": receipt["decision"],
        "planned_lane": receipt["planned_lane"],
        "blockers": receipt["blockers"],
        "receipt_sha256": receipt["receipt_sha256"],
        "output": str(args.output),
    }, indent=2))
    return 3 if args.require_route and receipt["decision"] != "routed_read_only" else 0


if __name__ == "__main__":
    raise SystemExit(main())
