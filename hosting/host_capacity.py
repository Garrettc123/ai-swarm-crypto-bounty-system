#!/usr/bin/env python3
"""Offline capacity gate. A policy estimate, never an Immunefi host requirement.

Consumes a profile from a bounded observation report or a trusted operator's
local preflight. Does not start containers, lease instances or assert a PoC.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from mesh_dispatch import load_policy, digest

FIELDS = {
    "cpu_count": "min_cpus",
    "memory_gib": "min_memory_gib",
    "free_disk_gib": "min_free_disk_gib",
}


def assess(profile: dict, thresholds: dict) -> dict:
    checks = {}
    for observed, minimum in FIELDS.items():
        value = profile.get(observed)
        bound = thresholds.get(minimum)
        ok = (type(value) in (int, float) and type(bound) in (int, float)
              and bound > 0 and value >= bound)
        checks[observed] = {
            "observed": value if type(value) in (int, float) else None,
            "operator_policy_minimum": bound,
            "meets_threshold": ok,
        }
    checks["linux"] = {
        "observed": profile.get("platform"),
        "meets_threshold": profile.get("platform") == "Linux",
    }
    checks["docker_daemon"] = {
        "observed": profile.get("docker_daemon_accessible") is True,
        "meets_threshold": profile.get("docker_daemon_accessible") is True,
    }
    missing = sorted(k for k, row in checks.items() if row["meets_threshold"] is not True)
    return {
        "assessment": "capacity_candidate_only" if not missing else "insufficient_or_unverified",
        "all_policy_checks_pass": not missing,
        "missing_checks": missing,
        "checks": checks,
        "threshold_source": "Garcar operator safety policy, not official Everest specifications",
        "production_everest_config_verified": False,
        "validated_running_devnet": False,
        "permission_to_execute": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", type=Path,
                        default=Path("artifacts/burst-host-health.json"))
    parser.add_argument("--output", type=Path,
                        default=Path("artifacts/host-capacity.json"))
    args = parser.parse_args()
    policy = load_policy()
    observations = json.loads(args.observation.read_text(encoding="utf-8"))
    profile = observations["source_research"]["runner"]
    result = assess(profile, policy["everest_candidate_capacity"])
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_observation_sha256": digest(observations),
        "result": result,
        "proof_hash": None,
        "axiom_12_score": None,
        "devnet_started": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "assessment": result["assessment"],
        "missing_checks": result["missing_checks"],
        "output": str(args.output)
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
