#!/usr/bin/env python3
"""Offline intake of Base Everest competition scope (not vulnerability testing).

Do not classify an audit competition as a regular Immunefi bug-bounty listing.
This file validates pinned source references and emits a non-proof status report.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

COMPETITION_PREFIX = "https://immunefi.com/audit-competition/audit-comp-base-everest/"
HEX_COMMIT = re.compile(r"^[a-f0-9]{40}$")
# Immutable revisions listed in the official competition resources and confirmed
# in the dedicated Immunefi competition-fork repositories.
BASELINE_PINS = {
    "base/base": "689054ee14933cb2ee5bd54eadcd8dacbe1cc517",
    "base/reth": "2b20e42de9c42b51ea0fb56599fda3c2f22640ef",
    "base/contracts": "b9b76d97dca3c420098f597ebc65bee4f28001b7",
    "base/contract-deployments": "e6797dfd6ac03b35d0ddd7eb369ab94bbc5fcd31",
    "base/nitro-validator": "0ea0d12366b4fa44f9e07e4755f2ad36561cb674",
}
SCOPE_CLASS = {
    "base/base": "in_scope_offchain",
    "base/reth": "declared_dependency_scope_limited",
    "base/contracts": "implementation_contracts",
    "base/contract-deployments": "in_scope_deployment_scripts",
    "base/nitro-validator": "in_scope_tee_attestation",
}


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Competition dates must use UTC Z timestamps")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset().total_seconds() != 0:
        raise ValueError("Expected UTC time")
    return result


def validate(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object")
    if manifest.get("schema_version") != 1 or manifest.get("id") != "immunefi:audit-comp-base-everest":
        raise ValueError("Unrecognized competition manifest")
    if manifest.get("kind") != "audit_competition":
        raise ValueError("Competition must not be passed to a regular bounty feed")
    start = parse_utc(manifest.get("start_utc"))
    end = parse_utc(manifest.get("end_utc"))
    if not start < end:
        raise ValueError("Invalid competition time window")
    for key, suffix in (
        ("official_information_url", "information/"),
        ("official_scope_url", "scope/"),
        ("official_resources_url", "resources/"),
    ):
        if manifest.get(key) != COMPETITION_PREFIX + suffix:
            raise ValueError("Unexpected official competition URL: " + key)
    if manifest.get("advertised_total_pool_usd") != 250000:
        raise ValueError("Unexpected advertised shared reward pool")
    organ = manifest.get("organ")
    if not isinstance(organ, dict) or organ.get("name") != "base-everest-hunter":
        raise ValueError("Missing ZEUS research organ reference")
    if organ.get("source_repo") != "Garrettc123/zeus-dashboard":
        raise ValueError("Unexpected organ repository")
    if organ.get("source_path") != "organs/base-everest-hunter-organ.yaml":
        raise ValueError("Unexpected organ file")
    if not HEX_COMMIT.fullmatch(str(organ.get("source_commit", ""))):
        raise ValueError("Organ revision must be a full SHA")
    targets = manifest.get("targets_to_verify")
    if not isinstance(targets, list):
        raise ValueError("Missing competition source targets")
    seen = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("Malformed target")
        repo = target.get("upstream_repo")
        if not isinstance(repo, str) or repo not in BASELINE_PINS or repo in seen:
            raise ValueError("Unknown or duplicated target repository")
        seen.add(repo)
        sha = target.get("pinned_commit")
        if not isinstance(sha, str) or not HEX_COMMIT.fullmatch(sha):
            raise ValueError("A full pinned revision is required")
        if sha != BASELINE_PINS[repo]:
            raise ValueError("Wrong competition revision for " + repo)
        if target.get("scope_class") != SCOPE_CLASS[repo]:
            raise ValueError("Asset scope classification mismatch for " + repo)
        required_status = ("verify_exact_component_scope_before_testing" if repo == "base/reth"
                           else "manual_scope_review_required")
        if target.get("status") != required_status:
            raise ValueError("Scope review gate missing for " + repo)
    if seen != set(BASELINE_PINS):
        raise ValueError("The official competition target registry is incomplete")
    if manifest.get("testing_environment") != "designated_local_everest_devnet_only":
        raise ValueError("No live/public testing is authorized")
    if manifest.get("runnable_poc_required") is not True:
        raise ValueError("Runnable PoC requirement cannot be waived")
    verification = manifest.get("verification")
    if not isinstance(verification, dict):
        raise ValueError("Missing verification gate")
    for key in ("host_runtime_verified", "zeus_run_once_verified",
                "local_devnet_verified", "finding_verified"):
        if verification.get(key) is not False:
            raise ValueError("Intake cannot assert proof-stage completion: " + key)
    for key in ("proof_hash", "srr_hash", "seal_hash", "axiom_12_score"):
        if verification.get(key, "MISSING") is not None:
            raise ValueError("No proof hash or AXIOM-12 may be asserted by intake: " + key)
    if verification.get("reward_verified_usd") != 0:
        raise ValueError("Discovery cannot credit bounty earnings")


def produce(manifest_path: Path, output_path: Path, at: datetime | None = None) -> dict:
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    validate(manifest)
    now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start, end = parse_utc(manifest["start_utc"]), parse_utc(manifest["end_utc"])
    window = "not_started" if now < start else "closed" if now >= end else "open"
    result = {
        "id": manifest["id"],
        "kind": "audit_competition",
        "intake_mode": "curated_offline_scope_reference",
        "generated_at": now.isoformat(timespec="seconds"),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "competition_window": window,
        "reported_pool_usd": manifest["advertised_total_pool_usd"],
        "organ": manifest["organ"],
        "official_scope_url": manifest["official_scope_url"],
        "target_baselines": manifest["targets_to_verify"],
        "research_state": "blocked_pending_scope_and_host_proof",
        "authorized_execution": False,
        "allowed_test_environment": manifest["testing_environment"],
        "known_issues_recheck_required": True,
        "proof_hash": None,
        "srr_hash": None,
        "seal_hash": None,
        "axiom_12_score": None,
        "verified_reward_usd": 0,
        "note": "Static intake is not a live feed scan, vulnerability, PoC, submission, or payout.",
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="crypto/base_everest_target.json")
    parser.add_argument("--output", default="artifacts/base-everest-intake.json")
    args = parser.parse_args()
    result = produce(Path(args.manifest), Path(args.output))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
