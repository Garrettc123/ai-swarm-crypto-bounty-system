#!/usr/bin/env python3
"""Read-only preflight for a *local* Base Everest devnet host.

No package installation, downloads, container startup, or external probing.
This gate establishes prerequisites, not successful Production config or a PoC.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

PIN = "689054ee14933cb2ee5bd54eadcd8dacbe1cc517"


def command_ok(argv: list[str], timeout: int = 8) -> bool:
    try:
        result = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def checkout_sha(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    try:
        result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], text=True,
                                capture_output=True, timeout=8, check=True)
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None


def preflight(source: Path | None = None, which=shutil.which,
              command=command_ok, sha_reader=checkout_sha) -> dict:
    osname = platform.system()
    checks = {
        "linux_host": osname == "Linux",
        "git_available": bool(which("git")),
        "just_available": bool(which("just")),
        "docker_cli_available": bool(which("docker")),
    }
    checks["docker_daemon_accessible"] = bool(
        checks["docker_cli_available"] and command(["docker", "info", "--format", "{{.ServerVersion}}"])
    )
    if source is not None:
        checks["pinned_offchain_checkout"] = (
            checks["git_available"] and sha_reader(source.resolve()) == PIN
        )
    else:
        checks["pinned_offchain_checkout"] = False
    # Diagnostic only: the competition does not specify an official minimum here.
    try:
        disk = shutil.disk_usage(str(source if source and source.exists() else Path.home()))
        free_gib = round(disk.free / (1024 ** 3), 2)
    except OSError:
        free_gib = None
    missing = sorted([key for key, ok in checks.items() if not ok])
    return {
        "kind": "local_devnet_host_preflight",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operation": "read_only",
        "target_repository": "immunefi-team/audit-comp-base-everest-base",
        "target_commit": PIN,
        "source_checkout": str(source.resolve()) if source else None,
        "checks": checks,
        "free_disk_gib_advisory": free_gib,
        "blocking_checks": missing,
        "ready_to_attempt_local_devnet": not missing,
        "production_config_verified": False,
        "devnet_started": False,
        "poc_reproduced": False,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_earnings_usd": 0,
        "note": "Prerequisites only: actual resource adequacy, Production flags, known issues and test results must be verified separately.",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--checkout", type=Path, help="Pinned local checkout of competition source")
    p.add_argument("--output", type=Path, default=Path("artifacts/everest-host-preflight.json"))
    p.add_argument("--require-ready", action="store_true",
                   help="Return error when blocked (safe for host-only release gates)")
    args = p.parse_args()
    result = preflight(args.checkout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "ready_to_attempt_local_devnet": result["ready_to_attempt_local_devnet"],
        "blocking_checks": result["blocking_checks"],
        "output": str(args.output),
    }, indent=2))
    return 2 if args.require_ready and not result["ready_to_attempt_local_devnet"] else 0


if __name__ == "__main__":
    sys.exit(main())
