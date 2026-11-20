#!/usr/bin/env python3
"""Cost-guarded burst hosting: inspect GitHub runner and existing Railway health.

No provisioning, secret access, code execution on Railway, public network scans,
user requests outside fixed service /health, or live vulnerability testing.
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
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

MESH_PATH = Path(__file__).with_name("burst_host_mesh.json")
ALLOWED_HEALTH = "https://garcar-crypto-bounty-discovery-canary-staging.up.railway.app/health"
LIMIT = 128 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_mesh(path: Path = MESH_PATH) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema_version") != 1:
        raise ValueError("Unknown hosting mesh schema")
    lanes = doc.get("lanes")
    if not isinstance(lanes, dict) or set(lanes) != {
        "source_research", "bounty_metadata", "everest_devnet"
    }:
        raise ValueError("Host lanes missing or unexpected")
    if lanes["source_research"].get("host") != "github_actions":
        raise ValueError("Read-only jobs must use GitHub ephemeral Linux")
    meta = lanes["bounty_metadata"]
    if meta.get("host") != "railway" or meta.get("health_url") != ALLOWED_HEALTH:
        raise ValueError("Unexpected public endpoint; refusing unreviewed outbound route")
    if meta.get("public_vulnerability_disclosures") is not False:
        raise ValueError("Never publish vulnerability details to status plane")
    deep = lanes["everest_devnet"]
    if deep.get("status") != "blocked_no_connected_host":
        raise ValueError("A host cannot be declared connected by static configuration")
    for key in ("auto_start", "auto_provision", "vulnerability_submissions"):
        if deep.get(key) is not False:
            raise ValueError("Devnet actions are not authorized by the hosting manifest")
    for key, allowed in doc.get("security", {}).items():
        if allowed is not False:
            raise ValueError("Unsafe hosting policy: " + key)
    return doc


def _command_available(name: str) -> bool:
    return shutil.which(name) is not None


def _docker_ready() -> bool:
    if not _command_available("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            check=False, capture_output=True, timeout=7,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _memory_gib() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / (1024**2), 2)
    except (OSError, ValueError, IndexError):
        return None
    return None


def profile_runner() -> dict:
    base = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/tmp"
    disk = shutil.disk_usage(base)
    return {
        "platform": platform.system(),
        "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
        "cpu_count": os.cpu_count(),
        "memory_gib": _memory_gib(),
        "free_disk_gib": round(disk.free / (1024**3), 2),
        "tools": {x: _command_available(x) for x in ("git", "python3", "just", "docker")},
        "docker_daemon_accessible": _docker_ready(),
        "everest_devnet_proven": False,
        "validated_full_devnet_capacity": False,
    }


def railway_health(opener=None) -> dict:
    req = Request(ALLOWED_HEALTH, headers={
        "User-Agent": "Garcar-Burst-Host-Mesh/1.0",
        "Accept": "application/json",
    }, method="GET")
    try:
        client = opener if opener is not None else build_opener(NoRedirect())
        with client.open(req, timeout=10) as resp:
            if getattr(resp, "status", None) != 200:
                raise ValueError("Non-200 health response")
            if resp.geturl() != ALLOWED_HEALTH:
                raise ValueError("Unexpected health URL redirect")
            data = resp.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("Oversize health response")
        obj = json.loads(data)
        if not isinstance(obj, dict) or obj.get("alive") is not True:
            raise ValueError("No active service attestation in health response")
        if obj.get("service") != "garcar-crypto-bounty-discovery":
            raise ValueError("Unexpected connected service")
        return {
            "result": "connected_health_verified",
            "service": "garcar-crypto-bounty-discovery",
            "alive": True,
            "scanner_state": obj.get("scan_state", "unknown"),
            "note": "Public GET /health only. No privileged API or exploit operations.",
        }
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "result": "health_unverified",
            "reason_type": type(exc).__name__,
            "note": "This check did not change any Railway service or GitHub config.",
        }


def report(mesh: dict, profile: dict, railway: dict, now: datetime | None = None) -> dict:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if mesh["lanes"]["everest_devnet"]["status"] != "blocked_no_connected_host":
        raise ValueError("Cannot assert a devnet host")
    return {
        "timestamp_utc": now.isoformat(timespec="seconds"),
        "name": mesh["architecture"],
        "source_research": {
            "status": "runner_observed" if profile["github_actions"] else "local_profile_only",
            "runner": profile,
        },
        "railway_staging": railway,
        "routing": {
            "read_only_source_review": "github_actions_ephemeral",
            "public_bounty_metadata": "existing_railway_staging",
            "everest_devnet": "blocked_until_dedicated_host_verified",
        },
        "new_billable_resources_created": 0,
        "new_vulnerability_submissions": 0,
        "devnet_started": False,
        "proof_hash": None,
        "axiom_12_score": None,
        "verified_bounty_earnings_usd": 0,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="artifacts/burst-host-health.json")
    args = p.parse_args()
    try:
        mesh = load_mesh()
        doc = report(mesh, profile_runner(), railway_health())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("Hosting mesh failed closed: " + type(exc).__name__)
        return 2
    dest = Path(args.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "github_actions_linux": doc["source_research"]["runner"]["platform"] == "Linux",
        "docker_daemon_accessible": doc["source_research"]["runner"]["docker_daemon_accessible"],
        "railway_staging": doc["railway_staging"]["result"],
        "everest_devnet": doc["routing"]["everest_devnet"],
        "output": str(dest),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
