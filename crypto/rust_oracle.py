#!/usr/bin/env python3
"""ZEUS Rust Oracle: execute *real, immutable upstream unit tests* offline.

This intentionally narrow oracle compiles the unchanged pinned Base Everest
batch/validity.rs source via rustc --test, with a fixed wrapper that adds two
separately labeled invariants. It is NOT a full workspace build, devnet,
security vulnerability proof, exploit or bounty submission.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "crypto"))
import zeus
from crypto.autohunt import load_json, verify_source_review, check_policy, compact_digest
from crypto.base_everest_intake import validate as validate_manifest

MANIFEST = ROOT / "crypto" / "base_everest_target.json"
AUTOHUNT_POLICY = ROOT / "crypto" / "autohunt_policy.json"
RUST_POLICY = ROOT / "crypto" / "rust_oracle_policy.json"
SRC = "crates/consensus/protocol/src/batch/validity.rs"
PIN = "dbc88782419cb9ee46ea29cfe2e18873352fd494"
UPSTREAM_NAMES = (
    "validity::tests::test_batch_validity",
    "validity::tests::test_batch_drop_reason_display",
    "validity::tests::test_batch_validity_display",
)
SUPPLEMENT_NAMES = (
    "zeus_invariant_tests::batch_classification_is_mutually_exclusive",
    "zeus_invariant_tests::everest_drop_reason_stays_distinguishable",
)

# The original upstream source is never modified. This *separately authored*
# wrapper deliberately avoids external crate dependencies and external targets.
WRAPPER = r"""#![allow(dead_code)]
extern crate alloc;
#[path = "validity.rs"]
mod validity;

#[cfg(test)]
mod zeus_invariant_tests {
    use super::validity::{BatchDropReason as Reason, BatchValidity as Validity};

    #[test]
    fn batch_classification_is_mutually_exclusive() {
        fn assert_one_hot(v: Validity, expected: usize) {
            let flags = [v.is_accept(), v.is_drop(), v.is_outdated(), v.is_future()];
            assert_eq!(flags.into_iter().filter(|b| *b).count(), expected);
        }
        assert_one_hot(Validity::Accept, 1);
        assert_one_hot(Validity::Drop(Reason::ParentHashMismatch), 1);
        assert_one_hot(Validity::Drop(Reason::TxBasePreEverest), 1);
        assert_one_hot(Validity::Past, 1);
        assert_one_hot(Validity::Future, 1);
        assert_one_hot(Validity::Undecided, 0);
    }

    #[test]
    fn everest_drop_reason_stays_distinguishable() {
        let pre_fork = Reason::TxBasePreEverest.to_string();
        let unrelated = Reason::ParentHashMismatch.to_string();
        assert!(pre_fork.contains("Everest"));
        assert_ne!(pre_fork, unrelated);
        assert!(Validity::Drop(Reason::TxBasePreEverest).is_drop());
    }
}
"""
TEST_RESULT = re.compile(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
    re.MULTILINE,
)
TEST_NAME = re.compile(r"^test ([A-Za-z0-9_:]+) \.\.\. ok\s*$", re.MULTILINE)


def validate_rust_policy(policy: dict) -> None:
    hardcoded = {
        "schema_version": 1,
        "kind": "isolated_pinned_upstream_rust_tests",
        "upstream": zeus.REPO,
        "commit": zeus.COMMIT,
        "path": SRC,
        "git_blob_sha1": PIN,
        "compile_timeout_seconds": 90,
        "execute_timeout_seconds": 30,
        "max_file_bytes": 1048576,
        "official_upstream_test_names": list(UPSTREAM_NAMES),
        "supplementary_test_names": list(SUPPLEMENT_NAMES),
        "requires_no_network_test_runtime": True,
        "actual_devnet_required_for_vulnerability_claim": True,
        "automatic_vulnerability_submission": False,
        "automatic_external_target_testing": False,
        "automatic_bounty_claims": False,
        "paid_host_provisioning": False,
    }
    for key, expected in hardcoded.items():
        value = policy.get(key)
        if type(value) is not type(expected) or value != expected:
            raise ValueError("Rust oracle policy mismatch at " + key)
    if zeus.TARGETS[SRC]["blob"] != PIN:
        raise ValueError("Source differs from vetted ZEUS immutable path")


def parse_passed_tests(output: str) -> list[str]:
    if not isinstance(output, str) or len(output) > 128 * 1024:
        raise ValueError("Unexpected or oversized rustc test report")
    match = TEST_RESULT.search(output)
    if not match:
        raise ValueError("Missing unequivocal successful rustc test summary")
    counts = tuple(int(x) for x in match.groups())
    if counts != (5, 0, 0, 0, 0):
        raise ValueError("Rust results do not match five required tests")
    names = TEST_NAME.findall(output)
    if len(names) != 5 or set(names) != set(UPSTREAM_NAMES + SUPPLEMENT_NAMES):
        raise ValueError("Actual tested Rust functions differ from verified oracle allowlist")
    return sorted(names)


def sanitized_rust_env(temp: str) -> dict:
    # GitHub credentials, OIDC request tokens, secrets and provider API keys
    # are deliberately *not* forwarded into rustc or the unit test binary.
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", temp),  # Preserve rustup toolchain path.
        "LC_ALL": "C",
        "RUST_BACKTRACE": "0",
        "CARGO_HOME": temp,
    }
    if os.environ.get("RUSTUP_HOME"):
        env["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    return env


def observed_run(review: dict, manifest: dict, autohunt_policy: dict, policy: dict,
                 *, fetcher=zeus.fetch_pinned,
                 invoke=subprocess.run,
                 rustc_path: str | None = None,
                 now: datetime | None = None) -> dict:
    validate_manifest(manifest)
    check_policy(autohunt_policy, manifest)
    validate_rust_policy(policy)
    observed = verify_source_review(review, autohunt_policy)
    if SRC not in observed or observed[SRC]["observed_git_blob_sha1"] != PIN:
        raise ValueError("Missing pinned upstream batch validity source")
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = datetime.fromisoformat(manifest["start_utc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(manifest["end_utc"].replace("Z", "+00:00"))
    if not start <= instant < end:
        return {
            "kind": "verified_upstream_rust_unit_test_oracle",
            "generated_at_utc": instant.isoformat(timespec="seconds"),
            "status": "skipped_outside_competition_window",
            "target_commit": zeus.COMMIT,
            "source_evidence_sha256": review["source_evidence_sha256"],
            "official_upstream_tests_passed": 0,
            "supplementary_tests_passed": 0,
            "test_execution_attempted": False,
            "devnet_started": False,
            "poc_reproduced": False,
            "verified_findings": 0,
            "verified_earnings_usd": 0,
            "proof_hash": None,
        }
    source = fetcher(SRC)
    if not isinstance(source, bytes) or len(source) > policy["max_file_bytes"]:
        raise ValueError("Source invalid or oversized")
    if zeus.blob_sha1(source) != PIN:
        raise ValueError("Original Rust file failed Git blob verification")
    content_sha = sha256(source).hexdigest()
    if content_sha != observed[SRC]["content_sha256"]:
        raise ValueError("Original Rust file failed source review SHA-256 consistency")
    compiler = rustc_path if rustc_path is not None else shutil.which("rustc")
    if not compiler:
        raise RuntimeError("rustc unavailable on this approved ephemeral Linux runner")
    with tempfile.TemporaryDirectory(prefix="zeus-rust-oracle-") as temp:
        work = Path(temp)
        (work / "validity.rs").write_bytes(source)
        (work / "oracle.rs").write_text(WRAPPER, encoding="utf-8")
        env = sanitized_rust_env(temp)
        version = invoke(
            [compiler, "--version"], cwd=work, env=env, capture_output=True,
            text=True, timeout=15, check=False,
        )
        if version.returncode != 0 or not re.fullmatch(
            r"rustc 1\.\d+\.\d+(?:[-+][^\n]+)?(?: \([^\n]+\))?\n?", version.stdout
        ):
            raise ValueError("rustc version unavailable or unrecognized")
        exe = work / "zeus-oracle-tests"
        build = invoke(
            [compiler, "--edition=2021", "--crate-name", "zeus_batch_oracle",
             "--test", str(work / "oracle.rs"), "-o", str(exe)],
            cwd=work, env=env, capture_output=True,
            text=True, timeout=policy["compile_timeout_seconds"], check=False,
        )
        if build.returncode != 0 or not exe.is_file():
            raise RuntimeError("Pinned upstream Rust test compilation did not succeed")
        tested = invoke(
            [str(exe), "--test-threads=1"], cwd=work, env=env, capture_output=True,
            text=True, timeout=policy["execute_timeout_seconds"], check=False,
        )
        if tested.returncode != 0:
            raise RuntimeError("Pinned upstream Rust unit tests failed")
        passed = parse_passed_tests(tested.stdout)
        executable_sha = sha256(exe.read_bytes()).hexdigest()
    result = {
        "kind": "verified_upstream_rust_unit_test_oracle",
        "generated_at_utc": instant.isoformat(timespec="seconds"),
        "status": "five_pinned_rust_tests_passed",
        "target_repository": zeus.REPO,
        "target_commit": zeus.COMMIT,
        "source_path": SRC,
        "source_git_blob_sha1": PIN,
        "source_sha256": content_sha,
        "source_evidence_sha256": review["source_evidence_sha256"],
        "harness_sha256": sha256(WRAPPER.encode("utf-8")).hexdigest(),
        "policy_sha256": compact_digest(policy),
        "rustc_version": version.stdout.strip(),
        "compiled_binary_sha256": executable_sha,
        "test_output_sha256": sha256(tested.stdout.encode("utf-8")).hexdigest(),
        "tests_passed": passed,
        "official_upstream_tests_passed": len(UPSTREAM_NAMES),
        "supplementary_tests_passed": len(SUPPLEMENT_NAMES),
        "test_execution_attempted": True,
        "test_execution_method": "rustc_test_immutable_source_and_fixed_separate_wrapper",
        "full_rust_workspace_built": False,
        "measured_test_coverage": None,
        "devnet_started": False,
        "poc_reproduced": False,
        "verified_findings": 0,
        "reports_submitted": 0,
        "verified_earnings_usd": 0,
        "proof_hash": None,
        "axiom_12_score": None,
        "note": "Actual pinned Rust tests pass in isolation. This is not a vulnerability or system-wide assurance.",
    }
    result["receipt_sha256"] = compact_digest(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-review", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/rust-oracle.json"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = observed_run(
            load_json(args.source_review), load_json(MANIFEST),
            load_json(AUTOHUNT_POLICY), load_json(RUST_POLICY),
        )
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        report = {
            "kind": "verified_upstream_rust_unit_test_oracle",
            "status": "failed_closed",
            "failure_type": type(exc).__name__,
            "compiled_tests_verified": False,
            "devnet_started": False,
            "poc_reproduced": False,
            "verified_findings": 0,
            "verified_earnings_usd": 0,
            "proof_hash": None,
        }
        args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("ZEUS pinned Rust test oracle failed closed: " + type(exc).__name__, file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "upstream_tests_passed": result["official_upstream_tests_passed"],
        "supplementary_tests_passed": result["supplementary_tests_passed"],
        "receipt_sha256": result.get("receipt_sha256"),
        "verified_findings": 0,
        "poc_reproduced": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
