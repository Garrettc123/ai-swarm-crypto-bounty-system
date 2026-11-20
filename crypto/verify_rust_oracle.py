#!/usr/bin/env python3
"""Independent consistency audit for a ZEUS Rust Oracle JSON receipt.

Not a digital signature, remote attestation or proof of correct execution:
this validates a runner's *claim* against pinned source and safety policy.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "crypto"))
import zeus
from crypto.autohunt import load_json, check_policy, compact_digest, verify_source_review
from crypto.base_everest_intake import validate as validate_manifest
from crypto.rust_oracle import (
    AUTOHUNT_POLICY, MANIFEST, PIN, RUST_POLICY, SRC, WRAPPER,
    UPSTREAM_NAMES, SUPPLEMENT_NAMES, validate_rust_policy,
)
from hashlib import sha256

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def verify(receipt: dict, source_review: dict, manifest: dict,
           autohunt_policy: dict, rust_policy: dict) -> dict:
    validate_manifest(manifest)
    check_policy(autohunt_policy, manifest)
    validate_rust_policy(rust_policy)
    verified = verify_source_review(source_review, autohunt_policy)
    digest = receipt.get("receipt_sha256")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError("Missing unsigned receipt digest")
    if digest != compact_digest({k: v for k, v in receipt.items()
                                if k != "receipt_sha256"}):
        raise ValueError("Tampered or inconsistent oracle receipt")
    if receipt.get("kind") != "verified_upstream_rust_unit_test_oracle":
        raise ValueError("Unknown receipt kind")
    if receipt.get("target_commit") != zeus.COMMIT:
        raise ValueError("Wrong target commit")
    if receipt.get("source_evidence_sha256") != source_review["source_evidence_sha256"]:
        raise ValueError("Source evidence does not match authenticated review")
    if any(receipt.get(k) != 0 for k in ("verified_findings", "verified_earnings_usd")):
        raise ValueError("Unverified finding or payout claim")
    if receipt.get("proof_hash") is not None or receipt.get("poc_reproduced") is not False:
        raise ValueError("Standalone Rust unit tests cannot claim an exploit proof")
    if receipt.get("devnet_started") is not False:
        raise ValueError("Standalone test oracle must never assert a running devnet")
    at = receipt.get("generated_at_utc")
    if not isinstance(at, str):
        raise ValueError("No timestamp")
    try:
        instant = datetime.fromisoformat(at)
    except ValueError as exc:
        raise ValueError("Invalid timestamp") from exc
    if instant.tzinfo is None:
        raise ValueError("UTC timestamp must be offset-aware")
    start = datetime.fromisoformat(manifest["start_utc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(manifest["end_utc"].replace("Z", "+00:00"))
    active = start <= instant < end
    status = receipt.get("status")
    if status == "skipped_outside_competition_window":
        if active or receipt.get("test_execution_attempted") is not False:
            raise ValueError("False competition-window skip")
        if receipt.get("official_upstream_tests_passed") != 0 or (
            receipt.get("supplementary_tests_passed") != 0
        ):
            raise ValueError("Skipped receipt cannot credit tests")
        verdict = "consistent_skipped_receipt"
    elif status == "five_pinned_rust_tests_passed":
        if not active or receipt.get("test_execution_attempted") is not True:
            raise ValueError("Rust tests cannot be credited outside the competition window")
        if receipt.get("target_repository") != zeus.REPO or receipt.get("source_path") != SRC:
            raise ValueError("Wrong original source path")
        if receipt.get("source_git_blob_sha1") != PIN:
            raise ValueError("Unexpected upstream Git blob")
        if receipt.get("source_sha256") != verified[SRC]["content_sha256"]:
            raise ValueError("Original source SHA-256 does not match review")
        if receipt.get("policy_sha256") != compact_digest(rust_policy):
            raise ValueError("Rust execution policy mismatch")
        if receipt.get("harness_sha256") != sha256(WRAPPER.encode("utf-8")).hexdigest():
            raise ValueError("ZEUS-authored wrapper changed")
        if receipt.get("official_upstream_tests_passed") != 3 or (
            receipt.get("supplementary_tests_passed") != 2
        ):
            raise ValueError("Missing exact upstream or supplemental test count")
        tests = receipt.get("tests_passed")
        if not isinstance(tests, list) or len(tests) != 5 or set(tests) != set(
            UPSTREAM_NAMES + SUPPLEMENT_NAMES
        ):
            raise ValueError("Unexpected original Rust test names")
        if receipt.get("test_execution_method") != (
            "rustc_test_immutable_source_and_fixed_separate_wrapper"
        ):
            raise ValueError("Unrecognized execution method")
        if receipt.get("full_rust_workspace_built") is not False or (
            receipt.get("measured_test_coverage") is not None
        ):
            raise ValueError("False workspace build or coverage claim")
        for field in ("compiled_binary_sha256", "test_output_sha256"):
            value = receipt.get(field)
            if not isinstance(value, str) or not HEX64.fullmatch(value):
                raise ValueError("Missing original execution digest: " + field)
        if not isinstance(receipt.get("rustc_version"), str) or not receipt["rustc_version"].startswith("rustc 1."):
            raise ValueError("Rust compiler version not recorded")
        if receipt.get("reports_submitted") != 0 or receipt.get("axiom_12_score") is not None:
            raise ValueError("Unverified submission or score")
        verdict = "receipt_consistent_not_execution_attested"
    else:
        raise ValueError("Failed or unknown test result")
    return {
        "verdict": verdict,
        "receipt_sha256": digest,
        "authenticated_operator": False,
        "cryptographically_attested_execution": False,
        "poc_reproduced": False,
        "verified_findings": 0,
        "verified_earnings_usd": 0,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--source-review", type=Path, required=True)
    args = p.parse_args()
    result = verify(
        load_json(args.receipt), load_json(args.source_review),
        load_json(MANIFEST), load_json(AUTOHUNT_POLICY), load_json(RUST_POLICY),
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
