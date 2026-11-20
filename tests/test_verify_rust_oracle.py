"""Offline tests for independent Rust Oracle receipt reconciliation."""
import copy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "crypto"))
sys.path.insert(0, str(ROOT / "tests"))
from test_autohunt import source_report
from crypto.autohunt import load_json, compact_digest
from crypto.rust_oracle import (
    MANIFEST, AUTOHUNT_POLICY, RUST_POLICY, SRC, PIN, WRAPPER,
    UPSTREAM_NAMES, SUPPLEMENT_NAMES,
)
from crypto.verify_rust_oracle import verify


def fake_receipt(review, rust_policy):
    """Synthetic metadata fixture: NOT a claim that Rust was executed."""
    r = {
        "kind": "verified_upstream_rust_unit_test_oracle",
        "generated_at_utc": "2026-11-20T10:30:00+00:00",
        "status": "five_pinned_rust_tests_passed",
        "target_repository": "immunefi-team/audit-comp-base-everest-base",
        "target_commit": "689054ee14933cb2ee5bd54eadcd8dacbe1cc517",
        "source_path": SRC,
        "source_git_blob_sha1": PIN,
        "source_sha256": next(x for x in review["files"] if x["path"] == SRC)["content_sha256"],
        "source_evidence_sha256": review["source_evidence_sha256"],
        "harness_sha256": sha256(WRAPPER.encode("utf-8")).hexdigest(),
        "policy_sha256": compact_digest(rust_policy),
        "rustc_version": "rustc 1.100.0 (test date)",
        "compiled_binary_sha256": "a" * 64,
        "test_output_sha256": "b" * 64,
        "tests_passed": sorted(UPSTREAM_NAMES + SUPPLEMENT_NAMES),
        "official_upstream_tests_passed": 3,
        "supplementary_tests_passed": 2,
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
    }
    r["receipt_sha256"] = compact_digest(r)
    return r


def reseal(report):
    result = copy.deepcopy(report)
    result.pop("receipt_sha256", None)
    result["receipt_sha256"] = compact_digest(result)
    return result


class TestRustOracleReceipt(unittest.TestCase):
    def setUp(self):
        self.manifest = load_json(MANIFEST)
        self.policy = load_json(AUTOHUNT_POLICY)
        self.rust_policy = load_json(RUST_POLICY)
        self.review = source_report(self.policy)
        self.receipt = fake_receipt(self.review, self.rust_policy)

    def check(self, report):
        return verify(report, self.review, self.manifest, self.policy, self.rust_policy)

    def test_consistent_fixture_is_only_a_receipt_not_attestation(self):
        result = self.check(self.receipt)
        self.assertEqual("receipt_consistent_not_execution_attested", result["verdict"])
        self.assertFalse(result["cryptographically_attested_execution"])
        self.assertFalse(result["authenticated_operator"])
        self.assertEqual(0, result["verified_findings"])

    def test_inplace_tampering_is_refused(self):
        changed = copy.deepcopy(self.receipt)
        changed["official_upstream_tests_passed"] = 5
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_resealed_fabricated_finding_is_refused(self):
        changed = copy.deepcopy(self.receipt)
        changed["verified_findings"] = 2
        with self.assertRaises(ValueError):
            self.check(reseal(changed))

    def test_resealed_wrong_source_digest_is_refused(self):
        changed = copy.deepcopy(self.receipt)
        changed["source_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            self.check(reseal(changed))

    def test_resealed_missing_original_test_is_refused(self):
        changed = copy.deepcopy(self.receipt)
        changed["tests_passed"] = changed["tests_passed"][:-1]
        with self.assertRaises(ValueError):
            self.check(reseal(changed))

    def test_resealed_modified_wrapper_is_refused(self):
        changed = copy.deepcopy(self.receipt)
        changed["harness_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            self.check(reseal(changed))

    def test_skip_after_competition_is_valid_if_no_test_execution(self):
        skipped = {
            "kind": "verified_upstream_rust_unit_test_oracle",
            "generated_at_utc": "2026-12-01T13:00:00+00:00",
            "status": "skipped_outside_competition_window",
            "target_commit": "689054ee14933cb2ee5bd54eadcd8dacbe1cc517",
            "source_evidence_sha256": self.review["source_evidence_sha256"],
            "official_upstream_tests_passed": 0,
            "supplementary_tests_passed": 0,
            "test_execution_attempted": False,
            "devnet_started": False,
            "poc_reproduced": False,
            "verified_findings": 0,
            "verified_earnings_usd": 0,
            "proof_hash": None,
        }
        r = self.check(reseal(skipped))
        self.assertEqual("consistent_skipped_receipt", r["verdict"])


if __name__ == "__main__":
    unittest.main()
