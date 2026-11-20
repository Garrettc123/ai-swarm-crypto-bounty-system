"""ZEUS AutoHunt offline safety, provenance and opportunity-coverage tests."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "crypto"))
from autohunt import (
    POLICY_PATH, MANIFEST_PATH, compact_digest, load_json, check_policy,
    verify_source_review, compile_queue, write_outputs,
)


def source_report(policy):
    files = []
    for q in policy["research_questions"]:
        files.append({
            "path": q["path"],
            "expected_git_blob_sha1": q["git_blob"],
            "observed_git_blob_sha1": q["git_blob"],
            "content_sha256": hashlib.sha256(q["path"].encode("utf-8")).hexdigest(),
            "classification": "static_review_anchor_not_a_vulnerability",
            "match_counts": {s: 1 for s in q["signals"]},
        })
    files.sort(key=lambda row: row["path"])
    material = [{
        "path": row["path"], "sha256": row["content_sha256"],
        "git_blob_sha1": row["observed_git_blob_sha1"],
    } for row in files]
    return {
        "schema_version": 1,
        "organ": "base-everest-hunter",
        "upstream_repository": policy["pinned_repository"],
        "upstream_pinned_commit": policy["pinned_commit"],
        "source_review_status": "completed_not_exploit_validation",
        "evidence_kind": "authenticated_immutable_source_inspection_only",
        "source_evidence_sha256": compact_digest(material),
        "reviewed_source_files": 5,
        "files": files,
        "proof_hash": None,
        "srr_hash": None,
        "seal_hash": None,
        "axiom_12_score": None,
        "poc_reproduced": False,
        "vulnerability_finding": None,
        "devnet_status": "not_executed",
        "verified_earnings_usd": 0,
    }


def public_discovery():
    return {
        "scanned_at": "2026-11-20T01:00:00+00:00",
        "discovered": 2,
        "source_errors": [],
        "top": [
            {"id": "immunefi:example", "platform": "immunefi", "title": "Program",
             "url": "https://immunefi.com/bug-bounty/example/information/",
             "reward_max_usd": 1000, "eligibility": "check_program_rules"},
            {"id": "github:owner/repo/issues/3", "platform": "github",
             "title": "Bounty labeled issue",
             "url": "https://github.com/owner/repo/issues/3",
             "reward_max_usd": None, "eligibility": "check_issue_rules"},
        ],
    }


NOW = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)


class TestZEUSAutoHunt(unittest.TestCase):
    def setUp(self):
        self.policy = load_json(POLICY_PATH)
        self.manifest = load_json(MANIFEST_PATH)
        self.source = source_report(self.policy)

    def test_policy_is_fail_closed(self):
        check_policy(self.policy, self.manifest)
        self.assertFalse(self.policy["automatic_bounty_submission"])
        self.assertFalse(self.policy["automatic_target_scanning"])
        self.assertFalse(self.policy["new_paid_host_provisioning"])

    def test_immutable_review_requires_full_evidence(self):
        mapped = verify_source_review(self.source, self.policy)
        self.assertEqual(5, len(mapped))
        self.assertEqual(5, len(set(mapped)))

    def test_compiles_priorities_but_no_claims(self):
        result = compile_queue(self.policy, self.manifest, self.source,
                               public_discovery(), at=NOW)
        self.assertEqual("open", result["competition_window"])
        self.assertEqual(5, result["review_questions_queued"])
        self.assertEqual(2, result["bounty_discovery"]["listing_count"])
        self.assertEqual({"immunefi": 1, "github": 1},
                         result["bounty_discovery"]["by_source"])
        self.assertEqual(0, result["findings_confirmed"])
        self.assertEqual(0, result["reports_submitted"])
        self.assertFalse(result["authorized_public_target_tests"])
        self.assertEqual(0, result["verified_earnings_usd"])
        self.assertTrue(all(x["status"] == "research_question_not_a_finding" for x in result["review_queue"]))
        self.assertTrue(all(x["submittable"] is False for x in result["review_queue"]))
        self.assertEqual(sorted((x["review_priority"] for x in result["review_queue"]), reverse=True),
                         [x["review_priority"] for x in result["review_queue"]])

    def test_tampered_review_digest_is_rejected(self):
        tampered = copy.deepcopy(self.source)
        tampered["files"][0]["content_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            compile_queue(self.policy, self.manifest, tampered, None, at=NOW)

    def test_changed_blob_pin_is_rejected(self):
        tampered = copy.deepcopy(self.source)
        tampered["files"][0]["observed_git_blob_sha1"] = "0" * 40
        with self.assertRaises(ValueError):
            compile_queue(self.policy, self.manifest, tampered, None, at=NOW)

    def test_fake_proof_is_rejected(self):
        tampered = copy.deepcopy(self.source)
        tampered["proof_hash"] = "0" * 64
        with self.assertRaises(ValueError):
            compile_queue(self.policy, self.manifest, tampered, None, at=NOW)

    def test_forged_submission_policy_is_rejected(self):
        unsafe = copy.deepcopy(self.policy)
        unsafe["automatic_bounty_submission"] = True
        with self.assertRaises(ValueError):
            compile_queue(unsafe, self.manifest, self.source, None, at=NOW)

    def test_partial_discovery_export_fails_closed(self):
        partial = public_discovery()
        partial["discovered"] = 3
        with self.assertRaises(ValueError):
            compile_queue(self.policy, self.manifest, self.source, partial, at=NOW)

    def test_duplicate_opportunities_fail_closed(self):
        partial = public_discovery()
        partial["top"].append(partial["top"][0])
        partial["discovered"] = 3
        with self.assertRaises(ValueError):
            compile_queue(self.policy, self.manifest, self.source, partial, at=NOW)

    def test_closed_contest_disables_review_queue(self):
        result = compile_queue(self.policy, self.manifest, self.source, None,
                               at=datetime(2026, 12, 1, 12, tzinfo=timezone.utc))
        self.assertEqual("closed", result["competition_window"])
        self.assertEqual([], result["review_queue"])

    def test_receipt_is_deterministic_with_fixed_time(self):
        first = compile_queue(self.policy, self.manifest, self.source, None, at=NOW)
        again = compile_queue(self.policy, self.manifest, self.source, None, at=NOW)
        self.assertEqual(first["receipt_sha256"], again["receipt_sha256"])
        audit = {k: v for k, v in first.items() if k != "receipt_sha256"}
        self.assertEqual(compact_digest(audit), first["receipt_sha256"])

    def test_report_is_public_safe_and_locally_saved(self):
        data = compile_queue(self.policy, self.manifest, self.source, None, at=NOW)
        with TemporaryDirectory() as tmp:
            path = Path(tmp)
            write_outputs(data, path)
            self.assertTrue((path / "autohunt-queue.json").is_file())
            md = (path / "AUTOHUNT.md").read_text(encoding="utf-8")
            self.assertIn("not confirmed bugs", md)
            self.assertIn("0 / 0 / $0", md)
            self.assertEqual(5, len(load_json(path / "autohunt-queue.json")["review_queue"]))


if __name__ == "__main__":
    unittest.main()
