"""Offline tests for ZEUS pinned-source review and no-fake-proof invariant."""
import importlib.util
from hashlib import sha256
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("zeus_research", ROOT / "zeus.py")
zeus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(zeus)


class TestZeusResearch(unittest.TestCase):
    def test_git_blob_hash_is_correct(self):
        self.assertEqual(
            "ce013625030ba8dba906f756967f9e9ca394464a",
            zeus.blob_sha1(b"hello\n"),
        )

    def test_only_explicit_source_paths_allowed(self):
        for value in ("../../etc/passwd", "/etc/passwd", "unknown/file.rs"):
            with self.assertRaises(ValueError):
                zeus.require_pinned_path(value)

    def test_commit_is_immutable_and_full_length(self):
        self.assertEqual("689054ee14933cb2ee5bd54eadcd8dacbe1cc517", zeus.COMMIT)
        self.assertEqual(40, len(zeus.COMMIT))

    def test_tampering_fails_closed(self):
        path = next(iter(zeus.TARGETS))
        settings = zeus.TARGETS[path]
        with self.assertRaises(ValueError):
            zeus.review_bytes(path, b"substituted source", settings["blob"],
                              settings["focus"], settings["patterns"])

    def test_deterministic_review_anchor(self):
        path = next(iter(zeus.TARGETS))
        src = b"fn wait_til_ready() {}\n"
        h = zeus.blob_sha1(src)
        row = zeus.review_bytes(path, src, h, "unit test", (r"wait_til_ready",))
        self.assertEqual(1, row["match_counts"]["wait_til_ready"])
        self.assertEqual(1, row["anchors"][0]["line"])
        self.assertEqual(sha256(src).hexdigest(), row["content_sha256"])

    def test_run_is_evidence_not_poc(self):
        path = next(iter(zeus.TARGETS))
        src = b"proofs_latest\n"
        targets = {
            path: {"blob": zeus.blob_sha1(src), "focus": "unit test",
                   "patterns": (r"proofs_latest",)}
        }
        result = zeus.run_once(fetcher=lambda _: src, targets=targets)
        self.assertEqual(1, result["reviewed_source_files"])
        self.assertEqual("completed_not_exploit_validation", result["source_review_status"])
        self.assertIsNone(result["proof_hash"])
        self.assertIsNone(result["srr_hash"])
        self.assertIsNone(result["seal_hash"])
        self.assertIsNone(result["axiom_12_score"])
        self.assertIsNone(result["vulnerability_finding"])
        self.assertFalse(result["poc_reproduced"])
        self.assertEqual(0, result["verified_earnings_usd"])


if __name__ == "__main__":
    unittest.main()
