"""Offline tests for source evidence mapping and validation boundaries."""
import copy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import zeus
from crypto.autohunt import POLICY_PATH, MANIFEST_PATH, load_json, compile_queue
from crypto.evidence_mapper import (
    RELATED_TESTS, index_rust, line_anchors, verify_autohunt_queue,
    build_map, write_reports,
)
from test_autohunt import source_report, NOW


class TestZEUSEvidenceMapper(unittest.TestCase):
    def setUp(self):
        self.policy = load_json(POLICY_PATH)
        self.manifest = load_json(MANIFEST_PATH)
        self.review = source_report(self.policy)
        self.queue = compile_queue(
            self.policy, self.manifest, self.review, None, at=NOW)

    def test_textual_function_and_test_index(self):
        raw = b"""fn ordinary() {}
#[tokio::test]
async fn async_works() {}
#[test]
fn sync_works() {}
fn another() {}
"""
        parsed = index_rust(raw)
        self.assertEqual(
            ["ordinary", "async_works", "sync_works", "another"],
            [row["name"] for row in parsed["function_declarations"]],
        )
        self.assertEqual(2, parsed["test_declaration_count"])

    def test_textual_pattern_locations(self):
        raw = b"""fn example() {
    let timestamp = 5;
}
"""
        signals = line_anchors(raw, ["timestamp", "not_present"])
        self.assertEqual(2, signals[0]["locations"][0]["line"])
        self.assertEqual("example", signals[0]["locations"][0]["nearest_declaration"])
        self.assertEqual([], signals[1]["locations"])

    def test_invalid_utf8_fails_closed(self):
        with self.assertRaises(ValueError):
            index_rust(b"\xff")
        with self.assertRaises(UnicodeDecodeError):
            line_anchors(b"\xff", ["test"])

    def test_active_queue_integrity_accepted(self):
        verify_autohunt_queue(self.queue, self.review, self.policy)

    def test_modified_queue_rejected(self):
        altered = copy.deepcopy(self.queue)
        altered["review_queue"][0]["submittable"] = True
        with self.assertRaises(ValueError):
            verify_autohunt_queue(altered, self.review, self.policy)

    def test_closed_competition_rejected(self):
        closed = compile_queue(self.policy, self.manifest, self.review, None,
                               at=datetime(2026, 12, 1, 12, tzinfo=timezone.utc))
        with self.assertRaises(ValueError):
            verify_autohunt_queue(closed, self.review, self.policy)

    def test_pinned_source_authentication_catches_substitution(self):
        # The fixture simulates offline content, not real pinned project files.
        with self.assertRaises(ValueError):
            build_map(self.review, self.queue, self.policy, self.manifest,
                      fetch_test=lambda path: b"untrusted test source",
                      fetch_source=lambda path: b"untrusted source", at=NOW)

    def test_unapproved_related_test_has_no_route(self):
        self.assertNotIn("../private.key", RELATED_TESTS)

    def test_public_report_is_bounded_and_nonproof(self):
        sample = {
            "source_files_verified": 1,
            "related_test_references_verified": 0,
            "records": [{
                "question_id": "EVEREST-PROOF-GATE",
                "validation_question": "Check proof readiness",
                "path": "crates/consensus/service/src/follow/proof_gate.rs",
                "function_count": 2,
                "inline_test_count": 0,
                "adjacent_test_references": [],
            }],
            "receipt_sha256": "a" * 64,
        }
        with TemporaryDirectory() as d:
            dest = Path(d)
            write_reports(sample, dest)
            md = (dest / "EVIDENCE_MAP.md").read_text(encoding="utf-8")
            self.assertIn("research observations", md)
            self.assertIn("No devnet started", md)
            self.assertTrue((dest / "evidence-map.json").is_file())


if __name__ == "__main__":
    unittest.main()
