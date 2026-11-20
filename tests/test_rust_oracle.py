"""Fail-closed tests for authentic pinned Rust execution on ephemeral workers."""
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import copy
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "crypto"))
sys.path.insert(0, str(ROOT / "tests"))
import zeus
from crypto.autohunt import load_json, compact_digest
from test_autohunt import source_report
from crypto.rust_oracle import (
    MANIFEST, AUTOHUNT_POLICY, RUST_POLICY, PIN, SRC,
    SUPPLEMENT_NAMES, UPSTREAM_NAMES, WRAPPER,
    parse_passed_tests, sanitized_rust_env, validate_rust_policy, observed_run,
)

NOW = datetime(2026, 11, 20, 15, tzinfo=timezone.utc)
RESULT_TEXT = (
    "\nrunning 5 tests\n" +
    "".join("test " + name + " ... ok\n"
            for name in UPSTREAM_NAMES + SUPPLEMENT_NAMES) +
    "\ntest result: ok. 5 passed; 0 failed; 0 ignored; "
    "0 measured; 0 filtered out; finished in 0.00s\n"
)


class TestRustOracle(unittest.TestCase):
    def setUp(self):
        self.manifest = load_json(MANIFEST)
        self.policy = load_json(AUTOHUNT_POLICY)
        self.oracle_policy = load_json(RUST_POLICY)
        self.review = source_report(self.policy)

    def test_exact_pins_and_no_external_operations(self):
        validate_rust_policy(self.oracle_policy)
        self.assertEqual(PIN, zeus.TARGETS[SRC]["blob"])
        for field in ("automatic_vulnerability_submission",
                      "automatic_external_target_testing",
                      "automatic_bounty_claims", "paid_host_provisioning"):
            self.assertFalse(self.oracle_policy[field])

    def test_modified_pin_refused(self):
        policy = copy.deepcopy(self.oracle_policy)
        policy["git_blob_sha1"] = "0" * 40
        with self.assertRaises(ValueError):
            validate_rust_policy(policy)

    def test_original_upstream_source_is_included_not_rewritten(self):
        self.assertIn('#[path = "validity.rs"]', WRAPPER)
        self.assertIn("extern crate alloc;", WRAPPER)
        self.assertIn("zeus_invariant_tests", WRAPPER)
        self.assertNotIn("http://", WRAPPER)
        self.assertNotIn("https://", WRAPPER)

    def test_only_exact_successful_rust_tests_are_accepted(self):
        self.assertEqual(
            sorted(UPSTREAM_NAMES + SUPPLEMENT_NAMES),
            parse_passed_tests(RESULT_TEXT),
        )
        for bad in (
            RESULT_TEXT.replace("5 passed", "4 passed"),
            RESULT_TEXT.replace("0 failed", "1 failed"),
            RESULT_TEXT.replace("test validity::tests::test_batch_validity ... ok",
                                "test validity::tests::test_other ... ok"),
            "running 0 tests\ntest result: ok. 0 passed; 0 failed;",
            "",
        ):
            with self.assertRaises(ValueError):
                parse_passed_tests(bad)

    def test_no_github_secrets_forwarded_to_rust_process(self):
        with patch.dict("os.environ", {
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "never-forward",
            "GITHUB_TOKEN": "never-forward",
            "AWS_SECRET_ACCESS_KEY": "never-forward",
            "HOME": "/tmp/test-home",
            "PATH": "/usr/bin",
        }):
            env = sanitized_rust_env("/tmp/zeus")
        self.assertEqual("/usr/bin", env["PATH"])
        self.assertEqual("/tmp/test-home", env["HOME"])
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)

    def test_closed_window_skips_without_fetching_or_compiling(self):
        def unexpected(*args, **kwargs):
            raise AssertionError("After end date, oracle must not fetch or execute")
        result = observed_run(
            self.review, self.manifest, self.policy, self.oracle_policy,
            now=datetime(2026, 12, 1, 14, tzinfo=timezone.utc),
            fetcher=unexpected, invoke=unexpected, rustc_path="rustc",
        )
        self.assertEqual("skipped_outside_competition_window", result["status"])
        self.assertEqual(0, result["official_upstream_tests_passed"])

    def test_unrecognized_source_digest_is_rejected(self):
        corrupted = copy.deepcopy(self.review)
        corrupted["source_evidence_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            observed_run(corrupted, self.manifest, self.policy,
                         self.oracle_policy, now=NOW,
                         fetcher=lambda _: b"fake",
                         rustc_path="rustc")

    def test_bogus_rust_file_refused_before_any_execution(self):
        with self.assertRaises(ValueError):
            observed_run(
                self.review, self.manifest, self.policy, self.oracle_policy,
                now=NOW, fetcher=lambda _: b"unverified upstream Rust source",
                rustc_path="rustc",
            )

    def test_test_oracle_mocked_process_does_not_assert_poc(self):
        # This is a *mock test of the report logic*. A passing real Rust run
        # must come from the separate, credential-minimized GitHub workflow.
        raw = b"mock-rust-original\n"
        reviewed = copy.deepcopy(self.review)
        for row in reviewed["files"]:
            if row["path"] == SRC:
                row["content_sha256"] = sha256(raw).hexdigest()
        refs = sorted(reviewed["files"], key=lambda x: x["path"])
        reviewed["source_evidence_sha256"] = compact_digest([
            {"path": r["path"], "sha256": r["content_sha256"],
             "git_blob_sha1": r["observed_git_blob_sha1"]} for r in refs
        ])

        def fake_invoke(argv, **kwargs):
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            if argv[1] == "--version":
                return SimpleNamespace(
                    returncode=0, stdout="rustc 1.90.0 (012345678 2026-01-01)\n")
            if argv[1] == "--edition=2021":
                Path(argv[-1]).write_bytes(b"mock binary, not a real Rust executable")
                return SimpleNamespace(returncode=0, stdout="")
            return SimpleNamespace(returncode=0, stdout=RESULT_TEXT)

        with patch.object(zeus, "blob_sha1", return_value=PIN):
            result = observed_run(
                reviewed, self.manifest, self.policy, self.oracle_policy,
                now=NOW, fetcher=lambda _: raw,
                invoke=fake_invoke, rustc_path="/usr/bin/rustc",
            )
        self.assertEqual(3, result["official_upstream_tests_passed"])
        self.assertEqual(2, result["supplementary_tests_passed"])
        self.assertEqual(0, result["verified_findings"])
        self.assertFalse(result["poc_reproduced"])
        self.assertIsNone(result["proof_hash"])


if __name__ == "__main__":
    unittest.main()
