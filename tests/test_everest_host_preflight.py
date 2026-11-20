"""Offline tests for read-only Everest host preflight."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/everest_host_preflight.py"
spec = importlib.util.spec_from_file_location("everest_preflight", SCRIPT)
pre = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pre)


class TestPreflight(unittest.TestCase):
    def test_missing_runtime_blocks(self):
        result = pre.preflight(which=lambda _: None, command=lambda _: False,
                               sha_reader=lambda _: pre.PIN)
        self.assertFalse(result["ready_to_attempt_local_devnet"])
        self.assertIn("docker_cli_available", result["blocking_checks"])
        self.assertIsNone(result["proof_hash"])
        self.assertFalse(result["devnet_started"])

    def test_missing_pinned_checkout_blocks(self):
        result = pre.preflight(which=lambda _: "/usr/bin/tool", command=lambda _: True)
        self.assertFalse(result["ready_to_attempt_local_devnet"])
        self.assertIn("pinned_offchain_checkout", result["blocking_checks"])

    def test_unpinned_checkout_blocks(self):
        with TemporaryDirectory() as tmp:
            result = pre.preflight(Path(tmp), which=lambda _: "/usr/bin/tool",
                                   command=lambda _: True, sha_reader=lambda _: "bad")
        self.assertIn("pinned_offchain_checkout", result["blocking_checks"])

    def test_pinned_runtime_is_attempt_ready_not_proof(self):
        with TemporaryDirectory() as tmp:
            result = pre.preflight(Path(tmp), which=lambda _: "/usr/bin/tool",
                                   command=lambda _: True, sha_reader=lambda _: pre.PIN)
        self.assertTrue(result["ready_to_attempt_local_devnet"])
        self.assertFalse(result["production_config_verified"])
        self.assertFalse(result["devnet_started"])
        self.assertFalse(result["poc_reproduced"])
        self.assertIsNone(result["axiom_12_score"])

    def test_pin_is_official_baseline(self):
        self.assertEqual(pre.PIN, "689054ee14933cb2ee5bd54eadcd8dacbe1cc517")


if __name__ == "__main__":
    unittest.main()
