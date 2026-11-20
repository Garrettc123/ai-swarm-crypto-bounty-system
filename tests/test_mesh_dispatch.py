"""Offline tests for deny-by-default burst hosting decisions."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import copy
import json
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mesh_dispatch", ROOT / "hosting" / "mesh_dispatch.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def observation(healthy=True):
    return {
        "source_research": {
            "runner": {"github_actions": True, "platform": "Linux",
                       "docker_daemon_accessible": True}
        },
        "railway_staging": {
            "result": "connected_health_verified" if healthy else "health_unverified",
            "alive": healthy,
        },
    }


class TestMeshDispatch(unittest.TestCase):
    def setUp(self):
        self.policy = mod.load_policy()

    def test_policy_denies_spending_and_external_submissions(self):
        self.assertTrue(self.policy["default_deny"])
        self.assertEqual(0, self.policy["spend_limit_usd"])
        self.assertFalse(self.policy["paid_provisioning_enabled"])
        self.assertFalse(self.policy["outbound_vulnerability_reports_enabled"])

    def test_read_only_source_review_routes_on_linux(self):
        r = mod.plan("source_review", observation(), self.policy)
        self.assertEqual("routed_read_only", r["decision"])
        self.assertEqual("github_actions_ephemeral", r["target_lane"])
        self.assertFalse(r["actual_execution"])
        self.assertEqual(0, r["new_cloud_resources"])
        self.assertIsNone(r["proof_hash"])

    def test_staging_requires_verified_identity_and_liveness(self):
        self.assertEqual("blocked", mod.plan(
            "staging_health", observation(False), self.policy)["decision"])
        self.assertEqual("routed_read_only", mod.plan(
            "staging_health", observation(True), self.policy)["decision"])

    def test_missing_runner_evidence_blocks_preflight(self):
        self.assertEqual(
            "blocked", mod.plan("devnet_preflight", None, self.policy)["decision"]
        )

    def test_unknown_jobs_rejected(self):
        with self.assertRaises(ValueError):
            mod.plan("send_funds", observation(), self.policy)

    def test_devnet_requires_manual_enrollment(self):
        r = mod.plan("everest_devnet", observation(), self.policy)
        self.assertEqual("blocked", r["decision"])
        self.assertIsNone(r["target_lane"])
        self.assertIn("manual enrollment", " ".join(r["blockers"]))
        self.assertFalse(r["vulnerability_submitted"])

    def test_receipt_hash_is_deterministic_with_fixed_time(self):
        instant = datetime(2026, 11, 20, 5, 0, tzinfo=timezone.utc)
        a = mod.plan("source_review", observation(), self.policy, at=instant)
        b = mod.plan("source_review", observation(), self.policy, at=instant)
        self.assertEqual(a["receipt_sha256"], b["receipt_sha256"])
        payload = {key: value for key, value in a.items() if key != "receipt_sha256"}
        self.assertEqual(mod.digest(payload), a["receipt_sha256"])

    def test_policy_rejects_generic_self_hosted_runner(self):
        modified = copy.deepcopy(self.policy)
        modified["dedicated_runner_labels"] = ["self-hosted", "linux"]
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "policy.json"
            target.write_text(json.dumps(modified), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.load_policy(target)

    def test_policy_rejects_paid_provisioning(self):
        modified = copy.deepcopy(self.policy)
        modified["paid_provisioning_enabled"] = True
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "policy.json"
            target.write_text(json.dumps(modified), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.load_policy(target)


if __name__ == "__main__":
    unittest.main()
