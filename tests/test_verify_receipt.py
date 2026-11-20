"""Independent integrity-verifier tests; no host or network needed."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

DIR = Path(__file__).resolve().parents[1] / "hosting"
sys.path.insert(0, str(DIR))
from mesh_dispatch import load_policy, plan, digest
spec = importlib.util.spec_from_file_location("mesh_receipt", DIR / "verify_receipt.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestReceiptVerifier(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()
        self.observation = {
            "source_research": {"runner": {"github_actions": True, "platform": "Linux"}},
            "railway_staging": {"result": "connected_health_verified", "alive": True},
        }
        self.good = plan("staging_health", self.observation, self.policy)

    def test_accepts_untampered_readonly_routing_receipt(self):
        verified = mod.verify(self.good, self.policy, self.observation)
        self.assertEqual("verified_integrity_only", verified["result"])
        self.assertFalse(verified["authenticated_operator"])

    def test_denies_tampering_without_digest_change(self):
        modified = copy.deepcopy(self.good)
        modified["decision"] = "blocked"
        with self.assertRaises(ValueError):
            mod.verify(modified, self.policy, self.observation)

    def test_denies_forged_proof_even_if_digest_updated(self):
        modified = copy.deepcopy(self.good)
        modified["proof_hash"] = "0" * 64
        modified.pop("receipt_sha256")
        modified["receipt_sha256"] = digest(modified)
        with self.assertRaises(ValueError):
            mod.verify(modified, self.policy, self.observation)

    def test_denies_modified_external_observation(self):
        with self.assertRaises(ValueError):
            mod.verify(self.good, self.policy, {"source_research": {}})

    def test_denies_policy_revision_change(self):
        modified = copy.deepcopy(self.policy)
        modified["connection"] = "different"
        with self.assertRaises(ValueError):
            mod.verify(self.good, modified, self.observation)

    def test_cannot_auto_allow_devnet_even_with_rehashed_receipt(self):
        modified = plan("everest_devnet", self.observation, self.policy)
        modified.pop("receipt_sha256")
        modified["decision"] = "routed_read_only"
        modified["target_lane"] = "github_actions_ephemeral"
        modified["blockers"] = []
        modified["receipt_sha256"] = digest(modified)
        with self.assertRaises(ValueError):
            mod.verify(modified, self.policy, self.observation)


if __name__ == "__main__":
    unittest.main()
