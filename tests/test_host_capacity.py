"""Offline capacity gates for brokered hosting."""
import importlib.util
from pathlib import Path
import sys
import unittest

HOSTING = Path(__file__).resolve().parents[1] / "hosting"
sys.path.insert(0, str(HOSTING))
spec = importlib.util.spec_from_file_location("host_capacity", HOSTING / "host_capacity.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
MINIMUMS = {"min_cpus": 8, "min_memory_gib": 32, "min_free_disk_gib": 80}


class TestHostCapacity(unittest.TestCase):
    def test_standard_ephemeral_runner_does_not_pass_candidate_gate(self):
        p = {"platform": "Linux", "cpu_count": 4, "memory_gib": 16,
             "free_disk_gib": 14, "docker_daemon_accessible": True}
        result = mod.assess(p, MINIMUMS)
        self.assertEqual("insufficient_or_unverified", result["assessment"])
        self.assertIn("free_disk_gib", result["missing_checks"])
        self.assertFalse(result["permission_to_execute"])

    def test_full_candidate_meets_policy_but_not_execution_authorization(self):
        p = {"platform": "Linux", "cpu_count": 16, "memory_gib": 64,
             "free_disk_gib": 250, "docker_daemon_accessible": True}
        result = mod.assess(p, MINIMUMS)
        self.assertTrue(result["all_policy_checks_pass"])
        self.assertFalse(result["validated_running_devnet"])
        self.assertFalse(result["permission_to_execute"])

    def test_missing_capacity_does_not_fabricate_readiness(self):
        result = mod.assess({}, MINIMUMS)
        self.assertFalse(result["all_policy_checks_pass"])
        self.assertIn("memory_gib", result["missing_checks"])

    def test_broken_threshold_fails_closed(self):
        result = mod.assess({"cpu_count": 16}, {
            "min_cpus": None, "min_memory_gib": 32, "min_free_disk_gib": 80})
        self.assertFalse(result["all_policy_checks_pass"])


if __name__ == "__main__":
    unittest.main()
