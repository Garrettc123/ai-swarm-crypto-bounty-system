"""Offline safeguards for GitHub burst host / Railway staging connectivity."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "hosting" / "burst_host_mesh.py"
spec = importlib.util.spec_from_file_location("burst_host_mesh", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FakeReply:
    status = 200

    def __init__(self, payload, url=None):
        self.data = json.dumps(payload).encode("utf-8")
        self.url = url or mod.ALLOWED_HEALTH

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def geturl(self):
        return self.url

    def read(self, n):
        return self.data[:n]


class FakeOpener:
    def __init__(self, reply):
        self.reply = reply
        self.requests = []

    def open(self, req, timeout):
        self.requests.append((req.full_url, req.get_method(), timeout))
        return self.reply


class TestBurstHostMesh(unittest.TestCase):
    def test_manifest_is_safe(self):
        doc = mod.load_mesh()
        self.assertFalse(doc["lanes"]["everest_devnet"]["auto_provision"])
        self.assertFalse(doc["lanes"]["everest_devnet"]["auto_start"])
        self.assertEqual("github_actions", doc["lanes"]["source_research"]["host"])

    def test_refuses_unrecognized_railway_endpoint(self):
        doc = mod.load_mesh()
        doc["lanes"]["bounty_metadata"]["health_url"] = "https://example.org/health"
        with self.assertRaises(ValueError):
            mod.validate_mesh(doc)

    def test_railway_fixed_get_only(self):
        op = FakeOpener(FakeReply({"service": "garcar-crypto-bounty-discovery",
                                   "alive": True, "scan_state": "ok"}))
        result = mod.railway_health(opener=op)
        self.assertEqual("connected_health_verified", result["result"])
        self.assertEqual([(mod.ALLOWED_HEALTH, "GET", 10)], op.requests)

    def test_bad_identity_is_not_connected(self):
        op = FakeOpener(FakeReply({"service": "another-service", "alive": True}))
        result = mod.railway_health(opener=op)
        self.assertEqual("health_unverified", result["result"])

    def test_redirect_is_not_connected(self):
        op = FakeOpener(FakeReply({"service": "garcar-crypto-bounty-discovery", "alive": True},
                                  url="https://example.org/"))
        result = mod.railway_health(opener=op)
        self.assertEqual("health_unverified", result["result"])

    def test_report_never_proves_devnet_or_payout(self):
        mesh = mod.load_mesh()
        profile = {"platform": "Linux", "github_actions": True, "docker_daemon_accessible": True}
        result = mod.report(mesh, profile, {"result": "connected_health_verified"})
        self.assertFalse(result["devnet_started"])
        self.assertIsNone(result["proof_hash"])
        self.assertIsNone(result["axiom_12_score"])
        self.assertEqual(0, result["verified_bounty_earnings_usd"])
        self.assertEqual(0, result["new_billable_resources_created"])


if __name__ == "__main__":
    unittest.main()
