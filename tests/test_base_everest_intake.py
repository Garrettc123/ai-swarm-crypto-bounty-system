"""Fail-closed tests for the Base Everest offline competition adapter."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'crypto'))
from base_everest_intake import validate, produce

MANIFEST = Path(__file__).resolve().parents[1] / 'crypto' / 'base_everest_target.json'


class TestBaseEverestIntake(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(MANIFEST.read_text(encoding='utf-8'))

    def test_current_manifest_is_valid_but_unverified(self):
        validate(self.data)
        self.assertIsNone(self.data['verification']['proof_hash'])
        self.assertFalse(self.data['verification']['finding_verified'])

    def test_rejects_relabel_as_regular_bounty(self):
        data = copy.deepcopy(self.data)
        data['kind'] = 'bug_bounty'
        with self.assertRaises(ValueError): validate(data)

    def test_rejects_public_testing_and_fake_proof(self):
        data = copy.deepcopy(self.data)
        data['testing_environment'] = 'public_base_mainnet'
        with self.assertRaises(ValueError): validate(data)
        data = copy.deepcopy(self.data)
        data['verification']['proof_hash'] = '0'*64
        with self.assertRaises(ValueError): validate(data)

    def test_rejects_unpinned_sha_and_fabricated_reward(self):
        data = copy.deepcopy(self.data)
        data['targets_to_verify'][0]['pinned_commit'] = 'deadbeef'
        with self.assertRaises(ValueError): validate(data)
        data = copy.deepcopy(self.data)
        data['verification']['reward_verified_usd'] = 250000
        with self.assertRaises(ValueError): validate(data)

    def test_generates_auditable_nonproof_snapshot(self):
        at = datetime(2026, 11, 20, 4, 23, tzinfo=timezone.utc)
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'intake.json'
            result = produce(MANIFEST, dest, at)
            self.assertEqual('open', result['competition_window'])
            self.assertFalse(result['authorized_execution'])
            self.assertIsNone(result['axiom_12_score'])
            self.assertEqual(0, result['verified_reward_usd'])
            self.assertEqual(result, json.loads(dest.read_text(encoding='utf-8')))


if __name__ == '__main__':
    unittest.main()
