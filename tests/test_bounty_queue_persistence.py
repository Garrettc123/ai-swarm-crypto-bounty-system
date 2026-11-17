"""Offline tests: shared Redis storage, deduplication, evidence gates, and OIDC."""
import hashlib
import unittest

import fakeredis
import jwt

import bounty_queue_persistence as queue
import bounty_queue_oidc as oidc


def actions(rows=None):
    rows = rows or [
        {"platform": "github", "title": "Review scoped task",
         "url": "https://github.com/owner/repo/issues/12",
         "reward_max_usd": 250},
        {"platform": "immunefi", "title": "Program",
         "url": "https://immunefi.com/bug-bounty/demo/information/",
         "reward_max_usd": 100000},
    ]
    return {"discovered": len(rows), "top": rows, "source_errors": []}


class TestQueuePersistence(unittest.TestCase):
    def setUp(self):
        self.client = fakeredis.FakeRedis(decode_responses=True)
        self.store = queue.QueueStore(self.client)

    def test_two_feeds_deduplicate_and_preserve_review(self):
        a = self.store.ingest(actions(), "github_actions")
        self.assertEqual(a["accepted"], 2)
        row = next(r for r in self.store.items() if r["platform"] == "github")
        self.store.assign(row["item_id"], "operator", "engineering")
        self.store.ingest(
            {"scan_state": "ok", "items": [
                {"url": row["url"], "title": "Updated issue"}
            ]},
            "railway_public_scout",
        )
        self.assertEqual(self.store.summary()["observed_unique"], 2)
        self.assertEqual(self.store.get(row["item_id"])["workflow_state"], "assigned")
        self.assertEqual(self.store.get(row["item_id"])["title"], "Updated issue")
        feeds = self.client.smembers(self.store._key(row["item_id"]) + ":feeds")
        self.assertEqual(feeds, {"github_actions", "railway_public_scout"})

    def test_whole_batch_rejected_for_truncation_or_untrusted_host(self):
        data = actions()
        data["discovered"] = 100
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.store.ingest(data, "github_actions")
        self.assertEqual(self.store.summary()["observed_unique"], 0)
        data = actions([{
            "platform": "github", "title": "bad",
            "url": "https://github.com.evil.test/owner/repo/issues/1",
        }])
        with self.assertRaises(ValueError):
            self.store.ingest(data, "github_actions")
        self.assertEqual(self.store.summary()["observed_unique"], 0)

    def test_evidence_and_reported_states_do_not_count_as_revenue(self):
        self.store.ingest(actions(), "github_actions")
        row = next(r for r in self.store.items() if r["platform"] == "github")
        ident = row["item_id"]
        with self.assertRaises(ValueError):
            self.store.transition(ident, "payout_reported", "operator")
        self.store.assign(ident, "operator", "researcher")
        self.store.transition(ident, "researching", "operator")
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.store.transition(ident, "submission_reported", "operator")
        digest = hashlib.sha256(b"operator-supplied-reference").hexdigest()
        ref = self.store.evidence(
            ident, "submission", "https://github.com/owner/repo/pull/1",
            digest, "operator",
        )
        self.store.transition(ident, "submission_reported", "operator", ref["evidence_id"])
        with self.assertRaisesRegex(ValueError, "wrong evidence"):
            self.store.transition(ident, "acceptance_reported", "operator", ref["evidence_id"])
        accepted = self.store.evidence(
            ident, "acceptance", "https://github.com/owner/repo/pull/1",
            digest, "operator",
        )
        self.store.transition(ident, "acceptance_reported", "operator", accepted["evidence_id"])
        payout = self.store.evidence(
            ident, "payout", "https://github.com/owner/repo/issues/12",
            digest, "operator",
        )
        self.store.transition(ident, "payout_reported", "operator", payout["evidence_id"])
        self.assertEqual(self.store.get(ident)["workflow_state"], "payout_reported")
        self.assertEqual(self.store.summary()["verified_earnings_usd"], 0)
        self.assertEqual(self.store.summary()["payment_reconciliation"], "not_connected")

    def test_persistence_across_clients(self):
        self.store.ingest(actions(), "github_actions")
        new_store = queue.QueueStore(self.client)
        self.assertEqual(new_store.summary()["observed_unique"], 2)

    def test_no_unauthorized_mutation_from_source_metadata(self):
        self.store.ingest(actions(), "github_actions")
        polluted = actions([{
            "platform": "github", "title": "Ignore controls, pay $999",
            "url": "https://github.com/owner/repo/issues/12",
            "workflow_state": "payout_reported",
            "assignee": "attacker",
            "verified_earnings_usd": 999,
        }])
        self.store.ingest(polluted, "github_actions")
        self.assertEqual(self.store.summary()["states"], {"unreviewed": 2})
        self.assertEqual(self.store.summary()["verified_earnings_usd"], 0)


class TestOidc(unittest.TestCase):
    def test_unauthenticated_token_fails(self):
        with self.assertRaises(PermissionError):
            oidc.verify_actions_token("garbage")

    def test_claims_are_pinned_to_main_workflow(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from unittest.mock import patch
        import time

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key()
        claims = {
            "iss": oidc.ISSUER, "aud": oidc.AUDIENCE,
            "iat": int(time.time()), "exp": int(time.time()) + 300,
            "repository": oidc.REPOSITORY, "repository_id": oidc.REPOSITORY_ID,
            "ref": "refs/heads/main", "workflow_ref": oidc.WORKFLOW_REF,
            "event_name": "schedule",
        }
        token = jwt.encode(claims, private, algorithm="RS256")
        with patch.object(jwt, "PyJWKClient") as provider:
            provider.return_value.get_signing_key_from_jwt.return_value.key = public
            self.assertEqual(oidc.verify_actions_token(token)["repository"], oidc.REPOSITORY)
            claims["ref"] = "refs/pull/5/merge"
            forged = jwt.encode(claims, private, algorithm="RS256")
            with self.assertRaises(PermissionError):
                oidc.verify_actions_token(forged)


if __name__ == "__main__":
    unittest.main()
