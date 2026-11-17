"""RHNS formal governance contract/property/concurrency tests.

All observations are local deterministic fixtures. They do not represent
real-world bounty payments, approval grants or executed security research.
"""
import concurrent.futures
from datetime import datetime, timedelta, timezone
import random
import threading
import unittest

from rhns_governance import (
    Approval, AuthorizationContext, AuthorizationPolicy, BudgetLedger,
    Check, EvidenceClaim, Grant, InvariantError, Lifecycle, ResourceVector,
    SearchNode, TaskContract, TaskLifecycle, authorized, dispatch_admissible,
    expansion_admissible, heuristic_voc, paired_ablation,
    public_governance_status, validate_plan, validate_review_orders,
)

NOW = datetime(2026, 11, 17, 18, 0, tzinfo=timezone.utc)
D = NOW + timedelta(hours=1)
R = lambda t=0, c=0, m=0: ResourceVector(t, c, m)


def contract(**kw):
    obj = dict(task_id="task-1", revision_id="rev-a", goal="Document a reviewed source",
               required_checks=frozenset({"source", "acceptance"}), deadline_utc=D,
               allocation=R(100, 10, 10000),
               allowed_actions=frozenset({"read_public_source"}))
    obj.update(kw)
    return TaskContract(**obj)


class TestLedger(unittest.TestCase):
    def test_integer_fixed_point_units_and_reject_bools(self):
        for value in (-1, 0.1, True, "2", None):
            with self.subTest(value=value), self.assertRaises(InvariantError):
                ResourceVector(tokens=value)

    def test_root_conservation(self):
        l = BudgetLedger()
        l.create_root("parent", R(100, 20, 5000))
        l.reserve("parent", "r1", R(50, 3, 1000))
        l.settle("parent", "r1", R(40, 2, 900))
        s = l.snapshot("parent")
        self.assertEqual(s["free"], R(60, 18, 4100).as_dict())
        self.assertEqual(s["direct_spent"], R(40, 2, 900).as_dict())
        l.assert_invariants()

    def test_delegation_not_double_counted(self):
        l = BudgetLedger()
        l.create_root("p", R(100, 20, 10000))
        l.allocate_child("p", "c", R(50, 10, 3000))
        l.reserve("c", "own", R(20, 2, 1000))
        l.settle("c", "own", R(15, 1, 700))
        self.assertEqual(l.free("p"), R(50, 10, 7000))
        self.assertEqual(l.free("c"), R(35, 9, 2300))
        l.return_child_free("p", "c", R(20, 3, 1000))
        self.assertEqual(l.free("p"), R(70, 13, 8000))
        self.assertEqual(l.snapshot("c")["direct_spent"], R(15, 1, 700).as_dict())
        l.assert_invariants()

    def test_cannot_spend_over_reserved_cap(self):
        l = BudgetLedger()
        l.create_root("p", R(10, 4, 100))
        l.reserve("p", "r", R(6, 2, 40))
        with self.assertRaises(InvariantError):
            l.settle("p", "r", R(7, 2, 40))
        self.assertEqual(l.snapshot("p")["direct_reserved"], R(6, 2, 40).as_dict())

    def test_reservation_idempotency_and_refund(self):
        l = BudgetLedger()
        l.create_root("p", R(10, 4, 100))
        l.reserve("p", "idempotency-key", R(3, 1, 30))
        with self.assertRaises(InvariantError):
            l.reserve("p", "idempotency-key", R(3, 1, 30))
        l.cancel("p", "idempotency-key")
        self.assertEqual(l.free("p"), R(10, 4, 100))
        with self.assertRaises(InvariantError):
            l.cancel("p", "idempotency-key")

    def test_no_double_allocation_and_no_spent_refunds(self):
        l = BudgetLedger()
        l.create_root("p", R(10, 2, 0))
        l.allocate_child("p", "c", R(8, 1, 0))
        with self.assertRaises(InvariantError):
            l.allocate_child("p", "c2", R(3, 0, 0))
        l.reserve("c", "r", R(8, 1, 0))
        l.settle("c", "r", R(8, 1, 0))
        with self.assertRaises(InvariantError):
            l.return_child_free("p", "c", R(1, 0, 0))

    def test_concurrent_reservations_never_oversubscribe(self):
        ledger = BudgetLedger()
        ledger.create_root("root", R(1000, 100, 0))
        workers = 60
        barrier = threading.Barrier(workers)

        def attempt(index):
            barrier.wait()
            try:
                ledger.reserve("root", f"task-{index}", R(30, 3, 0))
                return True
            except InvariantError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(attempt, range(workers)))
        self.assertEqual(sum(results), 33)  # max calls = floor(100/3)
        self.assertEqual(ledger.free("root").calls, 1)
        ledger.assert_invariants()

    def test_seeded_property_conservation_across_mixed_operations(self):
        randomizer = random.Random(31117)
        ledger = BudgetLedger()
        ledger.create_root("p", R(100000, 10000, 1000000))
        ledger.allocate_child("p", "c", R(40000, 4000, 400000))
        for index in range(250):
            task_id = randomizer.choice(["p", "c"])
            free = ledger.free(task_id)
            request = R(randomizer.randint(0, min(100, free.tokens)),
                        randomizer.randint(0, min(20, free.calls)),
                        randomizer.randint(0, min(500, free.money_microusd)))
            if request.positive():
                key = f"{task_id}-{index}"
                ledger.reserve(task_id, key, request)
                if index % 4 == 0:
                    ledger.cancel(task_id, key)
                else:
                    ledger.settle(task_id, key, R(request.tokens // 2,
                                                 request.calls // 2,
                                                 request.money_microusd // 2))
            ledger.assert_invariants()

    def test_duplicate_and_unknown_accounts_rejected(self):
        l = BudgetLedger()
        l.create_root("p", R(1, 1, 1))
        with self.assertRaises(InvariantError):
            l.create_root("p", R(1, 1, 1))
        with self.assertRaises(InvariantError):
            l.free("missing")


class TestLifecycleAndClaims(unittest.TestCase):
    def test_no_success_without_approved_nonempty_spec_and_passes(self):
        life = TaskLifecycle(contract())
        life.transition(Lifecycle.RUNNING, reason="ready", now=NOW)
        with self.assertRaises(InvariantError):
            life.transition(Lifecycle.SUCCEEDED, reason="agent returned success", now=NOW)
        life.approved_spec = True
        life.checks["source"] = Check.PASS
        life.checks["acceptance"] = Check.UNKNOWN
        with self.assertRaises(InvariantError):
            life.transition(Lifecycle.SUCCEEDED, reason="unknown not pass", now=NOW)
        life.checks["acceptance"] = Check.PASS
        life.transition(Lifecycle.SUCCEEDED, reason="all checks passed", now=NOW)
        self.assertEqual(life.state, Lifecycle.SUCCEEDED)

    def test_terminal_state_cannot_resume(self):
        life = TaskLifecycle(contract())
        life.transition(Lifecycle.CANCELLED, reason="operator canceled", now=NOW)
        with self.assertRaises(InvariantError):
            life.transition(Lifecycle.RUNNING, reason="not allowed", now=NOW)

    def test_pause_resume_and_deadline(self):
        life = TaskLifecycle(contract())
        life.transition(Lifecycle.RUNNING, reason="began", now=NOW)
        life.transition(Lifecycle.PAUSED, reason="approval needed", now=NOW)
        life.transition(Lifecycle.RUNNING, reason="approved", now=NOW)
        life.transition(Lifecycle.PAUSED, reason="clock expired", now=NOW)
        with self.assertRaises(InvariantError):
            life.transition(Lifecycle.RUNNING, reason="too late", now=D+timedelta(seconds=1))

    def test_bad_contracts_rejected(self):
        for invalid in (dict(required_checks=frozenset()),
                        dict(allowed_actions=frozenset({"wallet_sign"})),
                        dict(deadline_utc=datetime(2026, 11, 17))):
            with self.subTest(invalid=invalid), self.assertRaises(InvariantError):
                contract(**invalid)

    def test_evidence_ids_validated_and_status_is_not_truth(self):
        claim = EvidenceClaim("claim-1", "A payout occurred", "supported",
                              frozenset({"e1"}), frozenset(), {"chain": "8453"},
                              "blockscout:v2", NOW, None)
        claim.validate(frozenset({"e1"}))
        with self.assertRaises(InvariantError):
            claim.validate(frozenset())
        self.assertEqual(claim.status, "supported")

    def test_claim_review_clock_must_be_typed(self):
        claim = EvidenceClaim("c", "p", "unverified",
                              frozenset(), frozenset(), {}, None,
                              NOW, datetime(2026, 11, 17))
        with self.assertRaises(InvariantError):
            claim.validate(frozenset())


class TestAuthorization(unittest.TestCase):
    def setUp(self):
        self.grant = Grant("agent-a", "read_public_source",
                           "https://github.com/example/repo/issues/1", "staging")
        self.policy = AuthorizationPolicy("v1", frozenset({self.grant}))
        self.context = AuthorizationContext(
            "agent-a", "read_public_source", self.grant.target, "staging",
            "sha256:abc", "v1", NOW)
        self.approval = Approval(
            "approval-1", "agent-a", "read_public_source", self.grant.target,
            "staging", "sha256:abc", "v1", D, True)

    def test_exact_approval_context(self):
        self.assertTrue(authorized(self.policy, self.context, self.approval))
        self.assertTrue(dispatch_admissible(
            policy=self.policy, context=self.context, approval=self.approval,
            schema_ok=True, preconditions_met=True,
            resources=R(1, 1, 0), free_budget=R(2, 1, 0)))

    def test_reject_expired_approval(self):
        ctx = AuthorizationContext("agent-a", "read_public_source",
                                   self.grant.target, "staging", "sha256:abc", "v1", D+timedelta(seconds=1))
        self.assertFalse(authorized(self.policy, ctx, self.approval))

    def test_reject_replayed_approval_on_different_params(self):
        ctx = AuthorizationContext("agent-a", "read_public_source",
                                   self.grant.target, "staging", "sha256:tampered", "v1", NOW)
        self.assertFalse(authorized(self.policy, ctx, self.approval))

    def test_reject_wrong_environment_target_or_policy_version(self):
        for ctx in (
            AuthorizationContext("agent-a", "read_public_source",
                                 self.grant.target, "production", "sha256:abc", "v1", NOW),
            AuthorizationContext("agent-a", "read_public_source",
                                 "https://github.com/other", "staging", "sha256:abc", "v1", NOW),
            AuthorizationContext("agent-a", "read_public_source",
                                 self.grant.target, "staging", "sha256:abc", "v2", NOW),
        ):
            with self.subTest(ctx=ctx):
                self.assertFalse(authorized(self.policy, ctx, self.approval))

    def test_external_mutation_denied_even_with_grant(self):
        permission = Grant("agent-a", "wallet_sign", "0xabc", "staging")
        policy = AuthorizationPolicy("v1", frozenset({permission}))
        ctx = AuthorizationContext("agent-a", "wallet_sign", "0xabc", "staging",
                                   "sha256:signed", "v1", NOW)
        self.assertFalse(authorized(policy, ctx, None))

    def test_child_policy_no_escalation(self):
        parent = AuthorizationPolicy("v1", frozenset({self.grant}))
        child = AuthorizationPolicy("v1", frozenset())
        self.assertTrue(child.attenuates(parent))
        self.assertFalse(AuthorizationPolicy("v1", frozenset({
            self.grant, Grant("a", "trade", "market", "live")
        })).attenuates(parent))

    def test_budget_gate_denies_read_dispatch(self):
        self.assertFalse(dispatch_admissible(
            policy=self.policy, context=self.context, approval=self.approval,
            schema_ok=True, preconditions_met=True,
            resources=R(2, 2, 0), free_budget=R(1, 2, 0)))


class TestGraphAndVOC(unittest.TestCase):
    def test_separate_acyclic_precedence_and_decomposition(self):
        validate_plan({"a", "b", "c"}, {("a", "b"), ("b", "c")},
                      {("a", "b"), ("a", "c")}, {"a": D, "b": D, "c": D})

    def test_reject_dependency_cycle(self):
        with self.assertRaises(InvariantError):
            validate_plan({"a", "b"}, {("a", "b"), ("b", "a")},
                          set(), {"a": D, "b": D})

    def test_reject_shared_child(self):
        with self.assertRaises(InvariantError):
            validate_plan({"a", "b", "c"}, set(), {("a", "c"), ("b", "c")},
                          {"a": D, "b": D, "c": D})

    def test_reject_child_deadline_after_parent(self):
        with self.assertRaises(InvariantError):
            validate_plan({"a", "b"}, set(), {("a", "b")},
                          {"a": D, "b": D + timedelta(hours=1)})

    def test_search_root_and_child_depth(self):
        SearchNode("root", None, "digest", 0, frozenset({"retrieve"}))
        SearchNode("child", "root", "other", 1, frozenset({"validate"}))
        with self.assertRaises(InvariantError):
            SearchNode("bad", None, "digest", 1, frozenset())

    def test_voc_cost_charged_once(self):
        self.assertAlmostEqual(heuristic_voc(
            baseline_utility=10, continuation=[(0.25, 10), (0.75, 20)],
            immediate_cost_utility=2), 5.5)

    def test_voc_reject_malformed_probs(self):
        with self.assertRaises(InvariantError):
            heuristic_voc(baseline_utility=0, continuation=[(0.8, 3)],
                          immediate_cost_utility=1)

    def test_search_expansion_requires_permissions_time_budget_margin(self):
        base = dict(lifecycle=Lifecycle.RUNNING, search_depth=1, depth_limit=3,
                    authorized_computation=True, required=R(2, 1, 0),
                    available=R(10, 10, 0), now=NOW, deadline=D,
                    estimated_voc=1.5, margin=0.1)
        self.assertTrue(expansion_admissible(**base))
        for change in (dict(lifecycle=Lifecycle.PAUSED), dict(search_depth=3),
                       dict(authorized_computation=False),
                       dict(available=R(1, 1, 0)), dict(now=D),
                       dict(estimated_voc=0.1)):
            with self.subTest(change=change):
                self.assertFalse(expansion_admissible(**{**base, **change}))

    def test_paired_ablation_uses_only_given_data(self):
        stats = paired_ablation([1, 2, 3], [0, 1, 2])
        self.assertEqual(stats["n"], 3)
        self.assertEqual(stats["paired_mean_delta"], 1)
        self.assertEqual(stats["paired_standard_error"], 0)
        self.assertFalse(stats["significance_claim"])

    def test_insufficient_ablation_sample_fails(self):
        with self.assertRaises(InvariantError):
            paired_ablation([1], [2])


class TestWorkQueueGate(unittest.TestCase):
    def valid_order(self):
        return {
            "work_id": "work-1",
            "allowed_actions": ["read_public_source", "prepare_private_review_notes"],
            "approval_required": True, "external_execution_enabled": False,
            "payout_verified": False, "reward_funding_verified": False,
            "mode": "read_only_research",
        }

    def test_valid_read_only_order(self):
        result = validate_review_orders([self.valid_order()])
        self.assertTrue(result["passed"])
        self.assertFalse(result["external_dispatch_enabled"])

    def test_injected_execution_capability_blocks_whole_batch(self):
        good = self.valid_order()
        bad = dict(good, work_id="work-2",
                   allowed_actions=["read_public_source", "wallet_sign"])
        result = validate_review_orders([good, bad])
        self.assertFalse(result["passed"])
        self.assertIn("order_1:unauthorized_capability", result["violations"])

    def test_fabricated_financial_flag_blocks_batch(self):
        result = validate_review_orders([
            {**self.valid_order(), "payout_verified": True}
        ])
        self.assertFalse(result["passed"])

    def test_duplicate_id_and_oversized_collection(self):
        self.assertFalse(validate_review_orders([
            self.valid_order(), self.valid_order()])["passed"])
        self.assertFalse(validate_review_orders([self.valid_order()] * 26)["passed"])

    def test_malformed_permission_list_fails_closed(self):
        order = {**self.valid_order(), "allowed_actions": [{"action": "wallet_sign"}]}
        result = validate_review_orders([order])
        self.assertFalse(result["passed"])
        self.assertIn("order_0:unauthorized_capability", result["violations"])

    def test_duplicate_task_ids_rejected_by_plan(self):
        with self.assertRaises(InvariantError):
            validate_plan(["a", "a"], [], [], {"a": D})

    def test_public_governance_never_claims_external_dispatch(self):
        state = public_governance_status(scan_state="ok", source_ready=True,
                                         receipts_valid=True)
        self.assertTrue(state["review_queue_admissible"])
        self.assertFalse(state["external_execution_enabled"])
        self.assertEqual(state["capabilities"]["durable_distributed_accounting"],
                         "not_implemented")


if __name__ == "__main__":
    unittest.main()
