"""RHNS formal contract kernel for Garcar Bounty Intelligence (stdlib only).

Executable, bounded *local* governance primitives: typed fixed-point resource
ledger, approval binding, task lifecycle, DAG validation, evidence checks,
heuristic value-of-computation, and paired ablations.

This library never invokes an external target, signs transactions, submits a
bounty, spends funds, or grants authority on its own. Ledger instances live in
process memory; they are NOT durable, distributed, or suitable as payment rails.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import statistics
import threading
from typing import Any, Iterable, Mapping

VERSION = "rhns-governance-0.1"
READ_ACTIONS = frozenset({"read_public_source", "prepare_private_review_notes"})
EXTERNAL_ACTIONS = frozenset({
    "wallet_sign", "trade", "swap", "bridge", "submit_claim", "publish_pr",
    "send_message", "test_third_party_target", "withdraw_funds", "pay_fee",
    "merge", "deploy_production",
})


class InvariantError(ValueError):
    """A contract, resource, or authorization invariant was violated."""


def _aware(dt: datetime) -> bool:
    return isinstance(dt, datetime) and dt.tzinfo is not None and dt.utcoffset() is not None


@dataclass(frozen=True)
class ResourceVector:
    """Integer fixed-point units: tokens, tool calls, and micro-USD.

    Money is integer micro-USD to avoid floats during ledger conservation;
    conversion and settlement are outside this read-only system.
    """
    tokens: int = 0
    calls: int = 0
    money_microusd: int = 0

    def __post_init__(self) -> None:
        if any(type(v) is not int or v < 0
               for v in (self.tokens, self.calls, self.money_microusd)):
            raise InvariantError("resources must be nonnegative integer units")

    def __add__(self, other: "ResourceVector") -> "ResourceVector":
        return ResourceVector(self.tokens + other.tokens,
                              self.calls + other.calls,
                              self.money_microusd + other.money_microusd)

    def subtract(self, other: "ResourceVector") -> "ResourceVector":
        if not other.fits(self):
            raise InvariantError("insufficient free resources")
        return ResourceVector(self.tokens - other.tokens,
                              self.calls - other.calls,
                              self.money_microusd - other.money_microusd)

    def fits(self, capacity: "ResourceVector") -> bool:
        return (self.tokens <= capacity.tokens and self.calls <= capacity.calls
                and self.money_microusd <= capacity.money_microusd)

    def positive(self) -> bool:
        return any((self.tokens, self.calls, self.money_microusd))

    def as_dict(self) -> dict[str, int]:
        return {"tokens": self.tokens, "calls": self.calls,
                "money_microusd": self.money_microusd}


ZERO = ResourceVector()


@dataclass
class _Account:
    allocation: ResourceVector
    spent: ResourceVector = ZERO
    reservations: dict[str, ResourceVector] = field(default_factory=dict)
    parent: str | None = None
    children: set[str] = field(default_factory=set)


class BudgetLedger:
    """Process-local, atomically updated hierarchy. Not multi-host durable.

    alpha_i = direct_spend_i + direct_reservations_i
              + sum(alpha_direct_children) + free_i.
    Child allocation stays charged to its parent during child spending.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._accounts: dict[str, _Account] = {}

    def create_root(self, task_id: str, allocation: ResourceVector) -> None:
        with self._lock:
            self._check_new_id(task_id)
            self._accounts[task_id] = _Account(allocation)
            self.assert_invariants()

    def _check_new_id(self, task_id: str) -> None:
        if not isinstance(task_id, str) or not task_id or len(task_id) > 128:
            raise InvariantError("invalid task identifier")
        if task_id in self._accounts:
            raise InvariantError("duplicate task identifier")

    def _get(self, task_id: str) -> _Account:
        try:
            return self._accounts[task_id]
        except KeyError as exc:
            raise InvariantError("unknown task identifier") from exc

    def _free(self, task_id: str) -> ResourceVector:
        a = self._get(task_id)
        used = a.spent
        for amount in a.reservations.values():
            used = used + amount
        for child_id in a.children:
            used = used + self._get(child_id).allocation
        return a.allocation.subtract(used)

    def free(self, task_id: str) -> ResourceVector:
        with self._lock:
            return self._free(task_id)

    def allocate_child(self, parent_id: str, child_id: str,
                       allocation: ResourceVector) -> None:
        with self._lock:
            self._check_new_id(child_id)
            parent = self._get(parent_id)
            if not allocation.positive() or not allocation.fits(self._free(parent_id)):
                raise InvariantError("child allocation exceeds parent's free balance")
            self._accounts[child_id] = _Account(allocation, parent=parent_id)
            parent.children.add(child_id)
            self.assert_invariants()

    def reserve(self, task_id: str, reservation_id: str,
                amount: ResourceVector) -> ResourceVector:
        with self._lock:
            account = self._get(task_id)
            if (not isinstance(reservation_id, str) or not reservation_id
                    or len(reservation_id) > 128 or reservation_id in account.reservations):
                raise InvariantError("invalid or duplicate reservation")
            if not amount.positive() or not amount.fits(self._free(task_id)):
                raise InvariantError("reservation exceeds available resources")
            account.reservations[reservation_id] = amount
            self.assert_invariants()
            return self._free(task_id)

    def settle(self, task_id: str, reservation_id: str,
               actual: ResourceVector) -> ResourceVector:
        with self._lock:
            account = self._get(task_id)
            if reservation_id not in account.reservations:
                raise InvariantError("unknown reservation")
            reserved = account.reservations[reservation_id]
            if not actual.fits(reserved):
                raise InvariantError("actual use exceeds hard reservation cap")
            del account.reservations[reservation_id]
            account.spent = account.spent + actual
            self.assert_invariants()
            return self._free(task_id)

    def cancel(self, task_id: str, reservation_id: str) -> None:
        with self._lock:
            account = self._get(task_id)
            if reservation_id not in account.reservations:
                raise InvariantError("unknown reservation")
            del account.reservations[reservation_id]
            self.assert_invariants()

    def return_child_free(self, parent_id: str, child_id: str,
                          amount: ResourceVector) -> None:
        """Return unused child allocation; never return the child's spent funds."""
        with self._lock:
            parent = self._get(parent_id)
            child = self._get(child_id)
            if child.parent != parent_id or child_id not in parent.children:
                raise InvariantError("not an immediate child")
            if not amount.fits(self._free(child_id)):
                raise InvariantError("refund exceeds uncommitted child balance")
            child.allocation = child.allocation.subtract(amount)
            self.assert_invariants()

    def snapshot(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            a = self._get(task_id)
            reserved = ZERO
            for v in a.reservations.values():
                reserved = reserved + v
            child_total = ZERO
            for j in a.children:
                child_total = child_total + self._get(j).allocation
            return {
                "task_id": task_id, "parent_id": a.parent,
                "allocation": a.allocation.as_dict(),
                "direct_spent": a.spent.as_dict(),
                "direct_reserved": reserved.as_dict(),
                "delegated": child_total.as_dict(),
                "free": self._free(task_id).as_dict(),
                "ledger_scope": "single_process_only",
            }

    def assert_invariants(self) -> None:
        with self._lock:
            for ident, a in self._accounts.items():
                if a.parent is not None and ident not in self._get(a.parent).children:
                    raise InvariantError("orphaned parent pointer")
                for child in a.children:
                    if self._get(child).parent != ident:
                        raise InvariantError("child ownership mismatch")
                self._free(ident)  # underflow raises InvariantError
            for ident in self._accounts:
                visited: set[str] = set()
                current: str | None = ident
                while current is not None:
                    if current in visited:
                        raise InvariantError("cyclic task ownership")
                    visited.add(current)
                    current = self._get(current).parent


class Lifecycle(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Check(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not-applicable"


TRANSITIONS: Mapping[Lifecycle, frozenset[Lifecycle]] = {
    Lifecycle.PENDING: frozenset({Lifecycle.RUNNING, Lifecycle.CANCELLED}),
    Lifecycle.RUNNING: frozenset({Lifecycle.PAUSED, Lifecycle.SUCCEEDED,
                                Lifecycle.FAILED, Lifecycle.CANCELLED}),
    Lifecycle.PAUSED: frozenset({Lifecycle.RUNNING, Lifecycle.FAILED,
                               Lifecycle.CANCELLED}),
    Lifecycle.SUCCEEDED: frozenset(),
    Lifecycle.FAILED: frozenset(),
    Lifecycle.CANCELLED: frozenset(),
}


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    revision_id: str
    goal: str
    required_checks: frozenset[str]
    deadline_utc: datetime
    allocation: ResourceVector
    allowed_actions: frozenset[str]
    input_schema: Mapping[str, str] = field(default_factory=dict)
    output_schema: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id or not self.revision_id or not self.goal:
            raise InvariantError("task, revision and goal are mandatory")
        if not self.required_checks:
            raise InvariantError("approved acceptance specification cannot be empty")
        if not _aware(self.deadline_utc):
            raise InvariantError("absolute deadline requires timezone")
        if not self.allowed_actions.issubset(READ_ACTIONS):
            raise InvariantError("this service only permits research-only actions")


@dataclass
class TaskLifecycle:
    contract: TaskContract
    state: Lifecycle = Lifecycle.PENDING
    checks: dict[str, Check] = field(default_factory=dict)
    approved_spec: bool = False
    reason: str | None = None

    def accepted(self) -> bool:
        return (self.approved_spec and bool(self.contract.required_checks)
                and all(self.checks.get(k) is Check.PASS
                        for k in self.contract.required_checks))

    def transition(self, destination: Lifecycle, *, reason: str,
                   now: datetime) -> None:
        if not _aware(now) or not isinstance(destination, Lifecycle):
            raise InvariantError("invalid lifecycle time or destination")
        if destination not in TRANSITIONS[self.state]:
            raise InvariantError("illegal lifecycle transition")
        if not reason:
            raise InvariantError("transition reason required")
        if destination is Lifecycle.SUCCEEDED and not self.accepted():
            raise InvariantError("cannot mark success without all acceptance checks")
        if destination is Lifecycle.RUNNING and now > self.contract.deadline_utc:
            raise InvariantError("cannot start after deadline")
        self.state, self.reason = destination, reason


@dataclass(frozen=True)
class EvidenceClaim:
    claim_id: str
    proposition: str
    status: str
    supporting_ids: frozenset[str]
    contradicting_ids: frozenset[str]
    context: Mapping[str, str]
    verifier: str | None
    observed_at: datetime
    review_due_at: datetime | None = None

    def validate(self, evidence_ids: frozenset[str]) -> None:
        if (not self.claim_id or not self.proposition
                or self.status not in {"unverified", "supported", "contradicted",
                                       "contested", "expired"}):
            raise InvariantError("invalid claim")
        if not self.supporting_ids.issubset(evidence_ids) or not self.contradicting_ids.issubset(evidence_ids):
            raise InvariantError("claim references missing evidence")
        if not _aware(self.observed_at):
            raise InvariantError("claim observation time must be timezone-aware")
        if self.review_due_at is not None and not _aware(self.review_due_at):
            raise InvariantError("review deadline must be timezone-aware")
        # Supported is only an evidence-workflow status, not universal truth.


@dataclass(frozen=True)
class Grant:
    principal: str
    action: str
    target: str
    environment: str


@dataclass(frozen=True)
class AuthorizationPolicy:
    version: str
    grants: frozenset[Grant]

    def attenuates(self, parent: "AuthorizationPolicy") -> bool:
        return bool(self.version == parent.version and
                    self.grants.issubset(parent.grants))


@dataclass(frozen=True)
class AuthorizationContext:
    principal: str
    action: str
    target: str
    environment: str
    parameter_digest: str
    policy_version: str
    now: datetime


@dataclass(frozen=True)
class Approval:
    approval_id: str
    principal: str
    action: str
    target: str
    environment: str
    parameter_digest: str
    policy_version: str
    expires_at: datetime
    approved: bool


def authorized(policy: AuthorizationPolicy, context: AuthorizationContext,
               approval: Approval | None) -> bool:
    if not _aware(context.now):
        return False
    grant = Grant(context.principal, context.action,
                  context.target, context.environment)
    if context.policy_version != policy.version or grant not in policy.grants:
        return False
    if context.action in EXTERNAL_ACTIONS or context.action not in READ_ACTIONS:
        return False  # This service contains no external dispatcher.
    if approval is None:
        return True  # bounded public read / private draft only
    return (approval.approved
            and bool(approval.approval_id)
            and _aware(approval.expires_at)
            and context.now <= approval.expires_at
            and (approval.principal, approval.action, approval.target,
                 approval.environment, approval.parameter_digest,
                 approval.policy_version)
            == (context.principal, context.action, context.target,
                context.environment, context.parameter_digest,
                context.policy_version))


def dispatch_admissible(*, policy: AuthorizationPolicy,
                        context: AuthorizationContext, approval: Approval | None,
                        schema_ok: bool, preconditions_met: bool,
                        resources: ResourceVector,
                        free_budget: ResourceVector) -> bool:
    """Dispatch predicate only; never executes anything or reserves resources."""
    return (schema_ok is True and preconditions_met is True
            and resources.fits(free_budget)
            and authorized(policy, context, approval))


def validate_plan(task_ids: Iterable[str],
                  dependencies: Iterable[tuple[str, str]],
                  decomposition: Iterable[tuple[str, str]],
                  deadlines: Mapping[str, datetime]) -> None:
    """Validate two separate DAGs and single-owner child accounting."""
    node_list = list(task_ids)
    nodes = set(node_list)
    if (not nodes or len(nodes) != len(node_list)
            or any(not isinstance(i, str) or not i for i in node_list)):
        raise InvariantError("empty or invalid plan")
    if nodes != set(deadlines) or any(not _aware(d) for d in deadlines.values()):
        raise InvariantError("missing task deadlines")
    def dag(edges: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
        links = list(edges)
        graph: dict[str, set[str]] = {i: set() for i in nodes}
        for i, j in links:
            if i not in nodes or j not in nodes or i == j:
                raise InvariantError("invalid plan edge")
            graph[i].add(j)
        visited: set[str] = set()
        active: set[str] = set()
        def visit(n: str) -> None:
            if n in active:
                raise InvariantError("cycle detected")
            if n in visited:
                return
            active.add(n)
            for child in graph[n]:
                visit(child)
            active.remove(n)
            visited.add(n)
        for n in nodes:
            visit(n)
        return links
    dag(dependencies)
    children = dag(decomposition)
    owners: dict[str, str] = {}
    for i, j in children:
        if j in owners and owners[j] != i:
            raise InvariantError("shared child lacks unique accounting owner")
        owners[j] = i
        if deadlines[j] > deadlines[i]:
            raise InvariantError("child deadline later than parent deadline")


@dataclass(frozen=True)
class SearchNode:
    node_id: str
    parent_id: str | None
    hypothetical_state_digest: str
    depth: int
    candidate_computations: frozenset[str]

    def __post_init__(self) -> None:
        if (not self.node_id or not self.hypothetical_state_digest
                or type(self.depth) is not int or self.depth < 0
                or (self.parent_id is None and self.depth != 0)):
            raise InvariantError("invalid search node")


def heuristic_voc(*, baseline_utility: float,
                  continuation: Iterable[tuple[float, float]],
                  immediate_cost_utility: float) -> float:
    """VOC = E[continuation utility] - current utility - immediate cost.

    Probabilities and utilities are estimates, not measured probabilities
    of obtaining bounties. The continuation utility must exclude the
    computation's immediate cost; charge that cost here exactly once.
    """
    pairs = list(continuation)
    vals = [baseline_utility, immediate_cost_utility]
    vals += [x for p, x in pairs] + [p for p, x in pairs]
    if (not pairs or any(type(x) not in (float, int) or not math.isfinite(x)
                         for x in vals)
            or immediate_cost_utility < 0
            or any(p < 0 or p > 1 for p, _ in pairs)
            or not math.isclose(sum(p for p, _ in pairs), 1.0,
                                rel_tol=0.0, abs_tol=1e-9)):
        raise InvariantError("invalid heuristic VOC distribution or cost")
    return sum(p * value for p, value in pairs) - baseline_utility - immediate_cost_utility


def expansion_admissible(*, lifecycle: Lifecycle, search_depth: int,
                         depth_limit: int, authorized_computation: bool,
                         required: ResourceVector, available: ResourceVector,
                         now: datetime, deadline: datetime,
                         estimated_voc: float, margin: float = 0.0) -> bool:
    if not _aware(now) or not _aware(deadline):
        return False
    return (lifecycle is Lifecycle.RUNNING
            and type(estimated_voc) in (float, int)
            and type(margin) in (float, int)
            and type(search_depth) is int and type(depth_limit) is int
            and 0 <= search_depth < depth_limit
            and authorized_computation is True
            and required.fits(available)
            and now < deadline
            and math.isfinite(estimated_voc)
            and math.isfinite(margin) and margin >= 0
            and estimated_voc > margin)


def paired_ablation(full: Iterable[float], removed: Iterable[float]) -> dict[str, Any]:
    """Report paired score difference and uncertainty; never fabricate measurements."""
    full_scores, removed_scores = list(full), list(removed)
    if (len(full_scores) != len(removed_scores) or len(full_scores) < 2
            or any(type(z) not in (int, float) or not math.isfinite(z)
                   for z in full_scores + removed_scores)):
        raise InvariantError("paired finite observations with n>=2 required")
    differences = [a - b for a, b in zip(full_scores, removed_scores)]
    mean = statistics.mean(differences)
    sem = statistics.stdev(differences) / math.sqrt(len(differences))
    return {"n": len(differences), "paired_mean_delta": mean,
            "paired_standard_error": sem, "uncertainty_kind": "sample_standard_error",
            "significance_claim": False}


def validate_review_orders(orders: object) -> dict[str, Any]:
    """Validate public work-queue items before release from the read-only API.

    A single unsafe item invalidates the whole batch. No item is dispatched.
    """
    problems: list[str] = []
    if not isinstance(orders, list) or len(orders) > 25:
        return {"passed": False, "violations": ["invalid_order_collection"],
                "external_dispatch_enabled": False, "model": VERSION}
    ids: set[str] = set()
    for index, order in enumerate(orders):
        if not isinstance(order, dict):
            problems.append(f"order_{index}:invalid")
            continue
        ident = order.get("work_id")
        if not isinstance(ident, str) or not ident or ident in ids:
            problems.append(f"order_{index}:duplicate_or_invalid_id")
        else:
            ids.add(ident)
        permissions = order.get("allowed_actions")
        if (not isinstance(permissions, list)
                or any(not isinstance(action, str) for action in permissions)
                or not set(permissions).issubset(READ_ACTIONS)):
            problems.append(f"order_{index}:unauthorized_capability")
        if (order.get("external_execution_enabled") is not False
                or order.get("approval_required") is not True):
            problems.append(f"order_{index}:dispatch_gate_violation")
        if (order.get("payout_verified") is not False
                or order.get("reward_funding_verified") is not False):
            problems.append(f"order_{index}:unsupported_financial_claim")
        if order.get("mode") != "read_only_research":
            problems.append(f"order_{index}:invalid_mode")
    return {"passed": not problems, "violations": problems,
            "review_only": True, "external_dispatch_enabled": False,
            "evaluated_orders": len(orders), "model": VERSION}


def public_governance_status(*, scan_state: str, source_ready: bool,
                             receipts_valid: bool) -> dict[str, Any]:
    """No persistent ledger is exposed: live compliance and implementation scope."""
    return {
        "governance_version": VERSION,
        "scan_state": scan_state,
        "source_ready": source_ready,
        "volatile_receipts_valid": receipts_valid,
        "review_queue_admissible": scan_state == "ok" and source_ready and receipts_valid,
        "capabilities": {
            "typed_task_contracts": "implemented_offline",
            "process_local_atomic_resource_ledger": "implemented_offline",
            "task_lifecycle": "implemented_offline",
            "bounded_voc_scheduler": "implemented_offline_heuristic_only",
            "evidence_claim_validation": "implemented_offline",
            "exact_context_approval_matching": "implemented_offline",
            "dag_contract_checks": "implemented_offline",
            "paired_ablation_scoring": "implemented_offline",
            "work_order_governance": "enforced_at_read_only_api",
            "durable_distributed_accounting": "not_implemented",
            "real_external_agent_dispatch": "disabled",
            "calibrated_outcome_model": "not_implemented",
            "bounty_funding_verification": "unverified",
        },
        "external_execution_enabled": False,
        "wallet_actions_enabled": False,
        "security_target_testing_enabled": False,
        "automatic_submissions_enabled": False,
        "payouts_verified_by_kernel": False,
        "note": "Formal governance primitives are not evidence of actual bounty revenue.",
    }
