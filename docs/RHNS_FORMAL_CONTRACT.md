# RHNS Formal Governance v0.1 — Executable Contract

**Release scope:** Garcar Enterprise crypto-bounty read-only research canary.

This implementation formalizes specified invariants. It does not establish improved model performance, verified paid bounties, production authorization, or live external-agent execution.

## Variable assignments

| Symbol | Runtime concept |
|---|---|
| t | Control-cycle index |
| i, j | Task identifiers |
| n | Hypothetical search node |
| rho_i | TaskContract.revision_id; fixed goal per revision |
| G_i | TaskContract.goal |
| E_i | EvidenceClaim references; durable store not implemented |
| H_i, beta_i | Hypotheses and beliefs; not implemented, never treated as evidence |
| P_i | Separate precedence and decomposition DAGs |
| X_i | Execution receipts; durable storage not implemented |
| B_i | BudgetLedger.free(i) uncommitted budget |
| Pi_i | AuthorizationPolicy and exact context binding |
| ell_i | TaskLifecycle state |
| theta | Experimental architecture configuration, not a deployed optimizer |
| q | Proposed computation; not an external action |
| a | Proposed external action; disabled in this canary |
| omega | Run randomness in genuine paired evaluations |

## 1. Budget and accounting invariant

For task i, resource r and time t:

  alpha[i,r,t] = spent[i,r,t] + reserved[i,r,t]
                  + SUM(childAllocation[j,r,t]) + free[i,r,t].

ResourceVector uses integer token counts, integer call counts and integer
micro-USD fixed-point quantities. Child allocations remain charged to the
parent during child consumption. Only unused allocation can be refunded.

An RLock makes the ledger atomic between threads in ONE Python process.
It is not a multi-process, multi-host, ACID, or financially authoritative
ledger. The kernel never spends any of its accounting balances.

## 2. Lifecycle and acceptance

A contract has a fixed task ID, revision ID, goal, nonempty mandatory checks,
absolute timezone-aware deadline, permitted read-only operations and resource
allocation. TaskLifecycle accepts terminal success only if the specification
is approved and all mandatory checks pass. Unknown, missing, or not-applicable
checks do not count as pass.

Pending -> running -> paused/failed/cancelled/succeeded and
paused -> running/failed/cancelled are explicit legal transitions.
Terminal states cannot restart. Resume after deadline is forbidden.

## 3. Claims and verification

EvidenceClaim uses a stable claim ID, proposition, workflow status,
supporting/contradicting evidence ID sets, context, verification method,
observation time and optional review deadline. Evidence references must
exist in the supplied evidence store. A 'supported' workflow status is not
a proof of universal truth, accepted bounty work, or a payment.

## 4. Plans, uncertainty and value of computation

Precedence and decomposition graphs are checked independently for cycles.
Each child has one accounting owner and a deadline no later than its parent.
Retries are separate execution instances, not backward DAG edges.
Search nodes represent hypothetical, not live, execution states.

Estimated VOC = weighted expected continuation utility
                - baseline continuation utility
                - immediate computation cost.

The immediate cost must be charged only once. The supplied outcome
distribution is heuristic and not empirically calibrated.
Expansion requires an active lifecycle, depth bound, approved computation,
available budget, deadline, and VOC above a configured margin.

## 5. Exact context authorization

Policy grants bind principal, operation, target, environment, and version.
Approval records can additionally bind parameter digest, expiration and
approval identity. Child grants are a subset of parent grants.

Even if a forged approval record is provided, all wallet signing, trading,
claims, fees, messages, external security tests, merges and production
deployments are denied by the read-only policy. There is NO execution
dispatcher connected to this kernel.

## 6. Live staging integration

GET /governance reports the deployed governance version, source readiness,
volatile receipt integrity and conservative capability statuses.
GET /work-queue checks fresh readiness, receipt integrity, and every returned
work order against the read-only policy. Failure returns HTTP 503 with no
actionable work orders.

The queue endpoint does not dispatch research agents. No Immunefi automation,
external target testing, transaction signing or reward collection is enabled.

## 7. Validation and evaluation

The test suite covers input contracts, lifecycle transitions, authorization
replay, deadline and budget controls, cyclic DAGs, seeded accounting
invariants, and concurrent reservation attempts. These tests are LOCAL
fixtures and do not prove distributed crash recovery.

Paired ablations require actual externally supplied per-task observations;
the helper reports paired mean delta and standard error but does not
fabricate measurements or assert statistical significance.

Release gate: GitHub Actions on Python 3.11, 3.12, 3.13, browser JavaScript
syntax, Docker build and imports, HTTP route tests, staging-only deployment
pinned to a reviewed commit, live scan and endpoint validation.

### Unimplemented for production

- Durable atomic ledger and crash recovery
- Authenticated persistent approvals and real external dispatch
- Calibrated predictive distributions
- Persistent and independently anchored evidence receipts
- Measured ROI, paid bounties, or verified payout reconciliation

All revenue and financial outcomes remain unverified until supported by
independent settlement and acceptance evidence.
