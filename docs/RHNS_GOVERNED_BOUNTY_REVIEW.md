# Garcar RHNS-governed bounty work queue

## Scope and release boundary

This PR adds a **read-only** `/work-queue?limit=15` endpoint on the existing bounty discovery service. **This endpoint is not live until this review branch is merged and deployed.**

The queue uses verified GitHub issue metadata from the existing scanner; this evidence is **not** proof of a funded, payable, or available bounty.

## Deterministic process

1. **Discover:** existing scanner reads the three fixed GitHub public issue searches.
2. **Verify source:** only records from an `ok` scan with non-stale observations, explicit metadata provenance, canonical GitHub issue URL, and no blocking/mirror signals may enter review.
3. **Propose:** stable SHA-256 work IDs and fixed research-only instructions. Untrusted issue bodies do not become agent instructions.
4. **Hold:** fail closed on stale/partial/unavailable scans, blocking terms, misleading labels, mirror listings, and low technical-review scores. Work-queue output exposes aggregate hold reasons.
5. **Research only:** one bounded task may inspect an authoritative sponsor page and prepare **private** review notes; it may not claim, message, test security targets, transact, merge or deploy.
6. **Independent evidence:** the `blockscout_evidence.py` offline gate can evaluate a pinned EVM transfer, but it cannot prove program authenticity, award acceptance, entitlement, or real payout on its own.
7. **Explicit approval:** any real external action must pass the separate authenticated RHNS approval ledger with exact target/payload binding and expiry. No approval is created, granted, or consumed by this PR.

## Connected systems: confirmed vs blocked

| System | Verified observation | Role |
|---|---|---|
| GitHub | Read/write connected; active CI matrix | source review, code testing, draft PRs |
| Railway | staging `garcar-crypto-bounty-discovery-canary` deployment SUCCESS | runs read-only scout; old deployed version has no work-queue endpoint |
| RHNS Agent Core | independent repo with queue-only verifier and SQLite approval ledger | governance reference; not a live integrated remote agent |
| Blockscout MCP | chain discovery works; tx/block/token calls returned HTTP 402 exhausted PRO credits | on-chain checks blocked; no verified payment |
| Supabase | connected accounts list zero accessible projects | durable DB not provisioned |
| Railway Automations | disabled for this user | no scheduled agent execution available through this channel |
| Linear | connected and searchable | release and verification tracking |
| Notion | shared Garcar Unified Command Center available | human-readable audit checkpoints |

## Safety and evidence limits

- No auto-claim, trading, payout, on-chain write, security exploitation, user outreach, subscription or charging.
- Review queue has no persistent job-run state, external task runner or reward-verification source.
- A high `priority_score` means *worth reviewing*; it does not mean safe, funded, profitable, permissible, or claimable.
- No model-based text instruction is executed from candidates; only fixed internal instructions are emitted.
- Work IDs and queue digest are deterministic hash identifiers, **not signed legal proof or tamper-evident database receipts**.
- No background agent automation is created.
- The Blockscout offline contract module requires authenticated data capture from an approved integration before production interpretation.

## Validation and release

CI: `python -m unittest discover -s tests -p 'test_bounty_*.py' -v` on Python 3.11/3.12/3.13. No network is required for tests.

Merge this stacked PR only after the Blockscout and eligibility PRs are approved, then deploy and separately check staging `/health`, `/ready`, `/work-queue`, source freshness, and zero externally executed actions.
