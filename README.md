# Garcar Enterprise — Crypto Bounty Intelligence

**Current implementation:** read-only bounty discovery and technical qualification.
**Release:** staging canary on a review branch, not a production income system.

## Implemented

The Python standard-library service queries the public GitHub Search API for
open issue candidates associated with blockchain, Solidity, and crypto bounty
labels. It does not assume a GitHub issue is an active funded bounty.

Implemented controls:
- Stable candidate IDs, deduplication, keyword and skill classification.
- Explainable review-priority scores, not estimated payment probabilities.
- Per-source-query status, failure handling, stale-data retention, and readiness.
- In-memory SHA-256 hash-linked scan receipts, with integrity checks.
- Read-only responsive operator dashboard and HTTP APIs.
- Non-root Docker image without trading, wallet or payout credentials.

## Staging location

Railway project: garcar-review-staging
Service: garcar-crypto-bounty-discovery-canary
Git branch: feat/read-only-crypto-bounty-discovery-20261117

Staging dashboard:
https://garcar-crypto-bounty-discovery-canary-staging.up.railway.app/

This URL is a staging endpoint, not a production availability guarantee.
The deployment and external source state must be checked independently.

## API surface

- / — operator review dashboard
- /health and /status — process and scan state
- /ready — returns 503 without a fresh successful scan
- /bounties?limit=25&min_score=50&skill=python — ranked candidates
- /sources — per-query success/failure evidence
- /digest — changes observed between scans
- /receipts — volatile hash-linked scan receipts

Run local tests with:
    python3 -m unittest discover -s tests -p 'test_bounty_*.py' -v

Run locally with:
    PORT=8080 python3 bounty_discovery_service.py

The Dockerfile installs no third-party Python libraries. The broad
requirements.txt file belongs to legacy prototype modules and is not
required for the read-only canary.

## Business and security boundaries

This system does NOT automatically test security targets, trade cryptocurrency,
control wallets, submit bounty work, send outreach, or process payment.
Payouts, rewards, sponsor identity, security testing rights, and eligibility
are all unverified until confirmed from the authoritative program and
human-approved scope. A score is a review signal, never an earnings claim.

The older crypto/bounty_hunter.py and core/swarm_coordinator.py modules
contain simulated completion and payment routines and are NOT imported by
this live canary. They must not be presented as real earnings functionality.

The current GitHub Search API has rate limits and may return incomplete
results. The canary makes only three read-only queries every thirty minutes:
https://docs.github.com/en/rest/search/search

Do not add unauthorized automated Immunefi catalog collection. Its Terms of
Use restrict robots and automated website access, even though a public
program catalog is discoverable. Obtain explicit authorization first:
https://immunefi.com/terms-of-use/

Before any security research, a human must verify permitted targets,
program exclusions, required local testing and responsible disclosure rules.
A public issue label alone gives no right to probe or exploit any target.

## Evidence limits and planned releases

The scan receipt chain is stored only in process memory. It is not durable,
cryptographically signed, externally anchored or a proof of sponsor payment.
The dashboard may display stale observations when GitHub search fails.
The system does not prove a live bounty was funded, won, or paid.

Production promotion, additional authorized sources, persistent evidence
storage, legitimate bounty submission automation, and external payment
reconciliation require separate review and explicit authorization.

For release review use the draft pull request associated with this branch.
