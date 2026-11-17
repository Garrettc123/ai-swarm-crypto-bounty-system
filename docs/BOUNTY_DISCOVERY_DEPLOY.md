# Crypto bounty discovery — governed staging service

## Objective
Read-only candidate discovery. Not a bounty execution engine, trading bot,
wallet service, or autonomous income source.

## Source
The service queries public GitHub issue search via HTTPS GET:
- is:issue is:open label:bounty blockchain
- is:issue is:open label:bounty solidity
- is:issue is:open label:bounty crypto

The search is heuristic. An issue is a candidate, not a verified bounty
program, promised prize, security testing authorization, or payout.

## Runtime
Dockerfile: Python 3.12 standard library, unprivileged UID 10001, no
wallet secrets. PORT defaults to 8080. Queries run at startup and at a
30-minute interval. Output is in-memory and resets on restart.

GET /health and /status: service alive plus actual scan state and errors.
GET /bounties: current candidate index with source URLs, explicit unknown
reward and zero payout claims. A healthy HTTP endpoint is not evidence
the scanner reached GitHub; inspect scan_state and last_success_at.

## Hard policy boundaries
- No private keys, exchange/API trading credentials or wallet transactions.
- No automatic security scans, probing, exploitation, or third-party testing.
- No bounty submission, outreach, or reward collection.
- No payment processing or invented income tracker values.
- Do not infer program authorization from a GitHub issue label.
- Before any security research, a human must check a program's current
  scope, rules, safe-harbor terms and exclusions.
- Do not copy private bug reports or customer information into public logs.

## Verify
1. CI passes on Python 3.11, 3.12, 3.13.
2. Staging deploy builds and responds to GET /health.
3. GET /bounties returns classification=unverified_public_issue_candidates.
4. Check scan_state, last_success_at, source errors and timestamps.
5. Confirm action flags for wallet, trading, exploitation, submissions,
   payments, external messages are all false.
6. No promotion to production without separate review and authorization.

## Unimplemented
Paid marketplace integrations, authenticated bounty feeds, program legality
checks, bounty application/submission, payout verification, and persistent
database. Those must be built as independent approved phases.
