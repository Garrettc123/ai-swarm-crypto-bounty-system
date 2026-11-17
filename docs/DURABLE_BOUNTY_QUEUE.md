# Durable bounty review queue — staging runbook

## Scope

Metadata-only work queue, not a bounty executor or payment processor. The
Railway scout discovers public GitHub issues. GitHub Actions separately
discovers GitHub issues and Immunefi listings. Both are normalized to
canonical URLs and stored in the existing project Redis service.

This queue never tests third-party targets, claims bounties, sends messages,
submits pull requests, signs transactions, processes payments, or credits earnings.

## Storage

- BOUNTY_QUEUE_REDIS_URL must reference the staging Redis service using
  the Railway reference variable syntax (Redis.REDIS_URL).
- Redis has an existing /data volume and periodic RDB snapshots were observed.
- RDB provides restart persistence, not zero-loss transactions or multi-region DR.
- Source ingestion preserves manual workflow fields, and an append-only Redis
  event stream records observation batches and operator state changes.
- GET /queue-status reports queue health; missing Redis config returns 503.

## Two feeds

1. The Railway scanner imports a fresh, fully successful GitHub scout scan after
   each interval. Stale or failed scans are not imported as fresh.
2. GitHub Actions submits its complete public scanner JSON to /internal/ingest
   using GitHub Actions OIDC. Signature verification pins the repository ID,
   exact main-branch workflow, GitHub issuer, and dedicated audience.
   This route is enabled only when the main-branch scan workflow is updated,
   and pull-request runs cannot write.

Imports are size bounded and allow only exact GitHub issue or Immunefi program
URLs. Listings cannot change a review assignment or fabricate revenue.

## Operator state machine

New items are unreviewed. A trusted operator can assign and mark researching.
Submission/acceptance/payout states are **reported** only, with matching SHA-256
evidence references. They do not imply third-party acceptance or settlement.

From a trusted environment configured with the Redis URL:

- python queue_admin.py status
- python queue_admin.py list --limit 30
- python queue_admin.py assign --item-id ID --operator OP --assignee PERSON
- python queue_admin.py evidence --item-id ID --operator OP --kind submission
  --reference https://github.com/ORG/REPO/pull/NUMBER --sha256 HEX_DIGEST
- python queue_admin.py record-state --item-id ID --operator OP
  --state submission_reported --evidence-id ID

Do not include private findings, secrets, or exploit contents. Only record
reference URLs and hashes. The admin CLI is not exposed over HTTP.

## Limits

- Verified earnings remain zero in this disconnected software view; no external
  payment reconciliation has been performed.
- No exploitation, payout claims, automatic submissions, or outbound actions.
- Existing GitHub/Immunefi listings are observations, not proof of funding,
  eligibility, authorization, or award.
