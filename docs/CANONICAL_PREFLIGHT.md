# Canonical GitHub Bounty Preflight — 2026-11-17

**Status:** Review-only implementation on a separate branch. The command makes
bounded GET requests to the fixed GitHub REST API host. It does not authorize
testing, collect payments, apply for bounties, submit code, or message sponsors.

## Why

GitHub search results are discovery evidence, not proof that the original
issue is open, unassigned or funded. Live reviews on November 17, 2026
identified stale aggregator references and open-but-assigned work.

This preflight checks a maximum of five canonical GitHub issue URLs per
explicit invocation, returning one of:

- **hold**: the canonical source says closed, assigned, in-progress, disallowed,
  or has mismatched metadata that cannot be accepted
- **manual_review**: open, unassigned at inspection time, with no detected
  blocking signals, but funding, eligibility and submission terms unverified
- **source_unavailable**: request denied/failed; never infer an inaccessible
  issue is closed or available

No result makes external_action_allowed true. Every response includes
independent flags for funding, reward terms, testing authorization, payout
and current contribution availability; all remain unverified until further
authoritative program evidence and approval.

## Usage

Run from the repository root, with Python 3.11+:

    python3 -m unittest discover -s tests -p 'test_bounty_preflight.py' -v
    python3 bounty_preflight.py --url https://github.com/OWNER/REPOSITORY/issues/42

For bounded batches, create a private JSON array of one to five canonical
issue URLs, then run:

    python3 bounty_preflight.py --file /path/to/canonical-issues.json

No credentials or secret environment variables are necessary. A single
run causes at most five GET requests to api.github.com. It never follows
HTTP redirects, and caps each response at 350,000 bytes. The tool has no
hosting/deployment side effect, queue mutation, or submission capability.

## Manually observed examples — not payment verification

| Original issue or listing | Live inspection result on Nov. 17, 2026 | Current implication |
| --- | --- | --- |
| https://github.com/janzeerOrg/janzeer-sdk-python/issues/6 | Closed | Hold; previously surfaced in an open-search result |
| https://github.com/Spectral-Finance/lux/issues/78 | Open, labeled in-progress, assigned | Hold; not an unclaimed implementation opportunity |
| https://github.com/Spectral-Finance/lux/issues/81 | Open, no assignee shown, advertises $900 budget | Manual review only; payment and contributor terms unverified |
| https://github.com/Scottcjn/rustchain-bounties/issues/16471 | Open, audit task with 35 RTC reward advertised; hundreds of comments and documented payout-path failures | High-risk manual review; needs sponsor, scope and reward verification |
| https://github.com/Parabola-org/parabola/issues/5 | Canonical GitHub issue could not be retrieved while an aggregator mirrored its text | Source unavailable, not a verified active opportunity |

The observations above are point-in-time. An open issue may be claimed later,
a closed issue may reopen, and advertised reward figures do not prove an
escrow deposit, ability to claim, or actual payout.

## Limitations

- Does not infer real-time funding, escrow, payment policy, contributor
  registration or safe-harbor authorization from a GitHub issue
- An assigned issue is held for manual review even if contributors might
  be permitted by sponsor policy
- Title/body scanning is conservative and may mark some legitimate issues
  for manual review; absence of a warning is not a guarantee
- Does not automatically browse or test Immunefi program targets
- No persistent state, cron, or live API endpoint is added by this change
- Staging deployment remains on its existing pinned commit until a separately
  reviewed integration

**Acceptance gate:** offline tests pass on all configured Python versions,
reviewed output accurately reflects current canonical issue metadata, and no
external action permissions are added.
