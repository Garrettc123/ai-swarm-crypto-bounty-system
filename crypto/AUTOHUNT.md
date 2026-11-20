# ZEUS AutoHunt — autonomous research triage (v1)

ZEUS AutoHunt is a **passive, scope-aware research assistant**, not an autonomous exploit system. It uses the existing Garcar public bounty scanner and the authenticated five-file Base Everest source inspection to prioritize what a researcher should investigate next. It does not determine that a vulnerability exists.

## Routine

The existing [Public Crypto Bounty Scan](../.github/workflows/bounty-scan.yml) is scheduled daily at **14:17 UTC** and also supports manual `workflow_dispatch`. The single workflow now performs:

1. Validate the pinned Base Everest competition asset registry, times and scope boundaries.
2. Fetch and authenticate five competition source files at the immutable `base/base` SHA and generate ZEUS source evidence.
3. Discover public Immunefi bounty listings and GitHub issues, then normalize them through the existing strict triage parser.
4. Run [AutoHunt](autohunt.py), validating the policy, all five immutable Git blobs, the source-review digest and the completeness of the discovery export.
5. Assign **review-order scores only** from known research topics and observed source keyword coverage. Sort up to five **research questions** without claiming exploitability, severity, eligibility or reward value.
6. Archive the JSON queue, Markdown report and an **unsigned SHA-256 integrity receipt** in GitHub Actions artifacts with 14-day retention. The workflow's Step Summary distinguishes research questions from security findings.

A missing or tampered source record, incorrect pinned hash, partial/malformed discovery export, nonstandard scope, altered guard policy or purported proof/payout causes the AutoHunt step to fail. Any such failure blocks the downstream guarded staging sync in that run.

Once the competition closes on **December 1, 2026 at 12:00 UTC**, the queue becomes empty. Discovery of other public listings continues independently; those are never automatically authorized as targets.

## Run locally

```bash
python3 -m unittest discover -s tests -p 'test_autohunt.py' -v
python3 zeus.py run-once --intent "Base Everest bounty hunt organ" \
  --estimated-value-usd 250000 \
  --output artifacts/base-everest-source-review.json
python3 crypto/autohunt.py \
  --source-review artifacts/base-everest-source-review.json \
  --output-dir artifacts
```

The optional `--discovery artifacts/latest-bounties.json` flag joins the previously generated real public-source scan. It validates exact row coverage and rejects duplicates. Running `autohunt.py` never makes outbound HTTP requests.

## Human review and privilege boundary

Every queued item is a **hypothesis for code review**, not a confirmed issue. Human/manual gates remain mandatory: current in-scope definitions and known issues, eligibility and duplicates, authorized local testing, an independently runnable PoC, and private report review. These controls follow the [official Immunefi rules](https://immunefi.com/rules/) and the [Base Everest competition scope](https://immunefi.com/audit-competition/audit-comp-base-everest/scope/).

No public-network probing, fuzzing of live endpoints, browser interactions with third-party target systems, exploit execution, vulnerability reports, private evidence disclosure, billable provisioning, wallet actions or payout accounting are performed. The existing private, manually dispatched [ZEUS host readiness PR](https://github.com/Garrettc123/garcar-private-control-os/pull/2) remains separate from public CI; it does not start the Everest devnet.

The value of AutoHunt is an **auditable, repeatable pipeline** from listing discovery to source-backed research prioritization. Its success is measured by verified review coverage and reproducible PoCs, not number of speculative "bugs."
