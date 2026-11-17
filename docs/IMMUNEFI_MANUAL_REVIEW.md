# Immunefi — manual, authorized research intake

## Evidence and legal boundary

This system does **not** connect to an Immunefi API, scrape or crawl Immunefi,
automatically download program lists, scan any external security target, open
Immunefi sessions, submit reports, pay fees or withdraw rewards.

Immunefi Terms of Use section 4 prohibits using robots and comparable automated
processes to access its Website. Immunefi Rules prohibit unauthorized mainnet
or public-testnet testing, harmful high-traffic automated testing, low-quality
automated reports without the required asset impact, and private/public
disclosure outside the mandated reporting channel.

References, reviewed 2026-11-17:
- https://immunefi.com/terms-of-use/
- https://immunefi.com/rules/
- https://immunefi.com/common-vulnerabilities-to-exclude/
- https://immunefi.com/bug-bounty/

## Operator workflow

1. Open the official website in a normal user session and choose a program.
2. Independently confirm the program remains active, the exact in-scope assets
   and eligible impacts, exclusions, safe-harbor/research restrictions, PoC
   requirements, reward and fee rules, KYC, and responsible-disclosure terms.
3. If useful, create a **private local JSON metadata checklist** (no findings,
   credentials or customer data) with only:
   `program_url`, `scope_url`, `reviewed_at` (UTC ISO-8601),
   `source_mode` = `operator_manual`, and `checks`.
   The `checks` keys are the ones in `immunefi_review.REQUIRED_CHECKS`;
   each must be boolean `true` to record completion.
4. Validate locally: `python immunefi_review.py /path/to/private-review.json`.
   Use private storage outside Git and remove confidential content before
   moving anything into a public repo.
5. A passing checklist means only that a human claims they reviewed the terms.
   It **never verifies Immunefi's current program data or grants permission to
   test**, never proves reward funding or payout, and never changes the
   security-testing/submission controls from disabled.
6. Any actual permitted research should be confined to owned local code and
   isolated fork/test environments according to each program's rules.
   Do not test deployed mainnet/public testnet targets unless explicit rules
   and authorization permit it; no automated submissions are performed.
7. Report only genuine, reproducible, in-scope impacts through the approved
   official Immunefi reporting channel, with separately obtained approval.

## Public dashboard

The staging route `GET /immunefi-policy` returns safe static policy metadata
and official references. It **does not** return operator checklists or findings.
The web UI offers links to the official program directory and policies only.

## Operational status

- Automated Immunefi website collection: disabled
- Authorized authenticated Immunefi API: not connected
- Imported Immunefi programs: zero
- Security testing and report submissions: disabled
- Confirmed payouts: unverified
- Blockscout live on-chain verification: separate connector; previously
  blocked by exhausted PRO API credits, subject to a fresh check
