# ZEUS Rust Oracle — executable pinned-source validation

**Status:** a bounded Rust unit-test lane for the Base Everest audit competition, separate from the GitHub/Railway discovery and staging systems.

## What runs

This module compiles the **original, unchanged** pinned competition file:

- Repository: `immunefi-team/audit-comp-base-everest-base`
- Commit: `689054ee14933cb2ee5bd54eadcd8dacbe1cc517`
- File: `crates/consensus/protocol/src/batch/validity.rs`
- Git blob SHA-1: `dbc88782419cb9ee46ea29cfe2e18873352fd494`

It first verifies a **complete ZEUS five-file source review**, including the aggregate review SHA-256. It retrieves that exact additional original file, verifies its Git blob and SHA-256 again, then writes an isolated temporary directory.

The test harness compiles the immutable source **as a Rust module by reference** using `rustc --test`; it does not copy or modify its code to add tests. The separate wrapper contains two **ZEUS-authored** invariants for batch classification and Everest-specific drop-reason labeling.

| Origin | Number of tests |
|---|---:|
| Original competition Rust module (`#[test]`) | 3 |
| Additional ZEUS-authored, labeled invariant checks | 2 |
| Total expected and validated | 5 |

The runner checks the **exact five expected test names**, successful process exit, and the Rust test summary. Every deviation blocks the job. It records SHA-256 digests for the original source, wrapper, compiled binary, stdout and the overall **unsigned** JSON metadata receipt, along with the compiler version.

## Execution environment and safety

[ZEUS Rust Oracle workflow](../.github/workflows/rust-oracle.yml) executes on an **ephemeral GitHub-hosted Ubuntu** runner, with `contents: read`, checkout credentials disabled and only a minimal environment forwarded into compilation and test execution. It performs no paid VM creation, wallet operations, report submissions or target network probes. The runner can reach the network; operating-system egress isolation is **not** established or claimed. A source fetch to exact pinned public GitHub files precedes the unit tests.

The workflow runs at **14:43 UTC November 20–30**, and **10:43 UTC December 1** (during the 2026 competition window); it also supports relevant changes to main or manual dispatch. In later years the limited calendar cron may trigger a skipped run, but the code refuses testing outside the 2026 competition window. AutoHunt's public listing scanner continues daily at 14:17 UTC.

Competition end: **2026-12-01 12:00 UTC**. The oracle refuses to execute source tests outside its competition window, and records a skip instead.

## Run the original tests yourself

From the existing bounty repository on an approved Linux machine with Python 3 and `rustc`:

```bash
python3 -m unittest discover -s tests -p 'test_rust_oracle.py' -v

python3 zeus.py run-once \
  --intent "Base Everest bounty hunt organ" \
  --estimated-value-usd 250000 \
  --output artifacts/base-everest-source-review.json

python3 crypto/rust_oracle.py \
  --source-review artifacts/base-everest-source-review.json \
  --output artifacts/rust-oracle.json
```

`artifacts/rust-oracle.json` is an **evidence-backed execution receipt**, not a signature, proof hash, issue report or vulnerability.

## What this does not validate

It does **not** compile the full Everest workspace, test any other Rust modules, measure code coverage, launch a Production-config local devnet, prove network exploitability, establish economic severity, or create a valid bounty report. The original upstream unit tests may be insufficient to detect defects even if all pass. The full local devnet and private host readiness gate remain separately required.

The result enables an important honest transition: from *static source introspection* to *actually executing selected, immutable upstream tests*. Future self-contained modules can be added only after separate source review and explicit immutable policy pins.
