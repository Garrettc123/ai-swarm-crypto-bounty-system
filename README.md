# Garcar AI Swarm Crypto Bounty System

**Verified capability:** read-only discovery and evidence-based triage of public Immunefi bug-bounty listings and public GitHub issues. The GitHub Actions pipeline also runs a **separate curated Base Everest audit-competition source-review intake**.

This system **does not** autonomously exploit targets, submit vulnerability reports, execute financial transactions, collect bounties, or verify payout balances. A passing CI job is not a verified vulnerability. Revenue is recorded only from independent payment evidence.

## Live entry points

- [Bounty scanning workflow](.github/workflows/bounty-scan.yml): scheduled at 14:17 UTC daily, and triggered by pushes, PRs, or manual dispatch.
- [Discovery scanner](crypto/bounty_hunter.py): HTTPS-only Immunefi / GitHub public listing ingestion; SQLite snapshots; no target testing.
- [Triage](crypto/bounty_triage.py): normalized JSON, Markdown, and CSV review queue, with earnings pinned to zero unless verified elsewhere.
- [Governed staging queue](crypto/push_queue_oidc.py): OIDC-authenticated ingestion of public metadata on main-branch workflows only. Not a payout or report submission mechanism.
- [Base Everest competition manifest](crypto/base_everest_target.json): manually curated competition, deliberately not counted as a standard Immunefi bug-bounty listing.
- [ZEUS runner](zeus.py): `run-once` **source inspection**, validating immutable Git blob hashes for five pinned files and writing a provenance report. It does **not** run Everest or produce a PoC.
- [Host preflight](scripts/everest_host_preflight.py): read-only Linux/Docker/`just`/Git/check-out diagnostics. Not proof of successful testing.
- [Local Everest launcher](scripts/everest_local_devnet.sh): blocked by default; requires an explicitly authorized Linux host, official pinned source checkout, clean tree and `ZEUS_LOCAL_DEVNET_ALLOW_RUN=yes`.

## Base Everest execution

The audit competition is [Nov 19 – Dec 1, 2026](https://immunefi.com/audit-competition/audit-comp-base-everest/information/). Relevant official [scope](https://immunefi.com/audit-competition/audit-comp-base-everest/scope/) and [resources](https://immunefi.com/audit-competition/audit-comp-base-everest/resources/) must be rechecked before testing or privately reporting any finding. A runnable PoC is mandatory for accepted reports. The default testing target is the **designated local Everest devnet** at `base/base` v1.6.0-rc.9, commit `689054ee14933cb2ee5bd54eadcd8dacbe1cc517`, using official Production configuration. The competition permits specified component-level proof-system PoCs and certain local forks under its written rules; never test against public sequencer/mainnet endpoints. Known issues, mid-contest fixes, and scope exclusions are not automatically updated by this repository.

### Reproducible read-only research (Linux, Android/Termux, or CI)

```sh
python3 zeus.py run-once --intent "Base Everest bounty hunt organ" --estimated-value-usd 250000
python3 crypto/base_everest_intake.py
```

`--estimated-value-usd` refers to the contest's advertised **shared maximum reward pool**, not a projected personal award. Look for `artifacts/base-everest-source-review.json` and `artifacts/base-everest-intake.json`.

### Prepare a Linux devnet host (not Termux/proot)

Install Git, Python 3, Docker with a **working Docker daemon**, and `just` using the official instructions for your Linux distribution. Do not install through unreviewed curl-to-shell commands. Clone the public competition fork and check out the pinned revision:

```sh
git clone https://github.com/immunefi-team/audit-comp-base-everest-base.git "$HOME/base-everest-audit"
git -C "$HOME/base-everest-audit" checkout 689054ee14933cb2ee5bd54eadcd8dacbe1cc517
python3 scripts/everest_host_preflight.py --checkout "$HOME/base-everest-audit" --require-ready
bash scripts/everest_local_devnet.sh --check
```

The launcher **does not start a devnet by default**. To start on that Linux host, after confirming the competition's Production settings, resource suitability, and current scope:

```sh
ZEUS_LOCAL_DEVNET_ALLOW_RUN=yes bash scripts/everest_local_devnet.sh --start
```

This executes `just devnet up everest` from a verified pinned **clean** source checkout. This is a devnet startup, **not** a vulnerability PoC or award. The script will refuse any modified source tree; contract-testing variants that require official devnet-only #6682/#6680 setup patches must use a separately reviewed workflow consistent with the official scope.

Termux may run the Python-only read-only scanner and source review, but Android/proot environments generally cannot provide the required native Linux Docker daemon. Do not confuse CI's source review with a deployed devnet.

## Security and evidence policy

- Public-source intake is not authorization to test a target. Respect the competition rules, exclusions, known issues, disclosure process, and all testing boundaries.
- `proof_hash`, `srr_hash`, `seal_hash`, and AXIOM-12 remain **null** until an independently reproduced, validated proof pipeline exists; hashes of source files are labeled separately.
- Do not publish private vulnerability details, secrets, user data, or exploit payloads in this public repository.
- No automatic outbound submissions, wallet signing, charging, or payout recognition. No money is counted until independently verified as received.
- Staging queue data is candidate metadata, not accepted findings or bankable contract value.
- Artifacts are stored by the GitHub workflow for 14 days. Preserve verified evidence in a restricted evidence store where required, not through public release of exploit details.

## Tests

```sh
python3 -m unittest discover -s tests -p 'test_base_everest_intake.py' -v
python3 -m unittest discover -s tests -p 'test_zeus_research.py' -v
python3 -m unittest discover -s tests -p 'test_everest_host_preflight.py' -v
```

The bug-bounty discovery pipeline runs its additional unit tests in GitHub Actions. Production deployment, full Everest component integration, and real payments remain separately gated.

## Connected hosting: Garcar Burst Host Mesh (November 2026)

The new [host mesh manifest](hosting/burst_host_mesh.json) and [validated Linux/Railway health probe](hosting/burst_host_mesh.py) connect two separate existing hosting lanes:

- **GitHub Actions ephemeral Linux** executes time-bounded read-only source inspections, tests, and host-capacity probes. The [Burst Host Mesh workflow](.github/workflows/burst-host-mesh.yml) uses a restricted read-only token, an Ubuntu runner, and a 5-minute limit. It runs on relevant code pushes, by manual dispatch, and weekly. Standard public-repository GitHub-hosted runners are described as free under GitHub's current public-runner rules; deployment of additional paid compute is never implicit.
- **Existing Railway staging** remains the persistent public metadata/status plane. Its fixed `/health` endpoint is checked over HTTPS using an allowlisted GET; no secrets, exploit details, submissions, or custom untrusted URLs are forwarded. The existing bounty scanner separately synchronizes public listing metadata through an authenticated, guarded OIDC ingestion flow.
- **Everest full local devnet** remains an explicitly gated dedicated-Linux workload: the source-only GH runner does not certify official Production-config build capacity, and Railway's application container is not a host-level Docker daemon. No new DigitalOcean Droplet, cloud credit spend, or dedicated server has been provisioned.

The first verified end-to-end [hosting-health run #44683132434](https://github.com/Garrettc123/ai-swarm-crypto-bounty-system/actions/runs/44683132434) passed **six offline policy tests**, confirmed GitHub runner Docker-daemon access and Railway's live `/health` identity, and uploaded a redacted capacity/health JSON artifact. This is an **infrastructure connection**, not evidence of a bounty vulnerability or full Everest devnet execution.

Production-safety policy: no auto-provisioning, payment actions, production promotion, public exploit disclosure, or automated third-party testing. Development and proof generation require explicit review of current Immunefi scope and a separately verified host.
