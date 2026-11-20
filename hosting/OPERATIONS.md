# Garcar Burst Host Mesh v2 — Operator Runbook

**Status:** read-only burst compute and Railway connection are verified on the existing public bounty repository. The dedicated Everest host is not enrolled or validated.

## Hosting lanes and execution boundaries

| Lane | Backing host | Purpose | Automatic execution |
|---|---|---|---|
| source_review | GitHub-hosted Ubuntu ephemeral VM | Pinned read-only source inspection | Only when its allowed workflow is triggered |
| staging_health | GitHub-hosted Ubuntu to existing Railway | Fixed HTTPS GET /health | Weekly verification and manually invoked workflows |
| devnet_preflight | GitHub-hosted Ubuntu | Read-only diagnostics, not a full devnet | Only when explicitly selected |
| everest_devnet | Dedicated isolated Linux runner in the **private** control-plane repository | Future local devnet candidate | **Never** from the public job router |

The public repository never enrolls or runs self-hosted runners. It is intentionally unsuitable for executing untrusted pull requests on a private host. The private control plane should use a dedicated machine/VM and a uniquely labeled runner: `self-hosted`, `linux`, `x64`, `zeus-everest-isolated`. No private runner is currently connected.

The [private readiness PR](https://github.com/Garrettc123/garcar-private-control-os/pull/2) adds a manually dispatched **read-only** preflight, not container startup. After code review and enrollment through the private repository's **Settings → Actions → Runners**, invoke that workflow to see disk/CPU/RAM, Docker daemon and pinned-source status. Follow GitHub's generated enrollment instructions; do not paste enrollment tokens or credentials into chat or public repository issues.

## Read-only dispatch

After the public [v2 PR](https://github.com/Garrettc123/ai-swarm-crypto-bounty-system/pull/17) is merged, open the `Garcar Burst Host Mesh — Scoped Dispatch` workflow from the repository's Actions tab, choose a job, and run it. A GitHub-hosted runner invokes the same guarded policy on each run. The supported jobs are `source_review`, `staging_health`, `devnet_preflight`, and `everest_devnet`. The last option **only records a BLOCKED decision**—it does not start a devnet, wait indefinitely for an unknown host, or provision a VM.

Artifacts include:
- `dispatch-receipt.json`: requested job, route, explicit blockers, SHA-256 digest of the serialized receipt (unsigned metadata evidence)
- `burst-host-health.json`: GitHub runner resource observation and the exact existing Railway service's public /health status
- `host-capacity.json`: conservative operator capacity policy; this is **not** an official Everest resource requirement
- `base-everest-source-review.json`: immutable-source evidence only when read-only research was selected

All artifacts expire after the workflow's configured retention window and are **not vulnerability proofs**, signatures, acceptance notices, or verified revenue.

## Official Base Everest reproduction setup

Competition scope: https://immunefi.com/audit-competition/audit-comp-base-everest/scope/

Resource and pinned source instructions: https://immunefi.com/audit-competition/audit-comp-base-everest/resources/

Default code baseline is `base/base` at `689054ee14933cb2ee5bd54eadcd8dacbe1cc517`. Official scope requires a *local* Everest devnet running the production configuration and runnable in-scope code for an eligible PoC. Use `just devnet up everest` only on a qualified isolated Linux host. Live sequencer and public-network exploit tests are forbidden.

**Devnet setup compatibility issue:** The immutable competition baseline originally deploys bundled legacy contract artifacts. The official competition resources require applying upstream `base/base#6682` followed by `base/base#6680`, in that order, when building the devnet from `base/contracts` v8.5.0-rc.1. They are **devnet setup changes, not a scope expansion or an upgrade to the audited source**. The current `scripts/everest_local_devnet.sh --start` intentionally rejects any checkout whose HEAD differs from the audit pin, so it does **not** automatically support the patched-contract variant. A separate reviewed patch-aware bootstrap is required for that variant; do not bypass the verification checks by deleting them.

Do not represent component-level PoCs as end-to-end proof or assume live-node resources from shared GitHub runners. Full Everest execution remains blocked until the specific host, official config and local execution are demonstrated.

## Cost and approval model

The system's policy sets `spend_limit_usd=0` and never calls a cloud VM creation endpoint. This prevents new instance provisioning by this code; it does not override provider-level invoices or quotas for previously active services. Existing Railway services, pending patches, variables, databases and payment services are not modified by the hosting mesh.

Every outbound third-party vulnerability submission, charge, production promotion, or network exploit remains disabled without a distinct, explicit authorization and review of current scope.
