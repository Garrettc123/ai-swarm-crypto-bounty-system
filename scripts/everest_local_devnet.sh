#!/usr/bin/env bash
# Guarded LOCAL-ONLY Everest devnet launcher, never automatically invoked by CI.
set -Eeuo pipefail

PIN="689054ee14933cb2ee5bd54eadcd8dacbe1cc517"
REPO="https://github.com/immunefi-team/audit-comp-base-everest-base"
SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BOUNTY_ROOT="$(cd -- "$SELF_DIR/.." && pwd)"
CHECKOUT="${ZEUS_EVEREST_CHECKOUT:-$HOME/base-everest-audit}"
ACTION="${1:---check}"

case "$ACTION" in
  --check)
    python3 "$BOUNTY_ROOT/scripts/everest_host_preflight.py" \
      --checkout "$CHECKOUT" --output "$BOUNTY_ROOT/artifacts/everest-host-preflight.json"
    exit 0
    ;;
  --start) ;;
  *) echo "Usage: $0 [--check|--start]" >&2; exit 64 ;;
esac

if [[ "${ZEUS_LOCAL_DEVNET_ALLOW_RUN:-}" != "yes" ]]; then
  echo "Refusing startup: set ZEUS_LOCAL_DEVNET_ALLOW_RUN=yes explicitly" >&2
  exit 2
fi
python3 "$BOUNTY_ROOT/scripts/everest_host_preflight.py" \
  --checkout "$CHECKOUT" \
  --output "$BOUNTY_ROOT/artifacts/everest-host-preflight.json" \
  --require-ready
cd -- "$CHECKOUT"
HEAD="$(git rev-parse HEAD)"
if [[ "$HEAD" != "$PIN" ]]; then
  echo "Refusing startup: source checkout is not the official immutable competition revision" >&2
  exit 2
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing startup: checkout must be clean" >&2
  exit 2
fi
REMOTE="$(git remote get-url origin)"
case "$REMOTE" in
  "$REPO"|"$REPO.git"|git@github.com:immunefi-team/audit-comp-base-everest-base.git)
    ;;
  *) echo "Refusing startup: origin is not the official Immunefi competition fork" >&2; exit 2 ;;
esac

echo "Starting only the designated LOCAL Everest devnet from $PIN"
echo "This is not a PoC and does not generate proof, submit reports, or claim earnings."
exec just devnet up everest
