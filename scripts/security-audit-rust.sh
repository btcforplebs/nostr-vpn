#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

ensure_cargo_audit() {
  if cargo audit --version >/dev/null 2>&1; then
    return
  fi

  local version="${CARGO_AUDIT_VERSION:-0.22.1}"
  cargo install cargo-audit --version "$version" --locked
}

ensure_cargo_audit

# Temporary accepted upstream warnings:
# - RUSTSEC-2024-0384: `instant` is pulled by nostr 0.44.x; remove once fips/nostr
#   can move to the stable nostr line that replaces it.
# - RUSTSEC-2024-0436: `paste` is pulled by netlink-packet-core 0.8.1 via
#   netdev/rtnetlink; remove once rust-netlink ships a replacement.
audit_args=(
  --deny warnings
  --ignore RUSTSEC-2024-0384
  --ignore RUSTSEC-2024-0436
)

cargo audit "${audit_args[@]}"
(cd linux && cargo audit "${audit_args[@]}")
