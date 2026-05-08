#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

docker run --rm \
  --network bridge \
  -e CARGO_TARGET_DIR=/tmp/nostr-vpn-target \
  -v "$ROOT_DIR":/app/nostr-vpn:ro \
  -w /app/nostr-vpn \
  rust:1.93-bookworm \
  bash -lc '
    set -euo pipefail
    export PATH="/usr/local/cargo/bin:$PATH"
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends libclang-dev libdbus-1-dev pkg-config >/dev/null
    rm -rf /var/lib/apt/lists/*
    cargo test --locked -p nostr-vpn-app-core \
      lan_pairing::tests::lan_pairing_workers_exchange_invites_over_looped_multicast \
      -- --exact --nocapture
  '
