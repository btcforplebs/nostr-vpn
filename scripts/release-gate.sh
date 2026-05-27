#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

node scripts/sync-versions.mjs
./scripts/security-audit-rust.sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/e2e-update-cli.sh

case "${NVPN_RELEASE_GATE_DOCKER_E2E:-1}" in
  0|false|FALSE|False|no|NO|No|off|OFF|Off)
    echo "Skipping Docker e2e because NVPN_RELEASE_GATE_DOCKER_E2E=${NVPN_RELEASE_GATE_DOCKER_E2E}"
    ;;
  *)
    # The join-request flow is gated by e2e-bootstrap-discovery-docker.sh, which
    # exercises the same FIPS join-request control frame deterministically over a
    # direct static endpoint. e2e-join-request-docker.sh covers the public
    # open-discovery/relay path but depends on public Nostr relays, so it flakes
    # in CI; run it manually (or in a nightly) rather than in the blocking gate.
    ./scripts/e2e-bootstrap-discovery-docker.sh
    NVPN_FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}" \
      ./scripts/e2e-fips-routed-udp-docker.sh
    NVPN_FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}" \
      ./scripts/e2e-fips-nat-safe-mtu-docker.sh
    ;;
esac
