#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export NVPN_EXIT_NODE_E2E_PAID="${NVPN_EXIT_NODE_E2E_PAID:-1}"
export NVPN_EXIT_NODE_E2E_PAYMENT_MODE="${NVPN_EXIT_NODE_E2E_PAYMENT_MODE:-token}"
export NVPN_EXIT_NODE_E2E_PROJECT_NAME="${NVPN_EXIT_NODE_E2E_PROJECT_NAME:-nostr-vpn-e2e-paid-exit-token}"

exec "$SCRIPT_DIR/e2e-exit-node-docker.sh"
