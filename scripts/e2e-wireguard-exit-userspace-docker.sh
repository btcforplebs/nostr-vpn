#!/usr/bin/env bash
# Smoke-test the userspace (boringtun) WG upstream path by running
# `nvpn wg-upstream-test` against a real wg-quick server inside Docker.
# Probes only the handshake — no tun device, no route changes — so this
# is the safest possible integration test for the userspace WG code on
# any platform that supports boringtun + tokio.
#
# Topology (reuses docker-compose.wireguard-exit-e2e.yml so we don't have
# to maintain two compose files):
#   internet (198.51.100.0/24)        public (203.0.113.0/24)
#     - wg-upstream  198.51.100.20      - wg-upstream    203.0.113.20
#     - node-a       198.51.100.10      - internet-target 203.0.113.100
#
# Pass criteria: `nvpn wg-upstream-test` reports a completed handshake.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_NAME="nostr-vpn-e2e-wireguard-exit-userspace"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.wireguard-exit-e2e.yml")

WG_UPSTREAM_IP="198.51.100.20"
WG_LISTEN_PORT="51820"
WG_TUNNEL_NET="10.99.99.0/24"
WG_SERVER_TUNNEL_IP="10.99.99.1"
WG_CLIENT_TUNNEL_IP="10.99.99.2"

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm \
    "${PROJECT_NAME}_internet" \
    "${PROJECT_NAME}_public" >/dev/null 2>&1 || true
  for network in "${PROJECT_NAME}_internet" "${PROJECT_NAME}_public"; do
    for _ in $(seq 1 20); do
      docker network inspect "$network" >/dev/null 2>&1 || break
      sleep 1
    done
  done
}

dump_debug() {
  set +e
  echo "wg-upstream userspace e2e failed, collecting debug output..."
  "${COMPOSE[@]}" ps || true
  echo "--- node-a: nvpn version ---"
  "${COMPOSE[@]}" exec -T node-a nvpn version --json || true
  echo "--- node-a: cat wg-upstream.conf ---"
  "${COMPOSE[@]}" exec -T node-a sh -lc "cat /tmp/wg-upstream.conf 2>/dev/null || echo 'no config'" || true
  echo "--- wg-upstream: wg show ---"
  "${COMPOSE[@]}" exec -T wg-upstream sh -lc "wg show || true" || true
}

on_exit() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    dump_debug
  fi
  cleanup
  exit "$exit_code"
}
trap on_exit EXIT

wait_for_service() {
  local service="$1"
  local container_id=""
  for _ in $(seq 1 30); do
    container_id="$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$container_id" ]] \
      && [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" == "true" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "wg-upstream userspace e2e failed: service '$service' did not reach running state" >&2
  exit 1
}

cleanup

# Build only the services we actually need for the handshake probe —
# wg-upstream is the WG server, node-a is where we run nvpn. node-b /
# internet-target are unused here.
"${COMPOSE[@]}" build wg-upstream node-a >/dev/null
"${COMPOSE[@]}" up -d wg-upstream node-a >/dev/null
for service in wg-upstream node-a; do
  wait_for_service "$service"
done

# Generate WG keypairs on the upstream server.
# The e2e image only ships dash; do not enable -o pipefail here.
"${COMPOSE[@]}" exec -T wg-upstream sh -eu -c '
umask 077
mkdir -p /etc/wireguard
[ -s /etc/wireguard/server.key ] || wg genkey > /etc/wireguard/server.key
[ -s /etc/wireguard/client.key ] || wg genkey > /etc/wireguard/client.key
wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
wg pubkey < /etc/wireguard/client.key > /etc/wireguard/client.pub
' >/dev/null

SERVER_PRIV="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/server.key | tr -d '\r\n')"
SERVER_PUB="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/server.pub | tr -d '\r\n')"
CLIENT_PRIV="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/client.key | tr -d '\r\n')"
CLIENT_PUB="$("${COMPOSE[@]}" exec -T wg-upstream cat /etc/wireguard/client.pub | tr -d '\r\n')"

# Bring up the WG server interface on wg-upstream. No NAT / iptables here
# because the userspace test only exercises the handshake — no actual
# tunneled traffic flows.
"${COMPOSE[@]}" exec -T wg-upstream sh -eu -c "
ip link del wg0 2>/dev/null || true
ip link add dev wg0 type wireguard
ip address add ${WG_SERVER_TUNNEL_IP}/24 dev wg0
wg set wg0 listen-port ${WG_LISTEN_PORT} private-key /etc/wireguard/server.key
wg set wg0 peer ${CLIENT_PUB} allowed-ips ${WG_CLIENT_TUNNEL_IP}/32
ip link set wg0 up
" >/dev/null

# Compose the WG config text and drop it on node-a as a file. Reading
# from a file (rather than from --wireguard-exit-config inline) is what
# the production GUI flow does too, so this exercises the same parser
# path.
WG_CONFIG="[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${WG_CLIENT_TUNNEL_IP}/32
MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${WG_UPSTREAM_IP}:${WG_LISTEN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"

"${COMPOSE[@]}" exec -T node-a sh -lc 'cat > /tmp/wg-upstream.conf' <<<"$WG_CONFIG"

# Run the userspace handshake probe. The command exits 0 when the
# handshake completes within the timeout and non-zero otherwise; that's
# exactly what we want set -e to react to.
"${COMPOSE[@]}" exec -T node-a nvpn wg-upstream-test \
  --config-file /tmp/wg-upstream.conf \
  --timeout-secs 15

echo "wg-upstream userspace e2e passed: boringtun-based handshake completed against wg-quick server"
