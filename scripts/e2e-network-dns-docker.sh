#!/usr/bin/env bash
# Network-wide DNS override end-to-end check.
#
# node-a is the admin, node-b is an ordinary member, node-c plays the
# self-hosted Pi-hole: it runs dnsmasq on its own mesh tunnel IP. The admin
# points the network at node-c and turns on the override; node-b must then
# resolve through node-c without ever being touched directly, fail closed when
# node-c goes away, and go back to its normal resolver when the override is
# turned off.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_NAME="nostr-vpn-e2e-network-dns"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.e2e.yml")

NETWORK_ID="docker-network-dns"
# Sentinel only dnsmasq on node-c knows. Anything else answering means the
# override is not in effect.
PROBE_NAME="pihole-probe.example"
PROBE_ANSWER="203.0.113.7"

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${PROJECT_NAME}_e2e" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    docker network inspect "${PROJECT_NAME}_e2e" >/dev/null 2>&1 || break
    sleep 1
  done
}

dump_debug() {
  set +e
  echo "network DNS docker e2e failed, collecting debug output..."
  "${COMPOSE[@]}" ps || true
  for node in node-a node-b node-c; do
    echo "--- $node status ---"
    "${COMPOSE[@]}" exec -T "$node" nvpn status --json --discover-secs 0 || true
    echo "--- $node resolv.conf ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "cat /etc/resolv.conf 2>/dev/null || true" || true
    echo "--- $node config ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "cat /root/.config/nvpn/config.toml 2>/dev/null || true" || true
    echo "--- $node daemon.log ---"
    "${COMPOSE[@]}" exec -T "$node" sh -lc "tail -n 200 /root/.config/nvpn/daemon.log 2>/dev/null || true" || true
  done
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

fail() {
  echo "network DNS docker e2e failed: $1" >&2
  exit 1
}

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
  fail "$service never started"
}

read_npub() {
  local service="$1"
  "${COMPOSE[@]}" exec -T "$service" sh -lc \
    "nvpn init --force >/dev/null && awk '
      /^\\[nostr\\]$/ { in_nostr = 1; next }
      /^\\[/ { in_nostr = 0 }
      in_nostr && /^public_key[[:space:]]*=/ { print \$3; exit }
    ' /root/.config/nvpn/config.toml" | tr -d '\r\"'
}

start_daemon() {
  local service="$1"
  "${COMPOSE[@]}" exec -T "$service" sh -lc "nvpn start --daemon --connect >/tmp/nvpn-start.log 2>&1" \
    || fail "daemon start failed on $service"
}

reload_daemon() {
  local service="$1"
  local output=""
  for _ in $(seq 1 10); do
    if output="$("${COMPOSE[@]}" exec -T "$service" nvpn reload 2>&1)"; then
      return 0
    fi
    grep -q "did not acknowledge control request" <<<"$output" || break
    sleep 1
  done
  echo "$output" >&2
  fail "daemon reload failed on $service"
}

wait_for_connected_peer_count() {
  local service="$1" expected="$2" description="$3" current=""
  for _ in $(seq 1 80); do
    current="$("${COMPOSE[@]}" exec -T "$service" sh -lc \
      "nvpn status --json | perl -0ne 'print \$1 if /\"connected_peer_count\"\\s*:\\s*(\\d+)/'" || true)"
    [[ "$current" == "$expected" ]] && return 0
    sleep 1
  done
  fail "$description (expected connected_peer_count=$expected, got '$current')"
}

# sed/grep rather than a JSON parser: the e2e image has no python3, and
# `nvpn status --json` is pretty-printed so the block is contiguous.
status_network_dns_field() {
  local service="$1" field="$2"
  "${COMPOSE[@]}" exec -T "$service" sh -lc \
    "nvpn status --json \
       | sed -n '/\"network_dns\": {/,/^  }/p' \
       | grep '\"$field\"' \
       | sed 's/.*: *//; s/[\",]//g'" \
    2>/dev/null | tr -d '\r'
}

wait_for_network_dns_field() {
  local service="$1" field="$2" expected="$3" description="$4" current=""
  for _ in $(seq 1 90); do
    current="$(status_network_dns_field "$service" "$field" || true)"
    [[ "$current" == "$expected" ]] && return 0
    sleep 1
  done
  fail "$description (expected network_dns.$field=$expected, got '$current')"
}

resolve_probe() {
  local service="$1"
  "${COMPOSE[@]}" exec -T "$service" sh -lc \
    "dig +short +timeout=3 +tries=1 $PROBE_NAME A 2>/dev/null | head -1" | tr -d '\r'
}

wait_for_probe_answer() {
  local service="$1" expected="$2" description="$3" current=""
  for _ in $(seq 1 60); do
    current="$(resolve_probe "$service" || true)"
    [[ "$current" == "$expected" ]] && return 0
    sleep 1
  done
  fail "$description (expected '$expected', got '$current')"
}

cleanup

"${COMPOSE[@]}" build >/dev/null
"${COMPOSE[@]}" up -d node-a node-b node-c >/dev/null
for service in node-a node-b node-c; do
  wait_for_service "$service"
done

ALICE_NPUB="$(read_npub node-a)"
BOB_NPUB="$(read_npub node-b)"
CAROL_NPUB="$(read_npub node-c)"
[[ -n "$ALICE_NPUB" && -n "$BOB_NPUB" && -n "$CAROL_NPUB" ]] \
  || fail "unable to resolve participant npubs"

configure_node() {
  local service="$1" endpoint="$2"
  shift 2
  "${COMPOSE[@]}" exec -T "$service" nvpn set \
    --network-id "$NETWORK_ID" \
    --participant "$ALICE_NPUB" \
    --participant "$BOB_NPUB" \
    --participant "$CAROL_NPUB" \
    --endpoint "$endpoint" \
    --listen-port 51820 \
    --fips-advertise-endpoint true \
    --fips-nostr-discovery-enabled false \
    --fips-bootstrap-enabled false \
    "$@" >/dev/null
}

configure_node node-a "10.203.0.10:51820" \
  --fips-peer-endpoint "$BOB_NPUB=10.203.0.11:51820" \
  --fips-peer-endpoint "$CAROL_NPUB=10.203.0.12:51820"
configure_node node-b "10.203.0.11:51820" \
  --fips-peer-endpoint "$ALICE_NPUB=10.203.0.10:51820" \
  --fips-peer-endpoint "$CAROL_NPUB=10.203.0.12:51820"
configure_node node-c "10.203.0.12:51820" \
  --fips-peer-endpoint "$ALICE_NPUB=10.203.0.10:51820" \
  --fips-peer-endpoint "$BOB_NPUB=10.203.0.11:51820"

# Alice is the sole admin, so only she can set the network nameserver.
for service in node-a node-b node-c; do
  "${COMPOSE[@]}" exec -T "$service" nvpn add-admin --device "$ALICE_NPUB" >/dev/null
done

for service in node-a node-b node-c; do
  start_daemon "$service"
done
for service in node-a node-b node-c; do
  wait_for_connected_peer_count "$service" 2 "$service never reached the 2/2 mesh"
done

CAROL_TUNNEL_IP="$("${COMPOSE[@]}" exec -T node-c nvpn ip | tr -d '\r')"
[[ -n "$CAROL_TUNNEL_IP" ]] || fail "unable to resolve carol's mesh tunnel IP"
echo "network DNS e2e: carol serves DNS on $CAROL_TUNNEL_IP"

# The Pi-hole stand-in. --bind-interfaces keeps it off 127.0.0.1, which is where
# nvpn's own stub listens on this platform.
"${COMPOSE[@]}" exec -T -d node-c sh -lc \
  "dnsmasq --keep-in-foreground --no-resolv --no-hosts --bind-interfaces \
     --listen-address=$CAROL_TUNNEL_IP \
     --address=/$PROBE_NAME/$PROBE_ANSWER >/tmp/dnsmasq.log 2>&1"
sleep 2

"${COMPOSE[@]}" exec -T node-a sh -lc \
  "dig +short +timeout=3 +tries=1 @$CAROL_TUNNEL_IP $PROBE_NAME A" | tr -d '\r' | grep -qF "$PROBE_ANSWER" \
  || fail "carol's resolver is not answering on $CAROL_TUNNEL_IP over the mesh"

# Baseline: without the override nobody resolves the sentinel name.
[[ "$(resolve_probe node-b)" != "$PROBE_ANSWER" ]] \
  || fail "bob resolved the sentinel before the override was enabled"

echo "network DNS e2e: enabling the override on the admin"
"${COMPOSE[@]}" exec -T node-a nvpn set \
  --network-dns-node "$CAROL_NPUB" --network-dns-override >/dev/null
reload_daemon node-a

# Propagates over the signed roster, so bob is never touched directly.
wait_for_network_dns_field node-b override true \
  "bob never received the admin's network DNS override"
wait_for_network_dns_field node-b enforced true \
  "bob received the override but never enforced it"
wait_for_probe_answer node-b "$PROBE_ANSWER" \
  "bob never resolved through the network nameserver"
echo "network DNS e2e: bob resolves through carol"

# The nameserver device keeps its own DNS configuration.
wait_for_network_dns_field node-c role nameserver \
  "carol should report itself as the network nameserver"
[[ "$(status_network_dns_field node-c enforced)" == "false" ]] \
  || fail "carol must not install the override on itself"
echo "network DNS e2e: carol excluded itself"

# Mesh names keep resolving locally even while everything else is forwarded.
"${COMPOSE[@]}" exec -T node-b nvpn status --json >/dev/null \
  || fail "bob's daemon became unhealthy under the override"

echo "network DNS e2e: checking fail-closed behaviour"
"${COMPOSE[@]}" stop node-c >/dev/null
FAILED_CLOSED=0
for _ in $(seq 1 30); do
  if [[ "$(resolve_probe node-b)" != "$PROBE_ANSWER" ]]; then
    FAILED_CLOSED=1
    break
  fi
  sleep 1
done
[[ "$FAILED_CLOSED" == "1" ]] \
  || fail "bob kept resolving after the nameserver went away; the override did not fail closed"
echo "network DNS e2e: resolution failed closed with the nameserver offline"

echo "network DNS e2e: turning the override off"
"${COMPOSE[@]}" exec -T node-a nvpn set --network-dns-override false >/dev/null
reload_daemon node-a
wait_for_network_dns_field node-b enforced false \
  "bob never dropped the override after the admin turned it off"

# Clean revert: bob's ordinary resolver works again.
for _ in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T node-b sh -lc \
    "dig +short +timeout=3 +tries=1 localhost A >/dev/null 2>&1"; then
    break
  fi
  sleep 1
done
"${COMPOSE[@]}" exec -T node-b sh -lc "grep -q . /etc/resolv.conf" \
  || fail "bob was left without any resolver after the override was turned off"

echo "network DNS docker e2e passed"
