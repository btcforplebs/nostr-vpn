#!/usr/bin/env bash
# Retry perf-docker until its placement guard hits the requested FSP lane.
#
# This is intentionally a thin wrapper around the single-shot benchmark. It is
# useful for stress/soak evidence where generated endpoint identities make the
# FSP owner placement probabilistic, but a placement-matched artifact matters.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ATTEMPTS="${NVPN_DOCKER_PLACEMENT_ATTEMPTS:-12}"
EXPECT_FSP_OWNER_PLACEMENT="${NVPN_DOCKER_EXPECT_FSP_OWNER_PLACEMENT:-}"

usage() {
  cat <<'EOF'
usage: NVPN_DOCKER_EXPECT_FSP_OWNER_PLACEMENT=worker-open scripts/perf-docker-placement-hunt.sh

Retries scripts/perf-docker.sh until the requested node-b FSP owner placement is
observed, or until NVPN_DOCKER_PLACEMENT_ATTEMPTS is exhausted.

Important env:
  NVPN_DOCKER_EXPECT_FSP_OWNER_PLACEMENT=local|handoff|worker-open|same|mismatch
  NVPN_DOCKER_PLACEMENT_ATTEMPTS=12
  NVPN_DOCKER_PLACEMENT_PREFLIGHT=1
  NVPN_DOCKER_OUTPUT_DIR=artifacts/nvpn-docker/<hunt-dir>

All other NVPN_DOCKER_* env is passed through to scripts/perf-docker.sh.
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

case "$ATTEMPTS" in
  '' | *[!0-9]*)
    printf 'perf placement hunt: NVPN_DOCKER_PLACEMENT_ATTEMPTS must be a positive integer, got %s\n' \
      "$ATTEMPTS" >&2
    exit 2
    ;;
esac
if ((ATTEMPTS < 1)); then
  printf 'perf placement hunt: NVPN_DOCKER_PLACEMENT_ATTEMPTS must be >= 1\n' >&2
  exit 2
fi

case "$EXPECT_FSP_OWNER_PLACEMENT" in
  local | handoff | worker-open | same | owner-same | mismatch | owner-mismatch)
    ;;
  *)
    printf 'perf placement hunt: set NVPN_DOCKER_EXPECT_FSP_OWNER_PLACEMENT to a concrete placement before retrying\n' >&2
    exit 2
    ;;
esac

BASE_OUTPUT_DIR="${NVPN_DOCKER_OUTPUT_DIR:-$ROOT_DIR/artifacts/nvpn-docker/$(date -u +%Y%m%dT%H%M%SZ)-placement-hunt}"
INITIAL_SKIP_BUILD="${NVPN_DOCKER_SKIP_BUILD:-}"
INITIAL_PLACEMENT_PREFLIGHT="${NVPN_DOCKER_PLACEMENT_PREFLIGHT:-}"
mkdir -p "$BASE_OUTPUT_DIR"

last_status=0
last_log=""
for attempt in $(seq 1 "$ATTEMPTS"); do
  attempt_dir="$BASE_OUTPUT_DIR/attempt-$attempt"
  attempt_log="$attempt_dir/perf-docker.log"
  rm -rf "$attempt_dir"
  mkdir -p "$attempt_dir"

  printf '## placement attempt %s/%s expect=%s output=%s\n' \
    "$attempt" "$ATTEMPTS" "$EXPECT_FSP_OWNER_PLACEMENT" "$attempt_dir"

  export NVPN_DOCKER_OUTPUT_DIR="$attempt_dir"
  if [[ -n "$INITIAL_SKIP_BUILD" ]]; then
    export NVPN_DOCKER_SKIP_BUILD="$INITIAL_SKIP_BUILD"
  elif ((attempt > 1)); then
    export NVPN_DOCKER_SKIP_BUILD=1
  else
    unset NVPN_DOCKER_SKIP_BUILD
  fi
  if [[ -n "$INITIAL_PLACEMENT_PREFLIGHT" ]]; then
    export NVPN_DOCKER_PLACEMENT_PREFLIGHT="$INITIAL_PLACEMENT_PREFLIGHT"
  else
    export NVPN_DOCKER_PLACEMENT_PREFLIGHT=1
  fi

  set +e
  "$ROOT_DIR/scripts/perf-docker.sh" 2>&1 | tee "$attempt_log"
  status=${PIPESTATUS[0]}
  set -e

  if ((status == 0)); then
    printf '%s\n' "$attempt_dir" >"$BASE_OUTPUT_DIR/success-output-dir.txt"
    printf 'perf placement hunt passed: attempt=%s output=%s\n' "$attempt" "$attempt_dir"
    exit 0
  fi

  last_status=$status
  last_log="$attempt_log"
  if grep -Eq 'expected (exclusive )?node-b FSP owner placement' "$attempt_log"; then
    printf 'perf placement hunt: attempt %s missed requested placement; retrying\n' "$attempt" >&2
    continue
  fi

  printf 'perf placement hunt: attempt %s failed for a non-placement reason; see %s\n' \
    "$attempt" "$attempt_log" >&2
  exit "$status"
done

printf 'perf placement hunt failed: no %s placement in %s attempts; last log: %s\n' \
  "$EXPECT_FSP_OWNER_PLACEMENT" "$ATTEMPTS" "$last_log" >&2
exit "${last_status:-2}"
