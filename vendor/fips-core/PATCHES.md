# Local patches to nvpn-fips-core 0.4.94

This directory is the crates.io release of nvpn-fips-core 0.4.94, byte for
byte,
plus the patch below. `git diff <vendor commit> -- vendor/fips-core` shows
exactly what changed. Once upstream ships an equivalent fix, drop this
directory and both `[patch.crates-io] nvpn-fips-core` entries: the root
`Cargo.toml` and `linux/Cargo.toml` (then refresh both `Cargo.lock` files).

## 1. Answer a restarted peer's SessionSetup after the settle window

`src/node/handlers/session/node_handshake.rs`, `handle_session_setup`.

An established initiator keeps its final XK msg3 until authenticated
inbound data confirms the epoch. While it holds it, upstream drops every
SessionSetup from that peer as a "late simultaneous" msg1. If the peer
lost its side before answering (VPN toggled, network change, restart, msg3
lost) and never sends data on that session, every reconnect attempt is
dropped. nvpn sets `idle_timeout_secs = 0`, which removes the idle purge
that would otherwise clear it after 90 s, so the peer stays locked out
until the box restarts or its own hourly rekey (`rekey.after_secs = 3600`)
replaces the stale msg3: up to about an hour.

The fix keeps the drop only within `handshake_timeout_secs` of session
start. A real late simultaneous msg1 must arrive inside that window,
because the peer abandons its Initiating state after the same timeout.
After the window, the setup takes the normal rekey or re-establishment
path.

Tests: `src/node/tests/session/surviving_initiator_restart.rs`
- past the window, the restarted peer re-establishes and the survivor ends
  on the peer's new epoch (fails without the fix)
- inside the window, the setup is still dropped (the upstream rule holds)

First written against fips-core 0.4.53 (nvpn 4.1.4). The guard is
unchanged in nvpn-fips-core 0.4.83 and 0.4.94, and the patch applies to
0.4.94 without edits.

## Known, not fixed here

- After the window, a stale or replayed msg1 from a peer that is alive but
  has not sent data yet can make the two sides echo SessionAcks at RTT
  speed until the rekey resend budget is exhausted (about 30 s). The rekey
  responder's retained ack is resent on a duplicate SessionAck in
  `handle_session_ack`. Bounded, needs a replay or an odd delay; raise
  upstream.
- If the peer lost its session without restarting (same epoch), recovery
  goes through the existing decrypt-failure rekey. Only the restart case
  is tested.
- `now_ms` is wall-clock; a backward clock step briefly restores the
  upstream drop.
