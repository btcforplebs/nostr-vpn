# Local patches to fips-core 0.4.53

This directory is the crates.io release of fips-core 0.4.53, byte for byte,
plus the patch below. `git diff <vendor commit> -- vendor/fips-core` shows
exactly what changed. Drop this directory and the `[patch.crates-io]` entry
once upstream ships an equivalent fix.

## 1. Answer a restarted peer's SessionSetup after the settle window

`src/node/handlers/session/node_handshake.rs`, `handle_session_setup`.

An established initiator keeps its final XK msg3 until authenticated
inbound data confirms the epoch. While it holds it, upstream drops every
SessionSetup from that peer as a "late simultaneous" msg1. If the peer
lost its side before answering (VPN toggled, network change, restart, msg3
lost), it never answers, so the setup is dropped forever. nvpn sets
`idle_timeout_secs = 0`, which removes the idle purge that would otherwise
clear it.

The fix keeps the drop only within `handshake_timeout_secs` of session
start. A real late simultaneous msg1 must arrive inside that window,
because the peer abandons its Initiating state after the same timeout.
After the window, the setup takes the normal rekey or re-establishment
path.

Tests: `src/node/tests/session/surviving_initiator_restart.rs`
- past the window, the restarted peer re-establishes (fails without the fix)
- inside the window, the setup is still dropped (the upstream rule holds)

The same guard is unchanged in nvpn-fips-core 0.4.83, and the
past-the-window test fails there too.
