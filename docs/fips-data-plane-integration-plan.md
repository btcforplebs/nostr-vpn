# FIPS Data Plane Integration Plan

This document describes how to move the private `nostr-vpn` mesh from
WireGuard to FIPS without exposing a FIPS-owned network adapter to the
system, while preserving `nostr-vpn` as the product, membership, and policy
layer.

The target architecture is library-first and endpoint-oriented, closer to the
Iroh model than to a system daemon model:

- the application owns membership and authorization
- the connectivity substrate owns peer reachability and path selection
- application protocols are explicit, named, and routed to handlers
- unknown peers can be connectivity peers without becoming private network
  members
- only the app decides which packets enter its VPN interface or in-app
  network

## Goals

- Use FIPS as the private mesh data plane for selected `nostr-vpn` networks.
- Do not create or expose a separate FIPS `fips0` or `utun` interface.
- Do not let arbitrary FIPS peers inject packets into the host or app private
  network.
- Allow broad FIPS connectivity for bridge/transit purposes when useful.
- Keep `nostr-vpn` rosters as the authority for private-network membership.
- Keep the option to use WireGuard for an internet exit provider such as
  Mullvad while using FIPS for the private mesh.
- Allow reuse of a local FIPS broker if one is running, without requiring one.

## Non-Goals

- Do not replace the `nostr-vpn` invite, roster, admin, GUI, or service model.
- Do not expose FIPS as a general host network interface in `nostr-vpn`.
- Do not make FIPS discovery membership-authoritative.
- Do not route non-roster peer traffic into the private VPN.
- Do not make mobile depend on a separately installed FIPS daemon.

## Design Principles From Iroh

Iroh's useful pattern is not the specific QUIC transport. The useful pattern is
the application-facing shape:

- one local endpoint owns identity, sockets, discovery, relays, and connection
  reuse
- applications register protocol handlers by explicit protocol identifiers
  such as ALPN strings
- accepted connections are delivered to handlers, not to the host network
- unsupported protocols are rejected or ignored
- identity and reachability are separated: endpoint id plus direct addresses,
  relay addresses, or custom transport addresses
- relay/bridge paths are reachability options, not membership grants

The FIPS integration should copy that boundary:

```rust
let endpoint = FipsEndpoint::builder()
    .identity(nostr_identity)
    .discovery_scope(format!("nostr-vpn:{network_id}"))
    .connectivity_policy(FipsConnectivityPolicy::OpenTransit)
    .bind()
    .await?;

endpoint.accept_protocol(
    b"nostr-vpn/ip/1",
    NostrVpnIpHandler {
        roster,
        route_policy,
        packet_sink,
    },
);
```

The handler, not FIPS discovery, decides whether a peer is a private network
member.

## Target Architecture

### Default: Embedded Endpoint

For desktop and mobile app sessions, `nostr-vpn` embeds FIPS as a library:

```text
nostr-vpn runtime
  -> packet classifier and route policy
  -> embedded FIPS endpoint
  -> FIPS peer links, bridges, NAT traversal, TCP/Tor fallback
```

FIPS does not create a TUN interface in this mode. It receives and emits
packets through app-owned channels.

For system-wide VPN behavior, the only visible adapter is still the
`nostr-vpn` adapter. On mobile this is the Android `VpnService` or iOS packet
tunnel. On desktop this can be the existing `nostr-vpn` tunnel interface. FIPS
is only the private mesh transport behind that adapter.

For app-only behavior, no system adapter is needed. The app sends explicit
application traffic through the embedded endpoint.

### Optional: Local FIPS Broker

If a trusted local FIPS broker is running, `nostr-vpn` can use it instead of
creating its own endpoint:

```text
nostr-vpn runtime
  -> local authenticated IPC
  -> local FIPS broker
  -> remote FIPS peers and bridges
```

The broker must be a connectivity broker, not an ambient network adapter. It
must not expose a FIPS TUN interface for this use case.

The broker owns reusable resources:

- UDP/TCP/Tor sockets
- FIPS peer links
- Nostr advert cache
- NAT/STUN state
- bridge and relay paths
- metrics and path selection

The app still owns private-network policy:

```rust
broker.register_protocol(
    b"nostr-vpn/ip/1",
    allowed_remote_npubs,
    app_packet_channel,
);
```

If no compatible local broker is available, the app falls back to an embedded
endpoint.

## Policy Model

Separate peer roles explicitly:

| Role | Meaning | Policy owner |
| --- | --- | --- |
| Connectivity peer | A FIPS node we can connect to or use as a path | FIPS plus app config |
| Transit peer | A FIPS node whose traffic may be forwarded through us | `nostr-vpn` policy |
| Private member | A roster npub allowed into this VPN network | `nostr-vpn` roster |
| Host service peer | A peer allowed to reach local host services | Explicit app policy |

Default `nostr-vpn` policy:

```text
connect to FIPS peers: allowed when useful
use public bridge peers: allowed when useful
forward transit traffic: configurable
deliver local private packets: roster npubs only
deliver packets to host services: deny by default
```

This means "FIPS connect to anyone" is compatible with "do not route anyone's
traffic into our system".

## Required FIPS Library Work

### 1. Embedded Runtime Without TUN

Add a FIPS runtime mode that disables FIPS-owned TUN and DNS setup.

Proposed API shape:

```rust
pub struct FipsEndpointBuilder {
    // identity, transports, discovery, policy
}

impl FipsEndpointBuilder {
    pub fn identity_nsec(self, nsec: String) -> Self;
    pub fn discovery_scope(self, scope: String) -> Self;
    pub fn without_system_tun(self) -> Self;
    pub async fn bind(self) -> Result<FipsEndpoint>;
}
```

The runtime must not create `fips0`, configure routes, install DNS resolver
state, or expose local host services.

### 2. External Packet I/O

Expose app-owned packet I/O:

```rust
impl FipsEndpoint {
    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<()>;
    pub async fn recv_ip_packet(&self) -> Option<FipsDeliveredPacket>;
}

pub struct FipsDeliveredPacket {
    pub source_npub: String,
    pub destination: FipsAddress,
    pub packet: Vec<u8>,
}
```

`source_npub` is required so `nostr-vpn` can enforce roster membership before
writing to a VPN FD or app packet sink.

### 3. Application Protocol Handlers

Add an Iroh-like protocol routing layer:

```rust
pub trait FipsProtocolHandler: Send + Sync + 'static {
    async fn accept(&self, session: FipsSession) -> Result<()>;
}

impl FipsEndpoint {
    pub fn accept_protocol(
        &self,
        protocol: &'static [u8],
        handler: impl FipsProtocolHandler,
    );

    pub async fn connect_protocol(
        &self,
        remote: Npub,
        protocol: &'static [u8],
    ) -> Result<FipsSession>;
}
```

The first application protocol needed by `nostr-vpn` is:

```text
nostr-vpn/ip/1
```

It carries private mesh IP packets between roster members.

Unknown protocols must not be delivered to the app. They should be rejected or
ignored.

### 4. Local Delivery vs Transit

FIPS should expose enough hooks for the app to distinguish local delivery from
transit forwarding.

Minimum requirement:

- app can disable all automatic local packet delivery
- app receives only packets for registered protocols
- app can inspect source npub before accepting payload

Optional later feature:

```rust
pub enum LocalDeliveryDecision {
    Accept,
    Drop,
}

pub trait LocalDeliveryPolicy {
    fn decide(&self, source: &Npub, protocol: &[u8]) -> LocalDeliveryDecision;
}
```

### 5. Discovery Scope

FIPS Nostr discovery must be scoped per `nostr-vpn` network:

```text
node.discovery.nostr.app = "nostr-vpn:<network_id>"
```

This prevents unrelated FIPS users from sharing one advert namespace.

### 6. Broker IPC

Add an optional local broker API later. It should be local-only and
authenticated.

Required broker operations:

- version/capability negotiation
- register protocol handler
- connect protocol to npub
- send packet/session data
- receive packet/session data with source npub
- list peer/link/path status
- subscribe to status changes
- unregister protocol on app exit

The broker must not be required for mobile.

## Required `nostr-vpn` Work

### 1. Data Plane Selection

Add config fields while preserving current defaults:

```toml
private_data_plane = "wireguard" # wireguard | fips
exit_data_plane = "wireguard"    # none | wireguard
```

The initial release should keep WireGuard as default.

### 2. Backend Abstraction

Split the current tunnel runtime behind a trait:

```rust
trait PrivateMeshBackend {
    async fn apply(
        &mut self,
        app: &AppConfig,
        presence: &PeerPresenceBook,
        route_policy: &RoutePolicy,
    ) -> Result<()>;

    async fn stop(&mut self);
    async fn status(&self) -> Result<BackendStatus>;
}
```

Implementations:

- `WireGuardPrivateMeshBackend` wrapping current `CliTunnelRuntime`
- `FipsPrivateMeshBackend` using embedded FIPS or local broker

### 3. Protocol Evolution

Current `Announce.public_key` is the WireGuard public key. In FIPS mode this
is not the tunnel identity.

Add data-plane explicit fields:

```json
{
  "data_plane": "fips",
  "fips": {
    "npub": "npub1...",
    "protocols": ["nostr-vpn/ip/1"]
  }
}
```

Keep existing WireGuard fields for compatibility:

```json
{
  "data_plane": "wireguard",
  "public_key": "<wireguard public key>",
  "endpoint": "host:port"
}
```

Receivers must ignore unsupported data planes instead of treating them as
offline peers.

### 4. Roster-Backed Packet Admission

`nostr-vpn` must enforce:

```rust
if active_roster.contains(source_npub) && route_policy.allows(packet) {
    vpn_fd.write(packet)?;
} else {
    drop(packet);
}
```

This is the core safety boundary.

### 5. Route Classification

In FIPS mode, private mesh routing should initially be limited to:

- FIPS IPv6 peer addresses
- `.fips` or `nostr-vpn` private names mapped to FIPS addresses
- explicitly configured private application routes

Do not initially promise full compatibility with existing `10.44.0.0/16`
WireGuard addressing unless an IPv4-to-FIPS shim is added.

### 6. Hybrid WireGuard Exit

Keep WireGuard/boringtun for exit traffic:

```text
private mesh destinations -> FIPS backend
default route / Mullvad -> WireGuard backend
Nostr/STUN/FIPS control -> explicit underlay route policy
```

On desktop this can be done with platform routing. On mobile, there is usually
only one active VPN profile, so the `nostr-vpn` packet tunnel must dispatch
internally:

```text
private mesh packet -> FIPS endpoint
default internet packet -> WireGuard exit runtime
```

### 7. GUI and Status

Expose backend state without exposing FIPS implementation details:

- private mesh backend: WireGuard or FIPS
- connectivity peers
- roster members connected
- bridge/transit paths in use
- packets dropped by roster policy
- optional WireGuard exit status

## Phased Implementation

### Phase 0: Reset Assumptions

- Keep the current WireGuard implementation as default.
- Add this document and track FIPS work as experimental.
- Confirm FIPS can use the existing `nostr-vpn` Nostr `nsec` as identity.
- Decide whether FIPS lives as a git dependency, workspace sibling path, or
  extracted crate.

### Phase 1: FIPS Embedded API Prototype

In `~/src/fips`:

- add a minimal embedded endpoint API
- allow `tun.enabled = false` without losing packet delivery APIs
- expose delivered packet source npub
- add a protocol identifier to local delivery
- write in-process tests with two endpoints and no system TUN

Success criteria:

- two embedded FIPS endpoints exchange an app protocol payload
- no system interface is created
- source npub is available to the receiver
- unsupported protocol is not delivered

### Phase 2: `nostr-vpn` Backend Abstraction

In `~/src/nostr-vpn`:

- introduce `PrivateMeshBackend`
- move current CLI WireGuard runtime behind it
- keep all existing tests passing
- add a feature-gated `FipsPrivateMeshBackend` stub

Success criteria:

- no behavior change with `private_data_plane = "wireguard"`
- backend status remains compatible with GUI and CLI status output

### Phase 3: FIPS Private Mesh MVP

- map active roster participants to allowed FIPS npubs
- register `nostr-vpn/ip/1`
- send private packets through FIPS
- drop received packets from non-roster npubs
- support direct/Nostr-discovered FIPS connectivity
- keep WireGuard exit disabled in this phase

Success criteria:

- two `nostr-vpn` nodes exchange private packets over FIPS
- non-roster FIPS peers can be connected but cannot inject private packets
- no separate FIPS TUN interface exists

### Phase 4: Bridge and Transit Policy

- allow configured public bridge FIPS peers
- optionally allow open FIPS connectivity for bridge discovery
- expose "transit only" vs "private member" status
- add bandwidth and abuse controls for transit forwarding

Success criteria:

- two NAT-limited nodes can communicate through a reachable FIPS bridge
- bridge peers do not become private network members
- dropped non-roster local-delivery packets are counted

### Phase 5: Optional Local FIPS Broker

- design local IPC protocol
- add broker discovery and capability negotiation
- use broker if compatible and authorized
- fall back to embedded endpoint otherwise

Success criteria:

- broker reuse works for desktop
- app policy remains enforced by `nostr-vpn`
- killing the app unregisters its protocol handler

### Phase 6: Hybrid WireGuard Exit

- split private mesh and exit routing
- keep FIPS for private network destinations
- keep WireGuard for default-route exit
- protect Nostr/STUN/FIPS control traffic from accidental exit-route loops

Success criteria:

- private peer traffic uses FIPS
- internet default route uses WireGuard/Mullvad
- control traffic remains stable during exit reconnects

### Phase 7: Mobile

- embed FIPS in Android and iOS packet tunnel runtimes
- reuse the existing mobile packet dispatch loop
- dispatch private packets to FIPS and exit packets to WireGuard when enabled

Success criteria:

- mobile private mesh works without a FIPS daemon
- mobile hybrid exit works inside one OS VPN profile
- no separate FIPS adapter is visible

## Tests

### FIPS Tests

- embedded endpoint creates no TUN
- app protocol payload exchange
- unsupported protocol rejected
- delivered packet includes source npub
- roster-like delivery hook drops unauthorized source
- bridge/transit path does not imply local delivery

### `nostr-vpn` Unit Tests

- backend selection defaults to WireGuard
- FIPS mode omits WireGuard public key requirements
- FIPS announcements parse with explicit `data_plane`
- packet admission drops non-roster source npubs
- route classifier sends private packets to FIPS and exit packets to WireGuard

### Integration Tests

- two-node FIPS private mesh
- three-node topology with public FIPS bridge
- non-roster FIPS peer connected but unable to inject private packets
- WireGuard exit plus FIPS private mesh
- relay outage while FIPS bridge path remains active

### Mobile Tests

- Android packet dispatch to FIPS backend
- iOS packet dispatch to FIPS backend
- hybrid FIPS private route plus WireGuard default route

## Migration

Initial compatibility mode:

- existing networks continue using WireGuard
- new networks can opt into FIPS experimentally
- rosters and invites remain compatible
- peers advertise supported data planes

Later migration:

- allow a network admin to set preferred private data plane
- show mixed-mode peers as partially compatible
- once FIPS is stable, create new networks with FIPS as default private mesh
- keep WireGuard as an exit backend and legacy private backend

## Open Questions

- Should FIPS endpoint identity always be the `nostr-vpn` Nostr identity, or
  should each network get a derived FIPS identity?
- Should transit forwarding be enabled by default or require explicit opt-in?
- Should bridge peers be discovered from FIPS open discovery, `nostr-vpn`
  service records, or both?
- How much IPv4 compatibility is needed before FIPS mode is useful?
- Should local broker IPC carry plaintext app packets, or should apps add an
  extra encryption layer over broker transport?
- What status model best explains "connected as transit peer" vs "private
  network member" in the GUI?

## First Concrete Patch Set

1. Add FIPS embedded endpoint API skeleton behind an experimental feature.
2. Add a two-endpoint no-TUN FIPS test.
3. Add `PrivateMeshBackend` to `nostr-vpn` and wrap current WireGuard runtime.
4. Add config parsing for `private_data_plane`, defaulting to WireGuard.
5. Add FIPS announcement fields behind a compatibility parser.
6. Add packet admission tests for roster npub filtering.
