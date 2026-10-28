//! English explanations of the Routing › BFD window (G3.6c), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bfd.attach"##, r##"## What it does
Puts a BFD profile (`default`, 300 ms × 3) on every BGP connection and OSPF interface template without one of its own or from a template. BGP and OSPF then go down when BFD sees the failure, instead of waiting for the hold time or the dead interval.

## Careful
The other side needs BFD too; until the session has come up once, it brings nothing down."##),
    (r##"bfd.engine"##, r##"## What it is
CoreRouter's BFD engine: N threads (`bfd-0`…), each with its own sessions, sockets and timer wheel. **reuseport-cbpf**: a BPF program on the socket group hands each packet to the thread that owns its session, with no lock. CPU is per thread, % of one core.

With FRR, the engine is bfdd's data plane: bfdd creates the sessions BGP and OSPF ask for and hands them to the engine."##),
    (r##"bfd.history.change"##, r##"## What it is
The session's state change (RFC 5880 §6.2). **dampened**: back up, but held down for its clients."##),
    (r##"bfd.history.diag"##, r##"## What it is
The RFC 5880 §4.1 diagnostic: why the session went down (control-detection-time-expired: no packet within the detection time; neighbor-signaled-session-down: the peer said so; administratively-down: turned off here)."##),
    (r##"bfd.history.time"##, r##"## What it is
When it happened (router clock)."##),
    (r##"bfd.peer"##, r##"## What it is
An explicit BFD session (FRR `peer`): the neighbor's address and a profile. BGP and OSPF ask for theirs with their own `bfd` field."##),
    (r##"bfd.peer.address"##, r##"## What it is
The neighbor's address; with multihop and the local address it is the session."##),
    (r##"bfd.peer.disabled"##, r##"## What it is
Turns the session off, keeping it in the config."##),
    (r##"bfd.peer.interface"##, r##"## What it is
Ties a single-hop session to an interface (optional)."##),
    (r##"bfd.peer.local_address"##, r##"## What it is
The source address. Required for multihop (RFC 5883 §3)."##),
    (r##"bfd.peer.multihop"##, r##"## What it is
A neighbor more than one hop away (RFC 5883, port 4784). Single hop (RFC 5881, port 3784) only takes packets with TTL 255."##),
    (r##"bfd.peer.name"##, r##"## What it is
The peer's name; empty: its address."##),
    (r##"bfd.peer.profile"##, r##"## What it is
The profile with the session's timers, dampening and auth."##),
    (r##"bfd.profile"##, r##"## What it is
Timers and options BGP, OSPF and peers share by name (Cisco `bfd-template`, FRR `bfd profile`). Built in: **default** (300 ms × 3) and **fast** (50 ms × 3); removing one restores it."##),
    (r##"bfd.profile.auth"##, r##"## What it is
Packet authentication (RFC 5880 §6.7.4): keyed-sha1 or meticulous-keyed-sha1 (a new sequence number in every packet)."##),
    (r##"bfd.profile.auth_key_id"##, r##"## What it is
The key's id (0–255), the same on both sides."##),
    (r##"bfd.profile.auth_secret"##, r##"## What it is
The shared key, 1–20 bytes. Empty when editing keeps it."##),
    (r##"bfd.profile.dampening"##, r##"## What it is
Each flap adds 1000, halving every 15 s; above 2500 (about 3 quick flaps) the session is held down for its clients until it is quiet (or 120 s)."##),
    (r##"bfd.profile.detect"##, r##"## What it is
Detection time: multiplier × the larger of Min TX and Min RX (RFC 5880 §6.8.4)."##),
    (r##"bfd.profile.min_rx"##, r##"## What it is
The fastest interval we accept packets at (Required Min RX, ms)."##),
    (r##"bfd.profile.min_ttl"##, r##"## What it is
Multihop only: the lowest TTL accepted (RFC 5883 §5)."##),
    (r##"bfd.profile.min_tx"##, r##"## What it is
The interval we want to send at once up (Desired Min TX, ms); at least 1 s while not up (RFC 5880 §6.8.3)."##),
    (r##"bfd.profile.multiplier"##, r##"## What it is
How many intervals without a packet bring the session down (3 is usual)."##),
    (r##"bfd.profile.name"##, r##"## What it is
The profile's name, as BGP, OSPF and peers name it."##),
    (r##"bfd.profile.options"##, r##"## What it is
dampening, passive (wait for the peer, RFC 5880 §6.1), sha1 (authenticated)."##),
    (r##"bfd.profile.passive"##, r##"## What it is
Passive role (RFC 5880 §6.1): send nothing until the peer speaks."##),
    (r##"bfd.profile.used_by"##, r##"## What it is
Who uses the profile."##),
    (r##"bfd.session.detect"##, r##"## What it is
The detection time in force (RFC 5880 §6.8.4)."##),
    (r##"bfd.session.flaps"##, r##"## What it is
Times the session went down from up in the last 24 h."##),
    (r##"bfd.session.jitter"##, r##"## What it is
p99 of how late our periodic packets left: the engine's load (not the deliberate RFC 5880 §6.8.7 jitter)."##),
    (r##"bfd.session.peer"##, r##"## What it is
The neighbor's address; **multihop**: across hops (RFC 5883)."##),
    (r##"bfd.session.state"##, r##"## What it is
up, down, init (handshake), dampened (up but held down for its clients), inactive (configured, not run by the engine)."##),
    (r##"bfd.session.txrx"##, r##"## What it is
The interval we send at and the Min RX the peer asked for."##),
    (r##"bfd.session.users"##, r##"## What it is
Who asked for the session: BGP, OSPF, peer or FRR. They all go down with it."##),
    (r##"bfd.tab.history"##, r##"## What it is
State changes, newest first."##),
    (r##"bfd.tab.profiles"##, r##"## What it is
The profiles shared by BGP, OSPF and peers."##),
    (r##"bfd.tab.sessions"##, r##"## What it is
The live BFD sessions."##),
];
