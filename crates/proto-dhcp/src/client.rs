//! DHCPv4 client state machine (RFC 2131 §4.4), pure: no sockets, no clock,
//! no randomness of its own. The engine feeds it time (`now`, milliseconds
//! of a monotonic clock), received datagrams and ARP-probe results, and
//! carries out the [`Action`]s it returns (send, probe, install or remove
//! the lease). That makes every timer testable with a simulated clock.
//!
//! ```text
//!  INIT ─DISCOVER→ SELECTING ─OFFER/REQUEST→ REQUESTING ─ACK→ PROBING ─1 s→ BOUND
//!   ↑                  │ backoff 4,8,16,32,64 s    │ NAK / 4 tries     │ ARP answer
//!   │                  ↓                           ↓                   ↓ DECLINE, 10 s
//!   └──────────────────────────────────────────────┴───────────────────┘
//!  BOUND ─T1→ RENEWING (unicast) ─T2→ REBINDING (broadcast) ─expiry→ INIT (lease lost)
//!            └──ACK→ BOUND, NAK→ INIT ┘
//! ```
//!
//! Choices (documented in `docs/dhcp-client.md`):
//! - the first acceptable OFFER wins (no collection window), as most
//!   routers do; answers ask for broadcast (we have no address yet);
//! - `allowed_servers` filters OFFER, ACK and NAK alike, so a rogue server
//!   can neither give an address nor take one away;
//! - disabling or removing the client drops the lease without a RELEASE
//!   (the ISP keeps it for us); `release` sends one.

use std::net::Ipv4Addr;

use corerouter_hal::dhcp::{Datagram, Dest};
use dhcproto::v4::MessageType;
use ipnet::Ipv4Net;

use crate::v4::{self, Incoming, Outgoing};

/// First retransmission wait; doubles up to [`MAX_BACKOFF_MS`] (RFC 2131 §4.1).
pub const FIRST_BACKOFF_MS: u64 = 4_000;
pub const MAX_BACKOFF_MS: u64 = 64_000;
/// REQUESTs sent in REQUESTING before starting over.
pub const REQUEST_TRIES: u32 = 4;
/// ARP probe length before using an address (shorter than RFC 5227's
/// 1–3 s + 2 s, which matters for a router coming up; **estimado** enough).
pub const PROBE_MS: u64 = 1_000;
/// Wait after a DECLINE before starting over (RFC 2131 §3.1.5).
pub const DECLINE_WAIT_MS: u64 = 10_000;
/// Minimum wait between retransmissions while renewing / rebinding.
pub const MIN_RENEW_RETRY_MS: u64 = 60_000;
/// T1 never comes sooner than this after binding, whatever the server says.
pub const MIN_T1_MS: u64 = 5_000;
/// Lease used when an ACK has none (RFC 2131 requires one; some servers forget).
pub const DEFAULT_LEASE_SECS: u32 = 3_600;

/// Where the client is (RouterOS shows the coarse [`State::status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    Init,
    Selecting,
    Requesting,
    Probing,
    Bound,
    Renewing,
    Rebinding,
    /// After a DECLINE, waiting to start over.
    Declined,
}

impl State {
    /// RouterOS' `status`.
    pub fn status(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Init | Self::Selecting | Self::Declined => "searching",
            Self::Requesting | Self::Probing => "requesting",
            Self::Bound => "bound",
            Self::Renewing => "renewing",
            Self::Rebinding => "rebinding",
        }
    }
}

/// What the client sends with every message, already in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub mac: [u8; 6],
    pub client_id: Vec<u8>,
    pub host_name: String,
    pub vendor_class: Vec<u8>,
    pub extra: Vec<(u8, Vec<u8>)>,
}

/// A lease the client holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub address: Ipv4Net,
    pub server: Ipv4Addr,
    pub server_mac: Option<[u8; 6]>,
    pub routers: Vec<Ipv4Addr>,
    pub classless: Vec<(Ipv4Net, Ipv4Addr)>,
    pub dns: Vec<Ipv4Addr>,
    pub ntp: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    /// `u32::MAX`: infinite.
    pub lease_secs: u32,
    /// When it was (last) granted, in the engine's milliseconds.
    pub granted_ms: u64,
    pub t1_ms: u64,
    pub t2_ms: u64,
    /// `None`: never expires.
    pub expires_ms: Option<u64>,
    /// Every option of the ACK as (code, bytes), for `ip.dhcp-client.options`.
    /// Routers and classless gateways are as the server sent them: the
    /// engine decides which routes can be installed.
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Lease {
    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.routers.first().copied()
    }
}

/// Something worth a line in the client's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Searching,
    Offered {
        server: Ipv4Addr,
        address: Ipv4Addr,
    },
    Bound {
        address: Ipv4Net,
        server: Ipv4Addr,
        lease_secs: u32,
    },
    Renewed {
        address: Ipv4Net,
        server: Ipv4Addr,
        lease_secs: u32,
    },
    /// The lease is gone: expired, refused by a NAK, released or stopped.
    Lost {
        address: Ipv4Net,
        reason: String,
    },
    Nak {
        server: Ipv4Addr,
        message: Option<String>,
    },
    /// A server outside `allowed_servers` answered.
    Refused {
        server: Ipv4Addr,
        mac: Option<[u8; 6]>,
    },
    /// Someone already uses the address: DECLINE sent.
    Declined {
        address: Ipv4Addr,
        by: [u8; 6],
    },
    /// A reply that made no sense (bad address, no server id).
    Ignored {
        server: Ipv4Addr,
        why: String,
    },
    /// Could not build a message (bad extra option).
    Error(String),
}

/// What the engine must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send {
        payload: Vec<u8>,
        src: Ipv4Addr,
        dest: Dest,
    },
    /// Start an ARP probe for this address; report with [`Client::conflict`].
    Probe(Ipv4Addr),
    /// The probe is over.
    EndProbe,
    /// Install (or refresh) the lease's address and routes.
    Bind(Box<Lease>),
    /// Remove what [`Action::Bind`] installed.
    Unbind,
    Log(Event),
}

/// Which servers may answer: (their IPs, their MAC) → allowed.
type Filter = Box<dyn Fn(&[Ipv4Addr], Option<[u8; 6]>) -> bool + Send>;

/// The address fields of a message the client sends.
#[derive(Debug, Clone, Copy)]
struct Addrs {
    ciaddr: Ipv4Addr,
    requested: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
}

impl Addrs {
    fn from(ciaddr: Ipv4Addr) -> Self {
        Self {
            ciaddr,
            requested: None,
            server_id: None,
        }
    }
}

/// The selected offer while REQUESTING.
#[derive(Debug, Clone)]
struct Offer {
    address: Ipv4Addr,
    server: Ipv4Addr,
}

pub struct Client {
    settings: Settings,
    /// Server filter: (ips the reply comes from, its MAC) → allowed.
    allowed: Filter,
    state: State,
    xid: u32,
    rng: u64,
    /// When the next timer fires.
    deadline: u64,
    tries: u32,
    /// When this exchange began (the `secs` field).
    began: u64,
    offer: Option<Offer>,
    lease: Option<Lease>,
    /// Lease waiting for the ARP probe.
    pending: Option<Lease>,
    /// Consecutive NAKs, for the wait before starting over.
    naks: u32,
    /// Servers already reported as refused in this exchange.
    refused: Vec<Ipv4Addr>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("state", &self.state)
            .field("xid", &self.xid)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A stopped client. `seed` varies transaction ids and jitter between
    /// clients and restarts (the engine passes clock and MAC bits).
    pub fn new(
        settings: Settings,
        allowed: impl Fn(&[Ipv4Addr], Option<[u8; 6]>) -> bool + Send + 'static,
        seed: u64,
    ) -> Self {
        Self {
            settings,
            allowed: Box::new(allowed),
            state: State::Stopped,
            xid: 0,
            rng: seed | 1,
            deadline: 0,
            tries: 0,
            began: 0,
            offer: None,
            lease: None,
            pending: None,
            naks: 0,
            refused: Vec::new(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// Time of the next timer, for "expires after" and tests.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// The offered server while requesting.
    pub fn offered_by(&self) -> Option<Ipv4Addr> {
        self.offer.as_ref().map(|o| o.server)
    }

    /// New settings take effect from the next message.
    pub fn set_settings(&mut self, settings: Settings) {
        self.settings = settings;
    }

    /// New server filter, from the next answer on.
    pub fn set_allowed(
        &mut self,
        allowed: impl Fn(&[Ipv4Addr], Option<[u8; 6]>) -> bool + Send + 'static,
    ) {
        self.allowed = Box::new(allowed);
    }

    fn random(&mut self) -> u64 {
        // xorshift64: plenty for transaction ids and jitter.
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// `base` ± up to 1 s (RFC 2131 §4.1 randomization).
    fn jitter(&mut self, base: u64) -> u64 {
        let j = self.random() % 2_001;
        base.saturating_add(j).saturating_sub(1_000)
    }

    fn backoff(&mut self) -> u64 {
        let base = FIRST_BACKOFF_MS
            .saturating_mul(1u64 << self.tries.min(4))
            .min(MAX_BACKOFF_MS);
        self.jitter(base)
    }

    /// Start (or restart) acquiring at `now`.
    pub fn start(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        self.drop_lease(&mut out, "client restarted");
        self.restart_at(now, now);
        out.extend(self.poll(now));
        out
    }

    /// Stop: drop the lease (no RELEASE) and go quiet.
    pub fn stop(&mut self, reason: &str) -> Vec<Action> {
        let mut out = Vec::new();
        if self.state == State::Probing {
            out.push(Action::EndProbe);
        }
        self.drop_lease(&mut out, reason);
        self.state = State::Stopped;
        self.offer = None;
        self.pending = None;
        out
    }

    fn drop_lease(&mut self, out: &mut Vec<Action>, reason: &str) {
        if let Some(l) = self.lease.take() {
            out.push(Action::Unbind);
            out.push(Action::Log(Event::Lost {
                address: l.address,
                reason: reason.to_owned(),
            }));
        }
    }

    fn restart_at(&mut self, now: u64, at: u64) {
        self.state = State::Init;
        self.deadline = at;
        self.tries = 0;
        self.began = now;
        self.offer = None;
        self.pending = None;
        self.refused.clear();
    }

    /// `ip.dhcp-client.renew`: renew now when bound, else start over.
    pub fn renew(&mut self, now: u64) -> Vec<Action> {
        match self.state {
            State::Bound | State::Renewing | State::Rebinding => {
                self.state = State::Renewing;
                self.xid = self.random() as u32;
                self.began = now;
                self.tries = 0;
                self.deadline = now;
                self.poll(now)
            }
            _ => self.start(now),
        }
    }

    /// `ip.dhcp-client.release`: RELEASE to the server, drop the lease and
    /// start over (RouterOS restarts the client).
    pub fn release(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        if let Some(l) = self.lease.clone() {
            self.xid = self.random() as u32;
            match self.message(
                MessageType::Release,
                l.address.addr(),
                None,
                Some(l.server),
                false,
            ) {
                Ok(payload) => out.push(Action::Send {
                    payload,
                    src: l.address.addr(),
                    dest: Dest::Unicast(l.server),
                }),
                Err(e) => out.push(Action::Log(Event::Error(e))),
            }
        }
        self.drop_lease(&mut out, "released");
        self.restart_at(now, now);
        out.extend(self.poll(now));
        out
    }

    fn message(
        &self,
        kind: MessageType,
        ciaddr: Ipv4Addr,
        requested: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
        broadcast: bool,
    ) -> Result<Vec<u8>, String> {
        Outgoing {
            kind,
            xid: self.xid,
            secs: 0,
            mac: self.settings.mac,
            ciaddr,
            broadcast,
            requested,
            server_id,
            client_id: &self.settings.client_id,
            host_name: Some(self.settings.host_name.as_str()),
            vendor_class: Some(self.settings.vendor_class.as_slice()),
            extra: &self.settings.extra,
        }
        .encode()
        .map_err(|e| e.to_string())
    }

    fn send(&self, out: &mut Vec<Action>, kind: MessageType, a: Addrs, dest: Dest, now: u64) {
        let ciaddr = a.ciaddr;
        let broadcast = ciaddr.is_unspecified();
        match self.message(kind, ciaddr, a.requested, a.server_id, broadcast) {
            Ok(mut payload) => {
                // `secs`: seconds since this exchange began (bytes 8..10).
                let secs =
                    u16::try_from(now.saturating_sub(self.began) / 1_000).unwrap_or(u16::MAX);
                if let Some(field) = payload.get_mut(8..10) {
                    field.copy_from_slice(&secs.to_be_bytes());
                }
                out.push(Action::Send {
                    payload,
                    src: ciaddr,
                    dest,
                });
            }
            Err(e) => out.push(Action::Log(Event::Error(e))),
        }
    }

    /// Fire the timers due at `now`.
    pub fn poll(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        match self.state {
            State::Stopped => {}
            State::Init if now >= self.deadline => {
                self.xid = self.random() as u32;
                self.began = now;
                self.tries = 0;
                self.refused.clear();
                self.state = State::Selecting;
                out.push(Action::Log(Event::Searching));
                self.discover(&mut out, now);
            }
            State::Selecting if now >= self.deadline => {
                self.tries = self.tries.saturating_add(1);
                self.discover(&mut out, now);
            }
            State::Requesting if now >= self.deadline => {
                self.tries = self.tries.saturating_add(1);
                if self.tries >= REQUEST_TRIES {
                    self.restart_at(now, now);
                    return self.poll(now);
                }
                self.request_selected(&mut out, now);
            }
            State::Probing if now >= self.deadline => {
                out.push(Action::EndProbe);
                if let Some(lease) = self.pending.take() {
                    self.bind(&mut out, lease, false);
                }
            }
            State::Declined if now >= self.deadline => {
                self.restart_at(now, now);
                return self.poll(now);
            }
            State::Bound | State::Renewing | State::Rebinding => self.lease_timers(&mut out, now),
            _ => {}
        }
        out
    }

    fn discover(&mut self, out: &mut Vec<Action>, now: u64) {
        self.send(
            out,
            MessageType::Discover,
            Addrs::from(Ipv4Addr::UNSPECIFIED),
            Dest::Broadcast,
            now,
        );
        let wait = self.backoff();
        self.deadline = now.saturating_add(wait);
    }

    fn request_selected(&mut self, out: &mut Vec<Action>, now: u64) {
        let Some(o) = self.offer.clone() else {
            self.restart_at(now, now);
            return;
        };
        let a = Addrs {
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested: Some(o.address),
            server_id: Some(o.server),
        };
        self.send(out, MessageType::Request, a, Dest::Broadcast, now);
        let wait = self.backoff();
        self.deadline = now.saturating_add(wait);
    }

    fn lease_timers(&mut self, out: &mut Vec<Action>, now: u64) {
        let Some(l) = self.lease.clone() else {
            self.restart_at(now, now);
            return;
        };
        if l.expires_ms.is_some_and(|e| now >= e) {
            self.drop_lease(out, "lease expired: no server renewed it");
            self.restart_at(now, now);
            out.extend(self.poll(now));
            return;
        }
        let me = l.address.addr();
        if self.state == State::Bound && now >= l.t1_ms {
            self.state = State::Renewing;
            self.xid = self.random() as u32;
            self.began = now;
            self.deadline = now;
        }
        if self.state == State::Renewing && now >= l.t2_ms {
            self.state = State::Rebinding;
            self.xid = self.random() as u32;
            self.deadline = now;
        }
        if now < self.deadline {
            return;
        }
        // Retry at half the time left to the next stage, at least a minute.
        let (dest, until) = match self.state {
            State::Renewing => (Dest::Unicast(l.server), l.t2_ms),
            State::Rebinding => (Dest::Broadcast, l.expires_ms.unwrap_or(u64::MAX)),
            _ => return,
        };
        self.send(out, MessageType::Request, Addrs::from(me), dest, now);
        let half = until.saturating_sub(now) / 2;
        self.deadline = now.saturating_add(half.max(MIN_RENEW_RETRY_MS)).min(until);
    }

    /// A datagram arrived on the client port.
    pub fn input(&mut self, now: u64, d: &Datagram) -> Vec<Action> {
        let mut out = Vec::new();
        if self.state == State::Stopped {
            return out;
        }
        let Ok(msg) = v4::decode(&d.payload) else {
            return out;
        };
        if msg.xid != self.xid || msg.chaddr != self.settings.mac {
            return out;
        }
        let server = msg.server_id.unwrap_or(d.src);
        if !(self.allowed)(&[server, d.src], d.src_mac) {
            if !self.refused.contains(&server) && self.refused.len() < 16 {
                self.refused.push(server);
                out.push(Action::Log(Event::Refused {
                    server,
                    mac: d.src_mac,
                }));
            }
            return out;
        }
        match (self.state, msg.kind) {
            (State::Selecting, MessageType::Offer) => self.on_offer(&mut out, now, &msg, server),
            (State::Requesting, MessageType::Ack) => {
                if self.offer.as_ref().is_some_and(|o| o.server == server) {
                    self.on_ack(&mut out, now, &msg, d, server, true);
                }
            }
            (State::Renewing | State::Rebinding, MessageType::Ack) => {
                self.on_ack(&mut out, now, &msg, d, server, false);
            }
            (State::Requesting, MessageType::Nak) => {
                if self.offer.as_ref().is_some_and(|o| o.server == server) {
                    self.on_nak(&mut out, now, &msg, server);
                }
            }
            (State::Renewing | State::Rebinding, MessageType::Nak) => {
                let ours = self.lease.as_ref().is_some_and(|l| l.server == server)
                    || self.state == State::Rebinding;
                if ours {
                    self.on_nak(&mut out, now, &msg, server);
                }
            }
            _ => {}
        }
        out
    }

    fn on_offer(&mut self, out: &mut Vec<Action>, now: u64, msg: &Incoming, server: Ipv4Addr) {
        if let Err(why) = usable(msg.yiaddr) {
            out.push(Action::Log(Event::Ignored { server, why }));
            return;
        }
        out.push(Action::Log(Event::Offered {
            server,
            address: msg.yiaddr,
        }));
        self.offer = Some(Offer {
            address: msg.yiaddr,
            server,
        });
        self.state = State::Requesting;
        self.tries = 0;
        self.request_selected(out, now);
    }

    fn on_ack(
        &mut self,
        out: &mut Vec<Action>,
        now: u64,
        msg: &Incoming,
        d: &Datagram,
        server: Ipv4Addr,
        fresh: bool,
    ) {
        let lease = match lease_from(now, msg, d, server) {
            Ok(l) => l,
            Err(why) => {
                out.push(Action::Log(Event::Ignored { server, why }));
                return;
            }
        };
        self.naks = 0;
        let same = self
            .lease
            .as_ref()
            .is_some_and(|old| old.address == lease.address);
        if fresh || !same {
            if !same {
                self.drop_lease(out, "the server gave another address");
            }
            self.pending = Some(lease.clone());
            self.state = State::Probing;
            self.deadline = now.saturating_add(PROBE_MS);
            out.push(Action::Probe(lease.address.addr()));
        } else {
            self.bind(out, lease, true);
        }
    }

    fn bind(&mut self, out: &mut Vec<Action>, lease: Lease, renewed: bool) {
        let event = if renewed {
            Event::Renewed {
                address: lease.address,
                server: lease.server,
                lease_secs: lease.lease_secs,
            }
        } else {
            Event::Bound {
                address: lease.address,
                server: lease.server,
                lease_secs: lease.lease_secs,
            }
        };
        self.state = State::Bound;
        self.offer = None;
        self.deadline = lease.t1_ms;
        self.lease = Some(lease.clone());
        out.push(Action::Bind(Box::new(lease)));
        out.push(Action::Log(event));
    }

    fn on_nak(&mut self, out: &mut Vec<Action>, now: u64, msg: &Incoming, server: Ipv4Addr) {
        out.push(Action::Log(Event::Nak {
            server,
            message: msg.message.clone(),
        }));
        self.drop_lease(out, "the server said NAK");
        self.naks = self.naks.saturating_add(1);
        // Do not hammer a server that keeps saying no: 0, 2, 4 … 64 s.
        let wait = if self.naks <= 1 {
            0
        } else {
            (1_000u64 << self.naks.min(6)).min(MAX_BACKOFF_MS)
        };
        self.restart_at(now, now.saturating_add(wait));
        out.extend(self.poll(now));
    }

    /// The running ARP probe found `by` using the address: DECLINE it.
    pub fn conflict(&mut self, now: u64, by: [u8; 6]) -> Vec<Action> {
        let mut out = Vec::new();
        if self.state != State::Probing {
            return out;
        }
        out.push(Action::EndProbe);
        if let Some(l) = self.pending.take() {
            let addr = l.address.addr();
            let a = Addrs {
                ciaddr: Ipv4Addr::UNSPECIFIED,
                requested: Some(addr),
                server_id: Some(l.server),
            };
            self.send(&mut out, MessageType::Decline, a, Dest::Broadcast, now);
            out.push(Action::Log(Event::Declined { address: addr, by }));
        }
        self.state = State::Declined;
        self.offer = None;
        self.deadline = now.saturating_add(DECLINE_WAIT_MS);
        out
    }
}

/// Whether a server may give us `ip`.
fn usable(ip: Ipv4Addr) -> Result<(), String> {
    if ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_loopback()
        || ip.octets().first().is_some_and(|o| *o >= 240)
    {
        return Err(format!("unusable address {ip}"));
    }
    Ok(())
}

/// Prefix length of a contiguous mask, or `None`.
fn prefix_of(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from(mask);
    let len = m.leading_ones();
    (m.checked_shl(len).unwrap_or(0) == 0)
        .then(|| u8::try_from(len).ok())
        .flatten()
}

/// The lease an ACK grants, checked.
fn lease_from(now: u64, msg: &Incoming, d: &Datagram, server: Ipv4Addr) -> Result<Lease, String> {
    usable(msg.yiaddr)?;
    let prefix = match msg.mask {
        Some(m) => prefix_of(m).ok_or_else(|| format!("subnet mask {m} is not contiguous"))?,
        // Classful default (RFC 2131 leaves it to the client).
        None => match msg.yiaddr.octets().first().copied().unwrap_or(0) {
            0..=127 => 8,
            128..=191 => 16,
            _ => 24,
        },
    };
    if prefix > 32 || prefix == 0 {
        return Err(format!("subnet mask /{prefix} is not usable"));
    }
    let address = Ipv4Net::new(msg.yiaddr, prefix).map_err(|e| e.to_string())?;
    if prefix < 31 && (msg.yiaddr == address.network() || msg.yiaddr == address.broadcast()) {
        return Err(format!("{address} is the network or broadcast address"));
    }
    let lease_secs = msg.lease_secs.unwrap_or(DEFAULT_LEASE_SECS);
    let (t1, t2, expires) = if lease_secs == u32::MAX {
        (u64::MAX, u64::MAX, None)
    } else {
        let lease_ms = u64::from(lease_secs).saturating_mul(1_000);
        let mut t1 = msg
            .renew_secs
            .map(|s| u64::from(s).saturating_mul(1_000))
            .unwrap_or(lease_ms / 2);
        let mut t2 = msg
            .rebind_secs
            .map(|s| u64::from(s).saturating_mul(1_000))
            .unwrap_or(lease_ms.saturating_mul(7) / 8);
        // Absurd timers from the server fall back to the RFC defaults.
        if t2 > lease_ms || t2 == 0 {
            t2 = lease_ms.saturating_mul(7) / 8;
        }
        if t1 > t2 || t1 == 0 {
            t1 = lease_ms / 2;
        }
        let t1 = t1.max(MIN_T1_MS.min(lease_ms / 2));
        (
            now.saturating_add(t1),
            now.saturating_add(t2.max(t1)),
            Some(now.saturating_add(lease_ms)),
        )
    };
    Ok(Lease {
        address,
        server,
        server_mac: d.src_mac,
        routers: msg.routers.clone(),
        classless: msg.classless.clone(),
        dns: msg.dns.clone(),
        ntp: msg.ntp.clone(),
        domain: msg.domain.clone(),
        lease_secs,
        granted_ms: now,
        t1_ms: t1,
        t2_ms: t2,
        expires_ms: expires,
        options: v4::raw_options(&d.payload),
    })
}

#[cfg(test)]
mod tests;
