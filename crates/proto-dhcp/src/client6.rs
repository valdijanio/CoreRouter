//! DHCPv6 client state machine (RFC 8415 §18), pure like the DHCPv4 one:
//! the engine feeds it time (`now`, milliseconds of a monotonic clock) and
//! received datagrams, and carries out the [`Action`]s it returns (send,
//! install or remove the lease, log). Every timer is testable with a
//! simulated clock.
//!
//! ```text
//!  INIT ─delay 0–1 s→ SOLICITING ─Advertise (best of the first RT)→ REQUESTING ─Reply→ BOUND
//!      ↑               │ RT 1 s ×2 … SOL_MAX_RT     │ REQ_MAX_RC tries / nothing bound   │
//!      └───────────────┴────────────────────────────┘                                   │
//!  BOUND ─T1→ RENEWING (to the server) ─T2→ REBINDING (any server) ─all lifetimes over→ INIT
//!            └──Reply→ BOUND; NoBinding → REQUESTING ┘
//!  release: RELEASING (REL_MAX_RC tries) → INIT
//! ```
//!
//! One address (IA_NA) and one delegated prefix (IA_PD), each optional, in
//! one exchange — what a CPE router asks for (RFC 7084 WAA-? / WPD-?). The
//! first usable address and prefix of the IAs are kept; the IAs share the
//! smallest T1/T2 (as `odhcp6c` does). Choices are documented in
//! `docs/dhcp-client.md` §9.

use std::net::Ipv6Addr;

use corerouter_hal::dhcp::Datagram6;
use ipnet::Ipv6Net;

use crate::v6::{self, INFINITY, Ia, IaReq, Incoming, Outgoing, msg, status};

// RFC 8415 §7.6, transmission and retransmission parameters (ms).
pub const SOL_MAX_DELAY_MS: u64 = 1_000;
pub const SOL_TIMEOUT_MS: u64 = 1_000;
pub const SOL_MAX_RT_MS: u64 = 3_600_000;
pub const REQ_TIMEOUT_MS: u64 = 1_000;
pub const REQ_MAX_RT_MS: u64 = 30_000;
pub const REQ_MAX_RC: u32 = 10;
pub const REN_TIMEOUT_MS: u64 = 10_000;
pub const REN_MAX_RT_MS: u64 = 600_000;
pub const REB_TIMEOUT_MS: u64 = 10_000;
pub const REB_MAX_RT_MS: u64 = 600_000;
pub const REL_TIMEOUT_MS: u64 = 1_000;
pub const REL_MAX_RC: u32 = 4;
/// T1 never comes sooner than this after binding (a server sending tiny
/// timers cannot make us flood it; **estimado**).
pub const MIN_T1_MS: u64 = 5_000;
/// Wait before soliciting again after a server refused everything:
/// 1, 2, 4 … 64 s (like the DHCPv4 NAK backoff).
pub const MAX_REFUSAL_WAIT_MS: u64 = 64_000;
/// Rate limit (RFC 9915 §14.1): at most this many messages per window.
pub const RATE_MAX: usize = 20;
pub const RATE_WINDOW_MS: u64 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    /// Waiting the random delay before the first Solicit (§18.2.1).
    Init,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Releasing,
}

impl State {
    /// RouterOS' `status`.
    pub fn status(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Init | Self::Soliciting | Self::Releasing => "searching",
            Self::Requesting => "requesting",
            Self::Bound => "bound",
            Self::Renewing => "renewing",
            Self::Rebinding => "rebinding",
        }
    }
}

/// What the client asks for and how it identifies itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Our DUID (Client Identifier).
    pub duid: Vec<u8>,
    /// IAID of both IAs (one of each kind per interface).
    pub iaid: u32,
    pub address: bool,
    pub prefix: bool,
    /// Prefix hint in the IA_PD of a Solicit (`::/56` asks for a /56).
    pub prefix_hint: Option<Ipv6Net>,
    pub rapid_commit: bool,
    /// With both asked for, bind only when the server gives both (RouterOS
    /// `accept-prefix-without-address=no`).
    pub require_both: bool,
}

/// A binding with its lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held<T> {
    pub value: T,
    pub preferred: u32,
    pub valid: u32,
    /// `None`: infinite.
    pub expires_ms: Option<u64>,
}

/// What the client holds from one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub server_duid: Vec<u8>,
    /// Source of the last Reply (the server's or relay's link-local).
    pub server_addr: Ipv6Addr,
    pub server_mac: Option<[u8; 6]>,
    pub address: Option<Held<Ipv6Addr>>,
    pub prefix: Option<Held<Ipv6Net>>,
    pub dns: Vec<Ipv6Addr>,
    pub domains: Vec<String>,
    pub granted_ms: u64,
    /// `u64::MAX`: never.
    pub t1_ms: u64,
    pub t2_ms: u64,
    /// Asked for but not granted, with the server's reason.
    pub missing: Vec<String>,
    /// Every top-level option of the last Reply, for `options`.
    pub options: Vec<(u16, Vec<u8>)>,
}

impl Lease {
    /// When the last binding expires (`None`: never).
    pub fn expires_ms(&self) -> Option<u64> {
        let a = self.address.map(|h| h.expires_ms);
        let p = self.prefix.map(|h| h.expires_ms);
        match (a, p) {
            (Some(None), _) | (_, Some(None)) => None,
            (Some(Some(x)), Some(Some(y))) => Some(x.max(y)),
            (Some(Some(x)), None) | (None, Some(Some(x))) => Some(x),
            (None, None) => Some(self.granted_ms),
        }
    }

    pub fn server_text(&self) -> String {
        server_text(&self.server_duid, self.server_addr)
    }
}

/// `fe80::1 (0x0003…)`.
pub fn server_text(duid: &[u8], addr: Ipv6Addr) -> String {
    format!("{addr} ({})", v6::hex(duid))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Searching,
    Advertised {
        server: String,
        what: String,
        preference: u8,
    },
    Bound {
        server: String,
        what: String,
    },
    Renewed {
        server: String,
        what: String,
    },
    /// A binding is gone: expired, released, stopped, revoked.
    Lost {
        what: String,
        reason: String,
    },
    /// The server said no to something (status code).
    Status {
        server: String,
        text: String,
    },
    /// A server outside `allowed_servers` answered.
    Refused {
        server: String,
    },
    Ignored {
        server: String,
        why: String,
    },
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// To All_DHCP_Relay_Agents_and_Servers (ff02::1:2), port 547.
    Send(Vec<u8>),
    /// Install (or refresh) the lease's address, prefix and route.
    Bind(Box<Lease>),
    /// Remove what [`Action::Bind`] installed.
    Unbind,
    Log(Event),
}

/// Which servers may answer: (DUID, source address, source MAC) → allowed.
type Filter = Box<dyn Fn(&[u8], Ipv6Addr, Option<[u8; 6]>) -> bool + Send>;

/// An Advertise kept while collecting.
#[derive(Debug, Clone)]
struct Offer {
    duid: Vec<u8>,
    preference: u8,
    address: Option<Ipv6Addr>,
    prefix: Option<Ipv6Net>,
}

impl Offer {
    fn what(&self) -> String {
        what(self.address, self.prefix)
    }

    fn score(&self) -> (u8, u8) {
        (
            self.preference,
            u8::from(self.address.is_some()) + u8::from(self.prefix.is_some()),
        )
    }
}

fn what(address: Option<Ipv6Addr>, prefix: Option<Ipv6Net>) -> String {
    match (address, prefix) {
        (Some(a), Some(p)) => format!("address {a}, prefix {p}"),
        (Some(a), None) => format!("address {a}"),
        (None, Some(p)) => format!("prefix {p}"),
        (None, None) => "nothing".into(),
    }
}

pub struct Client {
    settings: Settings,
    allowed: Filter,
    state: State,
    xid: u32,
    rng: u64,
    deadline: u64,
    /// Retransmission timeout of the running exchange (RT, §15).
    rt: u64,
    tries: u32,
    /// When this exchange began (Elapsed Time, §21.9).
    began: u64,
    /// Whether the first RT of the Solicit is over (§18.2.9: collect
    /// Advertises until then, then take the first one).
    collected: bool,
    offers: Vec<Offer>,
    chosen: Option<Offer>,
    lease: Option<Lease>,
    /// Server-learned SOL_MAX_RT (§21.24).
    sol_max_rt: u64,
    /// Consecutive exchanges that ended with nothing bound.
    refusals: u32,
    refused: Vec<Vec<u8>>,
    /// When the last messages went out (§14.1 rate limit).
    sent: std::collections::VecDeque<u64>,
    /// Whether the rate limit already said so in this window.
    throttled: bool,
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
    pub fn new(
        settings: Settings,
        allowed: impl Fn(&[u8], Ipv6Addr, Option<[u8; 6]>) -> bool + Send + 'static,
        seed: u64,
    ) -> Self {
        Self {
            settings,
            allowed: Box::new(allowed),
            state: State::Stopped,
            xid: 0,
            rng: seed | 1,
            deadline: 0,
            rt: 0,
            tries: 0,
            began: 0,
            collected: false,
            offers: Vec::new(),
            chosen: None,
            lease: None,
            sol_max_rt: SOL_MAX_RT_MS,
            refusals: 0,
            refused: Vec::new(),
            sent: std::collections::VecDeque::new(),
            throttled: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// The server chosen while requesting.
    pub fn chosen(&self) -> Option<&[u8]> {
        self.chosen.as_ref().map(|o| o.duid.as_slice())
    }

    /// New settings. What is asked for changed: start over (the IAs differ).
    pub fn set_settings(&mut self, settings: Settings, now: u64) -> Vec<Action> {
        let restart = settings.address != self.settings.address
            || settings.prefix != self.settings.prefix
            || settings.duid != self.settings.duid
            || settings.iaid != self.settings.iaid;
        self.settings = settings;
        if restart && self.state != State::Stopped {
            self.start(now)
        } else {
            Vec::new()
        }
    }

    pub fn set_allowed(
        &mut self,
        allowed: impl Fn(&[u8], Ipv6Addr, Option<[u8; 6]>) -> bool + Send + 'static,
    ) {
        self.allowed = Box::new(allowed);
    }

    fn random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// RAND × `base`, RAND uniform in −0.1..=+0.1 (§15); `positive`:
    /// strictly above 0 (the first Solicit RT, §18.2.1).
    fn rand_of(&mut self, base: u64, positive: bool) -> i64 {
        let r = self.random();
        let permille = if positive {
            i64::try_from(r % 100).unwrap_or(0) + 1
        } else {
            i64::try_from(r % 201).unwrap_or(100) - 100
        };
        i64::try_from(base / 1_000)
            .unwrap_or(i64::MAX / 1_000)
            .saturating_mul(permille)
    }

    fn plus(base: u64, delta: i64) -> u64 {
        if delta >= 0 {
            base.saturating_add(delta.unsigned_abs())
        } else {
            base.saturating_sub(delta.unsigned_abs())
        }
    }

    /// RFC 8415 §15: the first RT (`irt` + RAND·`irt`), then
    /// 2·RTprev + RAND·RTprev, capped at `mrt` + RAND·`mrt`.
    fn next_rt(&mut self, irt: u64, mrt: u64, positive_first: bool) -> u64 {
        let rt = if self.rt == 0 {
            let d = self.rand_of(irt, positive_first);
            Self::plus(irt, d)
        } else {
            let d = self.rand_of(self.rt, false);
            Self::plus(self.rt.saturating_mul(2), d)
        };
        let rt = if mrt > 0 && rt > mrt {
            let d = self.rand_of(mrt, false);
            Self::plus(mrt, d)
        } else {
            rt
        };
        self.rt = rt.max(1);
        self.rt
    }

    fn new_exchange(&mut self, now: u64) {
        self.xid = (self.random() as u32) & 0x00ff_ffff;
        self.began = now;
        self.rt = 0;
        self.tries = 0;
    }

    fn drop_lease(&mut self, out: &mut Vec<Action>, reason: &str) {
        if let Some(l) = self.lease.take() {
            out.push(Action::Unbind);
            out.push(Action::Log(Event::Lost {
                what: what(l.address.map(|h| h.value), l.prefix.map(|h| h.value)),
                reason: reason.to_owned(),
            }));
        }
    }

    /// Start (or restart) at `now`: drop what we hold, then solicit after
    /// the random delay of §18.2.1.
    pub fn start(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        self.drop_lease(&mut out, "client restarted");
        let delay = self.random() % (SOL_MAX_DELAY_MS + 1);
        self.restart_at(now.saturating_add(delay));
        out.extend(self.poll(now));
        out
    }

    fn restart_at(&mut self, at: u64) {
        self.state = State::Init;
        self.deadline = at;
        self.offers.clear();
        self.chosen = None;
        self.refused.clear();
    }

    /// Stop: drop the lease (no Release) and go quiet.
    pub fn stop(&mut self, reason: &str) -> Vec<Action> {
        let mut out = Vec::new();
        self.drop_lease(&mut out, reason);
        self.state = State::Stopped;
        self.offers.clear();
        self.chosen = None;
        out
    }

    /// `ipv6.dhcp-client.renew`: renew now when bound, else start over.
    pub fn renew(&mut self, now: u64) -> Vec<Action> {
        match self.state {
            State::Bound | State::Renewing | State::Rebinding if self.lease.is_some() => {
                self.state = State::Renewing;
                self.new_exchange(now);
                self.deadline = now;
                self.poll(now)
            }
            _ => self.start(now),
        }
    }

    /// `ipv6.dhcp-client.release`: stop using the bindings, then Release
    /// them to the server (§18.2.7: the client MUST stop using them before
    /// sending) and start over once it answers or REL_MAX_RC tries pass.
    pub fn release(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(l) = self.lease.clone() else {
            return self.start(now);
        };
        self.drop_lease(&mut out, "released");
        self.chosen = Some(Offer {
            duid: l.server_duid.clone(),
            preference: 0,
            address: l.address.map(|h| h.value),
            prefix: l.prefix.map(|h| h.value),
        });
        self.state = State::Releasing;
        self.new_exchange(now);
        self.deadline = now;
        out.extend(self.poll(now));
        out
    }

    fn ias(
        &self,
        address: Option<Ipv6Addr>,
        prefix: Option<Ipv6Net>,
    ) -> (Option<IaReq>, Option<IaReq>) {
        let s = &self.settings;
        let na = s.address.then(|| IaReq {
            iaid: s.iaid,
            addrs: address.into_iter().collect(),
            prefixes: Vec::new(),
        });
        let pd = s.prefix.then(|| IaReq {
            iaid: s.iaid,
            addrs: Vec::new(),
            prefixes: prefix.into_iter().collect(),
        });
        (na, pd)
    }

    fn send(
        &mut self,
        out: &mut Vec<Action>,
        kind: u8,
        server: Option<&[u8]>,
        ias: (Option<IaReq>, Option<IaReq>),
        now: u64,
    ) {
        // §14.1: a client MUST rate-limit what it sends (a token bucket of
        // RATE_MAX per RATE_WINDOW_MS per interface).
        while self
            .sent
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= RATE_WINDOW_MS)
        {
            self.sent.pop_front();
        }
        if self.sent.len() >= RATE_MAX {
            if !self.throttled {
                self.throttled = true;
                out.push(Action::Log(Event::Error(format!(
                    "rate limit: more than {RATE_MAX} messages in {} s, holding back",
                    RATE_WINDOW_MS / 1_000
                ))));
            }
            return;
        }
        self.throttled = false;
        self.sent.push_back(now);
        // §21.9: hundredths of a second, 0xffff when longer.
        let elapsed = u16::try_from(now.saturating_sub(self.began) / 10).unwrap_or(u16::MAX);
        let oro: &[u16] = if kind == msg::RELEASE {
            &[]
        } else {
            &v6::REQUESTED
        };
        let m = Outgoing {
            kind,
            xid: self.xid,
            client_id: &self.settings.duid,
            server_id: server,
            elapsed_cs: elapsed,
            rapid_commit: kind == msg::SOLICIT && self.settings.rapid_commit,
            ia_na: ias.0,
            ia_pd: ias.1,
            oro,
        };
        out.push(Action::Send(m.encode()));
    }

    /// Fire the timers due at `now`.
    pub fn poll(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        match self.state {
            State::Stopped => {}
            State::Init if now >= self.deadline => {
                self.state = State::Soliciting;
                self.collected = false;
                self.offers.clear();
                self.new_exchange(now);
                out.push(Action::Log(Event::Searching));
                self.solicit(&mut out, now);
            }
            State::Soliciting if now >= self.deadline => {
                if !self.collected {
                    // End of the first RT: take the best Advertise, if any.
                    self.collected = true;
                    if let Some(best) = self.best() {
                        self.choose(&mut out, best, now);
                        return out;
                    }
                }
                self.tries = self.tries.saturating_add(1);
                self.solicit(&mut out, now);
            }
            State::Requesting if now >= self.deadline => {
                self.tries = self.tries.saturating_add(1);
                if self.tries >= REQ_MAX_RC {
                    // §18.2.2: the exchange failed; start over with Solicit.
                    self.refused_all(&mut out, now, "no Reply to REQ_MAX_RC Requests");
                    return out;
                }
                self.request(&mut out, now);
            }
            State::Releasing if now >= self.deadline => {
                if self.tries >= REL_MAX_RC {
                    self.restart_at(now);
                    return self.poll(now);
                }
                if let Some(o) = self.chosen.clone() {
                    let ias = self.ias(o.address, o.prefix);
                    self.send(&mut out, msg::RELEASE, Some(&o.duid), ias, now);
                }
                self.tries = self.tries.saturating_add(1);
                let rt = self.next_rt(REL_TIMEOUT_MS, 0, false);
                self.deadline = now.saturating_add(rt);
            }
            State::Bound | State::Renewing | State::Rebinding => self.lease_timers(&mut out, now),
            _ => {}
        }
        out
    }

    fn solicit(&mut self, out: &mut Vec<Action>, now: u64) {
        let hint = self.settings.prefix_hint;
        let ias = self.ias(None, hint);
        self.send(out, msg::SOLICIT, None, ias, now);
        let rt = self.next_rt(SOL_TIMEOUT_MS, self.sol_max_rt, true);
        self.deadline = now.saturating_add(rt);
    }

    fn request(&mut self, out: &mut Vec<Action>, now: u64) {
        let Some(o) = self.chosen.clone() else {
            self.restart_at(now);
            return;
        };
        let ias = self.ias(o.address, o.prefix);
        self.send(out, msg::REQUEST, Some(&o.duid), ias, now);
        let rt = self.next_rt(REQ_TIMEOUT_MS, REQ_MAX_RT_MS, false);
        self.deadline = now.saturating_add(rt);
    }

    fn best(&mut self) -> Option<Offer> {
        let mut best: Option<&Offer> = None;
        for o in &self.offers {
            if best.is_none_or(|b| o.score() > b.score()) {
                best = Some(o);
            }
        }
        best.cloned()
    }

    fn choose(&mut self, out: &mut Vec<Action>, o: Offer, now: u64) {
        self.chosen = Some(o);
        self.offers.clear();
        self.state = State::Requesting;
        self.new_exchange(now);
        self.request(out, now);
    }

    /// Nothing bound from this exchange: solicit again after 1, 2 … 64 s.
    fn refused_all(&mut self, out: &mut Vec<Action>, now: u64, why: &str) {
        self.refusals = self.refusals.saturating_add(1);
        let wait = (1_000u64 << self.refusals.min(6)).min(MAX_REFUSAL_WAIT_MS);
        if let Some(o) = &self.chosen {
            out.push(Action::Log(Event::Ignored {
                server: v6::hex(&o.duid),
                why: why.to_owned(),
            }));
        }
        self.drop_lease(out, why);
        self.restart_at(now.saturating_add(wait));
    }

    fn lease_timers(&mut self, out: &mut Vec<Action>, now: u64) {
        let Some(mut l) = self.lease.clone() else {
            self.restart_at(now);
            return;
        };
        // Bindings whose valid lifetime is over go away one by one.
        let mut gone = Vec::new();
        if let Some(a) = l.address.filter(|h| h.expires_ms.is_some_and(|e| now >= e)) {
            gone.push(format!("address {}", a.value));
            l.address = None;
        }
        if let Some(p) = l.prefix.filter(|h| h.expires_ms.is_some_and(|e| now >= e)) {
            gone.push(format!("prefix {}", p.value));
            l.prefix = None;
        }
        if !gone.is_empty() {
            if l.address.is_none() && l.prefix.is_none() {
                self.drop_lease(out, "valid lifetime over: no server renewed it");
                self.restart_at(now);
                out.extend(self.poll(now));
                return;
            }
            out.push(Action::Log(Event::Lost {
                what: gone.join(", "),
                reason: "valid lifetime over".into(),
            }));
            self.lease = Some(l.clone());
            out.push(Action::Bind(Box::new(l.clone())));
        }
        if self.state == State::Bound && now >= l.t1_ms {
            self.state = State::Renewing;
            self.new_exchange(now);
            self.deadline = now;
        }
        if self.state == State::Renewing && now >= l.t2_ms {
            // §18.2.5: Rebind to any server, a new transaction.
            self.state = State::Rebinding;
            self.new_exchange(now);
            self.deadline = now;
        }
        if self.state == State::Bound {
            self.deadline = l.t1_ms;
            return;
        }
        if now < self.deadline {
            return;
        }
        let ias = self.ias(l.address.map(|h| h.value), l.prefix.map(|h| h.value));
        match self.state {
            State::Renewing => {
                self.send(out, msg::RENEW, Some(&l.server_duid), ias, now);
                let rt = self.next_rt(REN_TIMEOUT_MS, REN_MAX_RT_MS, false);
                // MRD: the Renew exchange ends at T2.
                self.deadline = now.saturating_add(rt).min(l.t2_ms);
            }
            State::Rebinding => {
                self.send(out, msg::REBIND, None, ias, now);
                let rt = self.next_rt(REB_TIMEOUT_MS, REB_MAX_RT_MS, false);
                let end = l.expires_ms().unwrap_or(u64::MAX);
                self.deadline = now.saturating_add(rt).min(end);
            }
            _ => {}
        }
    }

    /// A datagram arrived on port 546.
    pub fn input(&mut self, now: u64, d: &Datagram6) -> Vec<Action> {
        let mut out = Vec::new();
        if self.state == State::Stopped || self.state == State::Init {
            return out;
        }
        let Ok(m) = v6::decode(&d.payload) else {
            return out;
        };
        // §16.10/16.11: our transaction, our Client Identifier, a Server
        // Identifier.
        if m.xid != self.xid || m.client_id.as_deref() != Some(self.settings.duid.as_slice()) {
            return out;
        }
        let Some(server) = m.server_id.clone() else {
            return out;
        };
        if m.reconfigure {
            return out;
        }
        if !(self.allowed)(&server, d.src, d.src_mac) {
            if !self.refused.contains(&server) && self.refused.len() < 16 {
                self.refused.push(server.clone());
                out.push(Action::Log(Event::Refused {
                    server: server_text(&server, d.src),
                }));
            }
            return out;
        }
        if let Some(rt) = m.sol_max_rt {
            self.sol_max_rt = u64::from(rt).saturating_mul(1_000);
        }
        match (self.state, m.kind) {
            (State::Soliciting, msg::ADVERTISE) => self.on_advertise(&mut out, now, &m, &server, d),
            (State::Soliciting, msg::REPLY) if m.rapid_commit && self.settings.rapid_commit => {
                // §18.2.1: a Rapid Commit Reply to our Solicit binds at once.
                self.on_reply(&mut out, now, &m, &server, d);
            }
            (State::Requesting, msg::REPLY) => {
                if self.chosen.as_ref().is_some_and(|o| o.duid == server) {
                    self.on_reply(&mut out, now, &m, &server, d);
                }
            }
            (State::Renewing, msg::REPLY) => {
                if self.lease.as_ref().is_some_and(|l| l.server_duid == server) {
                    self.on_reply(&mut out, now, &m, &server, d);
                }
            }
            (State::Rebinding, msg::REPLY) => self.on_reply(&mut out, now, &m, &server, d),
            (State::Releasing, msg::REPLY) => {
                self.restart_at(now);
                out.extend(self.poll(now));
            }
            _ => {}
        }
        out
    }

    /// Our IA in `ias`. RFC 9915 §21.4/§21.21: an IA with T1 > T2 (both
    /// non-zero) is discarded, as if the server had not sent it.
    fn ours<'a>(&self, ias: &'a [Ia]) -> Option<&'a Ia> {
        ias.iter()
            .find(|ia| ia.iaid == self.settings.iaid)
            .filter(|ia| !(ia.t1 > 0 && ia.t2 > 0 && ia.t1 > ia.t2))
    }

    fn on_advertise(
        &mut self,
        out: &mut Vec<Action>,
        now: u64,
        m: &Incoming,
        server: &[u8],
        d: &Datagram6,
    ) {
        let address = if self.settings.address {
            self.ours(&m.ia_na)
                .and_then(|ia| {
                    ia.addrs
                        .iter()
                        .find(|a| usable_address(a.addr).is_ok() && a.valid > 0)
                })
                .map(|a| a.addr)
        } else {
            None
        };
        let prefix = if self.settings.prefix {
            self.ours(&m.ia_pd)
                .and_then(|ia| {
                    ia.prefixes
                        .iter()
                        .find(|p| usable_prefix(p.prefix).is_ok() && p.valid > 0)
                })
                .map(|p| p.prefix)
        } else {
            None
        };
        // §18.2.9: an Advertise with no address and no prefix is ignored
        // (and one without both, when both are required).
        let short = self.settings.require_both && (address.is_none() || prefix.is_none());
        if address.is_none() && prefix.is_none() || short {
            let why = status_texts(m, self.settings.iaid);
            out.push(Action::Log(Event::Ignored {
                server: server_text(server, d.src),
                why: if why.is_empty() {
                    if short {
                        "Advertise without both an address and a prefix \
                         (accept-prefix-without-address=no)"
                            .into()
                    } else {
                        "Advertise without an address or a prefix".into()
                    }
                } else {
                    why
                },
            }));
            return;
        }
        let o = Offer {
            duid: server.to_vec(),
            preference: m.preference,
            address,
            prefix,
        };
        out.push(Action::Log(Event::Advertised {
            server: server_text(server, d.src),
            what: o.what(),
            preference: o.preference,
        }));
        // §18.2.9: preference 255 → at once; after the first RT, the first
        // Advertise is taken.
        if o.preference == 255 || self.collected {
            self.choose(out, o, now);
        } else if self.offers.len() < 16 {
            self.offers.push(o);
        }
    }

    fn on_reply(
        &mut self,
        out: &mut Vec<Action>,
        now: u64,
        m: &Incoming,
        server: &[u8],
        d: &Datagram6,
    ) {
        let st = m.status_code();
        let stext = || m.status.as_ref().map(|s| s.text()).unwrap_or_default();
        match st {
            status::SUCCESS => {}
            // §18.2.10: NotOnLink → start over with Solicit.
            status::NOT_ON_LINK => {
                out.push(Action::Log(Event::Status {
                    server: server_text(server, d.src),
                    text: stext(),
                }));
                self.drop_lease(out, "the server said NotOnLink");
                self.restart_at(now);
                out.extend(self.poll(now));
                return;
            }
            // UseMulticast: we always multicast; anything else: a failed
            // exchange (retransmission goes on).
            _ => {
                out.push(Action::Log(Event::Status {
                    server: server_text(server, d.src),
                    text: stext(),
                }));
                return;
            }
        }
        let na = self.ours(&m.ia_na).cloned();
        let pd = self.ours(&m.ia_pd).cloned();
        let renewing = matches!(self.state, State::Renewing | State::Rebinding);
        // §18.2.10.1: NoBinding in a Reply to Renew/Rebind → Request.
        let no_binding = [na.as_ref(), pd.as_ref()]
            .into_iter()
            .flatten()
            .any(|ia| ia.status_code() == status::NO_BINDING);
        if renewing && no_binding {
            out.push(Action::Log(Event::Status {
                server: server_text(server, d.src),
                text: "NoBinding: requesting again".into(),
            }));
            let held = self.lease.clone();
            self.chosen = Some(Offer {
                duid: server.to_vec(),
                preference: m.preference,
                address: held.as_ref().and_then(|l| l.address.map(|h| h.value)),
                prefix: held.as_ref().and_then(|l| l.prefix.map(|h| h.value)),
            });
            self.state = State::Requesting;
            self.new_exchange(now);
            self.request(out, now);
            return;
        }
        let old = self.lease.clone();
        let mut missing = Vec::new();
        let mut notes = Vec::new();
        let address = if self.settings.address {
            pick(na.as_ref(), "address", &mut missing, &mut notes, |ia| {
                ia.addrs
                    .iter()
                    .filter(|a| a.valid > 0)
                    .map(|a| {
                        usable_address(a.addr).map(|()| held(a.addr, a.preferred, a.valid, now))
                    })
                    .collect()
            })
        } else {
            None
        };
        let prefix = if self.settings.prefix {
            pick(pd.as_ref(), "prefix", &mut missing, &mut notes, |ia| {
                ia.prefixes
                    .iter()
                    .filter(|p| p.valid > 0)
                    .map(|p| {
                        usable_prefix(p.prefix).map(|()| held(p.prefix, p.preferred, p.valid, now))
                    })
                    .collect()
            })
        } else {
            None
        };
        for n in notes {
            out.push(Action::Log(Event::Ignored {
                server: server_text(server, d.src),
                why: n,
            }));
        }
        // While renewing, a binding the Reply leaves out stays until its
        // valid lifetime ends (§18.2.10.1); a zero valid lifetime removes it.
        let keep = |new: Option<Held<Ipv6Addr>>, old: Option<Held<Ipv6Addr>>, ia: Option<&Ia>| {
            new.or_else(|| old.filter(|_| renewing && !revoked_addr(ia, old)))
        };
        let address = keep(
            address.filter(|h| h.valid > 0),
            old.as_ref().and_then(|l| l.address),
            na.as_ref(),
        );
        let prefix = prefix.filter(|h| h.valid > 0).or_else(|| {
            old.as_ref().and_then(|l| l.prefix).filter(|_| {
                renewing && !revoked_prefix(pd.as_ref(), old.as_ref().and_then(|l| l.prefix))
            })
        });
        let short = self.settings.require_both && (address.is_none() || prefix.is_none());
        if address.is_none() && prefix.is_none() || short {
            let why = if missing.is_empty() {
                "the Reply grants nothing usable".to_owned()
            } else {
                missing.join("; ")
            };
            out.push(Action::Log(Event::Status {
                server: server_text(server, d.src),
                text: why.clone(),
            }));
            self.refused_all(out, now, &why);
            out.extend(self.poll(now));
            return;
        }
        let ias: Vec<&Ia> = [na.as_ref(), pd.as_ref()].into_iter().flatten().collect();
        let (t1, t2) = timers(&ias, address, prefix, now);
        let lease = Lease {
            server_duid: server.to_vec(),
            server_addr: d.src,
            server_mac: d.src_mac,
            address,
            prefix,
            dns: m.dns.clone(),
            domains: m.domains.clone(),
            granted_ms: now,
            t1_ms: t1,
            t2_ms: t2,
            missing,
            options: v6::raw_options(&d.payload),
        };
        self.refusals = 0;
        let same = old.as_ref().is_some_and(|o| {
            o.address.map(|h| h.value) == lease.address.map(|h| h.value)
                && o.prefix.map(|h| h.value) == lease.prefix.map(|h| h.value)
        });
        let event = if same && renewing {
            Event::Renewed {
                server: server_text(server, d.src),
                what: what(
                    lease.address.map(|h| h.value),
                    lease.prefix.map(|h| h.value),
                ),
            }
        } else {
            if let Some(o) = &old
                && !same
            {
                out.push(Action::Log(Event::Lost {
                    what: what(o.address.map(|h| h.value), o.prefix.map(|h| h.value)),
                    reason: "the server gave other bindings".into(),
                }));
            }
            Event::Bound {
                server: server_text(server, d.src),
                what: what(
                    lease.address.map(|h| h.value),
                    lease.prefix.map(|h| h.value),
                ),
            }
        };
        self.state = State::Bound;
        self.chosen = None;
        self.deadline = lease.t1_ms;
        self.lease = Some(lease.clone());
        out.push(Action::Bind(Box::new(lease)));
        out.push(Action::Log(event));
    }
}

fn revoked_addr(ia: Option<&Ia>, old: Option<Held<Ipv6Addr>>) -> bool {
    let (Some(ia), Some(old)) = (ia, old) else {
        return false;
    };
    ia.addrs.iter().any(|a| a.addr == old.value && a.valid == 0)
}

fn revoked_prefix(ia: Option<&Ia>, old: Option<Held<Ipv6Net>>) -> bool {
    let (Some(ia), Some(old)) = (ia, old) else {
        return false;
    };
    ia.prefixes
        .iter()
        .any(|p| p.prefix == old.value && p.valid == 0)
}

/// Pick the first usable entry of `ia`, noting why nothing was.
fn pick<T>(
    ia: Option<&Ia>,
    kind: &str,
    missing: &mut Vec<String>,
    notes: &mut Vec<String>,
    entries: impl Fn(&Ia) -> Vec<Result<Held<T>, String>>,
) -> Option<Held<T>> {
    let Some(ia) = ia else {
        missing.push(format!("no {kind}: the Reply has no IA for it"));
        return None;
    };
    if ia.status_code() != status::SUCCESS {
        let text = ia.status.as_ref().map(|s| s.text()).unwrap_or_default();
        missing.push(format!("no {kind}: {text}"));
        return None;
    }
    notes.extend(ia.dropped.iter().cloned());
    let all = entries(ia);
    let mut errors = Vec::new();
    for e in all {
        match e {
            Ok(h) => return Some(h),
            Err(why) => errors.push(why),
        }
    }
    match errors.first() {
        Some(why) => {
            notes.extend(errors.iter().cloned());
            missing.push(format!("no {kind}: {why}"));
        }
        None => missing.push(format!("no {kind} in the IA")),
    }
    None
}

fn held<T>(value: T, preferred: u32, valid: u32, now: u64) -> Held<T> {
    Held {
        value,
        preferred,
        valid,
        expires_ms: (valid != INFINITY)
            .then(|| now.saturating_add(u64::from(valid).saturating_mul(1_000))),
    }
}

/// Status codes of the message and of our IAs, for the history.
fn status_texts(m: &Incoming, iaid: u32) -> String {
    let mut out = Vec::new();
    if let Some(s) = &m.status {
        out.push(s.text());
    }
    for (kind, ias) in [("IA_NA", &m.ia_na), ("IA_PD", &m.ia_pd)] {
        for ia in ias.iter().filter(|ia| ia.iaid == iaid) {
            if let Some(s) = &ia.status {
                out.push(format!("{kind}: {}", s.text()));
            }
        }
    }
    out.join("; ")
}

/// T1/T2 of the bindings (ms since the epoch of `now`): the smallest
/// non-zero ones of the IAs; zero means the client picks 0.5 and 0.8 of
/// the shortest preferred lifetime (RFC 8415 §21.4, §21.21); T1 > T2 is
/// ignored the same way.
fn timers(
    ias: &[&Ia],
    address: Option<Held<Ipv6Addr>>,
    prefix: Option<Held<Ipv6Net>>,
    now: u64,
) -> (u64, u64) {
    let preferred = [address.map(|h| h.preferred), prefix.map(|h| h.preferred)]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(INFINITY);
    let valid = [address.map(|h| h.valid), prefix.map(|h| h.valid)]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(INFINITY);
    let mut t1 = u32::MAX;
    let mut t2 = u32::MAX;
    for ia in ias.iter().filter(|ia| ia.status_code() == status::SUCCESS) {
        if ia.t1 > 0 && ia.t2 > 0 && ia.t1 <= ia.t2 {
            t1 = t1.min(ia.t1);
            t2 = t2.min(ia.t2);
        }
    }
    if t1 == u32::MAX || t2 == u32::MAX {
        if preferred == INFINITY {
            return (u64::MAX, u64::MAX);
        }
        let p = u64::from(preferred);
        t1 = u32::try_from(p / 2).unwrap_or(u32::MAX);
        t2 = u32::try_from(p * 4 / 5).unwrap_or(u32::MAX);
    }
    if t1 == INFINITY {
        return (u64::MAX, u64::MAX);
    }
    // Never renew after the bindings are gone, nor in a storm.
    let valid_ms = u64::from(valid).saturating_mul(1_000);
    let mut t1_ms = u64::from(t1).saturating_mul(1_000);
    let mut t2_ms = u64::from(t2).saturating_mul(1_000);
    if valid != INFINITY {
        t2_ms = t2_ms.min(valid_ms.saturating_mul(7) / 8);
        t1_ms = t1_ms.min(valid_ms / 2);
    }
    let floor = if valid == INFINITY {
        MIN_T1_MS
    } else {
        MIN_T1_MS.min(valid_ms / 2)
    };
    t1_ms = t1_ms.max(floor);
    t2_ms = t2_ms.max(t1_ms);
    (now.saturating_add(t1_ms), now.saturating_add(t2_ms))
}

/// Whether a server may give us `ip` as an address.
pub fn usable_address(ip: Ipv6Addr) -> Result<(), String> {
    let first = ip.segments().first().copied().unwrap_or(0);
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || first & 0xffc0 == 0xfe80
        || ip.to_ipv4_mapped().is_some()
    {
        return Err(format!("unusable address {ip}"));
    }
    Ok(())
}

/// Whether a delegated prefix can number LANs: global, at most /64.
pub fn usable_prefix(p: Ipv6Net) -> Result<(), String> {
    let first = p.network().segments().first().copied().unwrap_or(0);
    if p.prefix_len() == 0
        || p.prefix_len() > 64
        || p.network().is_multicast()
        || p.network().is_loopback()
        || first & 0xffc0 == 0xfe80
    {
        return Err(format!(
            "unusable prefix {p} (a LAN needs a global /64 or shorter)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
