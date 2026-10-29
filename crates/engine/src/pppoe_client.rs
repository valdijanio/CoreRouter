//! PPPoE clients at run time (G3.9ga): one [`proto_pppoe::client::Client`]
//! per enabled `/interface pppoe-client` of the running config, on the port
//! the HAL opens for its Ethernet interface, driven by
//! [`Session::pppoe_client_service`] on the DHCP clients' clock (the app
//! calls it a few times a second).
//!
//! What a session brings — the address, the route to the BNG, the default
//! route and the DNS servers — is operational state, like a DHCP lease:
//! never in the config, shown with flag `D`, and given to the data plane
//! through [`Session::effective`]. The session's packets never pass here:
//! the HAL's relay carries them between the wire and the client's netdev.
//!
//! On top of the state machine (`docs/pppoe-client.md`):
//! - redial with back-off: 1 s doubling to 60 s with ±20 % jitter, and at
//!   least 30 s after the BNG refused the login, so a wrong password does
//!   not hammer the provider's BNG;
//! - PADT for the session a previous run left (RFC 2516 §5.5): the AC MAC
//!   and session id are kept in the storage while up, so after a reboot the
//!   BNG frees the stale session at once instead of after its keepalive;
//! - why the last session ended, as a code the UI explains.

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError};

use corerouter_hal::pppoe_client::{PppoeClientPort, PppoeLab, RelayCounters, SessionLink};
use corerouter_model::ppp::{Tri, UseIpv6};
use corerouter_model::pppoe_client::{Allow, PppoeClient};
use corerouter_model::route;
use corerouter_model::{
    AddressEntry, Config, Gateway, IfName, InterfaceKind, ItemId, RouteEntry, RoutingTable,
};
use corerouter_proto_pppoe::client::{
    self as pc, Client, ClientConfig, ClientDown, ClientEvent, ClientOutput, ClientPhase,
};
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::wire::Mac;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Session;

/// Ids of dynamic addresses and routes: `0xC8000000 | slot << 8 | n`.
pub const DYN_BASE: u32 = 0xC800_0000;
/// Events kept for `interface.pppoe-client.history` (a ring).
pub const MAX_HISTORY: usize = 256;
/// Clients run at once (the slot space of the ids is 2^18; a router dials
/// a handful of uplinks).
pub const MAX_CLIENTS: usize = 64;
/// Control frames read per client per service call (a flood cannot stall
/// the session lock).
const RECV_BUDGET: usize = 64;
/// Receive/send rounds per call: the lab answers at once, so a whole
/// Discovery…IPCP exchange fits in one call there.
const ROUNDS: usize = 12;
/// Retry opening a port that failed (interface missing in the kernel…).
const PORT_RETRY_MS: u64 = 10_000;
/// Redial back-off (G3.9ga): first wait, cap, and the floor after the BNG
/// refused the login (VyOS `holdoff` is 30 s).
const BACKOFF_MIN_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 60_000;
const BACKOFF_AUTH_MS: u64 = 30_000;
/// The storage state with the sessions to close on the next start.
pub const STALE_STATE: &str = "pppoe-client-sessions";

/// Whether `id` names an address or route a PPPoE client installed.
pub fn is_dynamic(id: ItemId) -> bool {
    id.0 & 0xFC00_0000 == DYN_BASE
}

fn dyn_id(slot: u32, n: usize) -> ItemId {
    let n = u32::try_from(n).unwrap_or(0xFF) & 0xFF;
    ItemId(DYN_BASE | ((slot & 0x3_FFFF) << 8) | n)
}

/// A session a previous run left up (RFC 2516 §5.5: close it with PADT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stale {
    pub interface: IfName,
    pub mac: [u8; 6],
    pub ac_mac: [u8; 6],
    pub session_id: u16,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StaleFile {
    sessions: BTreeMap<IfName, Stale>,
}

/// One line of the history.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub seq: u64,
    pub time: Option<u64>,
    pub name: IfName,
    /// `dialing`, `connected`, `down`, `error`, `padt-stale`.
    pub event: &'static str,
    pub message: String,
}

/// Why the last session ended, for `monitor` and the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastDown {
    /// `no-offer`, `service-error`, `ac-error`, `padt`, `lcp`,
    /// `auth-failed`, `ncp`, `keepalive`, `local`.
    pub reason: &'static str,
    /// The BNG's own words, when it gave any (PAP/CHAP failure message).
    pub message: Option<String>,
    pub time: Option<u64>,
    /// How long it had been up (0 when it never came up).
    pub uptime_secs: u64,
}

fn reason_code(r: ClientDown) -> &'static str {
    match r {
        ClientDown::NoOffer => "no-offer",
        ClientDown::ServiceError => "service-error",
        ClientDown::AcSystemError => "ac-error",
        ClientDown::Padt => "padt",
        ClientDown::LcpFailed => "lcp",
        ClientDown::AuthFailed => "auth-failed",
        ClientDown::NcpFailed => "ncp",
        ClientDown::Keepalive => "keepalive",
        ClientDown::Local => "local",
    }
}

/// English for the log (the UI explains the code in the operator's language).
fn reason_text(r: ClientDown) -> &'static str {
    match r {
        ClientDown::NoOffer => "no PPPoE server answered (no PADO)",
        ClientDown::ServiceError => "the server does not offer the service-name asked for",
        ClientDown::AcSystemError => "the server refused the session (AC-System-Error)",
        ClientDown::Padt => "the server ended the session (PADT)",
        ClientDown::LcpFailed => "LCP negotiation failed or the server closed the link",
        ClientDown::AuthFailed => "the server refused the login (user or password)",
        ClientDown::NcpFailed => "IPCP failed (no address from the server)",
        ClientDown::Keepalive => "the server stopped answering LCP echoes",
        ClientDown::Local => "closed by this router",
    }
}

/// Up session facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpInfo {
    pub session_id: u16,
    pub ac_mac: [u8; 6],
    pub ac_name: String,
    pub local: Ipv4Addr,
    pub remote: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: u16,
    pub mru: u16,
    /// RouterOS `encoding`: `mschap2`, `mschap1`, `chap`, `pap` or `none`.
    pub auth: &'static str,
    pub since_ms: u64,
    pub since_unix: Option<u64>,
}

/// The concentrator a session talked to: from its offer (PADO/PADS) and
/// LCP, known before authentication. Kept after the session ends, so a
/// refused login still shows which BNG refused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub ac_name: String,
    pub ac_mac: [u8; 6],
    /// 0 until the PADS came.
    pub session_id: u16,
    /// The authentication LCP agreed on, if it got that far.
    pub auth: Option<&'static str>,
}

/// RouterOS `encoding` of an authentication protocol.
fn auth_name(p: Option<AuthProto>) -> &'static str {
    match p {
        Some(AuthProto::MsChapV2) => "mschap2",
        Some(AuthProto::MsChapV1) => "mschap1",
        Some(AuthProto::ChapMd5) => "chap",
        Some(AuthProto::Pap) => "pap",
        None => "none",
    }
}

/// The BNG `c` is talking to, once it took an offer.
fn peer_of(c: &Client) -> Option<Peer> {
    let mac = c.ac_mac().0;
    if mac == [0xff; 6] || mac == [0; 6] {
        return None;
    }
    Some(Peer {
        ac_name: c
            .ac_name()
            .map(|n| String::from_utf8_lossy(n).chars().take(64).collect())
            .unwrap_or_default(),
        ac_mac: mac,
        session_id: c.session_id(),
        auth: c.auth_proto().map(|a| auth_name(Some(a))),
    })
}

/// One client at run time.
pub(crate) struct Runner {
    slot: u32,
    /// The settings it runs with (a change restarts it).
    pub(crate) cfg: PppoeClient,
    password: String,
    port: Option<Box<dyn PppoeClientPort>>,
    client: Option<Client>,
    out: ClientOutput,
    pub(crate) error: Option<String>,
    /// Next port open or redial.
    retry_at: u64,
    /// Sessions that ended without coming up, or failed, in a row.
    pub(crate) failures: u32,
    pub(crate) up: Option<UpInfo>,
    pub(crate) last_down: Option<LastDown>,
    /// The BNG of the last session that reached one (up or not).
    pub(crate) last_peer: Option<Peer>,
    pub(crate) addresses: Vec<AddressEntry>,
    pub(crate) routes: Vec<RouteEntry>,
    /// Jitter source (xorshift).
    rng: u64,
}

impl Runner {
    /// `dialing`, `connecting`, `authenticating`, `connected`,
    /// `disconnected` (waiting to redial), `error` (no port).
    pub(crate) fn status(&self) -> &'static str {
        if self.port.is_none() {
            return "error";
        }
        match self.client.as_ref().map(Client::phase) {
            Some(ClientPhase::Discovering | ClientPhase::Requesting) => "dialing",
            Some(ClientPhase::Establish) => "connecting",
            Some(ClientPhase::Authenticate) => "authenticating",
            Some(ClientPhase::Network) => "connecting",
            Some(ClientPhase::Up) => "connected",
            Some(ClientPhase::Terminate) => "disconnecting",
            Some(ClientPhase::Idle | ClientPhase::Closed(_)) | None => "disconnected",
        }
    }

    /// Milliseconds until the next redial, while waiting for one.
    pub(crate) fn retry_in(&self, now: u64) -> Option<u64> {
        let waiting = self.port.is_none()
            || self
                .client
                .as_ref()
                .is_none_or(|c| matches!(c.phase(), ClientPhase::Closed(_) | ClientPhase::Idle));
        waiting.then(|| self.retry_at.saturating_sub(now))
    }

    pub(crate) fn counters(&self) -> RelayCounters {
        self.port.as_ref().map(|p| p.counters()).unwrap_or_default()
    }

    fn jitter(&mut self) -> u64 {
        let mut x = self.rng.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// The wait before redial number `failures` (≥ 1).
    fn backoff(&mut self, reason: ClientDown) -> u64 {
        let exp = self.failures.saturating_sub(1).min(16);
        let base = BACKOFF_MIN_MS
            .saturating_mul(1u64 << exp)
            .min(BACKOFF_MAX_MS);
        let base = if reason == ClientDown::AuthFailed {
            base.max(BACKOFF_AUTH_MS)
        } else {
            base
        };
        // ±20 %: CPEs that lost the BNG together do not redial together.
        let spread = base / 5;
        let j = self.jitter() % (2 * spread + 1);
        base - spread + j
    }
}

/// The session's PPPoE clients at run time.
#[derive(Default)]
pub struct PppoeClients {
    pub(crate) runners: BTreeMap<IfName, Runner>,
    history: VecDeque<HistoryEntry>,
    seq: u64,
    stale: BTreeMap<IfName, Stale>,
    loaded: bool,
    pub(crate) now_ms: Option<u64>,
}

impl PppoeClients {
    pub fn history(&self) -> impl DoubleEndedIterator<Item = &HistoryEntry> {
        self.history.iter()
    }
}

/// What a runner asks the session for after a step.
enum Act {
    Up(UpInfo),
    Down(ClientDown, Option<String>),
    Log(&'static str, String),
}

/// The settings of client `name` if `cfg` runs it (enabled, both
/// interfaces up).
fn wanted(cfg: &Config) -> Vec<(IfName, PppoeClient)> {
    cfg.interfaces
        .values()
        .filter_map(|i| match &i.kind {
            InterfaceKind::PppoeClient(c)
                if !i.disabled && route::is_up(cfg, &i.name) && route::is_up(cfg, &c.interface) =>
            {
                Some((i.name.clone(), (**c).clone()))
            }
            _ => None,
        })
        .take(MAX_CLIENTS)
        .collect()
}

fn auth_set(allow: &[Allow]) -> AuthSet {
    let list: Vec<AuthProto> = allow
        .iter()
        .map(|a| match a {
            Allow::Mschap2 => AuthProto::MsChapV2,
            Allow::Mschap1 => AuthProto::MsChapV1,
            Allow::Chap => AuthProto::ChapMd5,
            Allow::Pap => AuthProto::Pap,
        })
        .collect();
    AuthSet::new(&list)
}

/// `host_uniq` hex as bytes (checked by the command).
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if !s.len().is_multiple_of(2) || s.len() > 64 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

/// The `ClientConfig` of `c` on a port with MAC `mac`.
fn client_config(c: &PppoeClient, password: &str, mac: [u8; 6], ipv6: bool, seed: u64) -> ClientConfig {
    // RouterOS `keepalive-timeout`: the link is down that long after the
    // last answer. Echo every timeout/3 with 3 misses tolerated.
    let (interval, misses) = match c.keepalive_timeout {
        0 => (0, 0),
        t => ((u64::from(t) * 1000 / 3).max(1000), 3),
    };
    let host_uniq = parse_hex(&c.host_uniq)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| seed.to_be_bytes().to_vec());
    ClientConfig {
        mac: Mac(mac),
        ifindex: 1,
        service_name: c.service_name.as_bytes().to_vec(),
        ac_name: c.ac_name.as_bytes().to_vec(),
        host_uniq: Some(host_uniq),
        username: c.user.as_bytes().to_vec(),
        password: password.to_owned(),
        auth: auth_set(&c.allow),
        mru: c.max_mru,
        mtu: c.max_mtu,
        // RFC 4638 only when the operator asked for more than 1492.
        max_payload: (c.max_mtu > corerouter_model::pppoe_client::MAX_MTU).then_some(c.max_mtu),
        want_dns: true,
        ipv6,
        ipv6_iid: None,
        // RFC 2516 §8 retransmission (doubling), then the back-off above.
        discovery_timeout_ms: 1000,
        discovery_attempts: 4,
        discovery_jitter_pct: 10,
        keepalive_interval_ms: interval,
        keepalive_misses: misses,
        ..ClientConfig::default()
    }
}

fn seed32(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    if crate::auth::random_bytes(&mut out).is_err() {
        // The browser lab has no random source: good enough to tell runs
        // apart, nothing there talks to a real BNG.
        for (i, b) in out.iter_mut().enumerate() {
            *b = (seed.rotate_left(i as u32 * 8) & 0xFF) as u8 ^ i as u8;
        }
    }
    out
}

impl Runner {
    /// Feed received frames and timers to the client; send what it wants.
    fn step(&mut self, now: u64, acts: &mut Vec<Act>) {
        let (Some(port), Some(client)) = (self.port.as_mut(), self.client.as_mut()) else {
            return;
        };
        let mut errors = Vec::new();
        for _ in 0..ROUNDS {
            let mut busy = false;
            for _ in 0..RECV_BUDGET {
                match port.recv() {
                    Ok(Some(f)) => {
                        client.handle_frame(now, &f, &mut self.out);
                        busy = true;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        errors.push(format!("receive: {e}"));
                        break;
                    }
                }
            }
            client.handle_timers(now, &mut self.out);
            for (_, f) in self.out.frames() {
                busy = true;
                if let Err(e) = port.send(f) {
                    errors.push(format!("send: {e}"));
                }
            }
            for ev in self.out.events.drain(..) {
                match ev {
                    ClientEvent::Up { sid, ac_mac, ipv4, dns } => {
                        let Some(local) = ipv4 else { continue };
                        let (mtu, mru) = client.mtu_mru();
                        acts.push(Act::Up(UpInfo {
                            session_id: sid,
                            ac_mac: ac_mac.0,
                            ac_name: client
                                .ac_name()
                                .map(|n| String::from_utf8_lossy(n).chars().take(64).collect())
                                .unwrap_or_default(),
                            local,
                            remote: client.peer_ipv4(),
                            dns: dns.into_iter().flatten().collect(),
                            mtu,
                            mru,
                            auth: auth_name(client.auth_proto()),
                            since_ms: now,
                            since_unix: None,
                        }));
                    }
                    ClientEvent::Down { reason } => {
                        if let Some(p) = peer_of(client) {
                            self.last_peer = Some(p);
                        }
                        acts.push(Act::Down(reason, client.auth_message().map(str::to_owned)));
                    }
                }
            }
            self.out.clear();
            if !busy {
                break;
            }
        }
        // Say each error once, not every frame.
        errors.dedup();
        for e in errors {
            if self.error.as_deref() != Some(e.as_str()) {
                self.error = Some(e.clone());
                acts.push(Act::Log("error", e));
            }
        }
    }
}

impl Session {
    fn ppp_rt(&mut self) -> Option<&mut PppoeClients> {
        self.ext_mut::<PppoeClients>()
    }

    /// The runtime, read-only (commands).
    pub(crate) fn pppoe_clients(&self) -> Option<&PppoeClients> {
        self.ext::<PppoeClients>()
    }

    /// Whether no client has anything installed (`effective` stays borrowed).
    pub(crate) fn pppoe_client_quiet(&self) -> bool {
        self.pppoe_clients().is_none_or(|rt| {
            rt.runners
                .values()
                .all(|r| r.addresses.is_empty() && r.routes.is_empty())
        })
    }

    /// Add what the sessions brought to `out` (clients `cfg` still runs).
    pub(crate) fn pppoe_client_extend(&self, cfg: &Config, out: &mut Config) {
        let Some(rt) = self.pppoe_clients() else { return };
        for (name, r) in &rt.runners {
            let live = matches!(
                cfg.interfaces.get(name).map(|i| (&i.kind, i.disabled)),
                Some((InterfaceKind::PppoeClient(c), false)) if c.interface == r.cfg.interface
            );
            if live {
                out.ip.addresses.extend(r.addresses.iter().cloned());
                out.ip.routes.extend(r.routes.iter().cloned());
            }
        }
    }

    /// DNS servers of the clients with `use_peer_dns`, without repeats.
    pub fn pppoe_peer_dns(&self) -> Vec<Ipv4Addr> {
        let mut out: Vec<Ipv4Addr> = Vec::new();
        if let Some(rt) = self.pppoe_clients() {
            for r in rt.runners.values().filter(|r| r.cfg.use_peer_dns) {
                for d in r.up.iter().flat_map(|u| u.dns.iter()) {
                    if !out.contains(d) {
                        out.push(*d);
                    }
                }
            }
        }
        out
    }

    /// Drive the PPPoE clients: start and stop them as the running config
    /// says, read their ports, fire their timers, install and remove what
    /// their sessions bring. `now_ms`: a monotonic clock.
    pub fn pppoe_client_service(&mut self, now_ms: u64) {
        let Some(rt) = self.ppp_rt() else { return };
        rt.now_ms = Some(now_ms);
        self.pppoe_load_stale();
        self.pppoe_reconcile(now_ms);
        let names: Vec<IfName> = self
            .pppoe_clients()
            .map(|rt| rt.runners.keys().cloned().collect())
            .unwrap_or_default();
        for name in names {
            self.pppoe_step(&name, now_ms);
        }
    }

    fn pppoe_step(&mut self, name: &IfName, now: u64) {
        let mut acts = Vec::new();
        let mut open = false;
        let mut dial = false;
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            if r.port.is_none() && r.retry_at <= now {
                open = true;
            } else if r.port.is_some() && r.retry_in(now) == Some(0) {
                dial = true;
            }
        }
        if open {
            self.pppoe_open(name, now);
            dial = self
                .pppoe_clients()
                .and_then(|rt| rt.runners.get(name))
                .is_some_and(|r| r.port.is_some());
        }
        if dial {
            self.pppoe_dial(name, now);
        }
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            r.step(now, &mut acts);
        }
        for a in acts {
            match a {
                Act::Up(info) => self.pppoe_up(name, info),
                Act::Down(reason, msg) => self.pppoe_down(name, now, reason, msg),
                Act::Log(event, msg) => self.pppoe_note(name, event, msg),
            }
        }
    }

    fn pppoe_open(&mut self, name: &IfName, now: u64) {
        let Some(uplink) = self
            .pppoe_clients()
            .and_then(|rt| rt.runners.get(name))
            .map(|r| r.cfg.interface.clone())
        else {
            return;
        };
        let opened = self.hal_mut().pppoe_client_port(name, &uplink);
        let stale = self
            .ppp_rt()
            .and_then(|rt| rt.stale.get(name).cloned())
            .filter(|s| s.interface == uplink);
        let mut note = None;
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            match opened {
                Ok(mut p) => {
                    // RFC 2516 §5.5: close what a previous run left up.
                    if let Some(s) = stale.as_ref().filter(|s| s.mac == p.mac()) {
                        let mut out = ClientOutput::new();
                        pc::padt(
                            Mac(s.mac),
                            Mac(s.ac_mac),
                            corerouter_proto_pppoe::eth::Vlans::NONE,
                            s.session_id,
                            1,
                            &mut out,
                        );
                        for (_, f) in out.frames() {
                            let _ = p.send(f);
                        }
                        note = Some((
                            "padt-stale",
                            format!(
                                "closed session {} left by the previous run (PADT to {})",
                                s.session_id,
                                Mac(s.ac_mac)
                            ),
                        ));
                    }
                    r.port = Some(p);
                    r.error = None;
                    r.retry_at = now;
                }
                Err(e) => {
                    let msg = format!("cannot open '{uplink}': {e}");
                    r.retry_at = now.saturating_add(PORT_RETRY_MS);
                    if r.error.as_deref() != Some(msg.as_str()) {
                        r.error = Some(msg.clone());
                        note = Some(("error", msg));
                    }
                }
            }
        }
        if let Some((event, msg)) = note {
            if event == "padt-stale" {
                self.pppoe_forget_stale(name);
            }
            self.pppoe_note(name, event, msg);
        }
    }

    fn pppoe_dial(&mut self, name: &IfName, now: u64) {
        let running = self.store().running();
        let profile = self
            .pppoe_clients()
            .and_then(|rt| rt.runners.get(name))
            .and_then(|r| running.ppp.profile(&r.cfg.profile));
        let ipv6 = profile.as_ref().is_some_and(|p| matches!(p.use_ipv6, UseIpv6::Yes | UseIpv6::Require));
        let mut msg = None;
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            let Some(mac) = r.port.as_ref().map(|p| p.mac()) else { return };
            let seed = u64::from(r.slot).rotate_left(40) ^ now ^ u64::from(r.failures);
            let cfg = client_config(&r.cfg, &r.password, mac, ipv6, seed);
            let mut c = Client::new(cfg, seed32(seed));
            c.start(now, &mut r.out);
            r.client = Some(c);
            r.retry_at = u64::MAX;
            msg = Some(format!(
                "dialing on {} as '{}'{}",
                r.cfg.interface,
                r.cfg.user,
                if r.failures > 0 {
                    format!(" (attempt {})", r.failures + 1)
                } else {
                    String::new()
                }
            ));
        }
        if let Some(m) = msg {
            self.pppoe_note(name, "dialing", m);
        }
    }

    /// What session `info` of runner `r` installs: our address, the route
    /// to the BNG and, with `add_default_route`, the default route.
    fn pppoe_entries(name: &IfName, r: &Runner, info: &UpInfo, table: RoutingTable) -> (Vec<AddressEntry>, Vec<RouteEntry>) {
        let address = AddressEntry {
            id: dyn_id(r.slot, 0),
            address: IpNet::V4(Ipv4Net::new(info.local, 32).unwrap_or_default()),
            interface: name.clone(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        };
        let route = |n: usize, dst: Ipv4Net, distance: u8| RouteEntry {
            id: dyn_id(r.slot, n),
            dst_address: IpNet::V4(dst),
            gateway: Gateway::interface(name.clone()),
            distance,
            routing_table: table.clone(),
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        };
        let mut routes = Vec::new();
        // The point-to-point peer (RouterOS lists it as the address' network).
        if let Some(peer) = info.remote.filter(|p| *p != info.local)
            && let Ok(dst) = Ipv4Net::new(peer, 32)
        {
            routes.push(route(1, dst, 0));
        }
        if r.cfg.add_default_route {
            routes.push(route(2, Ipv4Net::default(), r.cfg.default_route_distance.max(1)));
        }
        (vec![address], routes)
    }

    fn pppoe_up(&mut self, name: &IfName, mut info: UpInfo) {
        info.since_unix = self.now();
        let running = self.store().running().clone();
        let table = route::table_of(&running, name);
        let before = self.effective(&running).into_owned();
        let clamp = {
            let Some(r) = self.pppoe_clients().and_then(|rt| rt.runners.get(name)) else { return };
            let profile = running.ppp.profile(&r.cfg.profile);
            // RouterOS `change-tcp-mss` (built-in `default`: yes).
            (profile.is_none_or(|p| p.change_tcp_mss != Tri::No)).then_some(info.mtu)
        };
        let mut port_error = None;
        let mut stale = None;
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            let (a, routes) = Self::pppoe_entries(name, r, &info, table);
            r.addresses = a;
            r.routes = routes;
            r.failures = 0;
            r.error = None;
            if let Some(p) = r.port.as_mut() {
                stale = Some(Stale {
                    interface: r.cfg.interface.clone(),
                    mac: p.mac(),
                    ac_mac: info.ac_mac,
                    session_id: info.session_id,
                });
                if let Err(e) = p.set_session(Some(SessionLink {
                    session_id: info.session_id,
                    ac_mac: info.ac_mac,
                    clamp_mtu: clamp,
                })) {
                    port_error = Some(format!("relay not started: {e}"));
                }
            }
            r.up = Some(info.clone());
        }
        if let Some(s) = stale {
            self.pppoe_remember_stale(name, s);
        }
        let after = self.effective(&running).into_owned();
        let applied = if before == after {
            Ok(())
        } else {
            self.hal_mut().apply(&before, &after)
        };
        let msg = format!(
            "connected to {} ({}), session {}, address {}{}, mtu {}",
            if info.ac_name.is_empty() { "?" } else { info.ac_name.as_str() },
            Mac(info.ac_mac),
            info.session_id,
            info.local,
            info.remote.map(|p| format!(" peer {p}")).unwrap_or_default(),
            info.mtu
        );
        self.pppoe_note(name, "connected", msg);
        if let Err(e) = applied {
            let e = format!("session up but not applied: {e}");
            if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
                r.error = Some(e.clone());
            }
            self.pppoe_note(name, "error", e);
        }
        if let Some(e) = port_error {
            self.pppoe_note(name, "error", e);
        }
    }

    /// Take away what client `name` installed (session down or stopped).
    fn pppoe_uninstall(&mut self, name: &IfName) {
        let running = self.store().running().clone();
        let before = self.effective(&running).into_owned();
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            r.addresses.clear();
            r.routes.clear();
            r.up = None;
            if let Some(p) = r.port.as_mut() {
                let _ = p.set_session(None);
            }
        }
        let after = self.effective(&running).into_owned();
        if before != after
            && let Err(e) = self.hal_mut().apply(&before, &after)
        {
            log::warn!("pppoe-client {name}: removing the session's routes: {e}");
        }
    }

    fn pppoe_down(&mut self, name: &IfName, now: u64, reason: ClientDown, message: Option<String>) {
        let uptime = self
            .pppoe_clients()
            .and_then(|rt| rt.runners.get(name))
            .and_then(|r| r.up.as_ref())
            .map_or(0, |u| now.saturating_sub(u.since_ms) / 1000);
        self.pppoe_uninstall(name);
        self.pppoe_forget_stale(name);
        let time = self.now();
        let mut wait = 0;
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) {
            // A session that held for a minute starts the back-off over.
            if uptime >= 60 {
                r.failures = 0;
            }
            r.failures = r.failures.saturating_add(1);
            wait = r.backoff(reason);
            r.retry_at = now.saturating_add(wait);
            r.last_down = Some(LastDown {
                reason: reason_code(reason),
                message: message.clone(),
                time,
                uptime_secs: uptime,
            });
        }
        let said = message.map(|m| format!(" — server said: {m}")).unwrap_or_default();
        self.pppoe_note(
            name,
            "down",
            format!(
                "{}{said}; redialing in {} s",
                reason_text(reason),
                wait.div_ceil(1000)
            ),
        );
    }

    /// Make the runners match the running config.
    fn pppoe_reconcile(&mut self, now: u64) {
        let want = wanted(self.store().running());
        let gone: Vec<IfName> = self
            .pppoe_clients()
            .map(|rt| {
                rt.runners
                    .iter()
                    .filter(|(n, r)| !want.iter().any(|(w, c)| w == *n && *c == r.cfg))
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default();
        for name in gone {
            self.pppoe_stop(&name, now);
        }
        let key = want
            .iter()
            .any(|(n, _)| self.pppoe_clients().is_none_or(|rt| !rt.runners.contains_key(n)))
            .then(|| crate::sealing::key(self).ok())
            .flatten();
        for (name, c) in want {
            let Some(rt) = self.ppp_rt() else { return };
            if rt.runners.contains_key(&name) {
                continue;
            }
            let slot = (0..u32::try_from(MAX_CLIENTS).unwrap_or(64))
                .find(|s| rt.runners.values().all(|r| r.slot != *s))
                .unwrap_or(0);
            let password = crate::sealing::open_with(key.as_deref(), &c.password).unwrap_or_default();
            rt.runners.insert(
                name,
                Runner {
                    slot,
                    cfg: c,
                    password,
                    port: None,
                    client: None,
                    out: ClientOutput::new(),
                    error: None,
                    retry_at: now,
                    failures: 0,
                    up: None,
                    last_down: None,
                    last_peer: None,
                    addresses: Vec::new(),
                    routes: Vec::new(),
                    rng: now ^ (u64::from(slot) << 32) ^ 0x9E37_79B9_7F4A_7C15,
                },
            );
        }
    }

    /// Stop client `name`: PADT (or LCP Terminate) to the BNG, routes out.
    fn pppoe_stop(&mut self, name: &IfName, now: u64) {
        if let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name))
            && let (Some(c), Some(p)) = (r.client.as_mut(), r.port.as_mut())
        {
            // RFC 2516 §5.5: PADT at once; the BNG frees the session now.
            c.abort(&mut r.out);
            for (_, f) in r.out.frames() {
                let _ = p.send(f);
            }
            r.out.clear();
        }
        self.pppoe_uninstall(name);
        self.pppoe_forget_stale(name);
        let _ = now;
        if let Some(rt) = self.ppp_rt() {
            rt.runners.remove(name);
        }
    }

    /// Drop the session of `name` and dial again at once
    /// (`interface.pppoe-client.reconnect`). `false`: not running.
    pub(crate) fn pppoe_reconnect(&mut self, name: &IfName) -> bool {
        let now = self
            .pppoe_clients()
            .and_then(|rt| rt.now_ms)
            .unwrap_or_default();
        let Some(r) = self.ppp_rt().and_then(|rt| rt.runners.get_mut(name)) else {
            return false;
        };
        let was_up = r.up.is_some();
        if let (Some(c), Some(p)) = (r.client.as_mut(), r.port.as_mut()) {
            c.abort(&mut r.out);
            for (_, f) in r.out.frames() {
                let _ = p.send(f);
            }
            r.out.clear();
        }
        r.client = None;
        r.failures = 0;
        r.retry_at = now;
        if was_up {
            self.pppoe_uninstall(name);
        }
        self.pppoe_forget_stale(name);
        self.pppoe_note(name, "down", "reconnect asked by the operator".into());
        true
    }

    pub(crate) fn pppoe_note(&mut self, name: &IfName, event: &'static str, message: String) {
        match event {
            "error" | "down" => log::warn!("pppoe-client {name}: {message}"),
            _ => log::info!("pppoe-client {name}: {message}"),
        }
        let level = if matches!(event, "error" | "down") { "warning" } else { "info" };
        self.log_event(
            &["ppp", level],
            crate::logging::DAEMON,
            format!("pppoe-client {name}: {message}"),
            json!({"interface": name, "event": event}),
        );
        let time = self.now();
        let Some(rt) = self.ppp_rt() else { return };
        rt.seq = rt.seq.saturating_add(1);
        rt.history.push_back(HistoryEntry {
            seq: rt.seq,
            time,
            name: name.clone(),
            event,
            message,
        });
        while rt.history.len() > MAX_HISTORY {
            rt.history.pop_front();
        }
    }

    fn pppoe_load_stale(&mut self) {
        if self.pppoe_clients().is_some_and(|rt| rt.loaded) {
            return;
        }
        if let Some(rt) = self.ppp_rt() {
            rt.loaded = true;
        }
        let text = match self.storage_mut().load_state(STALE_STATE) {
            Ok(Some(t)) => t,
            Ok(None) => return,
            Err(e) => {
                log::warn!("pppoe-client: sessions of the previous run not read: {e}");
                return;
            }
        };
        match serde_json::from_str::<StaleFile>(&text) {
            Ok(f) => {
                if let Some(rt) = self.ppp_rt() {
                    rt.stale = f.sessions.into_iter().take(MAX_CLIENTS).collect();
                }
            }
            Err(e) => log::warn!("pppoe-client: {STALE_STATE} unreadable, ignored: {e}"),
        }
    }

    fn pppoe_save_stale(&mut self) {
        let Some(sessions) = self.pppoe_clients().map(|rt| rt.stale.clone()) else { return };
        let saved = serde_json::to_string(&StaleFile { sessions })
            .map_err(|e| e.to_string())
            .and_then(|t| {
                self.storage_mut()
                    .save_state(STALE_STATE, &t)
                    .map_err(|e| e.to_string())
            });
        if let Err(e) = saved {
            log::warn!("pppoe-client: session not remembered: {e}");
        }
    }

    fn pppoe_remember_stale(&mut self, name: &IfName, s: Stale) {
        if let Some(rt) = self.ppp_rt() {
            if rt.stale.get(name) == Some(&s) {
                return;
            }
            rt.stale.insert(name.clone(), s);
        }
        self.pppoe_save_stale();
    }

    fn pppoe_forget_stale(&mut self, name: &IfName) {
        let had = self
            .ppp_rt()
            .is_some_and(|rt| rt.stale.remove(name).is_some());
        if had {
            self.pppoe_save_stale();
        }
    }

    /// `interface.pppoe-client.monitor` of one client (`None`: not running).
    pub(crate) fn pppoe_monitor(&self, name: &IfName) -> Option<Value> {
        let rt = self.pppoe_clients()?;
        let r = rt.runners.get(name)?;
        let now = rt.now_ms.unwrap_or_default();
        Some(monitor_json(r, now))
    }
}

/// `monitor` fields (RouterOS names) of runner `r` at `now`.
pub(crate) fn monitor_json(r: &Runner, now: u64) -> Value {
    let c = r.counters();
    // The BNG: of the session up, else of the one being negotiated (after
    // its offer), else of the last attempt that reached one: a refused
    // login still says who refused it (and its session id, for its logs).
    let peer = match &r.up {
        Some(u) => Some(Peer {
            ac_name: u.ac_name.clone(),
            ac_mac: u.ac_mac,
            session_id: u.session_id,
            auth: Some(u.auth),
        }),
        None => r.client.as_ref().and_then(peer_of).or_else(|| r.last_peer.clone()),
    };
    let mut v = json!({
        "status": r.status(),
        "uptime_secs": r.up.as_ref().map(|u| now.saturating_sub(u.since_ms) / 1000),
        "service_name": r.cfg.service_name,
        "ac_name": peer.as_ref().map(|p| p.ac_name.clone()),
        "ac_mac": peer.as_ref().map(|p| Mac(p.ac_mac).to_string()),
        "session_id": peer.as_ref().map(|p| p.session_id).filter(|id| *id != 0),
        "mtu": r.up.as_ref().map(|u| u.mtu),
        "mru": r.up.as_ref().map(|u| u.mru),
        "encoding": peer.as_ref().and_then(|p| p.auth),
        "local_address": r.up.as_ref().map(|u| u.local.to_string()),
        "remote_address": r.up.as_ref().and_then(|u| u.remote).map(|a| a.to_string()),
        "dns": r.up.as_ref().map(|u| u.dns.iter().map(|d| d.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
        "attempts": r.failures,
        "retry_in_secs": r.retry_in(now).map(|ms| ms.div_ceil(1000)),
        "last_error": r.error,
        "rx_packets": c.rx_packets,
        "rx_bytes": c.rx_bytes,
        "tx_packets": c.tx_packets,
        "tx_bytes": c.tx_bytes,
        "dropped": c.dropped,
        "mss_clamped": c.mss_clamped,
    });
    if let (Some(d), Some(o)) = (&r.last_down, v.as_object_mut()) {
        o.insert(
            "last_down".into(),
            json!({
                "reason": d.reason,
                "message": d.message,
                "time": d.time,
                "uptime_secs": d.uptime_secs,
            }),
        );
    }
    v
}

/// A simulated BNG for the virtual lab (G3.9ga): accepts any user whose
/// password is not `wrong` over PAP, hands out 100.64.0.x from 100.64.0.1,
/// DNS 100.64.0.53. Enough for the demo and the engine's tests; the real
/// interoperability tests run against the BNG and RouterOS.
pub struct LabBng {
    /// Built on the first frame: every `Session` gets a lab BNG, and a
    /// `proto_pppoe::Server` is not free to make (the 3 500 tests and the
    /// command sweep build a session per case; G3.9ga, #439's CI).
    inner: Mutex<Option<LabInner>>,
}

struct LabInner {
    server: corerouter_proto_pppoe::server::Server,
    out: corerouter_proto_pppoe::server::ServerOutput,
    next: u8,
}

pub const LAB_AC_NAME: &str = "lab-bng";

impl LabBng {
    pub fn new() -> Self {
        LabBng {
            inner: Mutex::new(None),
        }
    }
}

impl LabInner {
    fn new() -> Self {
        use corerouter_proto_pppoe::server::{Server, ServerConfig, ServerOutput};
        let cfg = ServerConfig {
            ac_mac: Mac([0x02, 0xBB, 0, 0, 0, 1]),
            ac_name: LAB_AC_NAME.as_bytes().to_vec(),
            auth: AuthSet::new(&[AuthProto::Pap]),
            local_ipv4: Some(Ipv4Addr::new(100, 64, 0, 1)),
            max_mru: 1492,
            max_mtu: 1492,
            ..ServerConfig::default()
        };
        LabInner {
            server: Server::new(cfg, [7; 32], 0),
            out: ServerOutput::new(),
            next: 2,
        }
    }
}

impl Default for LabBng {
    fn default() -> Self {
        Self::new()
    }
}

impl PppoeLab for LabBng {
    fn answer(&self, _port: &IfName, _mac: [u8; 6], frame: &[u8], now_ms: u64) -> Vec<Vec<u8>> {
        use corerouter_proto_pppoe::server::{
            AuthMethod, AuthVerdict, Authorization, Event, Ipv4Assignment,
        };
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let LabInner { server, out, next } = g.get_or_insert_with(LabInner::new);
        out.clear();
        server.handle_frame(now_ms, 1, frame, out);
        server.handle_timers(now_ms, out);
        let mut frames: Vec<Vec<u8>> = out.frames().map(|(_, f)| f.to_vec()).collect();
        // Answer what the server asks for, then collect the frames of the
        // replies too (a few rounds: auth → address → IPCP).
        for _ in 0..4 {
            let events: Vec<Event> = std::mem::take(&mut out.events);
            if events.is_empty() {
                break;
            }
            out.clear();
            for ev in events {
                match ev {
                    Event::Authenticate { session, request } => {
                        let ok = match &request.method {
                            AuthMethod::Pap { password } => {
                                !password.is_empty() && password.as_ref() != b"wrong"
                            }
                            _ => false,
                        };
                        let verdict = if ok {
                            let ip = Ipv4Addr::new(100, 64, 0, *next);
                            *next = next.wrapping_add(1).max(2);
                            AuthVerdict::Accept(Authorization {
                                ipv4: Some(Ipv4Assignment {
                                    address: ip,
                                    dns: [Some(Ipv4Addr::new(100, 64, 0, 53)), None],
                                    nbns: [None, None],
                                }),
                                ..Authorization::default()
                            })
                        } else {
                            AuthVerdict::Reject {
                                message: b"invalid user name or password".to_vec().into(),
                            }
                        };
                        server.auth_reply(now_ms, session, verdict, out);
                    }
                    Event::NeedAddress { session } => {
                        server.address_reply(now_ms, session, None, out);
                    }
                    _ => {}
                }
            }
            frames.extend(out.frames().map(|(_, f)| f.to_vec()));
        }
        frames
    }
}

/// The lab BNG as the HAL takes it.
pub fn lab_bng() -> Arc<dyn PppoeLab> {
    Arc::new(LabBng::new())
}
