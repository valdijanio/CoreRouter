//! The DHCPv6 server (G4.2c), pure like the DHCPv4 one: messages and the
//! time in, [`Effect6`]s out. RFC 9915 (ex-8415), by section:
//!
//! - §16: what each message must and must not carry (a Solicit without a
//!   Client Identifier, a Request for another server: dropped).
//! - §18.3.1 Solicit → Advertise (with the Preference option), or Reply at
//!   once with Rapid Commit when both sides want it; §18.3.2 Request →
//!   Reply; §18.3.4/§18.3.5 Renew/Rebind extend a binding (Renew of an
//!   unknown IA: NoBinding; Rebind of addresses that are not for this link:
//!   returned with lifetimes 0); §18.3.7 Release, §18.3.8 Decline (the
//!   address is held), §18.3.3 Confirm (Success or NotOnLink), §18.3.6
//!   Information-request.
//! - §21.4/§21.21: T1 = 0.5 and T2 = 0.8 of the preferred lifetime; the
//!   preferred lifetime is ⅔ of the valid one (`lease_time`).
//! - §19/§9: relayed messages (Relay-Forw, nested up to the hop limit of 8)
//!   are unwrapped, the link is the innermost relay's link-address, and the
//!   reply goes back wrapped in Relay-Repl with the same hop count,
//!   addresses and Interface-Id.
//! - IA_NA addresses come from a pool of `prefix_length` 128 by a hash of
//!   the client (DUID + IAID), so a client gets the same address on every
//!   router and after a lost table; IA_PD prefixes from a pool cut in
//!   `prefix_length` pieces, the next free one, or the client's hint.
//!
//! What a binding means outside the server (the route to a delegated
//! prefix, the AAAA/PTR of an address) is the engine's, from the effects.

use std::collections::HashMap;
use std::net::Ipv6Addr;

use corerouter_model::dhcp6_server::{Dhcp6Binding, Ipv6Pool, parse_duid};
use corerouter_model::{Config, IfName};
use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::server::leases::{State, hex_plain, unhex};
use crate::server::{Level, Now};
use crate::v6::{self, ClientMsg, msg, opt, status};

/// Seconds an advertised address or prefix is held for its client.
pub const OFFER_HOLD: u64 = 120;
/// RFC 9915 §7.6: HOP_COUNT_LIMIT.
pub const HOP_COUNT_LIMIT: u8 = 8;
/// Free bindings remember their client this long (affinity, **estimado**).
pub const KEEP_FREE_SECS: u64 = 7 * 86_400;
/// Candidates an address pool tries from the client's hash.
const PROBES: u128 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IaKind {
    Na,
    Pd,
}

impl IaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Na => "na",
            Self::Pd => "pd",
        }
    }
}

mod hexv {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&crate::server::leases::hex_plain(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let t = String::deserialize(d)?;
        crate::server::leases::unhex(&t)
            .filter(|v| v.len() <= crate::v6::MAX_DUID)
            .ok_or_else(|| serde::de::Error::custom("bad DUID"))
    }
}

/// One address or prefix and its client. Also a journal line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease6 {
    #[serde(rename = "k")]
    pub kind: IaKind,
    /// `/128` for an address.
    #[serde(rename = "n")]
    pub net: Ipv6Net,
    #[serde(rename = "s")]
    pub server: String,
    #[serde(rename = "d", with = "hexv")]
    pub duid: Vec<u8>,
    #[serde(rename = "i")]
    pub iaid: u32,
    #[serde(rename = "st")]
    pub state: State,
    /// Unix time the valid lifetime ends (or the hold).
    #[serde(rename = "e")]
    pub expires: u64,
    #[serde(rename = "t", default)]
    pub lease_time: u32,
    /// Next hop of a delegated prefix: the client (direct) or the relay.
    #[serde(rename = "v")]
    pub via: Ipv6Addr,
    #[serde(rename = "if")]
    pub interface: String,
    #[serde(rename = "h", default, skip_serializing_if = "String::is_empty")]
    pub host_name: String,
    #[serde(rename = "l", default)]
    pub last_seen: u64,
}

impl Lease6 {
    fn key(&self) -> (Vec<u8>, u32, IaKind) {
        (self.duid.clone(), self.iaid, self.kind)
    }

    pub fn left(&self, now: u64) -> u64 {
        self.expires.saturating_sub(now)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Record6 {
    Lease(Lease6),
    Forget {
        #[serde(rename = "forget6")]
        forget: Ipv6Net,
    },
}

#[derive(Debug, Default, Clone)]
pub struct Leases6 {
    by_net: HashMap<Ipv6Net, Lease6>,
    by_client: HashMap<(Vec<u8>, u32, IaKind), Ipv6Net>,
}

impl Leases6 {
    pub fn len(&self) -> usize {
        self.by_net.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_net.is_empty()
    }

    pub fn get(&self, n: &Ipv6Net) -> Option<&Lease6> {
        self.by_net.get(n)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Lease6> {
        self.by_net.values()
    }

    fn of(&self, key: &(Vec<u8>, u32, IaKind)) -> Option<&Lease6> {
        self.by_client.get(key).and_then(|n| self.by_net.get(n))
    }

    fn put(&mut self, l: Lease6) {
        if let Some(old) = self.by_net.get(&l.net) {
            let k = old.key();
            if k != l.key() && self.by_client.get(&k) == Some(&l.net) {
                self.by_client.remove(&k);
            }
        }
        if let Some(prev) = self.by_client.insert(l.key(), l.net)
            && prev != l.net
            && let Some(p) = self.by_net.get(&prev)
            && p.key() == l.key()
        {
            // The client moved: its old record stays, unindexed.
            let mut p = p.clone();
            p.state = if p.state.free() {
                p.state
            } else {
                State::Released
            };
            self.by_net.insert(prev, p);
        }
        self.by_net.insert(l.net, l);
    }

    fn remove(&mut self, n: &Ipv6Net) -> Option<Lease6> {
        let l = self.by_net.remove(n)?;
        if self.by_client.get(&l.key()) == Some(n) {
            self.by_client.remove(&l.key());
        }
        Some(l)
    }

    pub fn replay<'a>(&mut self, lines: impl Iterator<Item = &'a str>) -> usize {
        let mut bad = 0;
        for line in lines.take(crate::server::leases::MAX_RECORDS) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Record6>(line) {
                Ok(Record6::Lease(l)) => self.put(l),
                Ok(Record6::Forget { forget }) => {
                    self.remove(&forget);
                }
                Err(_) => bad += 1,
            }
        }
        bad
    }

    pub fn compact(&self, now: u64) -> String {
        let mut keep: Vec<&Lease6> = self
            .by_net
            .values()
            .filter(|l| l.state != State::Offered)
            .filter(|l| !l.state.free() || l.expires.saturating_add(KEEP_FREE_SECS) > now)
            .collect();
        keep.sort_by_key(|l| u128::from(l.net.network()));
        let mut out = String::new();
        for l in keep {
            if let Ok(line) = serde_json::to_string(&Record6::Lease(l.clone())) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

/// One enabled server, compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server6Plan {
    pub name: String,
    pub interface: IfName,
    pub na: Option<Ipv6Pool>,
    pub pd: Option<Ipv6Pool>,
    pub lease_time: u32,
    pub preference: u8,
    pub rapid_commit: bool,
    pub route_distance: u8,
    pub relay: Option<Ipv6Addr>,
    pub dns: Vec<Ipv6Addr>,
    pub domain: String,
    pub zone: Option<String>,
}

impl Server6Plan {
    /// (preferred, valid, T1, T2), RFC 9915 §21.4.
    pub fn lifetimes(&self) -> (u32, u32, u32, u32) {
        let valid = self.lease_time;
        let preferred = valid / 3 * 2;
        (preferred, valid, preferred / 2, preferred / 5 * 4)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan6 {
    pub servers: Vec<Server6Plan>,
    pub statics: Vec<(Dhcp6Binding, Vec<u8>)>,
    /// The router's own IPv6 addresses (never handed out).
    pub router: Vec<Ipv6Addr>,
}

impl Plan6 {
    pub fn from_config(cfg: &Config) -> Self {
        let d = &cfg.ipv6.dhcp_server;
        let servers = d
            .servers
            .iter()
            .filter(|s| !s.disabled)
            .map(|s| Server6Plan {
                name: s.name.clone(),
                interface: s.interface.clone(),
                na: s.address_pool.as_deref().and_then(|p| d.pool(p)).cloned(),
                pd: s.prefix_pool.as_deref().and_then(|p| d.pool(p)).cloned(),
                lease_time: s.lease_time,
                preference: s.preference,
                rapid_commit: s.rapid_commit,
                route_distance: s.route_distance,
                relay: s.relay,
                dns: s.dns_server.clone(),
                domain: s.domain.clone(),
                zone: s.dns_zone.clone(),
            })
            .collect();
        let statics = d
            .bindings
            .iter()
            .filter(|b| !b.disabled)
            .filter_map(|b| parse_duid(&b.duid).map(|duid| (b.clone(), duid)))
            .collect();
        let router = cfg
            .ip
            .addresses
            .iter()
            .filter_map(|a| match a.address {
                IpNet::V6(n) => Some(n.addr()),
                IpNet::V4(_) => None,
            })
            .collect();
        Self {
            servers,
            statics,
            router,
        }
    }

    /// The server for a message heard on `iface` (direct) or relayed from
    /// `link` (the innermost relay's link-address).
    pub fn server_for(&self, iface: &IfName, link: Option<Ipv6Addr>) -> Option<usize> {
        match link {
            None => self
                .servers
                .iter()
                .position(|s| s.interface == *iface && s.relay.is_none()),
            Some(l) => self
                .servers
                .iter()
                .position(|s| s.relay == Some(l))
                .or_else(|| {
                    // A relay we know nothing about: the server whose pools
                    // hold its link (RFC 9915 §13.1, Kea's subnet choice).
                    self.servers.iter().position(|s| {
                        s.na.as_ref().is_some_and(|p| p.prefix.contains(&l))
                            || s.pd.as_ref().is_some_and(|p| p.prefix.contains(&l))
                    })
                }),
        }
    }

    fn static_for(&self, server: &str, duid: &[u8], iaid: u32) -> Option<&Dhcp6Binding> {
        self.statics
            .iter()
            .filter(|(b, d)| {
                d.as_slice() == duid && b.server.as_deref().is_none_or(|s| s == server)
            })
            .find(|(b, _)| b.iaid.is_none_or(|i| i == iaid))
            .map(|(b, _)| b)
    }

    fn reserved(&self, server: &str, net: &Ipv6Net, duid: &[u8]) -> bool {
        self.statics.iter().any(|(b, d)| {
            d.as_slice() != duid
                && b.server.as_deref().is_none_or(|s| s == server)
                && (b.address.is_some_and(|a| net.contains(&a))
                    || b.prefix.is_some_and(|p| p == *net))
        })
    }
}

/// A server's binding, outside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound6 {
    pub lease: Lease6,
    pub new: bool,
    /// (zone, host) of an address with a name.
    pub dns: Option<(String, String)>,
    pub ttl: u32,
    /// A delegated prefix's route distance.
    pub distance: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect6 {
    Send {
        interface: IfName,
        payload: Vec<u8>,
        to: Ipv6Addr,
        port: u16,
    },
    Bound(Bound6),
    Gone(Lease6),
    Journal(Record6),
    Log {
        level: Level,
        text: String,
    },
}

/// Counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Stats6 {
    /// By message name.
    pub received: std::collections::BTreeMap<String, u64>,
    pub sent: std::collections::BTreeMap<String, u64>,
    pub dropped: std::collections::BTreeMap<String, u64>,
}

fn name_of(kind: u8) -> &'static str {
    match kind {
        msg::SOLICIT => "solicit",
        msg::ADVERTISE => "advertise",
        msg::REQUEST => "request",
        msg::CONFIRM => "confirm",
        msg::RENEW => "renew",
        msg::REBIND => "rebind",
        msg::REPLY => "reply",
        msg::RELEASE => "release",
        msg::DECLINE => "decline",
        msg::INFORMATION_REQUEST => "information-request",
        msg::RELAY_FORW => "relay-forw",
        msg::RELAY_REPL => "relay-repl",
        _ => "other",
    }
}

/// One relay layer of a Relay-Forw (outermost first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub hop: u8,
    pub link: Ipv6Addr,
    pub peer: Ipv6Addr,
    pub interface_id: Option<Vec<u8>>,
}

/// Unwrap a Relay-Forw (RFC 9915 §9.1): its layers, outermost first, and
/// the client's message inside.
pub fn unwrap_relay(bytes: &[u8]) -> Option<(Vec<Layer>, Vec<u8>)> {
    let mut layers = Vec::new();
    let mut cur = bytes.to_vec();
    while cur.first() == Some(&msg::RELAY_FORW) {
        if layers.len() > usize::from(HOP_COUNT_LIMIT) || cur.len() > v6::MAX_MESSAGE {
            return None;
        }
        let hop = *cur.get(1)?;
        let link = Ipv6Addr::from(<[u8; 16]>::try_from(cur.get(2..18)?).ok()?);
        let peer = Ipv6Addr::from(<[u8; 16]>::try_from(cur.get(18..34)?).ok()?);
        let mut budget = v6::MAX_OPTIONS;
        let opts = v6::split(cur.get(34..)?, &mut budget).ok()?;
        let inner = opts.iter().find(|(c, _)| *c == opt::RELAY_MSG)?.1.to_vec();
        let interface_id = opts
            .iter()
            .find(|(c, _)| *c == opt::INTERFACE_ID)
            .map(|(_, d)| d.to_vec());
        layers.push(Layer {
            hop,
            link,
            peer,
            interface_id,
        });
        cur = inner;
    }
    Some((layers, cur))
}

/// Wrap a server's reply in Relay-Repl (RFC 9915 §9.2, §19.3), the
/// innermost layer first.
pub fn wrap_reply(layers: &[Layer], reply: Vec<u8>) -> Vec<u8> {
    let mut cur = reply;
    for l in layers.iter().rev() {
        let mut m = vec![msg::RELAY_REPL, l.hop];
        m.extend_from_slice(&l.link.octets());
        m.extend_from_slice(&l.peer.octets());
        if let Some(id) = &l.interface_id {
            v6::put(&mut m, opt::INTERFACE_ID, id);
        }
        v6::put(&mut m, opt::RELAY_MSG, &cur);
        cur = m;
    }
    cur
}

/// The relay agent (RFC 9915 §19.1): a message heard from a client (or
/// another relay) wrapped in a Relay-Forw. `None` past the hop limit.
pub fn relay_forward(
    link: Ipv6Addr,
    peer: Ipv6Addr,
    interface_id: &[u8],
    inner: &[u8],
) -> Option<Vec<u8>> {
    if inner.len() > v6::MAX_MESSAGE {
        return None;
    }
    let hop = match inner.first() {
        // §19.1.2: from another relay, one more hop; past the limit, dropped.
        Some(&msg::RELAY_FORW) => {
            let h = *inner.get(1)?;
            if h >= HOP_COUNT_LIMIT {
                return None;
            }
            h + 1
        }
        Some(&k)
            if !matches!(
                k,
                msg::ADVERTISE | msg::REPLY | msg::RECONFIGURE | msg::RELAY_REPL
            ) =>
        {
            0
        }
        _ => return None,
    };
    let mut m = vec![msg::RELAY_FORW, hop];
    m.extend_from_slice(&link.octets());
    m.extend_from_slice(&peer.octets());
    if !interface_id.is_empty() {
        v6::put(&mut m, opt::INTERFACE_ID, interface_id);
    }
    v6::put(&mut m, opt::RELAY_MSG, inner);
    Some(m)
}

/// The relay agent (§19.2): one layer of a server's Relay-Repl off: where
/// it goes (the peer), on which interface (Interface-Id) and what.
pub fn relay_unwrap_reply(bytes: &[u8]) -> Option<(Ipv6Addr, Option<Vec<u8>>, Vec<u8>)> {
    if bytes.first() != Some(&msg::RELAY_REPL) || bytes.len() > v6::MAX_MESSAGE {
        return None;
    }
    let peer = Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(18..34)?).ok()?);
    let mut budget = v6::MAX_OPTIONS;
    let opts = v6::split(bytes.get(34..)?, &mut budget).ok()?;
    let inner = opts.iter().find(|(c, _)| *c == opt::RELAY_MSG)?.1.to_vec();
    let id = opts
        .iter()
        .find(|(c, _)| *c == opt::INTERFACE_ID)
        .map(|(_, d)| d.to_vec());
    Some((peer, id, inner))
}

/// RFC 4704 §4: the host label a client calls itself (option 39).
fn fqdn_label(data: &[u8]) -> Option<String> {
    let names = v6::domain_list(data.get(1..)?)?;
    let first = names.into_iter().next()?;
    let label = crate::server::dns_label(&first);
    (!label.is_empty()).then_some(label)
}

pub struct Server6 {
    plan: Plan6,
    leases: Leases6,
    stats: Stats6,
    cursor: HashMap<String, u128>,
    last_tick: u64,
}

fn count(m: &mut std::collections::BTreeMap<String, u64>, k: &str) {
    *m.entry(k.to_owned()).or_default() += 1;
}

impl Server6 {
    pub fn new(plan: Plan6) -> Self {
        Self {
            plan,
            leases: Leases6::default(),
            stats: Stats6::default(),
            cursor: HashMap::new(),
            last_tick: 0,
        }
    }

    pub fn plan(&self) -> &Plan6 {
        &self.plan
    }

    pub fn leases(&self) -> &Leases6 {
        &self.leases
    }

    pub fn stats(&self) -> &Stats6 {
        &self.stats
    }

    pub fn replay<'a>(&mut self, lines: impl Iterator<Item = &'a str>) -> usize {
        self.leases.replay(lines)
    }

    pub fn compact(&self, now: u64) -> String {
        self.leases.compact(now)
    }

    /// A new running config; bindings of servers that are gone end.
    pub fn configure(&mut self, plan: Plan6) -> Vec<Effect6> {
        let mut out = Vec::new();
        let gone: Vec<Ipv6Net> = self
            .leases
            .iter()
            .filter(|l| !plan.servers.iter().any(|s| s.name == l.server))
            .map(|l| l.net)
            .collect();
        for n in gone {
            if let Some(l) = self.leases.remove(&n) {
                if l.state == State::Bound {
                    out.push(Effect6::Gone(l));
                }
                out.push(Effect6::Journal(Record6::Forget { forget: n }));
            }
        }
        self.plan = plan;
        out
    }

    fn drop(&mut self, why: &str) {
        count(&mut self.stats.dropped, why);
    }

    /// One message heard on `iface`, whose MAC makes the server's DUID.
    pub fn handle(
        &mut self,
        now: Now,
        iface: &IfName,
        mac: [u8; 6],
        src: Ipv6Addr,
        bytes: &[u8],
    ) -> Vec<Effect6> {
        let mut out = Vec::new();
        let Some((layers, inner)) = unwrap_relay(bytes) else {
            self.drop("malformed");
            return out;
        };
        let link = layers
            .iter()
            .rev()
            .map(|l| l.link)
            .find(|l| !l.is_unspecified());
        let link = if layers.is_empty() {
            None
        } else {
            link.or(Some(Ipv6Addr::UNSPECIFIED))
        };
        let m = match v6::decode_client(&inner) {
            Ok(m) => m,
            Err(_) => {
                self.drop("malformed");
                return out;
            }
        };
        count(&mut self.stats.received, name_of(m.kind));
        let Some(si) = self.plan.server_for(iface, link) else {
            self.drop("no-server");
            return out;
        };
        let Some(srv) = self.plan.servers.get(si).cloned() else {
            return out;
        };
        let me = v6::duid_ll(mac);
        // §16: identifiers.
        let Some(duid) = m.client_id.clone() else {
            self.drop("no-client-id");
            return out;
        };
        let for_us = m.server_id.as_ref().is_none_or(|s| *s == me);
        let needs_us = matches!(
            m.kind,
            msg::REQUEST | msg::RENEW | msg::RELEASE | msg::DECLINE
        );
        let must_not = matches!(m.kind, msg::SOLICIT | msg::REBIND | msg::CONFIRM);
        if (needs_us && m.server_id.as_ref() != Some(&me))
            || (must_not && m.server_id.is_some())
            || !for_us
        {
            self.drop("other-server");
            return out;
        }
        let host = v6::raw_options(&inner)
            .into_iter()
            .find(|(c, _)| *c == opt::CLIENT_FQDN)
            .and_then(|(_, d)| fqdn_label(&d))
            .unwrap_or_default();
        // The client's address (direct) or the relay's, for the route.
        let peer = layers.last().map_or(src, |l| l.peer);
        // The next hop of a delegated prefix: the client itself (direct)
        // or the relay that brought it.
        let via = src;
        let ctx = Ctx {
            srv: &srv,
            iface: iface.clone(),
            duid: duid.clone(),
            via,
            host,
            now,
        };
        let reply = match m.kind {
            msg::SOLICIT => {
                let commit = m.rapid_commit && srv.rapid_commit;
                let body = self.ias(
                    &ctx,
                    &m,
                    if commit { Act::Bind } else { Act::Offer },
                    &mut out,
                );
                let kind = if commit { msg::REPLY } else { msg::ADVERTISE };
                let mut r = self.head(kind, m.xid, &duid, &me);
                r.extend(body);
                if commit {
                    v6::put(&mut r, opt::RAPID_COMMIT, &[]);
                } else if srv.preference > 0 {
                    v6::put(&mut r, opt::PREFERENCE, &[srv.preference]);
                }
                self.config_options(&srv, &m, &mut r);
                Some(r)
            }
            msg::REQUEST => {
                let body = self.ias(&ctx, &m, Act::Bind, &mut out);
                let mut r = self.head(msg::REPLY, m.xid, &duid, &me);
                r.extend(body);
                self.config_options(&srv, &m, &mut r);
                Some(r)
            }
            msg::RENEW | msg::REBIND => {
                let act = if m.kind == msg::RENEW {
                    Act::Renew
                } else {
                    Act::Rebind
                };
                let body = self.ias(&ctx, &m, act, &mut out);
                let mut r = self.head(msg::REPLY, m.xid, &duid, &me);
                r.extend(body);
                self.config_options(&srv, &m, &mut r);
                Some(r)
            }
            msg::RELEASE | msg::DECLINE => {
                let act = if m.kind == msg::RELEASE {
                    Act::Release
                } else {
                    Act::Decline
                };
                let body = self.ias(&ctx, &m, act, &mut out);
                let mut r = self.head(msg::REPLY, m.xid, &duid, &me);
                r.extend(body);
                v6::put(
                    &mut r,
                    opt::STATUS_CODE,
                    &v6::status_body(status::SUCCESS, "done"),
                );
                Some(r)
            }
            msg::CONFIRM => {
                let addrs: Vec<Ipv6Addr> = m
                    .ia_na
                    .iter()
                    .flat_map(|ia| ia.addrs.iter().map(|a| a.addr))
                    .collect();
                if addrs.is_empty() {
                    // §18.3.3: nothing to confirm: no reply.
                    self.drop("confirm-empty");
                    None
                } else {
                    let on = srv
                        .na
                        .as_ref()
                        .is_some_and(|p| addrs.iter().all(|a| p.prefix.contains(a)));
                    let mut r = self.head(msg::REPLY, m.xid, &duid, &me);
                    let st = if on {
                        (status::SUCCESS, "on link")
                    } else {
                        (status::NOT_ON_LINK, "not for this link")
                    };
                    v6::put(&mut r, opt::STATUS_CODE, &v6::status_body(st.0, st.1));
                    Some(r)
                }
            }
            msg::INFORMATION_REQUEST => {
                let mut r = self.head(msg::REPLY, m.xid, &duid, &me);
                self.config_options(&srv, &m, &mut r);
                Some(r)
            }
            _ => {
                self.drop("unexpected");
                None
            }
        };
        let Some(reply) = reply else {
            return out;
        };
        let kind = reply.first().copied().unwrap_or(0);
        count(&mut self.stats.sent, name_of(kind));
        let (payload, to, port) = if layers.is_empty() {
            (reply, peer, 546)
        } else {
            (wrap_reply(&layers, reply), src, 547)
        };
        if payload.len() <= v6::MAX_MESSAGE {
            out.push(Effect6::Send {
                interface: iface.clone(),
                payload,
                to,
                port,
            });
        }
        out
    }

    fn head(&self, kind: u8, xid: u32, client: &[u8], me: &[u8]) -> Vec<u8> {
        let mut r = vec![kind];
        r.extend_from_slice(xid.to_be_bytes().get(1..).unwrap_or(&[0, 0, 0]));
        v6::put(&mut r, opt::CLIENTID, client);
        v6::put(&mut r, opt::SERVERID, me);
        r
    }

    fn config_options(&self, srv: &Server6Plan, m: &ClientMsg, r: &mut Vec<u8>) {
        let asked = |c: u16| m.oro.is_empty() || m.oro.contains(&c);
        if !srv.dns.is_empty() && asked(opt::DNS_SERVERS) {
            let b: Vec<u8> = srv.dns.iter().flat_map(|a| a.octets()).collect();
            v6::put(r, opt::DNS_SERVERS, &b);
        }
        if !srv.domain.is_empty() && asked(opt::DOMAIN_LIST) {
            let mut b = Vec::new();
            v6::encode_name(&srv.domain, &mut b);
            v6::put(r, opt::DOMAIN_LIST, &b);
        }
    }

    /// The IA options of the reply, binding (or offering, renewing,
    /// releasing…) what the client asked.
    fn ias(&mut self, ctx: &Ctx<'_>, m: &ClientMsg, act: Act, out: &mut Vec<Effect6>) -> Vec<u8> {
        let mut r = Vec::new();
        let (pref, valid, t1, t2) = ctx.srv.lifetimes();
        for (kind, ia) in [(IaKind::Na, &m.ia_na), (IaKind::Pd, &m.ia_pd)] {
            let Some(ia) = ia else { continue };
            let hint = match kind {
                IaKind::Na => ia
                    .addrs
                    .first()
                    .map(|a| Ipv6Net::new(a.addr, 128))
                    .and_then(Result::ok),
                IaKind::Pd => ia.prefixes.first().map(|p| p.prefix),
            };
            let result = self.ia(ctx, kind, ia.iaid, hint, act, out);
            let (code, body_none) = match kind {
                IaKind::Na => (opt::IA_NA, status::NO_ADDRS_AVAIL),
                IaKind::Pd => (opt::IA_PD, status::NO_PREFIX_AVAIL),
            };
            let body = match result {
                IaResult::Ok(net) => match kind {
                    IaKind::Na => {
                        v6::ia_na_body(ia.iaid, t1, t2, &[(net.addr(), pref, valid)], None)
                    }
                    IaKind::Pd => v6::ia_pd_body(ia.iaid, t1, t2, &[(net, pref, valid)], None),
                },
                IaResult::Zero(net) => match kind {
                    // §18.3.5: not for this link: lifetimes 0.
                    IaKind::Na => v6::ia_na_body(ia.iaid, 0, 0, &[(net.addr(), 0, 0)], None),
                    IaKind::Pd => v6::ia_pd_body(ia.iaid, 0, 0, &[(net, 0, 0)], None),
                },
                IaResult::Status(s, text) => match kind {
                    IaKind::Na => v6::ia_na_body(ia.iaid, 0, 0, &[], Some((s, text))),
                    IaKind::Pd => v6::ia_pd_body(ia.iaid, 0, 0, &[], Some((s, text))),
                },
                IaResult::None => match kind {
                    IaKind::Na => {
                        v6::ia_na_body(ia.iaid, 0, 0, &[], Some((body_none, "none free")))
                    }
                    IaKind::Pd => {
                        v6::ia_pd_body(ia.iaid, 0, 0, &[], Some((body_none, "none free")))
                    }
                },
                IaResult::Done => match kind {
                    IaKind::Na => {
                        v6::ia_na_body(ia.iaid, 0, 0, &[], Some((status::SUCCESS, "done")))
                    }
                    IaKind::Pd => {
                        v6::ia_pd_body(ia.iaid, 0, 0, &[], Some((status::SUCCESS, "done")))
                    }
                },
            };
            v6::put(&mut r, code, &body);
        }
        r
    }

    fn pool_of<'a>(srv: &'a Server6Plan, kind: IaKind) -> Option<&'a Ipv6Pool> {
        match kind {
            IaKind::Na => srv.na.as_ref(),
            IaKind::Pd => srv.pd.as_ref(),
        }
    }

    /// Whether `net` may go to client (duid, iaid) of `srv`.
    fn free_for(
        &self,
        srv: &Server6Plan,
        kind: IaKind,
        net: &Ipv6Net,
        key: &(Vec<u8>, u32, IaKind),
        now: u64,
    ) -> bool {
        let Some(pool) = Self::pool_of(srv, kind) else {
            return false;
        };
        if net.prefix_len() != pool.prefix_length || !pool.prefix.contains(net) {
            return false;
        }
        if kind == IaKind::Na
            && (self.plan.router.contains(&net.addr()) || net.addr() == pool.prefix.network())
        {
            return false;
        }
        if self.plan.reserved(&srv.name, net, &key.0) {
            return false;
        }
        match self.leases.get(net) {
            None => true,
            Some(l) if l.key() == *key => !matches!(l.state, State::Declined | State::Conflict),
            Some(l) => l.state.free() || (l.state == State::Offered && l.expires <= now),
        }
    }

    /// Choose for the client: static, its own, its hint, then the pool.
    fn choose(
        &mut self,
        ctx: &Ctx<'_>,
        kind: IaKind,
        iaid: u32,
        hint: Option<Ipv6Net>,
    ) -> Option<Ipv6Net> {
        let key = (ctx.duid.clone(), iaid, kind);
        let srv = ctx.srv;
        if let Some(b) = self.plan.static_for(&srv.name, &ctx.duid, iaid) {
            let fixed = match kind {
                IaKind::Na => b.address.and_then(|a| Ipv6Net::new(a, 128).ok()),
                IaKind::Pd => b.prefix,
            };
            if fixed.is_some() {
                return fixed;
            }
        }
        if let Some(l) = self.leases.of(&key)
            && self.free_for(srv, kind, &l.net, &key, ctx.now.unix)
        {
            return Some(l.net);
        }
        if let Some(h) = hint {
            let h = match kind {
                IaKind::Na => Some(h),
                // A prefix hint may give only the length (RFC 9915 §18.2.1).
                IaKind::Pd => (!h.network().is_unspecified()).then_some(h),
            };
            if let Some(h) = h
                && self.free_for(srv, kind, &h, &key, ctx.now.unix)
            {
                return Some(h);
            }
        }
        let pool = Self::pool_of(srv, kind)?.clone();
        let base = u128::from(pool.prefix.network());
        let bits = u32::from(pool.prefix_length.saturating_sub(pool.prefix.prefix_len()));
        let shift = 128 - u32::from(pool.prefix_length);
        match kind {
            IaKind::Na => {
                // A hash of the client: the same address everywhere.
                let space: u128 = if bits >= 64 {
                    1u128 << 64
                } else {
                    1u128 << bits
                };
                let h = u128::from(client_hash(&ctx.duid, iaid));
                for i in 0..PROBES.min(space) {
                    let off = (h + i) % space;
                    let Ok(net) = Ipv6Net::new(Ipv6Addr::from(base | off), 128) else {
                        continue;
                    };
                    if self.free_for(srv, kind, &net, &key, ctx.now.unix) {
                        return Some(net);
                    }
                }
                None
            }
            IaKind::Pd => {
                let count: u128 =
                    1u128 << bits.min(corerouter_model::dhcp6_server::MAX_POOL_BITS.into());
                let start = self.cursor.get(&pool.name).copied().unwrap_or(0) % count;
                for i in 0..count {
                    let off = (start + i) % count;
                    let Some(addr) = off.checked_shl(shift).map(|o| base | o) else {
                        continue;
                    };
                    let Ok(net) = Ipv6Net::new(Ipv6Addr::from(addr), pool.prefix_length) else {
                        continue;
                    };
                    if self.free_for(srv, kind, &net, &key, ctx.now.unix) {
                        self.cursor.insert(pool.name.clone(), off + 1);
                        return Some(net);
                    }
                }
                None
            }
        }
    }

    fn record(
        &self,
        ctx: &Ctx<'_>,
        kind: IaKind,
        iaid: u32,
        net: Ipv6Net,
        state: State,
        expires: u64,
    ) -> Lease6 {
        Lease6 {
            kind,
            net,
            server: ctx.srv.name.clone(),
            duid: ctx.duid.clone(),
            iaid,
            state,
            expires,
            lease_time: ctx.srv.lease_time,
            via: ctx.via,
            interface: ctx.iface.as_str().to_owned(),
            host_name: ctx.host.clone(),
            last_seen: ctx.now.unix,
        }
    }

    fn bind(
        &mut self,
        ctx: &Ctx<'_>,
        kind: IaKind,
        iaid: u32,
        net: Ipv6Net,
        out: &mut Vec<Effect6>,
    ) {
        let key = (ctx.duid.clone(), iaid, kind);
        let prev = self.leases.get(&net).cloned();
        let renewed = prev
            .as_ref()
            .is_some_and(|p| p.state == State::Bound && p.key() == key);
        let mut rec = self.record(
            ctx,
            kind,
            iaid,
            net,
            State::Bound,
            ctx.now.unix + u64::from(ctx.srv.lease_time),
        );
        if rec.host_name.is_empty()
            && let Some(p) = prev.as_ref().filter(|p| p.key() == key)
        {
            rec.host_name = p.host_name.clone();
        }
        if let Some(old) = self
            .leases
            .of(&key)
            .filter(|l| l.net != net && l.state == State::Bound)
            .cloned()
        {
            let mut o = old.clone();
            o.state = State::Released;
            o.expires = ctx.now.unix;
            self.leases.put(o.clone());
            out.push(Effect6::Journal(Record6::Lease(o)));
            out.push(Effect6::Gone(old));
        }
        self.leases.put(rec.clone());
        out.push(Effect6::Journal(Record6::Lease(rec.clone())));
        if !renewed {
            out.push(Effect6::Log {
                level: Level::Info,
                text: format!(
                    "{} {} {} to DUID {}",
                    ctx.srv.name,
                    if kind == IaKind::Pd {
                        "delegated"
                    } else {
                        "assigned"
                    },
                    net,
                    v6::duid_text(&ctx.duid)
                ),
            });
        }
        let dns = (kind == IaKind::Na)
            .then(|| ctx.srv.zone.clone())
            .flatten()
            .filter(|_| !rec.host_name.is_empty())
            .map(|z| (z, rec.host_name.clone()));
        out.push(Effect6::Bound(Bound6 {
            lease: rec,
            new: !renewed,
            dns,
            ttl: crate::server::dns_ttl(ctx.srv.lease_time),
            distance: ctx.srv.route_distance,
        }));
    }

    fn end(&mut self, net: &Ipv6Net, state: State, now: Now, hold: u64, out: &mut Vec<Effect6>) {
        let Some(mut l) = self.leases.get(net).cloned() else {
            return;
        };
        let was_bound = l.state == State::Bound;
        l.state = state;
        l.expires = now.unix + hold;
        self.leases.put(l.clone());
        out.push(Effect6::Journal(Record6::Lease(l.clone())));
        if was_bound {
            out.push(Effect6::Gone(l));
        }
    }

    fn ia(
        &mut self,
        ctx: &Ctx<'_>,
        kind: IaKind,
        iaid: u32,
        hint: Option<Ipv6Net>,
        act: Act,
        out: &mut Vec<Effect6>,
    ) -> IaResult {
        let key = (ctx.duid.clone(), iaid, kind);
        let now = ctx.now;
        match act {
            Act::Offer => match self.choose(ctx, kind, iaid, hint) {
                Some(net) => {
                    let held = self
                        .leases
                        .get(&net)
                        .is_some_and(|l| l.state == State::Bound && l.key() == key);
                    if !held {
                        let rec = self.record(
                            ctx,
                            kind,
                            iaid,
                            net,
                            State::Offered,
                            now.unix + OFFER_HOLD,
                        );
                        self.leases.put(rec);
                    }
                    IaResult::Ok(net)
                }
                None => {
                    self.drop("pool-exhausted");
                    IaResult::None
                }
            },
            Act::Bind => match self.choose(ctx, kind, iaid, hint) {
                Some(net) => {
                    self.bind(ctx, kind, iaid, net, out);
                    IaResult::Ok(net)
                }
                None => {
                    self.drop("pool-exhausted");
                    IaResult::None
                }
            },
            Act::Renew | Act::Rebind => {
                let mine = self
                    .leases
                    .of(&key)
                    .filter(|l| {
                        l.server == ctx.srv.name
                            && matches!(l.state, State::Bound | State::Expired | State::Released)
                    })
                    .map(|l| l.net);
                if let Some(net) = mine
                    && self.free_for(ctx.srv, kind, &net, &key, now.unix)
                {
                    self.bind(ctx, kind, iaid, net, out);
                    return IaResult::Ok(net);
                }
                match (act, hint) {
                    // §18.3.4: Renew of an IA we have no binding for.
                    (Act::Renew, _) | (_, None) => {
                        IaResult::Status(status::NO_BINDING, "no binding")
                    }
                    (_, Some(h)) => {
                        if self.free_for(ctx.srv, kind, &h, &key, now.unix) {
                            // §18.3.5: appropriate and free: bound again.
                            self.bind(ctx, kind, iaid, h, out);
                            IaResult::Ok(h)
                        } else if Self::pool_of(ctx.srv, kind)
                            .is_none_or(|p| !p.prefix.contains(&h))
                        {
                            IaResult::Zero(h)
                        } else {
                            IaResult::Status(status::NO_BINDING, "no binding")
                        }
                    }
                }
            }
            Act::Release | Act::Decline => {
                let Some(net) = self
                    .leases
                    .of(&key)
                    .filter(|l| l.state == State::Bound && l.server == ctx.srv.name)
                    .map(|l| l.net)
                else {
                    return IaResult::Status(status::NO_BINDING, "no binding");
                };
                if act == Act::Release {
                    self.end(&net, State::Released, now, 0, out);
                } else {
                    // §18.3.8: not handed out again for a while.
                    self.end(
                        &net,
                        State::Declined,
                        now,
                        u64::from(ctx.srv.lease_time),
                        out,
                    );
                    out.push(Effect6::Log {
                        level: Level::Warning,
                        text: format!(
                            "{}: {net} declined by DUID {}",
                            ctx.srv.name,
                            v6::duid_text(&ctx.duid)
                        ),
                    });
                }
                IaResult::Done
            }
        }
    }

    /// Once a second: bindings, offers and holds that ran out.
    pub fn tick(&mut self, now: Now) -> Vec<Effect6> {
        let mut out = Vec::new();
        if now.unix == self.last_tick {
            return out;
        }
        self.last_tick = now.unix;
        let due: Vec<(Ipv6Net, State)> = self
            .leases
            .iter()
            .filter(|l| !l.state.free() && l.expires <= now.unix)
            .map(|l| (l.net, l.state))
            .collect();
        for (net, state) in due {
            match state {
                State::Bound => self.end(&net, State::Expired, now, 0, &mut out),
                State::Offered => {
                    if let Some(mut l) = self.leases.get(&net).cloned() {
                        l.state = State::Expired;
                        self.leases.put(l);
                    }
                }
                _ => {
                    if let Some(mut l) = self.leases.get(&net).cloned() {
                        l.state = State::Expired;
                        self.leases.put(l.clone());
                        out.push(Effect6::Journal(Record6::Lease(l)));
                    }
                }
            }
        }
        let old: Vec<Ipv6Net> = self
            .leases
            .iter()
            .filter(|l| l.state.free() && l.expires.saturating_add(KEEP_FREE_SECS) <= now.unix)
            .map(|l| l.net)
            .collect();
        for n in old {
            self.leases.remove(&n);
            out.push(Effect6::Journal(Record6::Forget { forget: n }));
        }
        out
    }

    /// The operator ends a binding.
    pub fn release(&mut self, net: &Ipv6Net, now: Now) -> Result<Vec<Effect6>, String> {
        match self.leases.get(net) {
            Some(l)
                if l.state == State::Bound
                    || l.state == State::Offered
                    || l.state == State::Declined => {}
            Some(l) => return Err(format!("{net} is {} already", l.state.as_str())),
            None => return Err(format!("no binding for {net}")),
        }
        let mut out = Vec::new();
        self.end(net, State::Released, now, 0, &mut out);
        Ok(out)
    }
}

/// What the client's message asks of an IA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Offer,
    Bind,
    Renew,
    Rebind,
    Release,
    Decline,
}

enum IaResult {
    Ok(Ipv6Net),
    Zero(Ipv6Net),
    Status(u16, &'static str),
    None,
    Done,
}

struct Ctx<'a> {
    srv: &'a Server6Plan,
    iface: IfName,
    duid: Vec<u8>,
    via: Ipv6Addr,
    host: String,
    now: Now,
}

/// FNV-1a 64 of a client (DUID + IAID): where its address is looked for.
fn client_hash(duid: &[u8], iaid: u32) -> u64 {
    duid.iter()
        .chain(iaid.to_be_bytes().iter())
        .fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

/// DUIDs and lines for people.
pub fn hex(v: &[u8]) -> String {
    hex_plain(v)
}

/// The inverse of [`hex`].
pub fn from_hex(t: &str) -> Option<Vec<u8>> {
    unhex(t)
}

#[cfg(test)]
mod tests;

/// What the DHCPv6 server's config gets wrong (as `server::checks`: errors
/// refuse the commit, warnings are shown).
pub fn checks(cfg: &Config) -> Vec<crate::server::checks::Check> {
    use crate::server::checks::{Check, Level};
    use corerouter_model::ItemId;
    use corerouter_model::dhcp6_server::{
        MAX_BINDINGS, MAX_LEASE_TIME, MAX_LIST, MAX_POOL_BITS, MAX_POOLS, MAX_RELAYS, MAX_SERVERS,
        MIN_LEASE_TIME,
    };
    let d = &cfg.ipv6.dhcp_server;
    let mut out: Vec<Check> = Vec::new();
    let mut push = |path: String, item: ItemId, label: &'static str, level: Level, text: String| {
        out.push(Check {
            path,
            item,
            label,
            level,
            text,
        });
    };
    if d.pools.len() > MAX_POOLS
        || d.servers.len() > MAX_SERVERS
        || d.bindings.len() > MAX_BINDINGS
        || d.relays.len() > MAX_RELAYS
    {
        push(
            "ipv6.dhcp_server".into(),
            ItemId(0),
            "too many",
            Level::Error,
            "too many pools, servers, bindings or relays".into(),
        );
    }
    let client_pools: Vec<&str> = cfg
        .ipv6
        .dhcp_clients
        .iter()
        .map(|c| c.pool_name.as_str())
        .collect();
    let mut names = std::collections::BTreeSet::new();
    for (i, p) in d.pools.iter().enumerate() {
        let at = |f: &str| format!("ipv6.dhcp_server.pools[{}].{f}", p.id);
        if !corerouter_model::ip_pool::name_ok(&p.name) || !names.insert(p.name.as_str()) {
            push(
                at("name"),
                p.id,
                "name",
                Level::Error,
                format!("'{}': a unique name", p.name),
            );
        }
        if client_pools.contains(&p.name.as_str()) {
            push(
                at("name"),
                p.id,
                "name",
                Level::Error,
                format!("a DHCPv6 client fills pool '{}'", p.name),
            );
        }
        let plen = p.prefix_length;
        if plen > 128 || plen < p.prefix.prefix_len() {
            push(
                at("prefix_length"),
                p.id,
                "length",
                Level::Error,
                format!("{}..=128", p.prefix.prefix_len()),
            );
        } else if plen < 128 && plen - p.prefix.prefix_len() > MAX_POOL_BITS {
            push(
                at("prefix_length"),
                p.id,
                "size",
                Level::Error,
                format!("at most 2^{MAX_POOL_BITS} prefixes per pool (split it)"),
            );
        } else if plen < 128 && plen > 64 {
            push(
                at("prefix_length"),
                p.id,
                "length",
                Level::Warn,
                "a delegated prefix longer than /64 cannot do SLAAC".into(),
            );
        }
        for q in d.pools.iter().skip(i + 1) {
            if p.prefix.contains(&q.prefix.network()) || q.prefix.contains(&p.prefix.network()) {
                push(
                    at("prefix"),
                    p.id,
                    "overlap",
                    Level::Error,
                    format!("{} overlaps pool '{}' ({})", p.prefix, q.name, q.prefix),
                );
            }
        }
    }
    let mut links = std::collections::BTreeSet::new();
    let mut snames = std::collections::BTreeSet::new();
    for s in &d.servers {
        let at = |f: &str| format!("ipv6.dhcp_server.servers[{}].{f}", s.id);
        if !corerouter_model::ip_pool::name_ok(&s.name) || !snames.insert(s.name.as_str()) {
            push(
                at("name"),
                s.id,
                "name",
                Level::Error,
                format!("'{}': a unique name", s.name),
            );
        }
        if !cfg.interfaces.contains_key(&s.interface) {
            push(
                at("interface"),
                s.id,
                "interface",
                Level::Error,
                format!("interface '{}' does not exist", s.interface),
            );
        }
        if !(MIN_LEASE_TIME..=MAX_LEASE_TIME).contains(&s.lease_time) {
            push(
                at("lease_time"),
                s.id,
                "lease-time",
                Level::Error,
                format!("{MIN_LEASE_TIME}..={MAX_LEASE_TIME} seconds"),
            );
        }
        match s.address_pool.as_deref().map(|p| (p, d.pool(p))) {
            Some((p, None)) => push(
                at("address_pool"),
                s.id,
                "pool",
                Level::Error,
                format!("no pool '{p}' (ipv6.pool.add)"),
            ),
            Some((p, Some(pool))) if pool.prefix_length != 128 => push(
                at("address_pool"),
                s.id,
                "pool",
                Level::Error,
                format!(
                    "'{p}' hands out /{} prefixes: an address pool has prefix_length 128",
                    pool.prefix_length
                ),
            ),
            _ => {}
        }
        match s.prefix_pool.as_deref().map(|p| (p, d.pool(p))) {
            Some((p, None)) => push(
                at("prefix_pool"),
                s.id,
                "pool",
                Level::Error,
                format!("no pool '{p}' (ipv6.pool.add)"),
            ),
            Some((p, Some(pool))) if pool.prefix_length == 128 => push(
                at("prefix_pool"),
                s.id,
                "pool",
                Level::Error,
                format!(
                    "'{p}' hands out addresses (/128): a prefix pool needs prefix_length 48..=64"
                ),
            ),
            _ => {}
        }
        if s.address_pool.is_none() && s.prefix_pool.is_none() {
            push(
                at("address_pool"),
                s.id,
                "pools",
                Level::Warn,
                "no pool: only Information-request is answered".into(),
            );
        }
        if s.dns_server.len() > MAX_LIST {
            push(
                at("dns_server"),
                s.id,
                "DNS",
                Level::Error,
                format!("at most {MAX_LIST}"),
            );
        }
        if let Some(z) = &s.dns_zone
            && cfg.ip.dns_zones.zone(z).is_none()
        {
            push(
                at("dns_zone"),
                s.id,
                "DNS zone",
                Level::Error,
                format!("no zone '{z}' (ip.dns.zone.add)"),
            );
        }
        if !s.disabled && !links.insert((&s.interface, s.relay)) {
            push(
                at("interface"),
                s.id,
                "interface",
                Level::Error,
                format!("another DHCPv6 server already serves '{}'", s.interface),
            );
        }
        if let Some(why) = crate::server::checks::looks_like_wan(cfg, &s.interface) {
            push(at("interface"), s.id, "WAN?", Level::Warn, why);
        }
        if cfg
            .ipv6
            .dhcp_clients
            .iter()
            .any(|c| !c.disabled && c.interface == s.interface)
        {
            push(
                at("interface"),
                s.id,
                "WAN?",
                Level::Warn,
                format!("'{}' has a DHCPv6 client (upstream)", s.interface),
            );
        }
    }
    for b in &d.bindings {
        let at = |f: &str| format!("ipv6.dhcp_server.bindings[{}].{f}", b.id);
        if parse_duid(&b.duid).is_none() {
            push(
                at("duid"),
                b.id,
                "DUID",
                Level::Error,
                "a DUID: 0x0003000102…, 3..=130 bytes".into(),
            );
        }
        if b.address.is_none() && b.prefix.is_none() {
            push(
                at("address"),
                b.id,
                "nothing",
                Level::Error,
                "give it an address, a prefix or both".into(),
            );
        }
        if let Some(s) = &b.server
            && d.server(s).is_none()
        {
            push(
                at("server"),
                b.id,
                "server",
                Level::Error,
                format!("no DHCPv6 server '{s}'"),
            );
        }
    }
    for r in &d.relays {
        let at = |f: &str| format!("ipv6.dhcp_server.relays[{}].{f}", r.id);
        if !cfg.interfaces.contains_key(&r.interface) {
            push(
                at("interface"),
                r.id,
                "interface",
                Level::Error,
                format!("interface '{}' does not exist", r.interface),
            );
        }
        if r.dhcp_server.len() > MAX_LIST {
            push(
                at("dhcp_server"),
                r.id,
                "servers",
                Level::Error,
                format!("at most {MAX_LIST}"),
            );
        }
        if !r.disabled
            && d.servers
                .iter()
                .any(|s| !s.disabled && s.interface == r.interface && s.relay.is_none())
        {
            push(
                at("interface"),
                r.id,
                "server here",
                Level::Error,
                format!("a DHCPv6 server already answers on '{}'", r.interface),
            );
        }
    }
    out
}
