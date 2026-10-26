//! IPoE subscribers (G4.3f) as the engine sees them. The DHCPv4 server
//! (`dhcp_server.rs`) asks about each client of a server with `ipoe=yes`
//! or `use_radius` ([`AuthAsk`]) and reports its bindings; the daemon's
//! `ipoe` service owns the sessions (RADIUS, accounting, the XDP policer,
//! CoA/Disconnect) and registers itself with
//! [`Session::set_ipoe_backend`]. Its sessions join the PPP service's in
//! `ppp.active`, `ppp.why` and `ppp.history` ([`Session::ppp_backend`]
//! merges both).
//!
//! The local decision (`/ppp secret` with `service=ipoe`, then
//! `ipoe_unknown`) is [`local_verdict`], here so the engine's own lab
//! serves IPoE without the daemon; the service calls it first too, and asks
//! RADIUS only when it says so.
//!
//! Every backend call is made under the session lock, once a round: no
//! wait on the network (RADIUS answers come back through
//! [`IpoeBackend::verdicts`]).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_model::cow_list::CowList;
use corerouter_model::dhcp_server::{DhcpServer, StaticLease};
use corerouter_model::ipoe::{IpoeUnknown, UseRadius};
use corerouter_model::ppp::{AddrOrPool, DEFAULT_PROFILE, PppSecret, PppService};
use corerouter_model::{Config, IfName, ItemId, MacAddr};
use corerouter_proto_dhcp::server::Binding;
use corerouter_proto_dhcp::server::agent;
use corerouter_proto_dhcp::server::authorize::{AuthAsk, Grant, Verdict};
use corerouter_proto_dhcp::server::leases::Lease;

use crate::Session;

/// What the local list decided about a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Local {
    /// Decided: accept (with what the secret gives) or reject.
    Done(Verdict),
    /// Not in the list and the server asks RADIUS: the service asks.
    AskRadius { user: String },
}

/// What a disconnect asks of the DHCP server: end the leases of a client
/// and take its grant away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoke {
    pub server: String,
    pub client_key: Vec<u8>,
    pub why: String,
}

/// What the daemon's `ipoe` service offers the DHCP server.
pub trait IpoeBackend: Send + Sync {
    /// A client to authorize. `Some`: decided now (a local secret, or the
    /// server only accounts); `None`: asked of RADIUS, the verdict comes
    /// back through [`IpoeBackend::verdicts`].
    fn authorize(&self, ask: &AuthAsk, view: &IpoeView<'_>) -> Option<Verdict>;
    /// The verdicts that arrived: (server, client key, verdict).
    fn verdicts(&self) -> Vec<(String, Vec<u8>, Verdict)>;
    /// A lease of a session server was bound or renewed.
    fn bound(&self, b: &Binding, view: &IpoeView<'_>);
    /// A lease of a session server ended (released, expired, revoked).
    fn gone(&self, lease: &Lease, why: &str);
    /// Disconnects the service wants carried out (CoA Disconnect,
    /// `ppp.active.remove`, a keepalive that failed, a byte limit).
    fn revokes(&self) -> Vec<Revoke>;
    /// ARP pings it wants sent (keepalive): (interface, address).
    fn pings(&self) -> Vec<(IfName, Ipv4Addr)> {
        Vec::new()
    }
    /// A host answered on `interface` for `ip` with `mac`.
    fn arp_reply(&self, interface: &IfName, ip: Ipv4Addr, mac: [u8; 6]) {
        let _ = (interface, ip, mac);
    }
}

/// What the IPoE decisions look up per lease, followed once per config
/// revision: a lookup is O(1) with 100 000 secrets or static leases (a
/// scan of `/ppp secret` per DISCOVER was O(secrets) per client).
///
/// The secrets need nothing here: the config keeps their name index
/// itself ([`Secrets::first_named`], incremental since G4.3gb). The static
/// leases' rates are followed block by block ([`IpoeIndex::refresh`]): a
/// revision that changed one lease reads its block of 128, not the list
/// (rebuilding both on every revision cost 22 ms with 100 000, **medido**,
/// `config_store/ipoe_index/*`).
///
/// [`Secrets::first_named`]: corerouter_model::ppp_secrets::Secrets::first_named
#[derive(Debug, Default, Clone)]
pub struct IpoeIndex {
    revision: Option<u32>,
    /// The static leases `lease_rates` follows (shares their blocks).
    leases: CowList<StaticLease>,
    /// Static leases with a `rate_limit`, by address (enabled ones), with
    /// the lease's id.
    lease_rates: HashMap<Ipv4Addr, (ItemId, String)>,
    /// Two leases hold one address (a config edited by hand): every change
    /// rebuilds, so the last one wins as before.
    dup: bool,
}

fn rated(l: &StaticLease) -> bool {
    !l.disabled && !l.rate_limit.is_empty()
}

impl IpoeIndex {
    pub fn of(cfg: &Config) -> Self {
        let mut index = Self::default();
        index.refresh(cfg);
        index
    }

    /// Follow `cfg`: only the blocks of static leases that are not shared
    /// with the last config seen are read.
    pub fn refresh(&mut self, cfg: &Config) {
        let new = &cfg.ip.dhcp_server.leases;
        if CowList::ptr_eq(&self.leases, new) {
            return;
        }
        if self.dup {
            self.rebuild(new);
            return;
        }
        let old = std::mem::replace(&mut self.leases, new.clone());
        for (block, (_, shared)) in old.blocks().zip(old.shared_blocks(new)) {
            if shared.is_some() {
                continue;
            }
            for l in block.iter().filter(|l| rated(l)) {
                if self.lease_rates.get(&l.address).is_some_and(|(id, _)| *id == l.id) {
                    self.lease_rates.remove(&l.address);
                }
            }
        }
        for (block, (_, shared)) in new.blocks().zip(new.shared_blocks(&old)) {
            if shared.is_some() {
                continue;
            }
            for l in block.iter().filter(|l| rated(l)) {
                if let Some((id, _)) = self.lease_rates.insert(l.address, (l.id, l.rate_limit.clone()))
                    && id != l.id
                {
                    self.dup = true;
                }
            }
        }
        if self.dup {
            self.rebuild(new);
        }
    }

    fn rebuild(&mut self, leases: &CowList<StaticLease>) {
        self.lease_rates.clear();
        self.dup = false;
        for l in leases.iter().filter(|l| rated(l)) {
            if let Some((id, _)) = self.lease_rates.insert(l.address, (l.id, l.rate_limit.clone())) {
                self.dup |= id != l.id;
            }
        }
        self.leases = leases.clone();
    }
}

/// The running config as the IPoE decisions read it, with its index.
#[derive(Clone, Copy)]
pub struct IpoeView<'a> {
    pub cfg: &'a Config,
    index: &'a IpoeIndex,
}

impl<'a> IpoeView<'a> {
    /// `index` must be [`IpoeIndex::of`] this `cfg`, or refreshed to it.
    pub fn new(cfg: &'a Config, index: &'a IpoeIndex) -> Self {
        IpoeView { cfg, index }
    }

    /// The `/ppp secret` (service `ipoe`) named `user`, enabled or not.
    pub fn secret(&self, user: &str) -> Option<&'a PppSecret> {
        self.cfg.ppp.secrets.first_named(user, |s| s.service == PppService::Ipoe)
    }

    /// The `rate_limit` of the static lease of `ip`.
    pub fn lease_rate(&self, ip: Ipv4Addr) -> Option<&'a str> {
        self.index.lease_rates.get(&ip).map(|(_, r)| r.as_str())
    }
}

#[derive(Default)]
struct IpoeRuntime {
    backend: Option<Arc<dyn IpoeBackend>>,
    index: IpoeIndex,
}

impl Session {
    pub fn set_ipoe_backend(&mut self, backend: Arc<dyn IpoeBackend>) {
        if let Some(rt) = self.ext_mut::<IpoeRuntime>() {
            rt.backend = Some(backend);
        }
    }

    /// The daemon's IPoE service, if it runs one.
    pub fn ipoe_backend(&self) -> Option<Arc<dyn IpoeBackend>> {
        self.ext::<IpoeRuntime>()?.backend.clone()
    }

    /// Index the running config again if it changed (once a DHCP round).
    pub(crate) fn ipoe_refresh(&mut self) {
        let rev = self.store().current_revision();
        if self.ext::<IpoeRuntime>().is_some_and(|r| r.index.revision == Some(rev)) {
            return;
        }
        let Some(mut index) = self.ext_mut::<IpoeRuntime>().map(|r| std::mem::take(&mut r.index)) else {
            return;
        };
        index.refresh(self.store().running());
        index.revision = Some(rev);
        if let Some(rt) = self.ext_mut::<IpoeRuntime>() {
            rt.index = index;
        }
    }

    /// The running config and its index (fresh after [`Session::ipoe_refresh`]).
    pub(crate) fn ipoe_view(&self) -> Option<IpoeView<'_>> {
        let rt = self.ext::<IpoeRuntime>()?;
        Some(IpoeView::new(self.store().running(), &rt.index))
    }
}

/// The subscriber name of an asking client: what `ipoe_username` builds
/// from its MAC and option 82 (as text: `agent::text`).
pub fn user_of(srv: &DhcpServer, mac: [u8; 6], circuit: Option<&[u8]>, remote: Option<&[u8]>) -> Option<String> {
    let c = circuit.map(agent::text);
    let r = remote.map(agent::text);
    srv.ipoe_username.name(MacAddr(mac), c.as_deref(), r.as_deref())
}

/// The local decision about `ask` on `cfg`: its `/ppp secret`
/// (`service=ipoe`, enabled, named as `ipoe_username` says), else RADIUS
/// when `use_radius=yes`, else `ipoe_unknown`.
pub fn local_verdict(ask: &AuthAsk, view: &IpoeView<'_>) -> Local {
    let cfg = view.cfg;
    let Some(srv) = cfg.ip.dhcp_server.server(&ask.server) else {
        return Local::Done(Verdict::Reject("server gone".into()));
    };
    let Some(user) = user_of(srv, ask.mac, ask.circuit_id.as_deref(), ask.remote_id.as_deref()) else {
        return Local::Done(Verdict::Reject(format!(
            "no {} in the request (ipoe_username={})",
            match srv.ipoe_username {
                corerouter_model::ipoe::IpoeUsername::RemoteId => "option 82 remote id",
                _ => "option 82 circuit id",
            },
            srv.ipoe_username
        )));
    };
    if let Some(sec) = view.secret(&user) {
        if sec.disabled {
            return Local::Done(Verdict::Reject(format!("secret {user} is disabled")));
        }
        if sec.caller_id.is_some_and(|m| m.0 != ask.mac) {
            return Local::Done(Verdict::Reject(format!("secret {user}: caller-id mismatch")));
        }
        let e = cfg.ppp.effective(Some(sec), &sec.profile, DEFAULT_PROFILE);
        let mut g = Grant {
            address: sec.remote_address,
            ..Grant::default()
        };
        match e.remote_address {
            Some(AddrOrPool::Address(ip)) if g.address.is_none() => g.address = Some(ip),
            Some(AddrOrPool::Pool(p)) => g.pool = Some(p),
            _ => {}
        }
        if let Some(l) = e.address_list {
            g.address_lists.push(l);
        }
        return Local::Done(Verdict::Accept(g));
    }
    match (srv.use_radius, srv.ipoe_unknown) {
        (UseRadius::Yes, _) => Local::AskRadius { user },
        (_, IpoeUnknown::Accept) => Local::Done(Verdict::Accept(Grant::default())),
        (_, IpoeUnknown::Reject) => Local::Done(Verdict::Reject(format!("{user}: no ppp.secret with service=ipoe"))),
    }
}

impl Session {
    /// An [`AuthAsk`] of the DHCP server: the service's answer, or the
    /// local one without a service (RADIUS cannot be asked then).
    pub(crate) fn ipoe_authorize(&self, ask: &AuthAsk) -> Option<Verdict> {
        let view = self.ipoe_view()?;
        if let Some(b) = self.ipoe_backend() {
            return b.authorize(ask, &view);
        }
        Some(match local_verdict(ask, &view) {
            Local::Done(v) => v,
            Local::AskRadius { user } => Verdict::Reject(format!(
                "{user}: RADIUS needed but the daemon's ipoe service is not running"
            )),
        })
    }

    /// Switch the IPoE subscribers of the XDP data plane on for `ports`
    /// (G4.3f; they share the PPPoE session maps). `Err` says why not: the
    /// sessions then exist without the policer.
    pub fn ipoe_dataplane(&mut self, on: bool, ports: &[IfName]) -> Result<(), String> {
        self.hal_mut().ipoe_dataplane(on, ports).map_err(|e| e.to_string())
    }

    /// Whether `server` makes sessions of its leases.
    pub(crate) fn ipoe_server(&self, server: &str) -> bool {
        self.store()
            .running()
            .ip
            .dhcp_server
            .server(server)
            .is_some_and(DhcpServer::sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_proto_dhcp::server::request::Kind;
    use serde_json::json;

    fn ask(mac: [u8; 6], circuit: Option<&str>) -> AuthAsk {
        AuthAsk {
            server: "dhcp1".into(),
            interface: "ether2".parse().unwrap(),
            client_key: vec![1, 2, 0, 0, 0, 0, 1],
            mac,
            client_id: None,
            circuit_id: circuit.map(|c| c.as_bytes().to_vec()),
            remote_id: None,
            giaddr: Ipv4Addr::UNSPECIFIED,
            host_name: String::new(),
            vendor_class: String::new(),
            kind: Kind::Discover,
        }
    }

    fn lv(a: &AuthAsk, cfg: &corerouter_model::Config) -> Local {
        let idx = IpoeIndex::of(cfg);
        local_verdict(a, &IpoeView::new(cfg, &idx))
    }

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        for (id, p) in [
            ("ip.address.add", json!({"address": "10.9.0.1/24", "interface": "ether2"})),
            ("ip.pool.add", json!({"name": "subs", "ranges": "10.9.0.10-10.9.0.200"})),
            ("ip.pool.add", json!({"name": "vip", "ranges": "10.9.0.201-10.9.0.210"})),
            ("ip.dhcp-server.add", json!({"interface": "ether2", "address_pool": "subs", "ipoe": true})),
            ("ppp.profile.add", json!({"name": "gold", "remote_address": "vip", "address_list": "gold"})),
            ("ppp.secret.add", json!({"name": "02:00:00:00:00:01", "service": "ipoe", "profile": "gold"})),
            ("ppp.secret.add", json!({"name": "olt1/3", "service": "ipoe", "remote_address": "10.9.0.99"})),
            ("ppp.secret.add", json!({"name": "02:00:00:00:00:03", "password": "x", "service": "pppoe"})),
        ] {
            s.execute(id, &p).unwrap();
        }
        s
    }

    #[test]
    fn secrets_unknowns_and_radius() {
        let mut s = lab();
        let cfg = s.store().running().clone();
        let Local::Done(Verdict::Accept(g)) = lv(&ask([2, 0, 0, 0, 0, 1], None), &cfg) else {
            panic!("the secret's client is accepted");
        };
        assert_eq!(g.pool.as_deref(), Some("vip"));
        assert_eq!(g.address_lists, ["gold"]);
        // A PPPoE secret named like the MAC is not an IPoE grant: unknown,
        // accepted with the server's own settings (ipoe_unknown=accept).
        assert_eq!(
            lv(&ask([2, 0, 0, 0, 0, 3], None), &cfg),
            Local::Done(Verdict::Accept(Grant::default()))
        );
        s.execute("ip.dhcp-server.set", &json!({"id": "dhcp1", "ipoe_unknown": "reject"})).unwrap();
        let cfg = s.store().running().clone();
        assert!(matches!(lv(&ask([2, 0, 0, 0, 0, 3], None), &cfg), Local::Done(Verdict::Reject(_))));
        // By circuit id: the line's secret, its fixed address.
        s.execute("ip.dhcp-server.set", &json!({"id": "dhcp1", "ipoe_username": "circuit-id"})).unwrap();
        let cfg = s.store().running().clone();
        let Local::Done(Verdict::Accept(g)) = lv(&ask([2, 0, 0, 0, 0, 7], Some("olt1/3")), &cfg) else {
            panic!("the line's secret");
        };
        assert_eq!(g.address, Some(Ipv4Addr::new(10, 9, 0, 99)));
        // No option 82: no name, not served.
        assert!(matches!(lv(&ask([2, 0, 0, 0, 0, 7], None), &cfg), Local::Done(Verdict::Reject(_))));
        // RADIUS when the secret list does not know the client.
        s.execute("ip.dhcp-server.set", &json!({"id": "dhcp1", "use_radius": "yes", "ipoe_username": "mac"})).unwrap();
        let cfg = s.store().running().clone();
        assert_eq!(
            lv(&ask([2, 0, 0, 0, 0, 9], None), &cfg),
            Local::AskRadius { user: "02:00:00:00:00:09".into() }
        );
        // Without the daemon's service the engine cannot ask: refused.
        s.ipoe_refresh();
        assert!(matches!(s.ipoe_authorize(&ask([2, 0, 0, 0, 0, 9], None)), Some(Verdict::Reject(_))));
    }

    fn rates(idx: &IpoeIndex) -> Vec<(Ipv4Addr, String)> {
        let mut v: Vec<_> = idx.lease_rates.iter().map(|(a, (_, r))| (*a, r.clone())).collect();
        v.sort();
        v
    }

    fn lease(id: u32, last: u8, rate: &str) -> StaticLease {
        let mut l = StaticLease::new(ItemId(id), Ipv4Addr::new(10, 0, 0, last));
        l.rate_limit = rate.into();
        l
    }

    proptest::proptest! {
        /// The index followed block by block equals one built from scratch
        /// after any series of writes (adds, edits, removals, a duplicated
        /// address edited by hand).
        #[test]
        fn refresh_equals_a_rebuild(ops in proptest::collection::vec((0u8..5, 0u16..600, 0u8..40), 1..60)) {
            let mut cfg = Config::default();
            for i in 0..400u32 {
                cfg.ip.dhcp_server.leases.push(lease(i + 1, (i % 250) as u8, if i % 3 == 0 { "1M/1M" } else { "" }));
            }
            let mut idx = IpoeIndex::of(&cfg);
            let mut next = 1000u32;
            for (op, at, v) in ops {
                let mut c = cfg.clone();
                let leases = &mut c.ip.dhcp_server.leases;
                let at = usize::from(at) % leases.len().max(1);
                match op {
                    0 => {
                        next += 1;
                        leases.push(lease(next, 100 + v, "5M/5M"));
                    }
                    1 => {
                        leases.remove(at);
                    }
                    2 => {
                        if let Some(l) = leases.get_mut(at) {
                            l.rate_limit = format!("{v}M/{v}M");
                        }
                    }
                    3 => {
                        if let Some(l) = leases.get_mut(at) {
                            l.disabled = !l.disabled;
                        }
                    }
                    _ => {
                        if let Some(l) = leases.get_mut(at) {
                            l.address = Ipv4Addr::new(10, 0, 0, v);
                        }
                    }
                }
                idx.refresh(&c);
                proptest::prop_assert_eq!(rates(&idx), rates(&IpoeIndex::of(&c)));
                cfg = c;
            }
        }
    }
}
