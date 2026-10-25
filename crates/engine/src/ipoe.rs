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

use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_model::dhcp_server::DhcpServer;
use corerouter_model::ipoe::{IpoeUnknown, UseRadius};
use corerouter_model::ppp::{AddrOrPool, DEFAULT_PROFILE, PppService};
use corerouter_model::{Config, IfName, MacAddr};
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
    fn authorize(&self, ask: &AuthAsk, cfg: &Config) -> Option<Verdict>;
    /// The verdicts that arrived: (server, client key, verdict).
    fn verdicts(&self) -> Vec<(String, Vec<u8>, Verdict)>;
    /// A lease of a session server was bound or renewed.
    fn bound(&self, b: &Binding, cfg: &Config);
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

#[derive(Default)]
struct IpoeRuntime {
    backend: Option<Arc<dyn IpoeBackend>>,
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
pub fn local_verdict(ask: &AuthAsk, cfg: &Config) -> Local {
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
    let secret = cfg
        .ppp
        .secrets
        .iter()
        .find(|s| s.service == PppService::Ipoe && s.name == user);
    if let Some(sec) = secret {
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
        let cfg = self.store().running();
        if let Some(b) = self.ipoe_backend() {
            return b.authorize(ask, cfg);
        }
        Some(match local_verdict(ask, cfg) {
            Local::Done(v) => v,
            Local::AskRadius { user } => Verdict::Reject(format!(
                "{user}: RADIUS needed but the daemon's ipoe service is not running"
            )),
        })
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
        let Local::Done(Verdict::Accept(g)) = local_verdict(&ask([2, 0, 0, 0, 0, 1], None), &cfg) else {
            panic!("the secret's client is accepted");
        };
        assert_eq!(g.pool.as_deref(), Some("vip"));
        assert_eq!(g.address_lists, ["gold"]);
        // A PPPoE secret named like the MAC is not an IPoE grant: unknown,
        // accepted with the server's own settings (ipoe_unknown=accept).
        assert_eq!(
            local_verdict(&ask([2, 0, 0, 0, 0, 3], None), &cfg),
            Local::Done(Verdict::Accept(Grant::default()))
        );
        s.execute("ip.dhcp-server.set", &json!({"id": "dhcp1", "ipoe_unknown": "reject"})).unwrap();
        let cfg = s.store().running().clone();
        assert!(matches!(local_verdict(&ask([2, 0, 0, 0, 0, 3], None), &cfg), Local::Done(Verdict::Reject(_))));
        // By circuit id: the line's secret, its fixed address.
        s.execute("ip.dhcp-server.set", &json!({"id": "dhcp1", "ipoe_username": "circuit-id"})).unwrap();
        let cfg = s.store().running().clone();
        let Local::Done(Verdict::Accept(g)) = local_verdict(&ask([2, 0, 0, 0, 0, 7], Some("olt1/3")), &cfg) else {
            panic!("the line's secret");
        };
        assert_eq!(g.address, Some(Ipv4Addr::new(10, 9, 0, 99)));
        // No option 82: no name, not served.
        assert!(matches!(local_verdict(&ask([2, 0, 0, 0, 0, 7], None), &cfg), Local::Done(Verdict::Reject(_))));
        // RADIUS when the secret list does not know the client.
        s.execute("ip.dhcp-server.set", &json!({"id": "dhcp1", "use_radius": "yes", "ipoe_username": "mac"})).unwrap();
        let cfg = s.store().running().clone();
        assert_eq!(
            local_verdict(&ask([2, 0, 0, 0, 0, 9], None), &cfg),
            Local::AskRadius { user: "02:00:00:00:00:09".into() }
        );
        // Without the daemon's service the engine cannot ask: refused.
        assert!(matches!(s.ipoe_authorize(&ask([2, 0, 0, 0, 0, 9], None)), Some(Verdict::Reject(_))));
    }
}
