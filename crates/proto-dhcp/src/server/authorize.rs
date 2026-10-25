//! Clients a server authorizes before it serves them (IPoE, G4.3f): a
//! server with `use_radius=yes` or `ipoe=yes` asks, for each client it has
//! no grant for, [`Effect::Authorize`] — the engine's IPoE service answers
//! from `/ppp secret` (service `ipoe`) or RADIUS — and parks the message
//! until [`Server::authorized`] brings the verdict. MikroTik asks RADIUS
//! on the DISCOVER and offers nothing on a reject; so do we. A REQUEST
//! from a client without a grant (a renewal after a restart: grants are
//! not stored) is asked too, then ACKed or NAKed.
//!
//! What a grant may change (RADIUS reply, local secret): the address
//! (`Framed-IP-Address`), the pool (`Framed-Pool`), the lease time
//! (`Session-Timeout`, as RouterOS) and the address lists. A grant lasts
//! while the client holds a lease on that server; a lease that ends takes
//! it along (the next DISCOVER asks again). A reject is remembered
//! [`REJECT_HOLD_MS`]: a client retrying its DISCOVER every few seconds
//! does not become a RADIUS request each time.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use corerouter_model::IfName;

use super::leases::State;
use super::plan::ServerPlan;
use super::request::{Kind, Request};
use super::stats::Drop;
use super::{Effect, Level, Now, Server, agent, mac_text};

/// How long a parked message waits for its verdict (a RADIUS server tried
/// three times, three seconds each, plus a failover: 15 s). After that the
/// client's next retransmission asks again.
pub const AUTH_WAIT_MS: u64 = 15_000;
/// Messages waiting for a verdict at once (a DISCOVER flood of random MACs
/// is bounded here, like the probes' `MAX_PARKED`).
pub const MAX_AUTH_PENDING: usize = 8192;
/// Clients a server remembers a grant for (one per bound client; ~200 B
/// each, **estimado**: 50 MB at this size).
pub const MAX_GRANTS: usize = 1 << 18;
/// A rejected client is not asked about again for this long.
pub const REJECT_HOLD_MS: u64 = 30_000;
/// Rejected clients remembered at once.
const MAX_REJECTED: usize = 65_536;

/// What a server asks about a client before serving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAsk {
    pub server: String,
    pub interface: IfName,
    /// RFC 2131 §4.2: the client (its option 61, else `htype` + `chaddr`).
    pub client_key: Vec<u8>,
    pub mac: [u8; 6],
    pub client_id: Option<Vec<u8>>,
    /// RFC 3046 §3.1, §3.2: what the relay agent (or a trusted L2 agent)
    /// said; `None` when it said nothing or was not believed.
    pub circuit_id: Option<Vec<u8>>,
    pub remote_id: Option<Vec<u8>>,
    /// The relay agent (`giaddr`), 0 on the server's own link.
    pub giaddr: Ipv4Addr,
    pub host_name: String,
    pub vendor_class: String,
    /// The message that asked (DISCOVER or REQUEST).
    pub kind: Kind,
}

/// What an accepted client gets beyond the server's own settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Grant {
    /// This address and no other (`Framed-IP-Address`, a secret's
    /// `remote-address`).
    pub address: Option<Ipv4Addr>,
    /// Draw from this pool instead of the server's (`Framed-Pool`).
    pub pool: Option<String>,
    /// Seconds (`Session-Timeout`).
    pub lease_time: Option<u32>,
    pub address_lists: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept(Grant),
    /// Why, in plain words (the log line and the NAK message).
    Reject(String),
}

/// A message waiting for its verdict.
#[derive(Debug, Clone)]
pub(super) struct Pending {
    interface: IfName,
    req: Request,
    unicast: bool,
    deadline_ms: u64,
}

/// The gate's state, inside [`Server`].
#[derive(Debug, Clone, Default)]
pub(super) struct Gate {
    pending: HashMap<(String, Vec<u8>), Pending>,
    grants: HashMap<(String, Vec<u8>), Grant>,
    rejected: HashMap<(String, Vec<u8>), u64>,
}

impl Gate {
    pub(super) fn grant(&self, server: &str, key: &[u8]) -> Option<&Grant> {
        self.grants.get(&(server.to_owned(), key.to_vec()))
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn grants_len(&self) -> usize {
        self.grants.len()
    }

    /// Forget what belongs to servers that are gone or no longer ask.
    pub(super) fn keep(&mut self, asks: impl Fn(&str) -> bool) {
        self.pending.retain(|(s, _), _| asks(s));
        self.grants.retain(|(s, _), _| asks(s));
        self.rejected.retain(|(s, _), _| asks(s));
    }
}

impl AuthAsk {
    fn of(srv: &ServerPlan, iface: &IfName, req: &Request) -> Self {
        let sub = |code| {
            req.relay_info
                .as_deref()
                .and_then(|r| agent::get(r, code))
                .map(<[u8]>::to_vec)
        };
        AuthAsk {
            server: srv.name.clone(),
            interface: iface.clone(),
            client_key: req.client_key(),
            mac: req.mac(),
            client_id: req.client_id.clone(),
            circuit_id: sub(agent::CIRCUIT_ID),
            remote_id: sub(agent::REMOTE_ID),
            giaddr: req.giaddr,
            host_name: Server::host_of(req),
            vendor_class: req
                .vendor_class
                .as_deref()
                .map(|v| crate::v4::clip(&String::from_utf8_lossy(v)))
                .unwrap_or_default(),
            kind: req.kind,
        }
    }
}

impl Server {
    /// Clients waiting for a verdict.
    pub fn authorizing(&self) -> usize {
        self.gate.pending_len()
    }

    /// Clients with a grant.
    pub fn granted(&self) -> usize {
        self.gate.grants_len()
    }

    /// The grant of `key` on `server`, if it has one.
    pub fn grant(&self, server: &str, key: &[u8]) -> Option<&Grant> {
        self.gate.grant(server, key)
    }

    /// Whether this message must wait for a verdict first (and parks it,
    /// asking). `true`: it was taken (parked or dropped).
    pub(super) fn gate(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        unicast: bool,
        out: &mut Vec<Effect>,
    ) -> bool {
        if !srv.authorize || !matches!(req.kind, Kind::Discover | Kind::Request) {
            return false;
        }
        // A REQUEST that chose another server is the normal path's (it
        // frees our offer): nothing to authorize.
        if req.kind == Kind::Request && req.server_id.is_some_and(|sid| !srv.is_me(sid)) {
            return false;
        }
        let k = (srv.name.clone(), req.client_key());
        if self.gate.grants.contains_key(&k) {
            return false;
        }
        if let Some(until) = self.gate.rejected.get(&k) {
            if *until > now.ms {
                self.stats.drop(Drop::Rejected);
                return true;
            }
            self.gate.rejected.remove(&k);
        }
        if let Some(p) = self.gate.pending.get_mut(&k) {
            // A retransmission (or the REQUEST after our silence): the
            // newest message is the one answered.
            p.req = req.clone();
            p.interface = iface.clone();
            p.unicast = unicast;
            self.stats.drop(Drop::Authorizing);
            return true;
        }
        if self.gate.pending.len() >= MAX_AUTH_PENDING {
            self.stats.drop(Drop::Authorizing);
            return true;
        }
        self.gate.pending.insert(
            k,
            Pending {
                interface: iface.clone(),
                req: req.clone(),
                unicast,
                deadline_ms: now.ms.saturating_add(AUTH_WAIT_MS),
            },
        );
        self.stats.auth_asked = self.stats.auth_asked.saturating_add(1);
        out.push(Effect::Authorize(AuthAsk::of(srv, iface, req)));
        true
    }

    /// The verdict on client `key` of `server`: the parked message is
    /// answered now (an OFFER, an ACK, a NAK or nothing). A verdict nobody
    /// waits for (it came late) still records an accept's grant only if the
    /// client holds a lease; otherwise it is dropped.
    pub fn authorized(
        &mut self,
        now: Now,
        server: &str,
        key: &[u8],
        verdict: Verdict,
    ) -> Vec<Effect> {
        let mut out = Vec::new();
        let k = (server.to_owned(), key.to_vec());
        let pending = self.gate.pending.remove(&k);
        let Some(srv) = self.server(server).cloned().filter(|s| s.authorize) else {
            return out;
        };
        match verdict {
            Verdict::Reject(why) => {
                self.stats.auth_rejected = self.stats.auth_rejected.saturating_add(1);
                if self.gate.rejected.len() >= MAX_REJECTED {
                    self.gate.rejected.retain(|_, until| *until > now.ms);
                }
                if self.gate.rejected.len() < MAX_REJECTED {
                    self.gate
                        .rejected
                        .insert(k, now.ms.saturating_add(REJECT_HOLD_MS));
                }
                let Some(p) = pending else {
                    return out;
                };
                out.push(Effect::Log {
                    level: Level::Info,
                    text: format!(
                        "{}: {} not authorized: {why}",
                        srv.name,
                        mac_text(&p.req.mac())
                    ),
                });
                // RFC 2131 §4.3.2: a REQUEST we will not serve is NAKed (the
                // client goes back to INIT); a DISCOVER just gets no offer.
                if p.req.kind == Kind::Request {
                    self.set_agent(&srv.name, &p.req);
                    self.nak(now, &p.interface, &srv, &p.req, "not authorized", &mut out);
                }
            }
            Verdict::Accept(grant) => {
                self.stats.auth_accepted = self.stats.auth_accepted.saturating_add(1);
                let holds = self.leases.of_client(key, server).any(|l| l.state.active());
                if pending.is_none() && !holds {
                    return out;
                }
                if self.gate.grants.len() >= MAX_GRANTS {
                    // Full: forget grants of clients without a lease (they
                    // ask again on their next DISCOVER).
                    let leases = &self.leases;
                    self.gate
                        .grants
                        .retain(|(s, c), _| leases.of_client(c, s).any(|l| l.state.active()));
                    if self.gate.grants.len() >= MAX_GRANTS {
                        out.push(Effect::Log {
                            level: Level::Warning,
                            text: format!(
                                "{}: {MAX_GRANTS} authorized clients, no room for more",
                                srv.name
                            ),
                        });
                        return out;
                    }
                }
                self.gate.grants.insert(k, grant);
                if let Some(p) = pending {
                    self.set_agent(&srv.name, &p.req);
                    match p.req.kind {
                        Kind::Discover => {
                            self.discover(now, &p.interface, &srv, p.req, None, &mut out)
                        }
                        _ => self.request(now, &p.interface, &srv, &p.req, p.unicast, &mut out),
                    }
                }
            }
        }
        self.forget_ended(&out);
        out
    }

    /// Take the grant of `key` on `server` away and end its leases (a
    /// RADIUS Disconnect-Request, an operator's disconnect): the client's
    /// next renewal is NAKed and it starts over, authorized again.
    pub fn revoke(&mut self, now: Now, server: &str, key: &[u8], why: &str) -> Vec<Effect> {
        let mut out = Vec::new();
        self.gate.grants.remove(&(server.to_owned(), key.to_vec()));
        let ips: Vec<Ipv4Addr> = self
            .leases
            .of_client(key, server)
            .filter(|l| l.state == State::Bound)
            .map(|l| l.address)
            .collect();
        for ip in ips {
            self.end(ip, State::Released, now, why, &mut out);
        }
        out
    }

    /// Parked messages whose verdict did not come in time are forgotten
    /// (the client retransmits and asks again); old rejects go.
    pub(super) fn gate_tick(&mut self, now: Now) {
        let before = self.gate.pending.len();
        self.gate.pending.retain(|_, p| p.deadline_ms > now.ms);
        let lost = before - self.gate.pending.len();
        self.stats.auth_timeouts = self.stats.auth_timeouts.saturating_add(lost as u64);
        if !self.gate.rejected.is_empty() {
            self.gate.rejected.retain(|_, until| *until > now.ms);
        }
    }

    /// A lease that ended takes its client's grant along, unless the client
    /// still holds another (it moved to a new address in the same ACK).
    pub(super) fn forget_ended(&mut self, out: &[Effect]) {
        if self.gate.grants.is_empty() {
            return;
        }
        for e in out {
            if let Effect::Gone(l) = e {
                let key = l.client_key();
                let still = self
                    .leases
                    .of_client(&key, &l.server)
                    .any(|x| x.state.active());
                if !still {
                    self.gate.grants.remove(&(l.server.clone(), key));
                }
            }
        }
    }
}
