//! The virtual lab's DHCPv6 clients (G4.2c): behind every lab port where
//! the router runs a DHCPv6 server, two CPEs (`02:1A:B6:N:00:01`, `…:02`)
//! ask for an address and a delegated prefix (Solicit with Rapid Commit,
//! else Advertise → Request) and renew at T1, so the lab and the
//! screenshots show bindings without a network.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::sync::{Mutex, PoisonError};

use corerouter_hal::dhcp::{lab_net, link_local};
use corerouter_hal::dhcp_server::{Heard6, LabClients6};
use corerouter_model::IfName;

use crate::v6::{self, IaReq, Outgoing, msg};

const HOSTS: u8 = 2;
const RETRY: u64 = 4;
const MAX_PORTS: usize = 256;
const ORO: [u16; 2] = [v6::opt::DNS_SERVERS, v6::opt::DOMAIN_LIST];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Idle,
    Soliciting {
        at: u64,
    },
    Requesting {
        server: Vec<u8>,
        at: u64,
    },
    Bound {
        server: Vec<u8>,
        renew_at: u64,
        end: u64,
    },
    Renewing {
        server: Vec<u8>,
        at: u64,
        end: u64,
    },
}

#[derive(Debug, Clone)]
struct Host {
    mac: [u8; 6],
    xid: u32,
    phase: Phase,
    addr: Option<Ipv6Addr>,
    prefix: Option<ipnet::Ipv6Net>,
}

#[derive(Debug, Default)]
struct Port {
    hosts: Vec<Host>,
    outbox: Vec<Heard6>,
}

#[derive(Debug, Default)]
pub struct LabHosts6 {
    ports: Mutex<BTreeMap<IfName, Port>>,
}

impl Host {
    fn duid(&self) -> Vec<u8> {
        v6::duid_ll(self.mac)
    }

    fn message(&mut self, kind: u8, server: Option<&[u8]>) -> Heard6 {
        self.xid = (self.xid + 1) & 0x00ff_ffff;
        let duid = self.duid();
        let iaid = u32::from(self.mac[5]);
        let ia_na = Some(IaReq {
            iaid,
            addrs: self.addr.into_iter().collect(),
            prefixes: Vec::new(),
        });
        let ia_pd = Some(IaReq {
            iaid,
            addrs: Vec::new(),
            prefixes: self.prefix.into_iter().collect(),
        });
        let payload = Outgoing {
            kind,
            xid: self.xid,
            client_id: &duid,
            server_id: server,
            elapsed_cs: 0,
            rapid_commit: kind == msg::SOLICIT,
            ia_na,
            ia_pd,
            oro: &ORO,
        }
        .encode();
        Heard6 {
            payload,
            src: link_local(self.mac),
        }
    }

    fn step(&mut self, now: u64) -> Option<Heard6> {
        match self.phase.clone() {
            Phase::Idle => {
                self.phase = Phase::Soliciting { at: now };
                Some(self.message(msg::SOLICIT, None))
            }
            Phase::Soliciting { at } | Phase::Requesting { at, .. } if now >= at + RETRY => {
                self.phase = Phase::Soliciting { at: now };
                Some(self.message(msg::SOLICIT, None))
            }
            Phase::Bound {
                server,
                renew_at,
                end,
            } if now >= renew_at => {
                self.phase = Phase::Renewing {
                    server: server.clone(),
                    at: now,
                    end,
                };
                Some(self.message(msg::RENEW, Some(&server)))
            }
            Phase::Renewing { server, at, end } if now >= at + RETRY => {
                if now >= end {
                    self.phase = Phase::Idle;
                    return None;
                }
                self.phase = Phase::Renewing {
                    server: server.clone(),
                    at: now,
                    end,
                };
                Some(self.message(msg::RENEW, Some(&server)))
            }
            _ => None,
        }
    }
}

impl LabHosts6 {
    fn with<T>(&self, port: &IfName, f: impl FnOnce(&mut Port) -> T) -> Option<T> {
        let mut ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
        if !ports.contains_key(port) && ports.len() >= MAX_PORTS {
            return None;
        }
        let n = lab_net(port);
        let p = ports.entry(port.clone()).or_insert_with(|| Port {
            hosts: (1..=HOSTS)
                .map(|k| Host {
                    mac: [0x02, 0x1a, 0xb6, n, 0, k],
                    xid: u32::from(k) << 16,
                    phase: Phase::Idle,
                    addr: None,
                    prefix: None,
                })
                .collect(),
            outbox: Vec::new(),
        });
        Some(f(p))
    }
}

impl LabClients6 for LabHosts6 {
    fn poll(&self, port: &IfName, now: u64) -> Vec<Heard6> {
        self.with(port, |p| {
            let mut out = std::mem::take(&mut p.outbox);
            for h in &mut p.hosts {
                out.extend(h.step(now));
            }
            out
        })
        .unwrap_or_default()
    }

    fn deliver(&self, port: &IfName, payload: &[u8], now: u64) {
        let Ok(m) = v6::decode(payload) else {
            return;
        };
        self.with(port, |p| {
            let Some(h) = p.hosts.iter_mut().find(|h| {
                m.client_id.as_deref() == Some(h.duid().as_slice())
                    && (m.xid & 0x00ff_ffff) == h.xid
            }) else {
                return;
            };
            let server = m.server_id.clone().unwrap_or_default();
            let lease = |h: &mut Host| {
                h.addr = m
                    .ia_na
                    .first()
                    .and_then(|ia| ia.addrs.first())
                    .map(|a| a.addr);
                h.prefix = m
                    .ia_pd
                    .first()
                    .and_then(|ia| ia.prefixes.first())
                    .map(|p| p.prefix);
                let t1 = m
                    .ia_na
                    .first()
                    .map(|ia| ia.t1)
                    .filter(|t| *t > 0)
                    .unwrap_or(300);
                let valid = m
                    .ia_na
                    .first()
                    .and_then(|ia| ia.addrs.first())
                    .map_or(600, |a| a.valid);
                (u64::from(t1), u64::from(valid))
            };
            match (m.kind, h.phase.clone()) {
                (msg::ADVERTISE, Phase::Soliciting { .. }) => {
                    h.phase = Phase::Requesting {
                        server: server.clone(),
                        at: now,
                    };
                    let _ = lease(h);
                    let req = h.message(msg::REQUEST, Some(&server));
                    p.outbox.push(req);
                }
                (
                    msg::REPLY,
                    Phase::Soliciting { .. } | Phase::Requesting { .. } | Phase::Renewing { .. },
                ) => {
                    let (t1, valid) = lease(h);
                    h.phase = Phase::Bound {
                        server,
                        renew_at: now + t1,
                        end: now + valid,
                    };
                }
                _ => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Now;
    use crate::server6::{Effect6, Plan6, Server6};
    use corerouter_model::dhcp6_server::{Dhcp6Server, Ipv6Pool};
    use corerouter_model::{Config, Interface, InterfaceKind, ItemId};

    #[test]
    fn lab_cpes_get_an_address_and_a_prefix() {
        let port: IfName = "ether2".parse().unwrap();
        let mut c = Config::default();
        c.interfaces.insert(
            port.clone(),
            Interface::new(port.clone(), InterfaceKind::Ethernet),
        );
        let d = &mut c.ipv6.dhcp_server;
        d.pools.push(Ipv6Pool {
            id: ItemId(1),
            name: "addrs".into(),
            prefix: "2001:db8:1::/64".parse().unwrap(),
            prefix_length: 128,
            comment: String::new(),
        });
        d.pools.push(Ipv6Pool {
            id: ItemId(2),
            name: "cpe".into(),
            prefix: "2001:db8:100::/40".parse().unwrap(),
            prefix_length: 56,
            comment: String::new(),
        });
        let mut s = Dhcp6Server::new(ItemId(3), "v6".into(), port.clone());
        s.address_pool = Some("addrs".into());
        s.prefix_pool = Some("cpe".into());
        d.servers.push(s);
        let lab = LabHosts6::default();
        let mut srv = Server6::new(Plan6::from_config(&c));
        let mut now = Now { ms: 0, unix: 1000 };
        for _ in 0..20 {
            now.ms += 500;
            now.unix = 1000 + now.ms / 1000;
            for h in lab.poll(&port, now.unix) {
                for e in srv.handle(now, &port, [2, 0, 0, 0, 0, 1], h.src, &h.payload) {
                    if let Effect6::Send { payload, .. } = e {
                        lab.deliver(&port, &payload, now.unix);
                    }
                }
            }
        }
        let bound: Vec<_> = srv
            .leases()
            .iter()
            .filter(|l| l.state == crate::server::leases::State::Bound)
            .collect();
        assert_eq!(bound.len(), 4, "two CPEs × address and prefix");
    }
}
