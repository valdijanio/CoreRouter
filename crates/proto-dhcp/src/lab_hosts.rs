//! The virtual lab's DHCP clients (G4.2a): behind every lab port where the
//! router runs a DHCP server live a few simulated hosts that get and renew
//! leases from it, so the lab, the GUI screenshots and the CI see a working
//! server without any network.
//!
//! | Host | MAC | Sends |
//! |---|---|---|
//! | `lab-laptop` | `02:1A:B0:N:00:01` | vendor class `MSFT 5.0` |
//! | `lab-phone` | `02:1A:B0:N:00:02` | `android-dhcp-14` |
//! | `lab-printer` | `02:1A:B0:N:00:03` | `HP LaserJet` |
//! | `lab-tv` | `02:1A:B0:N:00:04` | — |
//!
//! Also there: a squatter, `0E:5A:00:00:00:N`, that answers
//! ARP for every address ending in `.11` (the server's conflict detection
//! finds it), and a rogue DHCP server, `02:BA:D0:00:00:N` at
//! `192.0.2.250`, that sends an OFFER a minute (the alert finds it). N is
//! the port's lab number (`corerouter_hal::dhcp::lab_net`).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, PoisonError};

use corerouter_hal::dhcp::lab_net;
use corerouter_hal::dhcp_server::{Heard, LabClients, ReplyTo};
use corerouter_model::IfName;
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Encodable, Encoder};

use crate::v4::{self, Outgoing};

const HOSTS: [(&str, &str); 4] = [
    ("lab-laptop", "MSFT 5.0"),
    ("lab-phone", "android-dhcp-14"),
    ("lab-printer", "HP LaserJet"),
    ("lab-tv", ""),
];
/// Seconds before a client asks again (RFC 2131 §4.1 starts at 4 s).
const RETRY: u64 = 4;
/// The rogue server's OFFER period.
const ROGUE_EVERY: u64 = 60;
/// Ports remembered (hostile-free, but bounded).
const MAX_PORTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Idle,
    Selecting {
        at: u64,
    },
    Requesting {
        ip: Ipv4Addr,
        server: Ipv4Addr,
        at: u64,
    },
    Bound {
        ip: Ipv4Addr,
        server: Ipv4Addr,
        renew_at: u64,
        end: u64,
    },
    Renewing {
        ip: Ipv4Addr,
        server: Ipv4Addr,
        at: u64,
        end: u64,
    },
}

#[derive(Debug, Clone)]
struct Host {
    name: &'static str,
    vendor: &'static str,
    mac: [u8; 6],
    xid: u32,
    phase: Phase,
}

#[derive(Debug, Default)]
struct Port {
    hosts: Vec<Host>,
    outbox: Vec<Heard>,
    rogue_at: u64,
}

#[derive(Debug, Default)]
pub struct LabHosts {
    ports: Mutex<BTreeMap<IfName, Port>>,
}

/// The squatter's MAC behind port N.
pub fn squatter_mac(n: u8) -> [u8; 6] {
    [0x0e, 0x5a, 0, 0, 0, n]
}

/// The rogue server's MAC behind port N.
pub fn rogue_mac(n: u8) -> [u8; 6] {
    [0x02, 0xba, 0xd0, 0, 0, n]
}

pub const ROGUE_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 250);

fn new_port(n: u8) -> Port {
    let hosts = HOSTS
        .iter()
        .zip(1u8..)
        .map(|((name, vendor), k)| Host {
            name,
            vendor,
            mac: [0x02, 0x1a, 0xb0, n, 0, k],
            xid: (u32::from(n) << 16) | (u32::from(k) << 8),
            phase: Phase::Idle,
        })
        .collect();
    Port {
        hosts,
        outbox: Vec::new(),
        rogue_at: 0,
    }
}

impl Host {
    fn message(
        &mut self,
        kind: MessageType,
        ciaddr: Ipv4Addr,
        requested: Option<Ipv4Addr>,
        server: Option<Ipv4Addr>,
        dst: Ipv4Addr,
    ) -> Option<Heard> {
        self.xid = self.xid.wrapping_add(1);
        let mut id = vec![1u8];
        id.extend_from_slice(&self.mac);
        let payload = Outgoing {
            kind,
            xid: self.xid,
            secs: 0,
            mac: self.mac,
            ciaddr,
            broadcast: false,
            requested,
            server_id: server,
            client_id: &id,
            host_name: Some(self.name),
            vendor_class: (!self.vendor.is_empty()).then_some(self.vendor.as_bytes()),
            extra: &[],
        }
        .encode()
        .ok()?;
        Some(Heard {
            payload,
            src: ciaddr,
            dst,
            src_mac: self.mac,
            to_server: true,
        })
    }

    fn step(&mut self, now: u64) -> Option<Heard> {
        let none = Ipv4Addr::UNSPECIFIED;
        let bcast = Ipv4Addr::BROADCAST;
        match self.phase.clone() {
            Phase::Idle => {
                self.phase = Phase::Selecting { at: now };
                self.message(MessageType::Discover, none, None, None, bcast)
            }
            Phase::Selecting { at } if now >= at + RETRY => {
                self.phase = Phase::Selecting { at: now };
                self.message(MessageType::Discover, none, None, None, bcast)
            }
            Phase::Requesting { at, .. } if now >= at + RETRY => {
                self.phase = Phase::Idle;
                None
            }
            Phase::Bound {
                ip,
                server,
                renew_at,
                end,
            } if now >= renew_at => {
                self.phase = Phase::Renewing {
                    ip,
                    server,
                    at: now,
                    end,
                };
                self.message(MessageType::Request, ip, None, None, server)
            }
            Phase::Renewing {
                ip,
                server,
                at,
                end,
            } if now >= at + RETRY => {
                if now >= end {
                    self.phase = Phase::Idle;
                    return None;
                }
                self.phase = Phase::Renewing {
                    ip,
                    server,
                    at: now,
                    end,
                };
                self.message(MessageType::Request, ip, None, None, server)
            }
            _ => None,
        }
    }
}

fn rogue_offer(n: u8) -> Option<Heard> {
    let client = [0x02, 0x1a, 0xb0, n, 0, 1];
    let mut m = Message::new_with_id(
        0x0bad_0000 | u32::from(n),
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(192, 0, 2, 100),
        ROGUE_IP,
        Ipv4Addr::UNSPECIFIED,
        &client,
    );
    m.set_opcode(Opcode::BootReply);
    let o = m.opts_mut();
    o.insert(DhcpOption::MessageType(MessageType::Offer));
    o.insert(DhcpOption::ServerIdentifier(ROGUE_IP));
    o.insert(DhcpOption::AddressLeaseTime(300));
    let mut buf = Vec::new();
    m.encode(&mut Encoder::new(&mut buf)).ok()?;
    Some(Heard {
        payload: buf,
        src: ROGUE_IP,
        dst: Ipv4Addr::BROADCAST,
        src_mac: rogue_mac(n),
        to_server: false,
    })
}

impl LabHosts {
    fn with<T>(&self, port: &IfName, f: impl FnOnce(&mut Port) -> T) -> Option<T> {
        let mut ports = self.ports.lock().unwrap_or_else(PoisonError::into_inner);
        if !ports.contains_key(port) && ports.len() >= MAX_PORTS {
            return None;
        }
        let p = ports
            .entry(port.clone())
            .or_insert_with(|| new_port(lab_net(port)));
        Some(f(p))
    }
}

impl LabClients for LabHosts {
    fn poll(&self, port: &IfName, now: u64) -> Vec<Heard> {
        let n = lab_net(port);
        self.with(port, |p| {
            let mut out = std::mem::take(&mut p.outbox);
            for h in &mut p.hosts {
                out.extend(h.step(now));
            }
            if now >= p.rogue_at + ROGUE_EVERY {
                p.rogue_at = now;
                out.extend(rogue_offer(n));
            }
            out
        })
        .unwrap_or_default()
    }

    fn deliver(&self, port: &IfName, payload: &[u8], to: ReplyTo, now: u64) {
        let Ok(m) = v4::decode(payload) else {
            return;
        };
        let _ = to;
        self.with(port, |p| {
            let Some(h) = p
                .hosts
                .iter_mut()
                .find(|h| h.mac == m.chaddr && h.xid == m.xid)
            else {
                return;
            };
            let server = m.server_id.unwrap_or(Ipv4Addr::UNSPECIFIED);
            match (m.kind, h.phase.clone()) {
                (MessageType::Offer, Phase::Selecting { .. }) => {
                    h.phase = Phase::Requesting {
                        ip: m.yiaddr,
                        server,
                        at: now,
                    };
                    let req = h.message(
                        MessageType::Request,
                        Ipv4Addr::UNSPECIFIED,
                        Some(m.yiaddr),
                        Some(server),
                        Ipv4Addr::BROADCAST,
                    );
                    p.outbox.extend(req);
                }
                (MessageType::Ack, Phase::Requesting { ip, .. } | Phase::Renewing { ip, .. }) => {
                    let lease = u64::from(m.lease_secs.unwrap_or(600));
                    let t1 = u64::from(m.renew_secs.unwrap_or(0)).max(lease / 2).max(1);
                    h.phase = Phase::Bound {
                        ip,
                        server,
                        renew_at: now + t1,
                        end: now + lease,
                    };
                }
                (MessageType::Nak, _) => h.phase = Phase::Idle,
                _ => {}
            }
        });
    }

    fn arp(&self, port: &IfName, ip: Ipv4Addr) -> Option<[u8; 6]> {
        let n = lab_net(port);
        if ip.octets()[3] == 11 {
            return Some(squatter_mac(n));
        }
        // The hosts answer for their own addresses.
        self.with(port, |p| {
            p.hosts.iter().find_map(|h| match h.phase {
                Phase::Bound { ip: mine, .. } | Phase::Renewing { ip: mine, .. } if mine == ip => {
                    Some(h.mac)
                }
                _ => None,
            })
        })
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::plan::Plan;
    use crate::server::{Effect, Now, Server};
    use corerouter_model::dhcp_server::{DhcpNetwork, DhcpServer};
    use corerouter_model::ip_pool::IpPool;
    use corerouter_model::{AddressEntry, Config, Interface, InterfaceKind, ItemId};

    /// The lab's hosts against the real server: everyone ends up bound,
    /// the squatter's address is a conflict, and leases renew.
    #[test]
    fn lab_hosts_get_leases_from_the_server() {
        let mut c = Config::default();
        let port: IfName = "ether2".parse().unwrap();
        c.interfaces.insert(
            port.clone(),
            Interface::new(port.clone(), InterfaceKind::Ethernet),
        );
        c.ip.addresses.push(AddressEntry {
            id: ItemId(1),
            address: "192.168.88.1/24".parse().unwrap(),
            interface: port.clone(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        c.ip.pools.pools.push(IpPool {
            id: ItemId(1),
            name: "lan".into(),
            ranges: vec!["192.168.88.10-192.168.88.50".parse().unwrap()],
            next_pool: None,
            comment: String::new(),
        });
        let mut s = DhcpServer::new(ItemId(2), "dhcp1".into(), port.clone());
        s.address_pool = Some("lan".into());
        s.lease_time = 600;
        c.ip.dhcp_server.servers.push(s);
        let mut n = DhcpNetwork::new(ItemId(3), "192.168.88.0/24".parse().unwrap());
        n.gateway = vec!["192.168.88.1".parse().unwrap()];
        c.ip.dhcp_server.networks.push(n);
        let lab = LabHosts::default();
        let mut srv = Server::new(Plan::from_config(&c), 0);
        let mut now = Now { ms: 0, unix: 1000 };
        for _ in 0..40 {
            now.ms += 250;
            now.unix = 1000 + now.ms / 1000;
            let mut fx = srv.tick(now);
            for h in lab.poll(&port, now.unix) {
                fx.extend(srv.handle(now, &port, &h));
            }
            for e in fx {
                match e {
                    Effect::Send { payload, to, .. } => lab.deliver(&port, &payload, to, now.unix),
                    Effect::Probe { ip, .. } => {
                        if let Some(m) = lab.arp(&port, ip) {
                            let _ = srv.probe_reply(now, &port, ip, m);
                        }
                    }
                    _ => {}
                }
            }
        }
        let bound = srv
            .leases()
            .iter()
            .filter(|l| l.state == crate::server::leases::State::Bound)
            .count();
        assert_eq!(bound, 4);
        let c11 = srv.leases().get("192.168.88.11".parse().unwrap()).unwrap();
        assert_eq!(c11.state, crate::server::leases::State::Conflict);
        assert_eq!(c11.mac, squatter_mac(2));
        assert!(
            lab.poll(&port, now.unix + 400)
                .iter()
                .any(|h| h.src.octets()[0] == 192),
            "renewals by unicast"
        );
    }
}
