//! The virtual lab's DHCP server: one simulated server behind every lab
//! port, answering DHCP clients deterministically (no network, no clock),
//! so the lab, the GUI screenshots and the CI see the same leases.
//!
//! Behind port `<name>N` (the trailing number of the port name, else a hash
//! of it, 1..=254) sits network `100.64.N.0/24`:
//!
//! | What | Value |
//! |---|---|
//! | server, router, DNS, NTP | `100.64.N.1` |
//! | address offered | `100.64.N.H/24`, H = 10 + (hash of the client MAC mod 200) |
//! | lease | 600 s (T1 300 s, T2 525 s) |
//! | domain | `lab.test` |
//! | classless routes (121) | `0.0.0.0/0` via `100.64.N.1`, `10.200.0.0/16` via `100.64.N.254` |
//! | server MAC | `02:DC:00:00:00:N` (answers ARP for `100.64.N.1`) |
//!
//! Tests turn [`Knobs`] to play a silent server, a NAKing one, a rogue one
//! or a host that already uses the address.

use std::net::Ipv4Addr;
use std::sync::{Mutex, PoisonError};

use corerouter_hal::dhcp::{Datagram, Dest, DhcpResponder};
use corerouter_model::IfName;
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Encodable, Encoder};
use ipnet::Ipv4Net;

/// How the simulated server behaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knobs {
    pub lease_secs: u32,
    /// Answers nothing (a dead server).
    pub silent: bool,
    /// NAKs every REQUEST.
    pub nak: bool,
    /// Calls itself this instead of `100.64.N.1` (a different server).
    pub server: Option<Ipv4Addr>,
    /// Sends option 121.
    pub classless: bool,
    /// A lab host already uses the offered address (ARP finds this MAC).
    pub squatter: Option<[u8; 6]>,
    /// The router `100.64.N.1` stops answering ARP (check-gateway, G4.7c).
    pub gateway_down: bool,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            lease_secs: 600,
            silent: false,
            nak: false,
            server: None,
            classless: true,
            squatter: None,
            gateway_down: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct LabServer {
    knobs: Mutex<Knobs>,
}

impl LabServer {
    pub fn new(knobs: Knobs) -> Self {
        Self {
            knobs: Mutex::new(knobs),
        }
    }

    pub fn knobs(&self) -> Knobs {
        self.knobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set(&self, f: impl FnOnce(&mut Knobs)) {
        f(&mut self.knobs.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Network number N of `port`.
    pub fn net_of(port: &IfName) -> u8 {
        corerouter_hal::dhcp::lab_net(port)
    }

    /// The address the lab gives `mac` behind `port`.
    pub fn address_for(port: &IfName, mac: [u8; 6]) -> Ipv4Addr {
        let host = 10 + hash(&mac) % 200;
        Ipv4Addr::new(
            100,
            64,
            Self::net_of(port),
            u8::try_from(host).unwrap_or(10),
        )
    }

    pub fn server_ip(port: &IfName) -> Ipv4Addr {
        Ipv4Addr::new(100, 64, Self::net_of(port), 1)
    }
}

fn hash(bytes: &[u8]) -> u32 {
    corerouter_hal::dhcp::lab_hash(bytes)
}

impl DhcpResponder for LabServer {
    fn answer(&self, port: &IfName, mac: [u8; 6], payload: &[u8], _dest: Dest) -> Vec<Datagram> {
        let k = self.knobs();
        if k.silent {
            return Vec::new();
        }
        let Ok(req) = crate::v4::decode_message(payload) else {
            return Vec::new();
        };
        if req.opcode() != Opcode::BootRequest {
            return Vec::new();
        }
        let n = Self::net_of(port);
        let me = k.server.unwrap_or_else(|| Self::server_ip(port));
        let mine = Self::address_for(port, mac);
        let kind = match req.opts().msg_type() {
            Some(MessageType::Discover) => MessageType::Offer,
            Some(MessageType::Request) => {
                let asked = match req.opts().get(dhcproto::v4::OptionCode::RequestedIpAddress) {
                    Some(DhcpOption::RequestedIpAddress(ip)) => *ip,
                    _ => req.ciaddr(),
                };
                let for_other = matches!(
                    req.opts().get(dhcproto::v4::OptionCode::ServerIdentifier),
                    Some(DhcpOption::ServerIdentifier(s)) if *s != me
                );
                if for_other {
                    return Vec::new();
                }
                if k.nak || asked != mine {
                    MessageType::Nak
                } else {
                    MessageType::Ack
                }
            }
            _ => return Vec::new(),
        };
        let yiaddr = if kind == MessageType::Nak {
            Ipv4Addr::UNSPECIFIED
        } else {
            mine
        };
        let mut m = Message::new_with_id(
            req.xid(),
            req.ciaddr(),
            yiaddr,
            Ipv4Addr::UNSPECIFIED,
            req.giaddr(),
            &mac,
        );
        m.set_opcode(Opcode::BootReply).set_flags(req.flags());
        let gw = Ipv4Addr::new(100, 64, n, 1);
        let o = m.opts_mut();
        o.insert(DhcpOption::MessageType(kind));
        o.insert(DhcpOption::ServerIdentifier(me));
        if kind == MessageType::Nak {
            o.insert(DhcpOption::Message("lab: address not yours".into()));
        } else {
            o.insert(DhcpOption::AddressLeaseTime(k.lease_secs));
            o.insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
            o.insert(DhcpOption::Router(vec![gw]));
            o.insert(DhcpOption::DomainNameServer(vec![gw]));
            o.insert(DhcpOption::NtpServers(vec![gw]));
            o.insert(DhcpOption::DomainName("lab.test".into()));
            if k.classless {
                let routes: Vec<(Ipv4Net, Ipv4Addr)> = [
                    (Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0), gw),
                    (
                        Ipv4Net::new(Ipv4Addr::new(10, 200, 0, 0), 16),
                        Ipv4Addr::new(100, 64, n, 254),
                    ),
                ]
                .into_iter()
                .filter_map(|(net, via)| net.ok().map(|net| (net, via)))
                .collect();
                o.insert(DhcpOption::ClasslessStaticRoute(routes));
            }
        }
        let mut buf = Vec::new();
        if m.encode(&mut Encoder::new(&mut buf)).is_err() {
            return Vec::new();
        }
        vec![Datagram {
            payload: buf,
            src: me,
            src_mac: Some([0x02, 0xdc, 0, 0, 0, n]),
        }]
    }

    fn conflict(&self, port: &IfName, ip: Ipv4Addr) -> Option<[u8; 6]> {
        let k = self.knobs();
        if ip == Self::server_ip(port) {
            // The lab router answers ARP for itself.
            let n = Self::net_of(port);
            return (!k.gateway_down).then(|| corerouter_hal::dhcp::lab_router_mac(n));
        }
        k.squatter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_numbers_pick_the_network() {
        let e1: IfName = "ether1".parse().unwrap();
        assert_eq!(LabServer::net_of(&e1), 1);
        assert!(LabServer::net_of(&"vlan300".parse().unwrap()) > 0);
        assert_eq!(
            LabServer::net_of(&"wan".parse().unwrap()),
            LabServer::net_of(&"wan".parse().unwrap())
        );
        let a = LabServer::address_for(&e1, [2, 0, 0, 0, 0, 1]);
        assert_eq!(a.octets()[..3], [100, 64, 1]);
        assert!((10..210).contains(&a.octets()[3]));
    }
}
