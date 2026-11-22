//! The storm shared by `benches/server_storm.rs` and the `storm` example:
//! a /16 pool, N clients with their DISCOVER and REQUEST already encoded.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use corerouter_hal::dhcp_server::Heard;
use corerouter_model::dhcp_server::{DhcpNetwork, DhcpServer};
use corerouter_model::ip_pool::IpPool;
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind, ItemId};
use corerouter_proto_dhcp::server::plan::Plan;
use corerouter_proto_dhcp::server::{Effect, Now, PROBE_WAIT_MS, Server};
use corerouter_proto_dhcp::v4::Outgoing;
use dhcproto::v4::MessageType;

pub struct Storm {
    cfg: Config,
    iface: IfName,
    discovers: Vec<Heard>,
    requests: Vec<Heard>,
}

fn heard(payload: Vec<u8>) -> Heard {
    Heard {
        payload,
        src: Ipv4Addr::UNSPECIFIED,
        dst: Ipv4Addr::BROADCAST,
        src_mac: [0; 6],
        to_server: true,
    }
}

impl Storm {
    pub fn new(n: usize, probed: bool) -> Self {
        Self::with(n, probed, false)
    }

    /// `ipoe`: the server authorizes each client first (G4.3f), and the
    /// run answers every ask at once (a local secret's verdict).
    pub fn with(n: usize, probed: bool, ipoe: bool) -> Self {
        // A /14 past 65 000 clients (a /16 holds fewer addresses).
        let (cidr, range, net) = if n > 60_000 {
            ("10.0.0.1/14", "10.0.1.0-10.3.255.254", "10.0.0.0/14")
        } else {
            ("10.0.0.1/16", "10.0.1.0-10.0.255.254", "10.0.0.0/16")
        };
        let iface: IfName = "ether2".parse().unwrap();
        let mut c = Config::default();
        c.interfaces.insert(
            iface.clone(),
            Interface::new(iface.clone(), InterfaceKind::Ethernet),
        );
        c.ip.addresses.push(AddressEntry {
            id: ItemId(1),
            address: cidr.parse().unwrap(),
            interface: iface.clone(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        c.ip.pools.pools.push(IpPool {
            id: ItemId(1),
            name: "storm".into(),
            ranges: vec![range.parse().unwrap()],
            next_pool: None,
            comment: String::new(),
        });
        let mut s = DhcpServer::new(ItemId(1), "dhcp1".into(), iface.clone());
        s.address_pool = Some("storm".into());
        s.conflict_detection = probed;
        s.client_rate_limit = 10;
        s.ipoe = ipoe;
        c.ip.dhcp_server.servers.push(s);
        let mut net = DhcpNetwork::new(ItemId(2), net.parse().unwrap());
        net.gateway = vec![Ipv4Addr::new(10, 0, 0, 1)];
        net.dns_server = vec![Ipv4Addr::new(10, 0, 0, 1)];
        net.domain = "isp.example".into();
        c.ip.dhcp_server.networks.push(net);
        let first = u32::from(Ipv4Addr::new(10, 0, 1, 0));
        let mut discovers = Vec::with_capacity(n);
        let mut requests = Vec::with_capacity(n);
        for i in 0..n {
            let k = u32::try_from(i).unwrap();
            let [_, a, b, d] = k.to_be_bytes();
            let mac = [0x02, 0x57, 0x0e, a, b, d];
            let id = [1, 0x02, 0x57, 0x0e, a, b, d];
            let msg = |kind, requested, server_id| {
                Outgoing {
                    kind,
                    xid: k,
                    secs: 0,
                    mac,
                    ciaddr: Ipv4Addr::UNSPECIFIED,
                    broadcast: false,
                    requested,
                    server_id,
                    client_id: &id,
                    host_name: Some("cpe"),
                    vendor_class: None,
                    extra: &[],
                }
                .encode()
                .unwrap()
            };
            discovers.push(heard(msg(MessageType::Discover, None, None)));
            requests.push(heard(msg(
                MessageType::Request,
                Some(Ipv4Addr::from(first + k)),
                Some(Ipv4Addr::new(10, 0, 0, 1)),
            )));
        }
        Self {
            cfg: c,
            iface,
            discovers,
            requests,
        }
    }

    pub fn server(&self) -> Server {
        Server::new(Plan::from_config(&self.cfg), 1_700_000_000)
    }

    /// The whole storm; `each` sees the time of every message it handles
    /// (nanoseconds, measured by the caller's closure around it). Returns
    /// the ACKs sent.
    pub fn run(&self, srv: &mut Server, mut each: impl FnMut(&mut dyn FnMut())) -> usize {
        let mut now = Now {
            ms: 1_000,
            unix: 1_700_000_000,
        };
        let mut acks = 0;
        let mut lines = 0usize;
        let count = |fx: Vec<Effect>, acks: &mut usize, lines: &mut usize| {
            for e in fx {
                match e {
                    Effect::Authorize(_) => {}
                    Effect::Send {
                        kind: corerouter_proto_dhcp::server::request::Kind::Ack,
                        ..
                    } => *acks += 1,
                    Effect::Journal(r) => *lines += serde_json::to_string(&r).unwrap().len(),
                    _ => {}
                }
            }
        };
        for d in &self.discovers {
            let mut fx = Vec::new();
            each(&mut || {
                fx = srv.handle(now, &self.iface, d);
                // G4.3f: the verdict at once (a local secret).
                let asks: Vec<_> = fx
                    .iter()
                    .filter_map(|e| match e {
                        Effect::Authorize(a) => Some(a.clone()),
                        _ => None,
                    })
                    .collect();
                for a in asks {
                    fx.extend(srv.authorized(
                        now,
                        &a.server,
                        &a.client_key,
                        corerouter_proto_dhcp::server::authorize::Verdict::Accept(
                            Default::default(),
                        ),
                    ));
                }
            });
            count(fx, &mut acks, &mut lines);
        }
        now.ms += PROBE_WAIT_MS;
        now.unix += 1;
        count(srv.tick(now), &mut acks, &mut lines);
        for r in &self.requests {
            let mut fx = Vec::new();
            each(&mut || fx = srv.handle(now, &self.iface, r));
            count(fx, &mut acks, &mut lines);
        }
        assert!(lines > 0);
        acks
    }
}
