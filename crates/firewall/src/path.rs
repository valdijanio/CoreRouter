//! The packet tester (G2.1c, `ip.firewall.test`): the way one packet takes
//! through the tables, chain after chain, in the kernel's order, with the
//! rules it matches and the one that decides its fate.
//!
//! Netfilter order (hook priorities, `nft(8)` "Chain priorities"):
//!
//! | Hook | Chains here, in order |
//! |---|---|
//! | prerouting | raw (-300) · conntrack (-200) · mangle (-150) · nat dstnat (-100) |
//! | routing decision | to the router (input) or through it (forward) |
//! | input / forward | mangle (-150) · filter (0) |
//! | output (from the router) | raw (-300) · conntrack · mangle (-150, route) · filter (0) |
//! | postrouting | mangle (-150) · nat srcnat (100) |
//!
//! What the kernel does between the chains is modelled too: a raw
//! `notrack` makes the later chains see `untracked`; NAT chains only see the
//! first packet of a tracked connection (`new`), never an untracked one; a
//! `dst-nat` changes the destination before the routing decision, and the
//! route is looked up again with it. The routing itself is the caller's
//! ([`Router`]): the engine knows the addresses and routes.
//!
//! The same assumptions as [`crate::eval`] (no marks, `limit` not exceeded,
//! address lists without the kernel's own entries).

use std::net::IpAddr;

use corerouter_model::firewall::{Action, ConnState, DynamicAddress, NatState, NatTarget, Table};
use corerouter_model::{Config, ItemId};

use crate::eval::{Hit, Outcome, Packet, Verdict, walk_traced};

/// Where routing sends a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// One of the router's own addresses: chain input.
    Local,
    /// Out through this interface: chain forward (or output).
    Out(String),
    /// No route: the kernel drops it (ICMP unreachable).
    Unreachable,
}

/// The routing decision, from the caller: `(destination, interface the
/// packet came in on)` → route.
pub type Router<'a> = dyn Fn(IpAddr, Option<&str>) -> Route + 'a;

/// One chain the packet went through, or why it skipped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub table: Table,
    pub chain: &'static str,
    /// Rules it matched, in order (the last one decided, if `rule`).
    pub hits: Vec<Hit>,
    /// The chain's verdict; `None` when skipped.
    pub outcome: Option<Outcome>,
    /// Why the kernel does not run this chain for this packet.
    pub skipped: Option<&'static str>,
}

/// How the packet ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Delivered to the router (chain input accepted it).
    Delivered,
    /// Forwarded, or sent by the router, out of an interface.
    Sent,
    /// A rule (or no route) dropped or rejected it.
    Dropped,
    NoRoute,
}

impl Fate {
    pub fn name(self) -> &'static str {
        match self {
            Fate::Delivered => "delivered",
            Fate::Sent => "sent",
            Fate::Dropped => "dropped",
            Fate::NoRoute => "no-route",
        }
    }
}

/// The whole way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub steps: Vec<Step>,
    /// The routing decision, after `dst-nat`.
    pub route: Route,
    pub fate: Fate,
    /// The rule that decided the fate: the drop/reject, or the last accept
    /// on the way (`None`: only chain policies).
    pub decided_by: Option<(Table, ItemId)>,
    /// The packet as it leaves (after NAT, with the state the filter saw).
    pub packet: Packet,
}

/// The first address and port of a NAT target.
fn nat_to(
    p: &mut Packet,
    to: &NatTarget,
    ports: Option<corerouter_model::firewall::PortRange>,
    dst: bool,
) {
    if dst {
        p.dst = to.first;
    } else {
        p.src = to.first;
    }
    if let Some(r) = ports {
        if dst {
            p.dst_port = p.dst_port.map(|_| r.first);
        } else {
            p.src_port = p.src_port.map(|_| r.first);
        }
    }
}

struct Walker<'a> {
    cfg: &'a Config,
    dynamic: &'a [DynamicAddress],
    p: Packet,
    steps: Vec<Step>,
    decided_by: Option<(Table, ItemId)>,
}

impl Walker<'_> {
    fn skip(&mut self, table: Table, chain: &'static str, why: &'static str) {
        self.steps.push(Step {
            table,
            chain,
            hits: Vec::new(),
            outcome: None,
            skipped: Some(why),
        });
    }

    /// Run `chain` of `table`; whether the packet goes on.
    fn chain(&mut self, table: Table, chain: &'static str) -> bool {
        // A table without rules in that chain is not even in the kernel.
        let present = self
            .cfg
            .ip
            .firewall
            .rules(table)
            .iter()
            .any(|r| !r.disabled && !r.section && r.chain.as_str() == chain);
        if !present {
            return true;
        }
        let mut hits = Vec::new();
        let o = walk_traced(
            self.cfg,
            self.dynamic,
            table,
            chain,
            &self.p,
            Some(&mut hits),
        );
        // Who decided: a drop/reject; else the last filter or raw rule that
        // let it through (a NAT or mark rule only when nothing else did).
        if let Some(id) = o.rule
            && (o.verdict.blocks()
                || matches!(table, Table::Filter | Table::Raw)
                || self.decided_by.is_none())
        {
            self.decided_by = Some((table, id));
        }
        match o.verdict {
            Verdict::Notrack => self.p.state = ConnState::Untracked,
            Verdict::Nat => {
                let rule = o.rule.and_then(|id| {
                    self.cfg
                        .ip
                        .firewall
                        .rules(table)
                        .iter()
                        .find(|r| r.id == id)
                });
                match rule.map(|r| &r.action) {
                    Some(Action::DstNat {
                        to_addresses,
                        to_ports,
                    }) => {
                        nat_to(&mut self.p, to_addresses, *to_ports, true);
                        self.p.nat = Some(NatState::Dstnat);
                    }
                    Some(Action::SrcNat {
                        to_addresses,
                        to_ports,
                    }) => nat_to(&mut self.p, to_addresses, *to_ports, false),
                    // masquerade: the out interface's address, not known here.
                    _ => {}
                }
            }
            _ => {}
        }
        let blocked = o.verdict.blocks();
        self.steps.push(Step {
            table,
            chain,
            hits,
            outcome: Some(o),
            skipped: None,
        });
        !blocked
    }

    /// NAT chains see the first packet of a tracked connection only.
    fn nat(&mut self, chain: &'static str) -> bool {
        match self.p.state {
            ConnState::Untracked => {
                self.skip(Table::Nat, chain, "untracked (raw notrack): no NAT");
                true
            }
            ConnState::New => self.chain(Table::Nat, chain),
            _ => {
                self.skip(
                    Table::Nat,
                    chain,
                    "not the first packet: NAT already chosen",
                );
                true
            }
        }
    }

    fn done(self, route: Route, fate: Fate) -> Path {
        Path {
            steps: self.steps,
            route,
            fate,
            decided_by: self.decided_by,
            packet: self.p,
        }
    }
}

/// The way of `p` through the firewall of `cfg`. A packet with an input
/// interface arrives from outside; without one, the router sends it.
pub fn path(cfg: &Config, dynamic: &[DynamicAddress], p: &Packet, router: &Router<'_>) -> Path {
    let mut w = Walker {
        cfg,
        dynamic,
        p: p.clone(),
        steps: Vec::new(),
        decided_by: None,
    };
    let incoming = p.in_interface.is_some();
    if incoming {
        if !w.chain(Table::Raw, "prerouting") || !w.chain(Table::Mangle, "prerouting") {
            return w.done(Route::Unreachable, Fate::Dropped);
        }
        if !w.nat("dstnat") {
            return w.done(Route::Unreachable, Fate::Dropped);
        }
        let route = router(w.p.dst, w.p.in_interface.as_deref());
        match route.clone() {
            Route::Local => {
                let ok = w.chain(Table::Mangle, "input") && w.chain(Table::Filter, "input");
                let fate = if ok { Fate::Delivered } else { Fate::Dropped };
                w.done(route, fate)
            }
            Route::Out(iface) => {
                w.p.out_interface = Some(iface);
                let ok = w.chain(Table::Mangle, "forward")
                    && w.chain(Table::Filter, "forward")
                    && w.chain(Table::Mangle, "postrouting")
                    && w.nat("srcnat");
                let fate = if ok { Fate::Sent } else { Fate::Dropped };
                w.done(route, fate)
            }
            Route::Unreachable => w.done(route, Fate::NoRoute),
        }
    } else {
        let route = router(w.p.dst, None);
        let Route::Out(iface) = route.clone() else {
            // To itself (lo) or nowhere.
            let fate = if route == Route::Local {
                Fate::Delivered
            } else {
                Fate::NoRoute
            };
            return w.done(route, fate);
        };
        w.p.out_interface = Some(iface);
        let ok = w.chain(Table::Raw, "output")
            && w.chain(Table::Mangle, "output")
            && w.chain(Table::Filter, "output")
            && w.chain(Table::Mangle, "postrouting")
            && w.nat("srcnat");
        let fate = if ok { Fate::Sent } else { Fate::Dropped };
        w.done(route, fate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{act, m, rule};
    use corerouter_model::firewall::Protocol;

    fn router(dst: IpAddr, _in: Option<&str>) -> Route {
        if dst.to_string() == "192.0.2.1" {
            Route::Local
        } else if dst.to_string().starts_with("10.") {
            Route::Out("ether2".into())
        } else {
            Route::Out("ether1".into())
        }
    }

    fn pkt(src: &str, dst: &str, port: u16, iface: Option<&str>, state: ConnState) -> Packet {
        Packet {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            protocol: Protocol::TCP,
            src_port: Some(40_000),
            dst_port: Some(port),
            icmp: None,
            in_interface: iface.map(Into::into),
            out_interface: None,
            state,
            nat: None,
        }
    }

    fn cfg() -> Config {
        let mut c = Config {
            interface_lists: crate::sample::sample().interface_lists,
            ..Config::default()
        };
        c.ip.firewall.raw = vec![
            rule(
                1,
                "prerouting",
                m(&[("src_address", "198.18.0.0/15")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
            rule(
                2,
                "prerouting",
                m(&[("protocol", "udp"), ("dst_port", "53")]).unwrap(),
                act(r#"{"type":"notrack"}"#).unwrap(),
            )
            .unwrap(),
        ]
        .into();
        c.ip.firewall.nat = vec![
            rule(
                3,
                "dstnat",
                m(&[("protocol", "tcp"), ("dst_port", "8080")]).unwrap(),
                act(r#"{"type":"dst-nat","to_addresses":"10.0.0.20","to_ports":"80"}"#).unwrap(),
            )
            .unwrap(),
            rule(
                4,
                "srcnat",
                m(&[("out_interface", "ether1")]).unwrap(),
                act(r#"{"type":"masquerade"}"#).unwrap(),
            )
            .unwrap(),
        ]
        .into();
        c.ip.firewall.filter = vec![
            rule(
                5,
                "forward",
                m(&[("connection_state", "established,related,untracked")]).unwrap(),
                Action::Accept,
            )
            .unwrap(),
            rule(
                6,
                "forward",
                m(&[("in_interface_list", "WAN"), ("connection_state", "new")]).unwrap(),
                act(r#"{"type":"log"}"#).unwrap(),
            )
            .unwrap(),
            rule(
                7,
                "forward",
                m(&[("dst_address", "10.0.0.20")]).unwrap(),
                Action::Accept,
            )
            .unwrap(),
            rule(
                8,
                "forward",
                m(&[("in_interface_list", "WAN")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
            rule(
                9,
                "input",
                m(&[("protocol", "tcp"), ("dst_port", "22")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
        ]
        .into();
        c
    }

    fn chains(p: &Path) -> Vec<String> {
        p.steps
            .iter()
            .map(|s| format!("{}/{}", s.table.name(), s.chain))
            .collect()
    }

    #[test]
    fn port_forward_goes_raw_dstnat_route_forward_srcnat() {
        let c = cfg();
        let p = path(
            &c,
            &[],
            &pkt(
                "203.0.113.9",
                "192.0.2.1",
                8080,
                Some("ether1"),
                ConnState::New,
            ),
            &router,
        );
        assert_eq!(
            chains(&p),
            [
                "raw/prerouting",
                "nat/dstnat",
                "filter/forward",
                "nat/srcnat"
            ]
        );
        assert_eq!(p.packet.dst.to_string(), "10.0.0.20", "dst-nat applied");
        assert_eq!(p.packet.dst_port, Some(80));
        assert_eq!(p.route, Route::Out("ether2".into()), "routed after dst-nat");
        assert_eq!(p.fate, Fate::Sent);
        let fwd = &p.steps[2];
        let hit: Vec<ItemId> = fwd.hits.iter().map(|h| h.rule).collect();
        assert_eq!(hit, [ItemId(6), ItemId(7)], "the log, then the accept");
        assert_eq!(p.decided_by, Some((Table::Filter, ItemId(7))));
    }

    #[test]
    fn raw_drop_ends_before_conntrack_and_notrack_skips_nat() {
        let c = cfg();
        let p = path(
            &c,
            &[],
            &pkt(
                "198.18.1.1",
                "10.0.0.5",
                443,
                Some("ether1"),
                ConnState::New,
            ),
            &router,
        );
        assert_eq!(chains(&p), ["raw/prerouting"]);
        assert_eq!(p.fate, Fate::Dropped);
        assert_eq!(p.decided_by, Some((Table::Raw, ItemId(1))));

        let mut dns = pkt(
            "203.0.113.9",
            "10.0.0.5",
            53,
            Some("ether1"),
            ConnState::New,
        );
        dns.protocol = Protocol::UDP;
        let p = path(&c, &[], &dns, &router);
        assert_eq!(p.packet.state, ConnState::Untracked);
        assert!(
            p.steps
                .iter()
                .any(|s| s.skipped.is_some_and(|w| w.contains("untracked")))
        );
        assert_eq!(
            p.decided_by,
            Some((Table::Filter, ItemId(5))),
            "accept untracked"
        );
        assert_eq!(p.fate, Fate::Sent);
    }

    #[test]
    fn input_and_output_and_no_route() {
        let c = cfg();
        let ssh = path(
            &c,
            &[],
            &pkt(
                "203.0.113.9",
                "192.0.2.1",
                22,
                Some("ether1"),
                ConnState::New,
            ),
            &router,
        );
        assert_eq!(ssh.route, Route::Local);
        assert_eq!(ssh.fate, Fate::Dropped);
        assert_eq!(ssh.decided_by, Some((Table::Filter, ItemId(9))));

        let est = path(
            &c,
            &[],
            &pkt(
                "203.0.113.9",
                "10.0.0.5",
                443,
                Some("ether1"),
                ConnState::Established,
            ),
            &router,
        );
        assert!(
            est.steps
                .iter()
                .any(|s| s.skipped.is_some_and(|w| w.contains("first packet")))
        );
        assert_eq!(est.fate, Fate::Sent);

        let out = path(
            &c,
            &[],
            &pkt("192.0.2.1", "198.51.100.1", 443, None, ConnState::New),
            &router,
        );
        assert_eq!(
            chains(&out),
            ["nat/srcnat"],
            "output: only chains with rules"
        );
        assert_eq!(out.fate, Fate::Sent);

        let none = |_: IpAddr, _: Option<&str>| Route::Unreachable;
        let lost = path(
            &c,
            &[],
            &pkt(
                "203.0.113.9",
                "10.9.9.9",
                443,
                Some("ether1"),
                ConnState::New,
            ),
            &none,
        );
        assert_eq!(lost.fate, Fate::NoRoute);
    }
}
