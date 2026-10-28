//! A router's forwarding table: the best route per prefix by distance
//! (connected 0, eBGP 20, OSPF 110, iBGP 200: FRR's and RouterOS'
//! defaults), and longest-prefix match over it.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::Serialize;

use crate::LinkId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Proto {
    Connected,
    Ebgp,
    Ospf,
    Ibgp,
}

impl Proto {
    pub fn distance(self) -> u8 {
        match self {
            Proto::Connected => 0,
            Proto::Ebgp => 20,
            Proto::Ospf => 110,
            Proto::Ibgp => 200,
        }
    }
}

/// One installed route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FibRoute {
    pub prefix: Ipv4Net,
    pub proto: Proto,
    pub metric: u32,
    /// The links packets leave by (several: ECMP). Empty: local (the
    /// router's own loopback).
    pub links: Vec<LinkId>,
    /// BGP: the next hop the links were resolved from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Fib {
    routes: BTreeMap<Ipv4Net, FibRoute>,
    /// Bit `n` set: some route has prefix length `n` (LPM probes only those).
    lens: u64,
}

impl Fib {
    /// Keep `r` if no route of a lower distance (or the same distance and a
    /// lower metric) holds the prefix.
    pub(crate) fn offer(&mut self, r: FibRoute) {
        self.lens |= 1u64 << r.prefix.prefix_len();
        match self.routes.get(&r.prefix) {
            Some(old) if (old.proto.distance(), old.metric) <= (r.proto.distance(), r.metric) => {}
            _ => {
                self.routes.insert(r.prefix, r);
            }
        }
    }

    pub(crate) fn get(&self, p: &Ipv4Net) -> Option<&FibRoute> {
        self.routes.get(p)
    }

    /// Replace (or drop) the route of one prefix.
    pub(crate) fn set(&mut self, p: Ipv4Net, r: Option<FibRoute>) {
        match r {
            Some(r) => {
                self.lens |= 1u64 << r.prefix.prefix_len();
                self.routes.insert(p, r);
            }
            None => {
                self.routes.remove(&p);
            }
        }
    }

    pub(crate) fn lookup(&self, a: Ipv4Addr) -> Option<&FibRoute> {
        let mut lens = self.lens;
        while lens != 0 {
            let len = 63 - lens.leading_zeros();
            lens &= !(1u64 << len);
            let Ok(len) = u8::try_from(len) else { continue };
            let Ok(net) = Ipv4Net::new(a, len) else {
                continue;
            };
            if let Some(r) = self.routes.get(&net.trunc()) {
                return Some(r);
            }
        }
        None
    }

    pub(crate) fn routes(&self) -> impl Iterator<Item = &FibRoute> {
        self.routes.values()
    }

    pub(crate) fn len(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(p: &str, proto: Proto, metric: u32, link: u32) -> FibRoute {
        FibRoute {
            prefix: p.parse().unwrap(),
            proto,
            metric,
            links: vec![LinkId(link)],
            via: None,
        }
    }

    #[test]
    fn longest_prefix_and_distance_win() {
        let mut f = Fib::default();
        f.offer(r("10.0.0.0/8", Proto::Ospf, 20, 1));
        f.offer(r("10.1.0.0/16", Proto::Ibgp, 0, 2));
        f.offer(r("10.1.0.0/16", Proto::Ospf, 30, 3));
        f.offer(r("10.1.0.0/16", Proto::Ospf, 40, 4));
        assert_eq!(
            f.lookup("10.1.2.3".parse().unwrap()).unwrap().links,
            vec![LinkId(3)]
        );
        assert_eq!(
            f.lookup("10.2.0.1".parse().unwrap()).unwrap().links,
            vec![LinkId(1)]
        );
        assert!(f.lookup("192.0.2.1".parse().unwrap()).is_none());
        f.offer(r("0.0.0.0/0", Proto::Ebgp, 0, 9));
        assert_eq!(
            f.lookup("192.0.2.1".parse().unwrap()).unwrap().links,
            vec![LinkId(9)]
        );
        assert_eq!(f.len(), 3);
    }
}
