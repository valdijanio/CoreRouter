//! The lab's LSPs (G3.5b): a fixed set of FECs, each a chain of simulated
//! LSRs that answer with the real [`respond`](super::respond::respond), so
//! the lab exercises the same code as two CoreRouters on a wire.
//!
//! | FEC | path |
//! |---|---|
//! | 10.255.0.2/32 … 10.255.0.6/32 | N−1 hops, the last the egress (PHP before it) |
//! | 10.255.9.9/32 | 3 hops; hop 2 lost its label entry (traffic is dropped, code 11 when traced) |
//! | 10.255.8.8/32 | 3 hops; hop 2 switches the label to another FEC's next hop (code 10 when traced) |
//!
//! Anything else has no labeled route. Deterministic: no clock, no
//! randomness; round trips are 0.4 ms plus 0.6 ms per hop.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

use corerouter_model::IfName;
use ipnet::IpNet;

use super::respond::{Heard, LsrView, Verdict, respond};
use super::{LspAnswer, LspPath, LspProber, LspRequest, LspSocket};
use crate::mpls::{MplsNexthop, MplsRoute, Origin};
use crate::probe::{MplsLabel, ProbeError};

/// Replies kept waiting in one socket.
const MAX_QUEUED: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// Hop 2 has no entry for its incoming label.
    NoLabel,
    /// Hop 2's entry leaves by another next hop than the FEC's route.
    WrongLabel,
}

/// One simulated LSR of a chain.
struct Hop {
    addr: Ipv4Addr,
    interface: IfName,
    labels: BTreeMap<u32, MplsRoute>,
    fecs: BTreeMap<IpNet, Vec<MplsNexthop>>,
    local: Vec<IpNet>,
}

impl LsrView for Hop {
    fn label_entry(&self, label: u32) -> Option<MplsRoute> {
        self.labels.get(&label).cloned()
    }
    fn fec_route(&self, prefix: IpNet) -> Option<Vec<MplsNexthop>> {
        self.fecs.get(&prefix).cloned()
    }
    fn is_local(&self, prefix: IpNet) -> bool {
        self.local.contains(&prefix)
    }
    fn interface_addrs(&self, interface: &IfName) -> Vec<IpAddr> {
        if *interface == self.interface {
            vec![IpAddr::V4(self.addr)]
        } else {
            Vec::new()
        }
    }
    fn mtu(&self, _: &IfName) -> Option<u16> {
        Some(1500)
    }
}

/// The chain of `fec`, or `None` when the lab has no LSP for it.
fn chain(fec: IpNet) -> Option<(Vec<Hop>, LspPath)> {
    let IpNet::V4(v4) = fec else { return None };
    if v4.prefix_len() != 32 {
        return None;
    }
    let [a, b, c, d] = v4.addr().octets();
    let (hops, fault) = match (a, b, c, d) {
        (10, 255, 0, n @ 2..=6) => (usize::from(n) - 1, Fault::None),
        (10, 255, 9, 9) => (3, Fault::NoLabel),
        (10, 255, 8, 8) => (3, Fault::WrongLabel),
        _ => return None,
    };
    // Hop k (1-based) is 10.<c+1>.k.2 on its ether1, its label 1000 +
    // 100·d + k; the last hop is the egress and advertised implicit null.
    let ether1: IfName = "ether1".parse().ok()?;
    let ether2: IfName = "ether2".parse().ok()?;
    let net = c.saturating_add(1);
    let label = |k: usize| 1000 + 100 * u32::from(d) + u32::try_from(k).unwrap_or(0);
    let addr = |k: usize| Ipv4Addr::new(10, net, u8::try_from(k).unwrap_or(0), 2);
    let out = |k: usize| -> Vec<u32> {
        if k + 1 >= hops {
            Vec::new()
        } else {
            vec![label(k + 1)]
        }
    };
    let chain: Vec<Hop> = (1..=hops)
        .map(|k| {
            let egress = k == hops;
            let mut labels = BTreeMap::new();
            let mut fecs = BTreeMap::new();
            if !egress {
                let nh = MplsNexthop {
                    via: Some(IpAddr::V4(addr(k + 1))),
                    interface: Some(ether2.clone()),
                    out_labels: out(k),
                };
                fecs.insert(fec, vec![nh.clone()]);
                let mut switched = nh;
                if k == 2 && fault == Fault::WrongLabel {
                    switched.via = Some(IpAddr::V4(Ipv4Addr::new(10, net, 99, 2)));
                }
                if !(k == 2 && fault == Fault::NoLabel) {
                    labels.insert(
                        label(k),
                        MplsRoute {
                            label: label(k),
                            origin: Origin::Ldp,
                            nexthops: vec![switched],
                        },
                    );
                }
            }
            Hop {
                addr: addr(k),
                interface: ether1.clone(),
                labels,
                fecs,
                local: if egress { vec![fec] } else { Vec::new() },
            }
        })
        .collect();
    let path = LspPath {
        labels: out(0),
        nexthop: Some(IpAddr::V4(addr(1))),
        interface: ether1,
        src: Some(IpAddr::V4(Ipv4Addr::new(10, net, 1, 1))),
        mtu: Some(1500),
        origin: Origin::Ldp,
    };
    Some((chain, path))
}

/// Opens [`SimLspSocket`]s.
#[derive(Debug, Default, Clone, Copy)]
pub struct SimLspProber;

impl LspProber for SimLspProber {
    fn describe(&self) -> String {
        "simulated LSPs (deterministic)".into()
    }
    fn open(&self) -> Result<Box<dyn LspSocket>, ProbeError> {
        Ok(Box::new(SimLspSocket::default()))
    }
}

/// Answers each request at once, through the simulated chain.
#[derive(Default)]
pub struct SimLspSocket {
    queue: Mutex<VecDeque<LspAnswer>>,
}

/// Where a request of TTL `ttl` along `hops` ends: the hop (0-based) and
/// the label stack it arrives with. `None`: dropped on the way.
fn walk(hops: &[Hop], first: &[u32], ttl: u8) -> Option<(usize, Vec<MplsLabel>)> {
    let mut stack: Vec<u32> = first.to_vec();
    let mut ttl = ttl;
    for (i, hop) in hops.iter().enumerate() {
        let arrived: Vec<MplsLabel> = stack
            .iter()
            .enumerate()
            .map(|(j, l)| MplsLabel {
                label: *l,
                tc: 0,
                bottom: j + 1 == stack.len(),
                ttl,
            })
            .collect();
        // Unlabeled: the egress (or a hop that is not one) gets the IP
        // packet to 127/8 and hands it to its control plane.
        let Some(top) = stack.first().copied() else {
            return Some((i, arrived));
        };
        if ttl <= 1 {
            return Some((i, arrived));
        }
        // The data plane: swap or pop, or drop what has no entry.
        let entry = hop.labels.get(&top)?;
        let nh = entry.nexthops.first()?;
        stack = nh.out_labels.clone();
        ttl -= 1;
    }
    None
}

impl LspSocket for SimLspSocket {
    fn paths(&mut self, fec: IpNet) -> Result<Vec<LspPath>, ProbeError> {
        Ok(chain(fec).map(|(_, p)| vec![p]).unwrap_or_default())
    }

    fn send(&mut self, req: &LspRequest<'_>) -> Result<(), ProbeError> {
        let Some(fec) = super::wire::parse(req.payload)
            .ok()
            .and_then(|e| e.fec_stack)
            .and_then(|f| f.first().and_then(super::wire::Fec::prefix))
        else {
            return Ok(());
        };
        let Some((hops, path)) = chain(fec) else {
            return Err(ProbeError::Unreachable("no labeled route".into()));
        };
        let Some((at, stack)) = walk(&hops, &path.labels, req.ttl) else {
            return Ok(());
        };
        let Some(hop) = hops.get(at) else {
            return Ok(());
        };
        let heard = Heard {
            interface: hop.interface.clone(),
            stack,
            src: path.src.unwrap_or(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
            dst: req.dst,
            src_port: 49_152,
            dst_port: super::wire::PORT,
            payload: req.payload.to_vec(),
        };
        if let Verdict::Reply { payload, .. } = respond(&heard, hop, (0, 0)) {
            let seq = super::wire::ids(req.payload).map_or(0, |(_, s)| s);
            let hops = u64::try_from(at).unwrap_or(0) + 1;
            let rtt = Duration::from_micros(400 + 600 * hops + u64::from(seq % 5) * 50);
            if let Ok(mut q) = self.queue.lock()
                && q.len() < MAX_QUEUED
            {
                q.push_back(LspAnswer {
                    from: IpAddr::V4(hop.addr),
                    payload,
                    rtt: Some(rtt),
                });
            }
        }
        Ok(())
    }

    fn recv(&mut self, _wait: Duration) -> Result<Option<LspAnswer>, ProbeError> {
        Ok(self.queue.lock().ok().and_then(|mut q| q.pop_front()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp::wire::{self, Echo, Fec, code};

    fn send(s: &mut SimLspSocket, path: &LspPath, e: &Echo, ttl: u8) -> Option<Echo> {
        let payload = wire::encode(e);
        s.send(&LspRequest {
            path,
            ttl,
            dst: crate::lsp::destination(false, 1),
            tos: 0,
            payload: &payload,
        })
        .unwrap();
        s.recv(Duration::ZERO)
            .unwrap()
            .map(|a| wire::parse(&a.payload).unwrap())
    }

    fn ask(fec: &str, ttl: u8, ddmap: bool) -> Option<Echo> {
        trace(fec, ttl, ddmap).pop().flatten()
    }

    /// TTL 1..=upto, each request with the DDMAP the previous hop sent
    /// back (RFC 8029 §4.6), the first with the ingress's own.
    fn trace(fec: &str, upto: u8, ddmap: bool) -> Vec<Option<Echo>> {
        let fec: IpNet = fec.parse().unwrap();
        let mut s = SimLspSocket::default();
        let Some(path) = s.paths(fec).unwrap().pop() else {
            return vec![None];
        };
        let mut e = Echo::request(7, 1, vec![Fec::Ldp(fec)]);
        if ddmap {
            e.ddmaps.push(crate::lsp::respond::ddmap_of(
                &MplsNexthop {
                    via: path.nexthop,
                    interface: Some(path.interface.clone()),
                    out_labels: path.labels.clone(),
                },
                Origin::Ldp,
                Some(1500),
                false,
            ));
        }
        let first = if ddmap { 1 } else { upto };
        let mut out = Vec::new();
        for ttl in first..=upto {
            let r = send(&mut s, &path, &e, ttl);
            if let Some(d) = r.as_ref().and_then(|r| r.ddmaps.first()) {
                e.ddmaps = vec![d.clone()];
            }
            out.push(r);
        }
        out
    }

    #[test]
    fn a_ping_reaches_the_egress() {
        let r = ask("10.255.0.4/32", 255, false).unwrap();
        assert_eq!((r.return_code, r.return_subcode), (code::EGRESS, 1));
        assert_eq!((r.handle, r.seq), (7, 1));
        // Two hops: PHP, the request reaches the egress unlabeled.
        assert_eq!(
            ask("10.255.0.2/32", 255, false).unwrap().return_code,
            code::EGRESS
        );
        assert!(ask("192.0.2.1/32", 255, false).is_none());
    }

    #[test]
    fn a_trace_sees_each_hop_switch() {
        let r = ask("10.255.0.4/32", 1, true).unwrap();
        assert_eq!(r.return_code, code::LABEL_SWITCHED);
        assert_eq!(r.ddmaps.len(), 1);
        assert_eq!(r.ddmaps[0].labels[0].label, 1402);
        let r = ask("10.255.0.4/32", 2, true).unwrap();
        assert_eq!(r.return_code, code::LABEL_SWITCHED);
        // The penultimate hop pops: implicit null downstream.
        assert_eq!(r.ddmaps[0].labels[0].label, wire::LABEL_IMPLICIT_NULL);
        assert_eq!(
            ask("10.255.0.4/32", 3, true).unwrap().return_code,
            code::EGRESS
        );
    }

    #[test]
    fn broken_lsps_say_where() {
        // Traffic is dropped at hop 2: a ping hears nothing…
        assert!(ask("10.255.9.9/32", 255, false).is_none());
        // …a trace hears hop 2 say it has no entry.
        let r = ask("10.255.9.9/32", 2, true).unwrap();
        assert_eq!((r.return_code, r.return_subcode), (code::NO_LABEL_ENTRY, 1));
        let r = ask("10.255.8.8/32", 2, true).unwrap();
        assert_eq!((r.return_code, r.return_subcode), (code::WRONG_LABEL, 1));
    }
}
