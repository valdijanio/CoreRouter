//! Lockout check (G2.1b): before a firewall change reaches the data plane,
//! would it cut the management connection that sent it?
//!
//! The control channel tells the engine which TCP connection each caller
//! is ([`Link`]: its peer and our local address). At commit time the
//! connection's packets are walked through the running and the candidate
//! firewall (`corerouter_firewall::eval`):
//!
//! - its packets and our replies in raw `prerouting`/`output` (G2.1c; a
//!   `notrack` there turns the filter's view into `untracked`),
//! - its established packets in `input` (the session itself),
//! - a new connection from the same address to the same port (logging in
//!   again after this session ends),
//! - our replies in `output`,
//! - the new connection in `dstnat` (a redirect would send it elsewhere).
//!
//! Each walk sees the interface that holds our address in *that* config,
//! and a change that takes the address away (removed, disabled, or its
//! interface disabled) is refused as well: no packet reaches us then.
//!
//! If the candidate drops one of them and the running config did not, the
//! commit is refused with the rule that would do it, unless the command
//! said `force: true` (or Safe Mode is on: then losing the connection
//! already undoes the change). Callers inside the process (the GUI lab,
//! tests, `corerouter-cli run`) have no connection to lose.

use std::net::{IpAddr, SocketAddr};

use corerouter_firewall::eval::{Outcome, Packet, Verdict, walk};
use corerouter_model::route::{self, Reach};
use corerouter_model::{Config, IfName, RoutingTable};
use corerouter_model::firewall::{ConnState, DynamicAddress, Protocol, Table};
use serde_json::Value;

use crate::cmd::args::opt_bool;
use crate::cmd::firewall::summary;
use crate::{EngineError, Result, Session};

/// The TCP connection behind a control-channel caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

/// `::ffff:10.0.0.1` (a dual-stack socket) is 10.0.0.1 to the firewall.
fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The interface that holds our local address: `lo` for loopback, else the
/// one the config gives the address to (`None` if no interface has it).
pub fn local_interface(cfg: &Config, local: IpAddr) -> Option<String> {
    if local.is_loopback() {
        return Some("lo".into());
    }
    cfg.ip
        .addresses
        .iter()
        .find(|a| !a.disabled && a.address.addr() == local)
        .map(|a| a.interface.as_str().to_owned())
}

/// Marks the current command as acknowledging a lockout (`force: true`).
pub(crate) fn take_force(s: &mut Session, p: &Value) -> Result<()> {
    if opt_bool(p, "force")?.unwrap_or(false) {
        s.lockout_ack = true;
    }
    Ok(())
}

const HOW_TO_PROCEED: &str = "Enter Safe Mode first \
     (config.safe-mode.enter: if the connection is lost the change is undone), \
     or repeat with force=true (transactional mode: config.commit force=true)";

struct Probe {
    what: &'static str,
    table: Table,
    chain: &'static str,
    packet: Packet,
}

/// The interface the caller's packets come in on (and our replies leave
/// by): the one routing points at for `peer`, in the table of the
/// interface that holds `local`. With management on a loopback /32 the
/// connection still arrives on the WAN port, not on `lo0` (audit-net).
/// `local_interface` when nothing routes to the peer.
fn ingress_interface(cfg: &Config, peer: IpAddr, local: IpAddr) -> Option<String> {
    let holder = local_interface(cfg, local);
    if local.is_loopback() {
        return holder;
    }
    way_back(cfg, peer, local).or(holder)
}

/// The interface routing points at for `peer` (the way back to the
/// caller), in the table of the interface that holds `local`; `None` when
/// no connected network nor active route reaches it.
fn way_back(cfg: &Config, peer: IpAddr, local: IpAddr) -> Option<String> {
    let holder = local_interface(cfg, local);
    let table = holder
        .as_deref()
        .and_then(|h| h.parse::<IfName>().ok())
        .map_or(RoutingTable::Main, |h| route::table_of(cfg, &h));
    route_out(cfg, peer, &table)
}

/// The interface routing sends `peer` out of in `table`: the longest
/// enabled connected network or active route (the packet tester uses it
/// too, G2.1c).
pub(crate) fn route_out(cfg: &Config, peer: IpAddr, table: &RoutingTable) -> Option<String> {
    let table = table.clone();
    // Longest prefix wins; a connected network beats a route of the same
    // length (distance 0), then the lower distance.
    let mut best: Option<(u8, u8, IfName)> = None;
    let mut consider = |len: u8, distance: u8, link: &IfName| {
        let better = best
            .as_ref()
            .is_none_or(|(l, d, _)| len > *l || (len == *l && distance < *d));
        if better {
            best = Some((len, distance, link.clone()));
        }
    };
    for a in &cfg.ip.addresses {
        if !a.disabled
            && a.address.contains(&peer)
            && route::is_up(cfg, &a.interface)
            && route::table_of(cfg, &a.interface) == table
        {
            consider(a.address.prefix_len(), 0, &a.interface);
        }
    }
    for r in &cfg.ip.routes {
        if r.routing_table != table || !r.dst_address.contains(&peer) {
            continue;
        }
        if let Reach::Active { link, .. } = route::reach(cfg, r) {
            consider(r.dst_address.prefix_len(), r.distance, &link);
        }
    }
    best.map(|(_, _, link)| link.as_str().to_owned())
}

/// The addresses of `cfg` this connection depends on (G1.28), with why:
/// the one it connects to, and the connected network it arrives through.
/// Taking one of them away (remove, disable, move) is refused without
/// `force` or Safe Mode. Only these few are checked, so a long list costs
/// one pass.
pub fn access_addresses(cfg: &Config, link: &Link) -> Vec<(corerouter_model::ItemId, String)> {
    let (peer, local) = (plain(link.peer.ip()), plain(link.local.ip()));
    if local.is_loopback() {
        return Vec::new();
    }
    let via = way_back(cfg, peer, local);
    cfg.ip
        .addresses
        .iter()
        .filter(|a| !a.disabled)
        .filter_map(|a| {
            let why = if a.address.addr() == local {
                format!("this session (tcp {} -> {}) connects to this address", link.peer, link.local)
            } else if a.address.contains(&peer) && via.as_deref() == Some(a.interface.as_str()) {
                format!(
                    "this session (tcp {} -> {}) arrives through this network on {}",
                    link.peer, link.local, a.interface
                )
            } else {
                return None;
            };
            Some((a.id, why))
        })
        .collect()
}

fn probes(cfg: &Config, dynamic: &[DynamicAddress], link: &Link) -> Vec<Probe> {
    let (peer, local) = (plain(link.peer.ip()), plain(link.local.ip()));
    let iface = ingress_interface(cfg, peer, local);
    let packet = |state| Packet {
        src: peer,
        dst: local,
        protocol: Protocol::TCP,
        src_port: Some(link.peer.port()),
        dst_port: Some(link.local.port()),
        icmp: None,
        in_interface: iface.clone(),
        out_interface: None,
        state,
        nat: None,
    };
    // A raw `notrack` makes the filter see the packets as untracked (an
    // `accept established` no longer takes them).
    let untracked = |chain, p: Packet| {
        if walk(cfg, dynamic, Table::Raw, chain, &p).verdict == Verdict::Notrack {
            Packet {
                state: ConnState::Untracked,
                ..p
            }
        } else {
            p
        }
    };
    let inbound = |state| untracked("prerouting", packet(state));
    let reply = Packet {
        src: local,
        dst: peer,
        protocol: Protocol::TCP,
        src_port: Some(link.local.port()),
        dst_port: Some(link.peer.port()),
        icmp: None,
        in_interface: None,
        out_interface: iface.clone(),
        state: ConnState::Established,
        nat: None,
    };
    vec![
        Probe {
            what: "would drop this connection before connection tracking",
            table: Table::Raw,
            chain: "prerouting",
            packet: packet(ConnState::Established),
        },
        Probe {
            what: "would drop the replies to this connection before connection tracking",
            table: Table::Raw,
            chain: "output",
            packet: reply.clone(),
        },
        Probe {
            what: "would drop this connection",
            table: Table::Filter,
            chain: "input",
            packet: inbound(ConnState::Established),
        },
        Probe {
            what: "would drop the replies to this connection",
            table: Table::Filter,
            chain: "output",
            packet: untracked("output", reply),
        },
        Probe {
            what: "would refuse a new login from your address (after this session ends)",
            table: Table::Filter,
            chain: "input",
            packet: inbound(ConnState::New),
        },
        Probe {
            what: "would redirect a new login from your address elsewhere (dst-nat)",
            table: Table::Nat,
            chain: "dstnat",
            packet: inbound(ConnState::New),
        },
    ]
}

fn cut(table: Table, o: Outcome) -> bool {
    match table {
        Table::Nat => o.verdict == Verdict::Nat,
        _ => o.verdict.blocks(),
    }
}

impl Session {
    /// The dynamic address-list entries as the data plane holds them.
    pub(crate) fn dynamic_now(&self) -> Vec<DynamicAddress> {
        let now = self.now();
        self.dynamic_addresses
            .entries()
            .iter()
            .map(|e| e.data_plane(now))
            .collect()
    }

    /// Refuse going from `before` (+ `dyn_before`) to `after` (+ `dyn_after`)
    /// if that cuts the caller's connection; see the module docs.
    pub(crate) fn check_lockout(
        &self,
        before: &Config,
        after: &Config,
        dyn_before: &[DynamicAddress],
        dyn_after: &[DynamicAddress],
    ) -> Result<()> {
        if self.lockout_ack || self.in_safe_mode() {
            return Ok(());
        }
        match self.lockout_reason(before, after, dyn_before, dyn_after) {
            Some(why) => Err(EngineError::Lockout(why)),
            None => Ok(()),
        }
    }

    /// Why going from `before` to `after` would cut the caller's
    /// connection, whatever `force` and Safe Mode say (a preview asks
    /// before the change is sent, G1.28). `None`: it would not, or the
    /// caller has no connection.
    pub(crate) fn lockout_reason(
        &self,
        before: &Config,
        after: &Config,
        dyn_before: &[DynamicAddress],
        dyn_after: &[DynamicAddress],
    ) -> Option<String> {
        let link = self.caller().link?;
        let local = plain(link.local.ip());
        let (iface_before, iface_after) =
            (local_interface(before, local), local_interface(after, local));
        let up = |cfg: &Config, iface: &Option<String>| {
            iface.as_deref().is_none_or(|name| {
                cfg.interfaces
                    .values()
                    .find(|i| i.name.as_str() == name)
                    .is_none_or(|i| !i.disabled)
            })
        };
        // The address itself goes away, or its interface goes down.
        if let Some(was_on) = &iface_before
            && up(before, &iface_before)
        {
            let lost = match &iface_after {
                None => Some(format!("would remove or disable {local}, the address")),
                Some(on) if !up(after, &iface_after) => {
                    Some(format!("would disable {on}, the interface holding {local},"))
                }
                Some(_) => None,
            };
            if let Some(what) = lost {
                return Some(format!(
                    "{what} this connection uses (tcp {} -> {} on {was_on}). {}",
                    link.peer, link.local, HOW_TO_PROCEED
                ));
            }
        }
        // The way back goes: the connected network (or route) the caller's
        // packets arrive through, removed or disabled (G1.28).
        let peer = plain(link.peer.ip());
        if !local.is_loopback()
            && let Some(was) = way_back(before, peer, local)
            && way_back(after, peer, local).is_none()
        {
            return Some(format!(
                "would remove the way back to {peer} (the network or route on {was}) this \
                 connection uses (tcp {} -> {}). {HOW_TO_PROCEED}",
                link.peer, link.local
            ));
        }
        // G2.5a: the XDP filter drops in the driver, before any rule.
        let ingress = ingress_interface(after, peer, local);
        if let Some(list) = crate::xdp::blocks(after, dyn_after, ingress.as_deref(), peer) {
            let was = ingress_interface(before, peer, local);
            if crate::xdp::blocks(before, dyn_before, was.as_deref(), peer).is_none() {
                return Some(format!(
                    "the XDP filter would drop {peer}, which is in its block list '{list}' \
                     (tcp {} -> {}); put it in an allow list (ip.firewall.xdp.set allow_lists). \
                     {HOW_TO_PROCEED}",
                    link.peer, link.local
                ));
            }
        }
        let same = before.ip.firewall == after.ip.firewall
            && before.interface_lists == after.interface_lists
            && dyn_before == dyn_after
            && iface_before == iface_after;
        if same {
            return None;
        }
        firewall_cut(before, after, dyn_before, dyn_after, &link)
            .map(|why| format!("{why}. {HOW_TO_PROCEED}"))
    }
}

/// The first of `link`'s packets (see [`probes`]) that the firewall of
/// `after` drops and the one of `before` did not, said as the rule (or
/// policy) that does it; `None`: none.
pub(crate) fn firewall_cut(
    before: &Config,
    after: &Config,
    dyn_before: &[DynamicAddress],
    dyn_after: &[DynamicAddress],
    link: &Link,
) -> Option<String> {
    let was_probes = probes(before, dyn_before, link);
    for (probe, old) in probes(after, dyn_after, link).into_iter().zip(was_probes) {
        let now = walk(after, dyn_after, probe.table, probe.chain, &probe.packet);
        let was = walk(before, dyn_before, old.table, old.chain, &old.packet);
        if !cut(probe.table, now) || cut(probe.table, was) {
            continue;
        }
        let by = match now.rule.and_then(|id| {
            after
                .ip
                .firewall
                .rules(probe.table)
                .iter()
                .find(|r| r.id == id)
        }) {
            Some(r) => format!("{} rule {} ({})", probe.table, r.id, summary(r)),
            None => format!("the {} policy", probe.chain),
        };
        let via = probe
            .packet
            .in_interface
            .as_deref()
            .map(|i| format!(" on {i}"))
            .unwrap_or_default();
        return Some(format!(
            "{by} {} (tcp {} -> {}{via})",
            probe.what, link.peer, link.local
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_addresses_and_interfaces() {
        assert_eq!(
            plain("::ffff:10.0.0.1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        let cfg = Config::default();
        assert_eq!(
            local_interface(&cfg, "127.0.0.1".parse().unwrap()).as_deref(),
            Some("lo")
        );
        assert_eq!(local_interface(&cfg, "192.0.2.1".parse().unwrap()), None);
    }
}
