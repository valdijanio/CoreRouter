//! Lockout check (G2.1b): before a firewall change reaches the data plane,
//! would it cut the management connection that sent it?
//!
//! The control channel tells the engine which TCP connection each caller
//! is ([`Link`]: its peer and our local address). At commit time the
//! connection's packets are walked through the running and the candidate
//! firewall (`corerouter_firewall::eval`):
//!
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
use corerouter_model::Config;
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

fn probes(cfg: &Config, link: &Link) -> Vec<Probe> {
    let (peer, local) = (plain(link.peer.ip()), plain(link.local.ip()));
    let iface = local_interface(cfg, local);
    let inbound = |state| Packet {
        src: peer,
        dst: local,
        protocol: Protocol::TCP,
        src_port: Some(link.peer.port()),
        dst_port: Some(link.local.port()),
        icmp: None,
        in_interface: iface.clone(),
        out_interface: None,
        state,
    };
    vec![
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
            packet: Packet {
                src: local,
                dst: peer,
                protocol: Protocol::TCP,
                src_port: Some(link.local.port()),
                dst_port: Some(link.peer.port()),
                icmp: None,
                in_interface: None,
                out_interface: iface.clone(),
                state: ConnState::Established,
            },
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
        let Some(link) = self.caller().link else {
            return Ok(());
        };
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
                return Err(EngineError::Lockout(format!(
                    "{what} this connection uses (tcp {} -> {} on {was_on}). {}",
                    link.peer,
                    link.local,
                    HOW_TO_PROCEED
                )));
            }
        }
        let same = before.ip.firewall == after.ip.firewall
            && before.interface_lists == after.interface_lists
            && dyn_before == dyn_after
            && iface_before == iface_after;
        if same {
            return Ok(());
        }
        let was_probes = probes(before, &link);
        for (probe, old) in probes(after, &link).into_iter().zip(was_probes) {
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
            return Err(EngineError::Lockout(format!(
                "{by} {} (tcp {} -> {}{via}). {HOW_TO_PROCEED}",
                probe.what, link.peer, link.local
            )));
        }
        Ok(())
    }
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
