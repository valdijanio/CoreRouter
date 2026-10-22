//! Router Advertisements (G4.7b): which managed interfaces accept them, in
//! the kernel's own words (`net.ipv6.conf.<if>.accept_ra`: 0 never, 1 only
//! while not forwarding, 2 always), from `corerouter_model::ipv6::ra_mode`.
//! The kernel does the rest (default router, SLAAC): CoreRouter reads back
//! what it learned ([`crate::netlink::learned`]) and shows it as dynamic.
//!
//! When an interface stops accepting RA — and on the first apply after
//! start-up, for whatever the kernel learned before CoreRouter ran — its
//! RA-learned addresses and routes are removed at once (RouterOS needs a
//! reboot for that). Writing `/proc/sys` is plain file I/O; a host where it
//! is read-only (a container) gets a warning, not a refused commit.

use std::collections::BTreeSet;
use std::path::PathBuf;

use corerouter_model::ipv6::ra_mode;
use corerouter_model::{Config, IfName};
use ipnet::IpNet;

/// `$COREROUTER_SYSCTL_ROOT` (tests) or `/proc/sys`.
fn conf_dir(name: &IfName) -> PathBuf {
    let root = std::env::var_os("COREROUTER_SYSCTL_ROOT").unwrap_or_else(|| "/proc/sys".into());
    PathBuf::from(root)
        .join("net/ipv6/conf")
        .join(name.as_str())
}

/// The current `accept_ra` of `name`, or `None` (no IPv6 there).
pub fn accept_ra(name: &IfName) -> Option<u8> {
    let text = std::fs::read_to_string(conf_dir(name).join("accept_ra")).ok()?;
    text.trim().parse().ok()
}

/// Make the kernel follow `to` on the managed interfaces `managed`. With
/// `first`, flush RA-learned state on every non-accepting interface, not
/// only on those that just stopped. Returns the problems, for the log.
pub fn sync(to: &Config, managed: &BTreeSet<IfName>, first: bool) -> Vec<String> {
    let mut problems = Vec::new();
    let mut flush = Vec::new();
    for name in to.interfaces.keys().filter(|n| managed.contains(*n)) {
        let Some(now) = accept_ra(name) else {
            continue;
        };
        let want = ra_mode(to, name).0.sysctl();
        if now != want {
            let path = conf_dir(name).join("accept_ra");
            if let Err(e) = std::fs::write(&path, format!("{want}\n")) {
                problems.push(format!("{}: {e}", path.display()));
                continue;
            }
            log::info!("ipv6: accept_ra={want} on '{name}' (was {now})");
        }
        if want == 0 && (now != 0 || first) {
            flush.push(name.clone());
        }
    }
    if !flush.is_empty() {
        let keep: Vec<(IfName, IpNet)> = to
            .ip
            .addresses
            .iter()
            .map(|a| (a.interface.clone(), a.address))
            .collect();
        match crate::netlink::flush_learned(&flush, &keep) {
            Ok(0) => {}
            Ok(n) => {
                log::info!("ipv6: removed {n} RA-learned addresses/routes (RA no longer accepted)")
            }
            Err(e) => problems.push(format!("removing RA-learned state: {e}")),
        }
    }
    problems
}
