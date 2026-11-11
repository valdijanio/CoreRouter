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
//!
//! G1.26i: a router forwards by default, and a forwarding kernel neither
//! takes an RA nor asks for one unless `accept_ra` is 2
//! (`ipv6_accept_ra`, include/net/ipv6.h; the Router Solicitation goes out
//! only when duplicate address detection ends, `addrconf_dad_completed`,
//! net/ipv6/addrconf.c). So an interface that starts accepting while its
//! link is already up would wait for the router's next periodic RA, up to
//! `MaxRtrAdvInterval` (600 s by default, RFC 4861 §6.2.1): CoreRouter
//! sends the Router Solicitation itself ([`solicit`]).

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddrV6};
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

/// A managed link, as [`sync`] needs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RaLink {
    /// Kernel interface index (the scope of the link-local destination).
    pub index: u32,
    /// Its Ethernet address, when it has one.
    pub mac: Option<[u8; 6]>,
}

/// `aa:bb:cc:dd:ee:ff` as bytes.
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The all-routers link-local group (RFC 4291 §2.7.1).
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// A Router Solicitation, RFC 4861 §4.1: type 133, code 0, the checksum
/// (left to the kernel), 4 reserved bytes and, with a known address, the
/// source link-layer address option (type 1, one unit of 8 bytes).
pub fn router_solicitation(mac: Option<[u8; 6]>) -> Vec<u8> {
    let mut m = vec![133, 0, 0, 0, 0, 0, 0, 0];
    if let Some(mac) = mac {
        m.extend_from_slice(&[1, 1]);
        m.extend_from_slice(&mac);
    }
    m
}

/// Ask the routers on `link` for an RA now (RFC 4861 §6.3.7). One
/// message, with no random delay: the delay of §6.3.7 keeps hosts that
/// boot together from asking together, and this follows one operator's
/// change. A link that is down or still has no link-local address fails
/// here, and the kernel asks by itself once that address is ready.
pub fn solicit(link: RaLink) -> std::io::Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    // RFC 4861 §4.1: hop limit 255, or the routers drop it.
    s.set_multicast_hops_v6(255)?;
    s.set_multicast_if_v6(link.index)?;
    let to = SocketAddrV6::new(ALL_ROUTERS, 0, 0, link.index);
    s.send_to(&router_solicitation(link.mac), &to.into())?;
    Ok(())
}

/// Make the kernel follow `to` on the managed interfaces `managed`. With
/// `first`, flush RA-learned state on every non-accepting interface, not
/// only on those that just stopped. Returns the problems, for the log.
pub fn sync(to: &Config, managed: &BTreeMap<IfName, RaLink>, first: bool) -> Vec<String> {
    let mut problems = Vec::new();
    let mut flush = Vec::new();
    for (name, link) in to
        .interfaces
        .keys()
        .filter_map(|n| Some((n, managed.get(n)?)))
    {
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
            // Accepted even while forwarding from now on: ask, since the
            // kernel only does when the link comes up.
            if want == 2 {
                match solicit(*link) {
                    Ok(()) => log::info!("ipv6: router solicitation sent on '{name}'"),
                    Err(e) => log::debug!("ipv6: no router solicitation on '{name}': {e}"),
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4861 §4.1: the fixed part is 8 bytes; the source link-layer
    /// option adds 8 (type 1, length 1 unit, the address).
    #[test]
    fn the_solicitation_is_what_the_rfc_draws() {
        assert_eq!(router_solicitation(None), [133, 0, 0, 0, 0, 0, 0, 0]);
        let mac = parse_mac("02:dc:00:00:00:01").unwrap();
        assert_eq!(
            router_solicitation(Some(mac)),
            [133, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0x02, 0xdc, 0, 0, 0, 1]
        );
        for bad in [
            "",
            "02:dc:00:00:00",
            "02:dc:00:00:00:01:02",
            "zz:dc:00:00:00:01",
            "0:1",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
    }
}
