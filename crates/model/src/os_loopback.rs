//! The OS loopback (G3.4i): a `loopback` interface named `lo` is the
//! operating system's own loopback (Linux `lo`, IFF_LOOPBACK), not a link
//! CoreRouter creates. Any other loopback is a Linux `dummy`.
//!
//! RouterOS v7 shows its built-in `lo` the same way, and VyOS configures the
//! kernel's `lo` as `interfaces loopback lo`. It matters for Segment Routing:
//! FRR's `ospfd` sets a prefix SID (and its N-flag, RFC 8665 §5: the SID of
//! the node, RFC 8402 §3.2) only on an IFF_LOOPBACK interface, so the node's
//! /32 has to be on `lo`.
//!
//! CoreRouter only adds and removes its own addresses there. The link (state,
//! MTU, master) and the OS's 127.0.0.0/8 and ::1 stay the OS's: a backend
//! never takes `lo` down (that cuts every local service) and never removes
//! 127.0.0.1.

use ipnet::IpNet;

use crate::{Config, IfName, InterfaceKind};

/// Name of the OS loopback.
pub const NAME: &str = "lo";

/// `name` is the OS loopback in `cfg`: a loopback interface named `lo`.
pub fn is_os_loopback(cfg: &Config, name: &IfName) -> bool {
    name.as_str() == NAME
        && cfg
            .interfaces
            .get(name)
            .is_some_and(|i| i.kind == InterfaceKind::Loopback)
}

/// An address the OS keeps on its loopback: 127.0.0.0/8 or ::1. Never put
/// there nor removed by CoreRouter.
pub fn is_os_address(addr: &IpNet) -> bool {
    match addr {
        IpNet::V4(n) => n.addr().is_loopback(),
        IpNet::V6(n) => n.addr().is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Interface;

    #[test]
    fn only_a_loopback_named_lo_is_the_os_one() {
        let mut cfg = Config::default();
        let lo: IfName = "lo".parse().unwrap();
        assert!(!is_os_loopback(&cfg, &lo), "absent");
        cfg.interfaces
            .insert(lo.clone(), Interface::new(lo.clone(), InterfaceKind::Loopback));
        assert!(is_os_loopback(&cfg, &lo));
        let lo0: IfName = "lo0".parse().unwrap();
        cfg.interfaces
            .insert(lo0.clone(), Interface::new(lo0.clone(), InterfaceKind::Loopback));
        assert!(!is_os_loopback(&cfg, &lo0), "lo0 is a dummy");
        cfg.interfaces
            .insert(lo.clone(), Interface::new(lo.clone(), InterfaceKind::Bridge));
        assert!(!is_os_loopback(&cfg, &lo));
    }

    #[test]
    fn os_addresses_are_127_8_and_v6_loopback() {
        for a in ["127.0.0.1/8", "127.1.2.3/32", "::1/128"] {
            assert!(is_os_address(&a.parse().unwrap()), "{a}");
        }
        for a in ["10.255.0.1/32", "2001:db8::1/128", "::2/128"] {
            assert!(!is_os_address(&a.parse().unwrap()), "{a}");
        }
    }
}
