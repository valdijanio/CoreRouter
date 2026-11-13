//! G1.31d: what makes a mangle `change-mss` rule do nothing, said when it
//! is written (`ip.firewall.mangle.add`/`set` → `warnings`). The hard rules
//! (protocol=tcp, tcp-flags=syn, clamp-to-pmtu after routing) are errors in
//! `corerouter_firewall::validate`; these are the soft ones.
//!
//! The kernel only ever lowers the MSS (`nft_exthdr_tcp_set_eval`: "increase
//! can cause connection to stall"), so a value at or above what the SYN
//! already carries changes nothing. A SYN from a host on an Ethernet carries
//! MTU − 40 (IPv4: 20 bytes of IP, 20 of TCP; RFC 9293 §3.7.1), 1460 on a
//! 1500-byte link.

use corerouter_model::Config;
use corerouter_model::firewall::{Action, FirewallRule, NewMss};

/// IPv4 and TCP headers without options (RFC 9293 §3.7.1).
const HEADERS: u16 = 40;
/// RFC 9293 §3.7.1 (and RFC 1122 §4.2.2.6): what a host assumes without the
/// option; a lower clamp makes every segment small.
const DEFAULT_MSS: u16 = 536;
/// What a SYN from a 1500-byte Ethernet carries.
const ETHERNET_MSS: u16 = 1460;

/// The positive `out-interface` of `r` and its MTU, when it is one we know.
fn out_mtu(cfg: &Config, r: &FirewallRule) -> Option<(String, u16)> {
    let o = r.matchers.out_interface.as_ref().filter(|o| !o.not)?;
    let i = cfg.interfaces.get(&o.value)?;
    Some((o.value.to_string(), i.mtu))
}

/// The warnings of rule `r` (empty for every other action).
pub(crate) fn warnings(cfg: &Config, r: &FirewallRule) -> Vec<String> {
    let Action::ChangeMss { new_mss, .. } = &r.action else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match (*new_mss, out_mtu(cfg, r)) {
        (NewMss::Value(v), Some((name, mtu))) if v >= mtu.saturating_sub(HEADERS) => {
            out.push(format!(
                "new-mss={v} changes nothing for SYNs leaving {name} (MTU {mtu}: they carry at most {} and the kernel never raises the MSS)",
                mtu.saturating_sub(HEADERS)
            ));
        }
        (NewMss::Value(v), None) if v >= ETHERNET_MSS => {
            out.push(format!(
                "new-mss={v} changes nothing for SYNs from 1500-byte links (they carry {ETHERNET_MSS} or less and the kernel never raises the MSS); use the tunnel's MTU minus {HEADERS}, or clamp-to-pmtu"
            ));
        }
        (NewMss::Value(v), _) if v < DEFAULT_MSS => {
            out.push(format!(
                "new-mss={v} is below {DEFAULT_MSS} (RFC 9293 §3.7.1): every segment of these connections gets that small"
            ));
        }
        (NewMss::ClampToPmtu, Some((name, mtu))) if mtu >= 1500 => {
            out.push(format!(
                "clamp-to-pmtu changes nothing on {name} (MTU {mtu}) unless a route through it has a smaller mtu; clamp on the tunnel (WireGuard, PPPoE, GRE) instead"
            ));
        }
        _ => {}
    }
    if r.chain.as_str() == "input" {
        out.push(
            "in chain input only the SYNs of connections to the router itself change; forward is the chain for traffic through it".into(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_firewall::sample::{act, m, rule};

    fn cfg() -> Config {
        let mut c = Config::default();
        for (n, mtu) in [("ether1", 1500u16), ("wg0", 1420)] {
            let mut i = corerouter_model::Interface::new(
                n.parse().unwrap(),
                corerouter_model::InterfaceKind::Ethernet,
            );
            i.mtu = mtu;
            c.interfaces.insert(i.name.clone(), i);
        }
        c
    }

    fn mss(chain: &str, out: Option<&str>, new_mss: &str) -> FirewallRule {
        let mut pairs = vec![("protocol", "tcp"), ("tcp_flags", "syn")];
        if let Some(o) = out {
            pairs.push(("out_interface", o));
        }
        let a = format!(r#"{{"type":"change-mss","new_mss":"{new_mss}"}}"#);
        rule(1, chain, m(&pairs).unwrap(), act(&a).unwrap()).unwrap()
    }

    #[test]
    fn useless_values_are_named() {
        let c = cfg();
        assert!(warnings(&c, &mss("forward", Some("wg0"), "1360")).is_empty());
        assert!(warnings(&c, &mss("forward", Some("wg0"), "clamp-to-pmtu")).is_empty());
        // 1420 − 40: what the SYN already carries.
        let w = warnings(&c, &mss("forward", Some("wg0"), "1380"));
        assert!(w[0].contains("MTU 1420"), "{w:?}");
        let w = warnings(&c, &mss("forward", None, "1460"));
        assert!(w[0].contains("1500-byte"), "{w:?}");
        let w = warnings(&c, &mss("forward", None, "300"));
        assert!(w[0].contains("below 536"), "{w:?}");
        let w = warnings(&c, &mss("forward", Some("ether1"), "clamp-to-pmtu"));
        assert!(w[0].contains("clamp on the tunnel"), "{w:?}");
        let w = warnings(&c, &mss("input", None, "1300"));
        assert!(w[0].contains("chain input"), "{w:?}");
    }
}
