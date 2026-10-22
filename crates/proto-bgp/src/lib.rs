//! L2 — BGP.
//!
//! Validates `routing.bgp` and renders it to FRR `bgpd` configuration. The
//! L1 driver `hal-frr` (docs/gaps.md G3.1) will feed the rendered text to
//! `frr-reload` as one transaction and read state back with
//! `vtysh -c 'show bgp summary json'`.
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use std::fmt::Write as _;

use corerouter_model::{BgpInstance, Config, Issue};

pub fn validate(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    for (key, inst) in &cfg.routing.bgp {
        let path = format!("routing.bgp.{key}");
        if inst.name != *key {
            out.push(Issue::new(&path, "instance name does not match its key"));
        }
        if inst.asn.is_reserved() {
            out.push(Issue::new(
                format!("{path}.asn"),
                format!("AS {} is reserved (0, 23456, 65535, 4294967295)", inst.asn),
            ));
        }
        if inst.router_id.is_unspecified() || inst.router_id.is_broadcast() {
            out.push(Issue::new(
                format!("{path}.router_id"),
                "router-id must not be 0.0.0.0 or 255.255.255.255",
            ));
        }
    }
    out
}

/// Render one instance as an FRR `router bgp` block.
pub fn render_frr(inst: &BgpInstance) -> String {
    let mut s = String::new();
    // Writing to a String cannot fail; ignore the fmt::Result.
    let _ = writeln!(s, "router bgp {}", inst.asn);
    let _ = writeln!(s, " bgp router-id {}", inst.router_id);
    let _ = writeln!(s, " no bgp default ipv4-unicast");
    if inst.disabled {
        let _ = writeln!(s, " bgp shutdown");
    }
    let _ = writeln!(s, "exit");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::Asn;

    fn inst(asn: u32, rid: [u8; 4]) -> BgpInstance {
        BgpInstance {
            name: "default".into(),
            asn: Asn(asn),
            router_id: rid.into(),
            disabled: false,
            comment: String::new(),
        }
    }

    #[test]
    fn rejects_reserved_and_bad_router_id() {
        let mut cfg = Config::default();
        cfg.routing
            .bgp
            .insert("default".into(), inst(23456, [0, 0, 0, 0]));
        let issues = validate(&cfg);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn renders_frr() {
        let text = render_frr(&inst(65000, [10, 0, 0, 1]));
        assert!(text.starts_with("router bgp 65000\n"));
        assert!(text.contains(" bgp router-id 10.0.0.1\n"));
    }
}
