//! L2 — BGP.
//!
//! Validates `routing.bgp` and renders it to FRR `bgpd` configuration. The
//! platform driver `hal-frr` (G3.1) diffs the render against what `bgpd`
//! runs and types only the difference, then reads the sessions back as
//! JSON.
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

/// The instance FRR runs in the default VRF; any other name is a BGP
/// `view` of its own (a separate instance with its own sessions and
/// table, not installed in the kernel) until G3.2 gives instances a VRF.
pub const DEFAULT_INSTANCE: &str = "default";

/// The FRR context header of an instance, as `show running-config` prints it.
pub fn frr_header(inst: &BgpInstance) -> String {
    if inst.name == DEFAULT_INSTANCE {
        format!("router bgp {}", inst.asn)
    } else {
        format!("router bgp {} view {}", inst.asn, inst.name)
    }
}

/// Render one instance as an FRR `router bgp` block, in FRR's own canonical
/// form (what `show running-config` gives back), so a diff against the
/// running config is empty when nothing changed.
///
/// eBGP sessions follow RFC 8212 (FRR's `bgp ebgp-requires-policy`, on by
/// default): no route is accepted or sent without a policy, which G3.2
/// brings.
pub fn render_frr(inst: &BgpInstance) -> String {
    let mut s = String::new();
    // Writing to a String cannot fail; ignore the fmt::Result.
    let _ = writeln!(s, "{}", frr_header(inst));
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
        let mut other = inst(65000, [10, 0, 0, 1]);
        other.name = "lab".into();
        assert!(render_frr(&other).starts_with("router bgp 65000 view lab\n"));
    }
}
