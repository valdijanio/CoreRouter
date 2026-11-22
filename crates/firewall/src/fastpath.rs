//! The fast path (G2.4) as table `inet corerouter_fastpath`: one
//! flowtable on the ports and one forward chain that feeds it.
//!
//! The chain hooks forward at `filter + 10`, after the firewall's own
//! forward chain (`inet corerouter`, priority `filter`): a packet the rules
//! dropped never gets here, so only accepted connections enter the
//! flowtable, and a later drop rule takes effect on new connections at
//! once (the flows already in the table expire or are flushed when the
//! firewall changes, see `hal-linux`). `ct state established`: the first
//! packet of a connection always crosses the rules (and the NAT).
//!
//! Kernel doc: Documentation/networking/nf_flowtable.rst (flow add,
//! `flags offload`, `counter`, what still takes the slow path).

use corerouter_model::fastpath::FastPath;

use crate::program::{
    Chain, ChainType, CtKey, Expr, Family, Flowtable, Hook, Rule, Table, ct_bits, l4proto_is,
};

pub const TABLE: &str = "corerouter_fastpath";
pub const FLOWTABLE: &str = "ft";

/// `ct state established` (`NF_CT_STATE_BIT(IP_CT_ESTABLISHED)`).
const CT_ESTABLISHED: u32 = 1 << 1;

/// The table for `fp` on `devices` (the ports that exist now), or `None`
/// when the fast path is off or has no port (the table is then deleted).
pub fn table(fp: &FastPath, devices: &[String], hw_offload: bool) -> Option<Table> {
    if !fp.enabled || devices.is_empty() {
        return None;
    }
    let mut t = Table {
        family: Family::Inet,
        name: TABLE.into(),
        ..Table::default()
    };
    t.flowtables.push(Flowtable {
        name: FLOWTABLE.into(),
        devices: devices.to_vec(),
        hw_offload,
        counter: fp.counters,
    });
    t.chains.push(Chain {
        name: "forward".into(),
        kind: ChainType::Filter,
        hook: Hook::Forward,
        priority: 10,
        priority_text: "filter + 10".into(),
    });
    for (proto, name) in [(6u8, "tcp"), (17, "udp")] {
        let mut exprs: Vec<Expr> = l4proto_is(proto).into();
        exprs.extend(ct_bits(CtKey::State, CT_ESTABLISHED));
        exprs.push(Expr::FlowAdd {
            table: FLOWTABLE.into(),
        });
        t.rules.push(Rule {
            chain: "forward".into(),
            exprs,
            text: format!("meta l4proto {name} ct state established flow add @{FLOWTABLE}"),
            nft: None,
            comment: None,
        });
    }
    Some(t)
}

/// The ports a config puts in the flowtable: the ones named, else every
/// Ethernet and bond port (not a bond's slaves), in config order, kept
/// only if `exists`.
pub fn devices(
    fp: &FastPath,
    cfg: &corerouter_model::config::Config,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    use corerouter_model::config::InterfaceKind;
    let names: Vec<String> = if fp.interfaces.is_empty() {
        cfg.interfaces
            .values()
            // A bond's slaves are not ports of their own: the bond is.
            .filter(|i| {
                !i.disabled
                    && i.bond.is_none()
                    && matches!(
                        i.kind,
                        InterfaceKind::Ethernet | InterfaceKind::Bonding { .. }
                    )
            })
            .map(|i| i.name.to_string())
            .collect()
    } else {
        fp.interfaces.iter().map(ToString::to_string).collect()
    };
    names.into_iter().filter(|n| exists(n)).collect()
}

/// Whether the part of the config the fast path depends on changed.
pub fn changed(
    from: &corerouter_model::config::Config,
    to: &corerouter_model::config::Config,
) -> bool {
    from.ip.fastpath != to.ip.fastpath
        || (to.ip.fastpath.enabled
            && (devices(&from.ip.fastpath, from, |_| true)
                != devices(&to.ip.fastpath, to, |_| true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_or_portless_is_no_table() {
        let mut fp = FastPath::default();
        assert!(table(&fp, &["ether1".into()], false).is_none());
        fp.enabled = true;
        assert!(table(&fp, &[], false).is_none());
    }

    #[test]
    fn the_table_reads_like_nft() {
        let fp = FastPath {
            enabled: true,
            ..FastPath::default()
        };
        let t = table(&fp, &["ether1".into(), "ether2".into()], true).unwrap();
        let text = t.text();
        assert!(
            text.starts_with("table inet corerouter_fastpath {"),
            "{text}"
        );
        assert!(text.contains("devices = { ether1, ether2 }"));
        assert!(text.contains("flags offload") && text.contains("counter"));
        assert!(text.contains("type filter hook forward priority filter + 10;"));
        assert!(text.contains("meta l4proto udp ct state established flow add @ft"));
        assert_eq!(t.flowtables[0].flags(), 3);
        assert!(
            !table(&fp, &["ether1".into()], false)
                .unwrap()
                .text()
                .contains("offload")
        );
    }
}
