//! The kernel's MPLS label table (G3.5): what each incoming label does.
//!
//! LDP's entries are installed by the routing suite (FRR's zebra); the
//! static ones (`/mpls static`) by the backend's `apply`. Both are read
//! back here for `/mpls forwarding-table`. A full LSR holds 10⁴–10⁵
//! labels, so the read runs on a thread of the app ([`MplsReader`]), never
//! under the session lock.

use std::net::IpAddr;

use corerouter_model::IfName;
use corerouter_model::mpls::Mpls;
use serde::Serialize;

use crate::HalError;

/// Why the MPLS commands are disabled, and what a missing table means.
pub const NO_MPLS: &str = "this kernel has no MPLS forwarding (module mpls_router, CONFIG_MPLS_ROUTING): load it with `modprobe mpls_router`";

/// Who installed a label entry (Linux `rtm_protocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// `/mpls static` (`RTPROT_STATIC`).
    Static,
    /// FRR: LDP (`RTPROT_LDP`, 193) or zebra on its behalf (`RTPROT_ZEBRA`).
    Ldp,
    /// FRR's BGP labeled unicast or another protocol of the suite.
    Bgp,
    /// Anything else (`ip -f mpls route add` by hand, another program).
    Other,
}

impl Origin {
    pub fn name(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Ldp => "ldp",
            Self::Bgp => "bgp",
            Self::Other => "other",
        }
    }
}

/// One way out of a label entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MplsNexthop {
    /// The next router (`RTA_VIA`); `None`: the packet leaves on
    /// `interface` as is (a point-to-point link).
    pub via: Option<IpAddr>,
    pub interface: Option<IfName>,
    /// The labels that replace the incoming one, top first; empty: pop
    /// (RFC 3032 §2.1 implicit NULL: the IP packet goes out unlabeled).
    pub out_labels: Vec<u32>,
}

/// One entry of the label table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MplsRoute {
    pub label: u32,
    pub origin: Origin,
    /// More than one: ECMP (`RTA_MULTIPATH`).
    pub nexthops: Vec<MplsNexthop>,
}

/// Reads the label table on a thread of its own.
pub trait MplsReader: Send {
    /// The whole table, sorted by label.
    fn routes(&mut self) -> Result<Vec<MplsRoute>, HalError>;
}

/// The label entries `cfg` puts in the kernel itself (`/mpls static`).
pub fn static_routes(mpls: &Mpls) -> Vec<MplsRoute> {
    mpls.statics
        .iter()
        .filter(|(_, s)| !s.disabled)
        .map(|(label, s)| MplsRoute {
            label: *label,
            origin: Origin::Static,
            nexthops: vec![MplsNexthop {
                via: Some(s.nexthop),
                interface: s.interface.clone(),
                out_labels: s.out_labels.clone(),
            }],
        })
        .collect()
}

/// A static change, in the order a backend applies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticOp {
    Remove(u32),
    /// Create or replace.
    Set(MplsRoute),
}

/// What turns the static entries of `from` into those of `to`: removals
/// first (a label that moves never has two entries), then the new or
/// changed ones. Unchanged entries are not touched.
pub fn static_diff(from: &Mpls, to: &Mpls) -> Vec<StaticOp> {
    let old = static_routes(from);
    let new = static_routes(to);
    let mut ops: Vec<StaticOp> = old
        .iter()
        .filter(|o| !new.iter().any(|n| n.label == o.label))
        .map(|o| StaticOp::Remove(o.label))
        .collect();
    // Both lists are sorted by label (BTreeMap order): one merge pass.
    let mut i = old.iter().peekable();
    for n in new {
        while i.next_if(|o| o.label < n.label).is_some() {}
        if i.peek().is_some_and(|o| **o == n) {
            continue;
        }
        ops.push(StaticOp::Set(n));
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::mpls::StaticLsp;

    fn lsp(nh: [u8; 4], out: &[u32]) -> StaticLsp {
        StaticLsp {
            nexthop: IpAddr::from(nh),
            interface: None,
            out_labels: out.to_vec(),
            disabled: false,
            comment: String::new(),
        }
    }

    #[test]
    fn the_diff_touches_only_what_changed() {
        let mut a = Mpls::default();
        a.statics.insert(100, lsp([10, 0, 0, 2], &[200]));
        a.statics.insert(101, lsp([10, 0, 0, 2], &[]));
        a.statics.insert(102, lsp([10, 0, 0, 3], &[]));
        let mut b = a.clone();
        b.statics.remove(&101);
        b.statics.insert(102, lsp([10, 0, 0, 3], &[300, 301]));
        b.statics.insert(103, lsp([10, 0, 0, 4], &[]));
        let ops = static_diff(&a, &b);
        assert_eq!(ops.len(), 3, "{ops:?}");
        assert_eq!(ops[0], StaticOp::Remove(101));
        assert!(matches!(&ops[1], StaticOp::Set(r) if r.label == 102));
        assert!(matches!(&ops[2], StaticOp::Set(r) if r.label == 103));
        assert!(static_diff(&b, &b).is_empty());
        // Disabled is removed.
        let mut c = b.clone();
        if let Some(s) = c.statics.get_mut(&100) {
            s.disabled = true;
        }
        assert_eq!(static_diff(&b, &c), vec![StaticOp::Remove(100)]);
    }
}
