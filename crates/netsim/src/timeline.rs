//! What happened, when: the timeline the window draws and the convergence
//! summary after a failure ("link cut → +0.9 s BFD → +1.2 s OSPF → +1.4 s
//! BGP stable, N prefixes lost").

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::{Fault, LinkId, NodeId, Time};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum RecordKind {
    Fault {
        fault: Fault,
    },
    AdjUp {
        link: LinkId,
        neighbor: Ipv4Addr,
    },
    AdjDown {
        link: LinkId,
        neighbor: Option<Ipv4Addr>,
        reason: &'static str,
    },
    BfdDown {
        link: LinkId,
    },
    BfdUp {
        link: LinkId,
    },
    /// SPF changed the OSPF routes.
    IgpChanged {
        routes: u32,
        added: u32,
        removed: u32,
    },
    BgpUp {
        peer: String,
    },
    BgpDown {
        peer: String,
        reason: String,
    },
    /// A configuration mismatch keeps a session down (reported once).
    BgpError {
        peer: String,
        reason: String,
    },
    /// The decision process changed best paths.
    BgpBest {
        prefixes: u32,
        added: u32,
        removed: u32,
        changed: u32,
    },
}

impl RecordKind {
    /// Protocol layer, for the timeline's colors and the summary.
    pub fn layer(&self) -> &'static str {
        match self {
            RecordKind::Fault { .. } => "fault",
            RecordKind::BfdDown { .. } | RecordKind::BfdUp { .. } => "bfd",
            RecordKind::AdjUp { .. }
            | RecordKind::AdjDown { .. }
            | RecordKind::IgpChanged { .. } => "ospf",
            RecordKind::BgpUp { .. }
            | RecordKind::BgpDown { .. }
            | RecordKind::BgpError { .. }
            | RecordKind::BgpBest { .. } => "bgp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub at: Time,
    /// `None`: the operator (a fault).
    pub node: Option<NodeId>,
    #[serde(flatten)]
    pub kind: RecordKind,
}

/// How the network reacted to the last fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Convergence {
    pub fault_at: Time,
    pub fault: Fault,
    /// First failure detection (BFD, dead timer, carrier, hold timer).
    pub detected_after: Option<Time>,
    /// Last OSPF route change.
    pub igp_after: Option<Time>,
    /// Last BGP best-path change.
    pub bgp_after: Option<Time>,
    /// Best BGP prefixes summed over the routers, just before the fault and now.
    pub bgp_prefixes_before: u64,
    pub bgp_prefixes_now: u64,
    /// No protocol change for this long (or more) since the last one.
    pub quiet_for: Time,
}

pub(crate) fn convergence(
    records: &[Record],
    fault_at: Time,
    fault: Fault,
    before: u64,
    now_prefixes: u64,
    now: Time,
) -> Convergence {
    let mut c = Convergence {
        fault_at,
        fault,
        detected_after: None,
        igp_after: None,
        bgp_after: None,
        bgp_prefixes_before: before,
        bgp_prefixes_now: now_prefixes,
        quiet_for: 0,
    };
    let mut last = fault_at;
    for r in records
        .iter()
        .filter(|r| r.at >= fault_at && r.node.is_some())
    {
        let after = r.at - fault_at;
        match &r.kind {
            RecordKind::BfdDown { .. }
            | RecordKind::AdjDown { .. }
            | RecordKind::BgpDown { .. } => {
                c.detected_after.get_or_insert(after);
            }
            _ => {}
        }
        match r.kind.layer() {
            "ospf" if matches!(r.kind, RecordKind::IgpChanged { .. }) => c.igp_after = Some(after),
            "bgp" if matches!(r.kind, RecordKind::BgpBest { .. }) => c.bgp_after = Some(after),
            _ => {}
        }
        last = last.max(r.at);
    }
    c.quiet_for = now.saturating_sub(last);
    c
}
