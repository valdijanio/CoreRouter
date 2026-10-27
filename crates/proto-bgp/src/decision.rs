//! "Why this route?" (G3.2c): the BGP decision process between two paths
//! of a prefix, step by step, so `routing.bgp.route.explain` can say which
//! step put each candidate behind the best one.
//!
//! The order is FRR 10.x `bgp_path_info_cmp` (bgpd/bgp_route.c), which the
//! routing daemon really runs, and each step names its RFC 4271 rule:
//! §9.1.1 (degree of preference: LOCAL_PREF) and the §9.1.2.2 tie-breaks
//! (a) AS_PATH length, (b) ORIGIN, (c) MULTI_EXIT_DISC between routes from
//! the same neighboring AS, (d) eBGP over iBGP, (e) interior cost to the
//! next hop, (f) BGP Identifier, (g) peer address; RFC 4456 §9 for the
//! ORIGINATOR_ID and CLUSTER_LIST of reflected routes. Weight, "local
//! route" and "older path" are FRR's (and Cisco's) own steps.
//!
//! Not modeled (off by default in FRR, not configured by CoreRouter):
//! AIGP, accept-own, `bestpath as-path multipath-relax`, equal cluster
//! length for multipath, EVPN. When FRR's choice differs from this
//! comparison (`deterministic-med` order effects, a knob above), the
//! answer says so instead of guessing.

use std::cmp::Ordering;
use std::net::IpAddr;

use corerouter_model::bgp_rib::{BgpPath, BgpPrefix, PeerKind, SegmentKind};
use serde::Serialize;

/// One step of the decision process, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    /// Not a candidate: next hop unreachable, AS loop, or the daemon
    /// marked it invalid (RFC 4271 §9.1.2).
    NotUsable,
    Weight,
    LocalPref,
    LocalRoute,
    AsPathLength,
    Origin,
    Med,
    PeerType,
    IgpMetric,
    ConfedPeerType,
    OlderPath,
    RouterId,
    ClusterLength,
    Stale,
    NeighborAddress,
    /// Nothing left to compare.
    Equal,
}

impl Step {
    pub const ALL: [Step; 16] = [
        Step::NotUsable,
        Step::Weight,
        Step::LocalPref,
        Step::LocalRoute,
        Step::AsPathLength,
        Step::Origin,
        Step::Med,
        Step::PeerType,
        Step::IgpMetric,
        Step::ConfedPeerType,
        Step::OlderPath,
        Step::RouterId,
        Step::ClusterLength,
        Step::Stale,
        Step::NeighborAddress,
        Step::Equal,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Step::NotUsable => "not-usable",
            Step::Weight => "weight",
            Step::LocalPref => "local-pref",
            Step::LocalRoute => "local-route",
            Step::AsPathLength => "as-path-length",
            Step::Origin => "origin",
            Step::Med => "med",
            Step::PeerType => "peer-type",
            Step::IgpMetric => "igp-metric",
            Step::ConfedPeerType => "confed-peer-type",
            Step::OlderPath => "older-path",
            Step::RouterId => "router-id",
            Step::ClusterLength => "cluster-length",
            Step::Stale => "stale",
            Step::NeighborAddress => "neighbor-address",
            Step::Equal => "equal",
        }
    }

    /// FRR's `selectionReason` text for the step.
    pub fn frr_reason(self) -> &'static str {
        match self {
            Step::NotUsable => "",
            Step::Weight => "Weight",
            Step::LocalPref => "Local Pref",
            Step::LocalRoute => "Local Route",
            Step::AsPathLength => "AS Path",
            Step::Origin => "Origin",
            Step::Med => "MED",
            Step::PeerType => "Peer Type",
            Step::IgpMetric => "IGP Metric",
            Step::ConfedPeerType => "Confed Peer Type",
            Step::OlderPath => "Older Path",
            Step::RouterId => "Router ID",
            Step::ClusterLength => "Cluster length",
            Step::Stale => "Path Staleness",
            Step::NeighborAddress => "Neighbor IP",
            Step::Equal => "Nothing left to compare",
        }
    }

    pub fn from_frr_reason(s: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|st| !st.frr_reason().is_empty() && st.frr_reason() == s)
    }

    /// The rule, in English (the window explains it in Portuguese).
    pub fn rule(self) -> &'static str {
        match self {
            Step::NotUsable => "unusable paths are not candidates (RFC 4271 §9.1.2)",
            Step::Weight => "higher weight wins (local to this router, not sent to peers)",
            Step::LocalPref => "higher LOCAL_PREF wins (RFC 4271 §9.1.1)",
            Step::LocalRoute => "a route originated here wins over a received one",
            Step::AsPathLength => "shorter AS_PATH wins; an AS_SET counts as one (RFC 4271 §9.1.2.2 a)",
            Step::Origin => "lower ORIGIN wins: IGP, then EGP, then incomplete (RFC 4271 §9.1.2.2 b)",
            Step::Med => "lower MED wins between routes from the same neighboring AS (RFC 4271 §9.1.2.2 c)",
            Step::PeerType => "a route from an eBGP peer wins over iBGP (RFC 4271 §9.1.2.2 d)",
            Step::IgpMetric => "lower interior cost to the next hop wins (RFC 4271 §9.1.2.2 e)",
            Step::ConfedPeerType => "a confederation-external route wins over a confederation-internal one",
            Step::OlderPath => "between eBGP routes the one already chosen stays (fewer flaps)",
            Step::RouterId => "lower BGP Identifier (ORIGINATOR_ID when reflected) wins (RFC 4271 §9.1.2.2 f, RFC 4456 §9)",
            Step::ClusterLength => "shorter CLUSTER_LIST wins (RFC 4456 §9)",
            Step::Stale => "a stale route (graceful restart) loses",
            Step::NeighborAddress => "lower peer address wins (RFC 4271 §9.1.2.2 g)",
            Step::Equal => "the paths are equal in every step",
        }
    }
}

/// Knobs of the decision process (FRR `bgp bestpath …`, `bgp default
/// local-preference`); the defaults are FRR's and CoreRouter's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub default_local_pref: u32,
    pub always_compare_med: bool,
    pub med_missing_as_worst: bool,
    pub as_path_ignore: bool,
    pub as_path_confed: bool,
    pub compare_router_id: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            default_local_pref: 100,
            always_compare_med: false,
            med_missing_as_worst: false,
            as_path_ignore: false,
            as_path_confed: false,
            compare_router_id: false,
        }
    }
}

/// RFC 4271 §9.1.2.2 (a): AS_SEQUENCE ASes count one each, an AS_SET one
/// in all; confederation segments do not count (RFC 5065 §5.3).
pub fn hops(p: &BgpPath) -> u32 {
    p.segments
        .iter()
        .map(|s| match s.kind {
            SegmentKind::Sequence => u32::try_from(s.asns.len()).unwrap_or(u32::MAX),
            SegmentKind::Set => 1,
            SegmentKind::ConfedSequence | SegmentKind::ConfedSet => 0,
        })
        .fold(0u32, u32::saturating_add)
}

fn confeds(p: &BgpPath) -> u32 {
    p.segments
        .iter()
        .map(|s| match s.kind {
            SegmentKind::ConfedSequence => u32::try_from(s.asns.len()).unwrap_or(u32::MAX),
            SegmentKind::ConfedSet => 1,
            _ => 0,
        })
        .fold(0u32, u32::saturating_add)
}

/// The neighboring AS (first AS of the first AS_SEQUENCE, past the
/// confederation segments): MED is compared only within it.
fn left_as(p: &BgpPath) -> Option<u32> {
    let s = p
        .segments
        .iter()
        .find(|s| !matches!(s.kind, SegmentKind::ConfedSequence | SegmentKind::ConfedSet))?;
    (s.kind == SegmentKind::Sequence).then(|| s.asns.first().copied()).flatten()
}

fn left_confed(p: &BgpPath) -> Option<u32> {
    let s = p.segments.first()?;
    (s.kind == SegmentKind::ConfedSequence).then(|| s.asns.first().copied()).flatten()
}

fn is_ebgp(p: &BgpPath) -> bool {
    p.peer_kind == PeerKind::External
}

/// The outcome of one comparison: which path won, at which step, and the
/// two values the step looked at (winner first), for the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    /// `Greater`: `a` is better.
    #[serde(skip)]
    pub order: Ordering,
    pub step: Step,
    pub winner_value: String,
    pub loser_value: String,
}

fn verdict<T: Ord + ToString>(step: Step, a: T, b: T, a_better_when_greater: bool) -> Option<Verdict> {
    let o = a.cmp(&b);
    if o == Ordering::Equal {
        return None;
    }
    let order = if a_better_when_greater { o } else { o.reverse() };
    let (w, l) = if order == Ordering::Greater { (a, b) } else { (b, a) };
    Some(Verdict {
        order,
        step,
        winner_value: w.to_string(),
        loser_value: l.to_string(),
    })
}

fn flag(step: Step, a: bool, b: bool, yes: &str, no: &str) -> Option<Verdict> {
    (a != b).then(|| Verdict {
        order: if a { Ordering::Greater } else { Ordering::Less },
        step,
        winner_value: yes.to_owned(),
        loser_value: no.to_owned(),
    })
}

fn kind_name(k: PeerKind) -> &'static str {
    match k {
        PeerKind::Local => "local",
        PeerKind::External => "ebgp",
        PeerKind::Internal => "ibgp",
        PeerKind::ConfedExternal => "confed-ebgp",
    }
}

/// Compare `a` with `b`. `a_selected`/`b_selected`: the path the daemon
/// holds as best now (the "older path" step keeps it).
pub fn compare(a: &BgpPath, b: &BgpPath, a_selected: bool, b_selected: bool, o: &Options) -> Verdict {
    // §9.1.2: only usable paths compete.
    if let Some(v) = flag(Step::NotUsable, a.valid, b.valid, "usable", "not usable") {
        return v;
    }
    if let Some(v) = verdict(Step::Weight, a.weight, b.weight, true) {
        return v;
    }
    let lp = |p: &BgpPath| p.local_pref.unwrap_or(o.default_local_pref);
    if let Some(v) = verdict(Step::LocalPref, lp(a), lp(b), true) {
        return v;
    }
    let local = |p: &BgpPath| p.peer_kind == PeerKind::Local;
    if let Some(v) = flag(Step::LocalRoute, local(a), local(b), "originated here", "received") {
        return v;
    }
    if !o.as_path_ignore {
        let len = |p: &BgpPath| {
            if o.as_path_confed {
                hops(p).saturating_add(confeds(p))
            } else {
                hops(p)
            }
        };
        if let Some(v) = verdict(Step::AsPathLength, len(a), len(b), false) {
            return v;
        }
    }
    if a.origin != b.origin {
        let a_wins = a.origin < b.origin;
        let (w, l) = if a_wins { (a, b) } else { (b, a) };
        return Verdict {
            order: if a_wins { Ordering::Greater } else { Ordering::Less },
            step: Step::Origin,
            winner_value: w.origin.name().into(),
            loser_value: l.origin.name().into(),
        };
    }
    let internal = hops(a) == 0 && hops(b) == 0;
    let same_left = left_as(a).is_some() && left_as(a) == left_as(b);
    let same_confed = left_confed(a).is_some() && left_confed(a) == left_confed(b);
    if o.always_compare_med || same_left || same_confed || internal {
        let missing = if o.med_missing_as_worst { u32::MAX } else { 0 };
        let med = |p: &BgpPath| p.med.unwrap_or(missing);
        if let Some(v) = verdict(Step::Med, med(a), med(b), false) {
            return v;
        }
    }
    // eBGP over iBGP and confederation peers.
    let ext = |p: &BgpPath| is_ebgp(p);
    let ibgpish = |p: &BgpPath| matches!(p.peer_kind, PeerKind::Internal | PeerKind::ConfedExternal);
    if ext(a) && ibgpish(b) || ext(b) && ibgpish(a) {
        return Verdict {
            order: if ext(a) { Ordering::Greater } else { Ordering::Less },
            step: Step::PeerType,
            winner_value: "ebgp".into(),
            loser_value: kind_name(if ext(a) { b.peer_kind } else { a.peer_kind }).into(),
        };
    }
    let igp = |p: &BgpPath| p.igp_metric.unwrap_or(0);
    if let Some(v) = verdict(Step::IgpMetric, igp(a), igp(b), false) {
        return v;
    }
    let cext = |p: &BgpPath| p.peer_kind == PeerKind::ConfedExternal;
    let cint = |p: &BgpPath| p.peer_kind == PeerKind::Internal;
    if cext(a) && cint(b) || cext(b) && cint(a) {
        return Verdict {
            order: if cext(a) { Ordering::Greater } else { Ordering::Less },
            step: Step::ConfedPeerType,
            winner_value: "confed-ebgp".into(),
            loser_value: "ibgp".into(),
        };
    }
    if !o.compare_router_id
        && ext(a)
        && ext(b)
        && let Some(v) = flag(Step::OlderPath, a_selected, b_selected, "chosen first", "newer")
    {
        return v;
    }
    let rid = |p: &BgpPath| u32::from(p.originator_id.or(p.peer_router_id).unwrap_or([0, 0, 0, 0].into()));
    if let Some(mut v) = verdict(Step::RouterId, rid(a), rid(b), false) {
        v.winner_value = std::net::Ipv4Addr::from(v.winner_value.parse::<u32>().unwrap_or(0)).to_string();
        v.loser_value = std::net::Ipv4Addr::from(v.loser_value.parse::<u32>().unwrap_or(0)).to_string();
        return v;
    }
    if let Some(v) = verdict(Step::ClusterLength, a.cluster_list_len, b.cluster_list_len, false) {
        return v;
    }
    if let Some(v) = flag(Step::Stale, !a.stale, !b.stale, "fresh", "stale") {
        return v;
    }
    let addr = |p: &BgpPath| p.peer.parse::<IpAddr>().ok().filter(|a| !a.is_unspecified());
    match (addr(a), addr(b)) {
        // Our own routes have no peer address: they lose here (FRR
        // "Locally configured route"; step 3 nearly always decided first).
        (None, Some(_)) | (Some(_), None) => {
            let a_wins = addr(a).is_some();
            return Verdict {
                order: if a_wins { Ordering::Greater } else { Ordering::Less },
                step: Step::NeighborAddress,
                winner_value: if a_wins { a.peer.clone() } else { b.peer.clone() },
                loser_value: if a_wins { b.peer.clone() } else { a.peer.clone() },
            };
        }
        (Some(x), Some(y)) if x != y => {
            let a_wins = x < y;
            return Verdict {
                order: if a_wins { Ordering::Greater } else { Ordering::Less },
                step: Step::NeighborAddress,
                winner_value: if a_wins { x } else { y }.to_string(),
                loser_value: if a_wins { y } else { x }.to_string(),
            };
        }
        _ => {}
    }
    Verdict {
        order: Ordering::Equal,
        step: Step::Equal,
        winner_value: String::new(),
        loser_value: String::new(),
    }
}

/// Why each path of a prefix is or is not the best.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explanation {
    /// The path the daemon chose (FRR `bestpath.overall`), else ours.
    pub best: Option<usize>,
    /// Our comparison picks the same best path.
    pub agrees: bool,
    /// One per path, in the daemon's order.
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub index: usize,
    pub best: bool,
    /// The step that put this path behind the best one (`None` for the
    /// best itself).
    pub lost_at: Option<Verdict>,
    /// For the best: the step that beat the runner-up.
    pub won_at: Option<Verdict>,
    /// This path beats the daemon's choice by our comparison: the daemon
    /// used something not modeled here (see the module doc).
    pub unexplained: bool,
}

/// Explain every path of `p` against the best.
pub fn explain(p: &BgpPrefix, o: &Options) -> Explanation {
    let daemon_best = p.paths.iter().position(|x| x.best);
    // Ours: one pass, each path against the winner so far (FRR's own
    // order-dependent walk, without deterministic-med grouping).
    let mut ours: Option<usize> = None;
    for (i, x) in p.paths.iter().enumerate() {
        if !x.valid {
            continue;
        }
        ours = match ours.and_then(|w| p.paths.get(w).map(|wp| (w, wp))) {
            None => Some(i),
            Some((w, wp)) => {
                let v = compare(x, wp, x.best, wp.best, o);
                if v.order == Ordering::Greater { Some(i) } else { Some(w) }
            }
        };
    }
    let best = daemon_best.or(ours);
    let agrees = daemon_best.is_none() || daemon_best == ours;
    let mut rows = Vec::with_capacity(p.paths.len());
    let mut runner_up: Option<Verdict> = None;
    for (i, x) in p.paths.iter().enumerate() {
        let Some(b) = best.and_then(|b| p.paths.get(b)) else {
            rows.push(Row {
                index: i,
                best: false,
                lost_at: Some(Verdict {
                    order: Ordering::Less,
                    step: Step::NotUsable,
                    winner_value: String::new(),
                    loser_value: "not usable".into(),
                }),
                won_at: None,
                unexplained: false,
            });
            continue;
        };
        if Some(i) == best {
            rows.push(Row {
                index: i,
                best: true,
                lost_at: None,
                won_at: None,
                unexplained: false,
            });
            continue;
        }
        let v = compare(b, x, true, x.best, o);
        let unexplained = v.order == Ordering::Less;
        if v.order == Ordering::Greater && runner_up.as_ref().is_none_or(|r| v.step > r.step) {
            runner_up = Some(v.clone());
        }
        rows.push(Row {
            index: i,
            best: false,
            lost_at: Some(v),
            won_at: None,
            unexplained,
        });
    }
    if let Some(row) = rows.iter_mut().find(|r| r.best) {
        row.won_at = runner_up;
    }
    Explanation { best, agrees, rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::bgp_rib::{AsSegment, Origin};

    fn path(peer: &str, kind: PeerKind, asns: &[u32]) -> BgpPath {
        BgpPath {
            peer: peer.into(),
            peer_router_id: peer.parse().ok(),
            peer_kind: kind,
            segments: if asns.is_empty() {
                vec![]
            } else {
                vec![AsSegment {
                    kind: SegmentKind::Sequence,
                    asns: asns.to_vec(),
                }]
            },
            valid: true,
            next_hop_reachable: true,
            ..BgpPath::default()
        }
    }

    fn step(a: &BgpPath, b: &BgpPath) -> (Ordering, Step) {
        let v = compare(a, b, false, false, &Options::default());
        (v.order, v.step)
    }

    #[test]
    fn each_step_in_frr_order() {
        let base = path("192.0.2.1", PeerKind::Internal, &[64500, 64501]);
        let mut x = base.clone();
        x.peer = "192.0.2.2".into();
        x.peer_router_id = Some([192, 0, 2, 2].into());
        assert_eq!(step(&base, &x), (Ordering::Greater, Step::RouterId));
        let mut w = x.clone();
        w.weight = 10;
        assert_eq!(step(&base, &w), (Ordering::Less, Step::Weight));
        let mut lp = x.clone();
        lp.local_pref = Some(200);
        // Unset LOCAL_PREF is the default 100.
        assert_eq!(step(&base, &lp), (Ordering::Less, Step::LocalPref));
        let mut short = x.clone();
        short.segments[0].asns.pop();
        assert_eq!(step(&base, &short), (Ordering::Less, Step::AsPathLength));
        let mut inc = x.clone();
        inc.origin = Origin::Incomplete;
        assert_eq!(step(&base, &inc), (Ordering::Greater, Step::Origin));
        let mut med = x.clone();
        med.med = Some(10);
        // Same neighboring AS (64500): lower MED (missing = 0) wins.
        assert_eq!(step(&base, &med), (Ordering::Greater, Step::Med));
        let mut other_as = med.clone();
        other_as.segments[0].asns[0] = 64999;
        // Different neighboring AS: MED not compared, next steps decide.
        assert_eq!(step(&base, &other_as).1, Step::RouterId);
        let mut ebgp = x.clone();
        ebgp.peer_kind = PeerKind::External;
        assert_eq!(step(&base, &ebgp), (Ordering::Less, Step::PeerType));
        let mut far = x.clone();
        far.igp_metric = Some(20);
        assert_eq!(step(&base, &far), (Ordering::Greater, Step::IgpMetric));
        let mut refl = x.clone();
        refl.originator_id = Some([10, 0, 0, 1].into());
        assert_eq!(step(&base, &refl), (Ordering::Less, Step::RouterId));
        let mut cl = base.clone();
        cl.cluster_list_len = 2;
        cl.peer = "192.0.2.9".into();
        assert_eq!(step(&base, &cl), (Ordering::Greater, Step::ClusterLength));
        let mut same = base.clone();
        same.peer = "192.0.2.0".into();
        assert_eq!(step(&base, &same), (Ordering::Less, Step::NeighborAddress));
        let mut bad = x.clone();
        bad.valid = false;
        assert_eq!(step(&base, &bad), (Ordering::Greater, Step::NotUsable));
        let mut local = path("0.0.0.0", PeerKind::Local, &[]);
        local.weight = 0;
        assert_eq!(step(&local, &base), (Ordering::Greater, Step::LocalRoute));
    }

    #[test]
    fn older_path_keeps_the_chosen_ebgp_route() {
        let a = path("192.0.2.9", PeerKind::External, &[64500]);
        let b = path("192.0.2.1", PeerKind::External, &[64501]);
        let v = compare(&a, &b, true, false, &Options::default());
        assert_eq!((v.order, v.step), (Ordering::Greater, Step::OlderPath));
        let o = Options {
            compare_router_id: true,
            ..Options::default()
        };
        assert_eq!(compare(&a, &b, true, false, &o).step, Step::RouterId);
    }

    #[test]
    fn explains_ten_paths() {
        let mut paths: Vec<BgpPath> = (1..=10)
            .map(|i| {
                let mut p = path(&format!("198.51.100.{i}"), PeerKind::Internal, &[64500, 64500 + i]);
                p.local_pref = Some(100 + i % 3);
                p
            })
            .collect();
        // FRR chose the first one with local-pref 102 and lowest router id.
        let best = paths.iter().position(|p| p.local_pref == Some(102)).unwrap();
        paths[best].best = true;
        paths[best].selection_reason = Some("Local Pref".into());
        let e = explain(&BgpPrefix { prefix: "10.0.0.0/8".into(), paths, ..BgpPrefix::default() }, &Options::default());
        assert_eq!(e.best, Some(best));
        assert!(e.agrees);
        let steps: Vec<Option<Step>> = e.rows.iter().map(|r| r.lost_at.as_ref().map(|v| v.step)).collect();
        assert_eq!(steps.iter().filter(|s| **s == Some(Step::LocalPref)).count(), 7);
        assert_eq!(steps.iter().filter(|s| **s == Some(Step::RouterId)).count(), 2);
        assert!(e.rows.iter().all(|r| !r.unexplained));
        let w = e.rows.iter().find(|r| r.best).unwrap().won_at.as_ref().unwrap();
        assert_eq!(w.step, Step::RouterId);
        assert_eq!(Step::from_frr_reason("Local Pref"), Some(Step::LocalPref));
    }

    #[test]
    fn a_daemon_choice_we_cannot_reproduce_is_flagged() {
        let mut a = path("192.0.2.1", PeerKind::Internal, &[64500]);
        let mut b = path("192.0.2.2", PeerKind::Internal, &[64500]);
        a.local_pref = Some(100);
        b.local_pref = Some(200);
        a.best = true;
        let e = explain(&BgpPrefix { prefix: "10.0.0.0/8".into(), paths: vec![a, b], ..BgpPrefix::default() }, &Options::default());
        assert!(!e.agrees);
        assert!(e.rows[1].unexplained);
    }
}
