//! Segment Routing over OSPFv2 (G3.4f): the checks, the `ospfd` lines,
//! the SID picked for a loopback, the conflicts with what the network
//! announces and the preview of switching SR on.
//!
//! FRR 10.7.1 (`ospfd/ospf_sr.c`, `ospf_ri.c`, `ospf_opaque.c`) sets the
//! rules the checks mirror: SR in the default VRF only, one SR database
//! per `ospfd`, blocks of at least 16 labels inside 16-1048575 that do
//! not overlap, an index below the SRGB size, an index used once, a prefix
//! SID only on a loopback's address. zebra's label manager refuses an SRGB
//! inside a non-default dynamic block (`zebra/label_manager.c`), so the
//! blocks also keep out of `/mpls settings dynamic-label-range`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use corerouter_model::config::InterfaceKind;
use corerouter_model::mpls::{FIRST_UNRESERVED, LABEL_BYTES, MAX_LABEL, MplsSettings};
use corerouter_model::ospf::{MAIN_VRF, OspfInstance, Version};
use corerouter_model::ospf_sr::{
    LabelBlock, MAX_INDEX, MAX_MSD, MAX_PREFIX_SIDS, MIN_BLOCK, PrefixSid, SidBehavior, SrDb,
    active,
};
use corerouter_model::ospf_state::OspfRoute;
use corerouter_model::{Config, IfName, Issue};
use ipnet::{IpNet, Ipv4Net};

use crate::bind::bindings;

/// Labels each SR hop adds: one prefix SID (RFC 8660 §2).
pub const SR_LABELS: u32 = 1;

pub fn validate(cfg: &Config, out: &mut Vec<Issue>) {
    let ospf = &cfg.routing.ospf;
    let Some(sr) = &ospf.segment_routing else {
        if !ospf.prefix_sids.is_empty() {
            out.push(Issue::new(
                "routing.ospf.prefix_sids",
                "prefix SIDs need Segment Routing (routing.ospf.segment-routing.set)",
            ));
        }
        return;
    };
    let path = "routing.ospf.segment_routing";
    match ospf.instances.get(&sr.instance) {
        None => out.push(Issue::new(
            format!("{path}.instance"),
            format!("no OSPF instance {}", sr.instance),
        )),
        Some(i) => instance_ok(i, path, out),
    }
    block(sr.srgb, &format!("{path}.srgb"), "SRGB", out);
    block(sr.srlb, &format!("{path}.srlb"), "SRLB", out);
    if sr.srgb.overlaps(sr.srlb) {
        out.push(Issue::new(
            format!("{path}.srlb"),
            format!("the SRLB {} overlaps the SRGB {}", sr.srlb, sr.srgb),
        ));
    }
    if sr.node_msd.is_some_and(|m| m == 0 || m > MAX_MSD) {
        out.push(Issue::new(
            format!("{path}.node_msd"),
            format!("1..={MAX_MSD} labels"),
        ));
    }
    labels_apart(cfg, sr.srgb, sr.srlb, path, out);
    sids(cfg, sr.srgb, out);
}

fn instance_ok(i: &OspfInstance, path: &str, out: &mut Vec<Issue>) {
    if i.version != Version::V2 {
        out.push(Issue::new(
            format!("{path}.instance"),
            "Segment Routing runs on the OSPFv2 instance (FRR's ospf6d has no SR-MPLS)",
        ));
    }
    if i.vrf != MAIN_VRF {
        out.push(Issue::new(
            format!("{path}.instance"),
            "FRR runs Segment Routing in VRF main only",
        ));
    }
}

/// FRR's `sr_range_is_valid`: 16..=1048575 and at least 16 labels.
fn block(b: LabelBlock, path: &str, what: &str, out: &mut Vec<Issue>) {
    if b.start < FIRST_UNRESERVED || b.end > MAX_LABEL || b.size() < MIN_BLOCK {
        out.push(Issue::new(
            path,
            format!(
                "{what} {b}: inside {FIRST_UNRESERVED}-{MAX_LABEL} (RFC 3032 §2.1 reserves 0-15), at least {MIN_BLOCK} labels"
            ),
        ));
    }
}

/// The SR blocks against LDP's dynamic range and the static LSPs.
fn labels_apart(
    cfg: &Config,
    srgb: LabelBlock,
    srlb: LabelBlock,
    path: &str,
    out: &mut Vec<Issue>,
) {
    let m = &cfg.routing.mpls;
    let (lo, hi) = m.settings.dynamic_label_range;
    if m.settings.dynamic_label_range != MplsSettings::default().dynamic_label_range {
        let dynamic = LabelBlock { start: lo, end: hi };
        for (b, what, key) in [(srgb, "SRGB", "srgb"), (srlb, "SRLB", "srlb")] {
            if b.overlaps(dynamic) {
                out.push(Issue::new(
                    format!("{path}.{key}"),
                    format!(
                        "the {what} {b} overlaps the LDP labels {dynamic} (mpls.settings dynamic_label_range): zebra refuses it; move one of them"
                    ),
                ));
            }
            if b.end > hi {
                out.push(Issue::new(
                    format!("{path}.{key}"),
                    format!(
                        "the {what} {b} ends past the kernel label table (labels up to {hi}, the end of dynamic_label_range): keep it below"
                    ),
                ));
            }
        }
    }
    for label in m.statics.keys() {
        for (b, what) in [(srgb, "SRGB"), (srlb, "SRLB")] {
            if b.contains(*label) {
                out.push(Issue::new(
                    format!("routing.mpls.statics.{label}"),
                    format!("static LSP label {label} is inside the {what} {b}"),
                ));
            }
        }
    }
}

fn sids(cfg: &Config, srgb: LabelBlock, out: &mut Vec<Issue>) {
    let ospf = &cfg.routing.ospf;
    if ospf.prefix_sids.len() > MAX_PREFIX_SIDS {
        out.push(Issue::new(
            "routing.ospf.prefix_sids",
            format!("at most {MAX_PREFIX_SIDS} prefix SIDs"),
        ));
    }
    let loopbacks = loopback_addresses(cfg);
    let announced: HashSet<Ipv4Net> = ospf
        .segment_routing
        .as_ref()
        .map(|sr| announced_loopbacks(cfg, &sr.instance))
        .unwrap_or_default()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    let mut by_index: HashMap<u32, Ipv4Net> = HashMap::new();
    let mut by_prefix: HashSet<Ipv4Net> = HashSet::new();
    for s in ospf.prefix_sids.iter().filter(|s| !s.disabled) {
        let path = format!("routing.ospf.prefix_sids[{}]", s.id);
        if s.prefix.prefix_len() != 32 {
            out.push(Issue::new(
                format!("{path}.prefix"),
                format!(
                    "{}: a prefix SID names a /32 (the loopback address)",
                    s.prefix
                ),
            ));
        } else if !loopbacks.contains_key(&s.prefix) {
            out.push(Issue::new(
                format!("{path}.prefix"),
                format!(
                    "{} is not an address of a loopback interface: FRR sets a prefix SID only there",
                    s.prefix
                ),
            ));
        } else if !announced.contains(&s.prefix) {
            out.push(Issue::new(
                format!("{path}.prefix"),
                format!(
                    "{}: its loopback is in no interface template of the SR instance, so OSPF does not announce it",
                    s.prefix
                ),
            ));
        }
        if s.index > MAX_INDEX || srgb.label(s.index).is_none() {
            out.push(Issue::new(
                format!("{path}.index"),
                format!(
                    "index {} must be below the SRGB size {} (label = {} + index)",
                    s.index,
                    srgb.size(),
                    srgb.start
                ),
            ));
        }
        if let Some(other) = by_index.insert(s.index, s.prefix) {
            out.push(Issue::new(
                format!("{path}.index"),
                format!("index {} is already the SID of {other}", s.index),
            ));
        }
        if !by_prefix.insert(s.prefix) {
            out.push(Issue::new(
                format!("{path}.prefix"),
                format!("{} already has a SID", s.prefix),
            ));
        }
    }
}

/// Every enabled /32 on a loopback interface, with the interface.
pub fn loopback_addresses(cfg: &Config) -> BTreeMap<Ipv4Net, IfName> {
    let mut out = BTreeMap::new();
    for a in cfg.ip.addresses.iter().filter(|a| !a.disabled) {
        let IpNet::V4(v4) = a.address else { continue };
        if v4.prefix_len() != 32 {
            continue;
        }
        let is_lo = cfg
            .interfaces
            .get(&a.interface)
            .is_some_and(|i| !i.disabled && matches!(i.kind, InterfaceKind::Loopback));
        if is_lo {
            out.insert(v4, a.interface.clone());
        }
    }
    out
}

/// The loopback /32s that instance `instance` announces (bound by a
/// template).
pub fn announced_loopbacks(cfg: &Config, instance: &str) -> Vec<(Ipv4Net, IfName)> {
    let bound: HashSet<IfName> = bindings(cfg)
        .into_iter()
        .filter(|b| b.instance.name == instance)
        .map(|b| b.interface)
        .collect();
    loopback_addresses(cfg)
        .into_iter()
        .filter(|(_, i)| bound.contains(i))
        .collect()
}

/// The lines SR adds under `router ospf` of `inst`, in the order they
/// are typed: the blocks before `segment-routing on` (FRR only stores them
/// while SR is off, instead of reserving the default SRGB and moving it),
/// the prefixes after it (FRR refuses them while SR is off). The diff
/// compares lines as a set, so the order FRR prints them in does not
/// matter; the removals go in the reverse order (`hal_frr::conf`).
pub fn router_lines(cfg: &Config, inst: &OspfInstance) -> Vec<String> {
    let ospf = &cfg.routing.ospf;
    let Some(sr) = active(ospf).filter(|s| s.instance == inst.name) else {
        return Vec::new();
    };
    let mut l = vec![
        "capability opaque".to_owned(),
        "router-info area".to_owned(),
    ];
    let (dg, dl) = (
        corerouter_model::ospf_sr::DEFAULT_SRGB,
        corerouter_model::ospf_sr::DEFAULT_SRLB,
    );
    // ospf_sr_config_write_router: the SRGB is printed when it or the
    // SRLB differs from the default, the SRLB only when it differs.
    if sr.srgb != dg || sr.srlb != dl {
        let mut g = format!(
            "segment-routing global-block {} {}",
            sr.srgb.start, sr.srgb.end
        );
        if sr.srlb != dl {
            let _ = write!(g, " local-block {} {}", sr.srlb.start, sr.srlb.end);
        }
        l.push(g);
    }
    l.push("segment-routing on".to_owned());
    if let Some(m) = sr.node_msd {
        l.push(format!("segment-routing node-msd {m}"));
    }
    for s in ospf.prefix_sids.iter().filter(|s| !s.disabled) {
        let mut p = format!("segment-routing prefix {} index {}", s.prefix, s.index);
        match s.behavior {
            SidBehavior::Php => {}
            SidBehavior::NoPhp => p.push_str(" no-php-flag"),
            SidBehavior::ExplicitNull => p.push_str(" explicit-null"),
        }
        l.push(p);
    }
    l
}

/// zebra's dynamic label block while SR runs and `/mpls settings` keeps
/// the default range: the larger free stretch outside the SR blocks (with
/// the defaults, 24000-1048575, as IOS-XR hands out its dynamic labels).
/// `None`: nothing to narrow.
pub fn dynamic_block(cfg: &Config) -> Option<LabelBlock> {
    let m = &cfg.routing.mpls.settings;
    if m.dynamic_label_range != MplsSettings::default().dynamic_label_range {
        return None;
    }
    let blocks = corerouter_model::ospf_sr::reserved(&cfg.routing.ospf);
    let lo = blocks.iter().map(|b| b.start).min()?;
    let hi = blocks.iter().map(|b| b.end).max()?;
    let below = LabelBlock {
        start: FIRST_UNRESERVED,
        end: lo.saturating_sub(1),
    };
    let above = LabelBlock {
        start: hi.saturating_add(1),
        end: MAX_LABEL,
    };
    [above, below]
        .into_iter()
        .filter(|b| b.size() >= MIN_BLOCK)
        .max_by_key(|b| b.size())
}

/// One prefix SID clash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Conflict {
    pub index: u32,
    pub prefix: String,
    /// The other side: a router id, or `this router`.
    pub router: String,
    pub other_prefix: String,
    /// `index` (one index, two prefixes) or `prefix` (one prefix, two
    /// indexes).
    pub kind: &'static str,
    pub detail: String,
}

/// The SID clashes in `db` (what `ospfd` learned), with `local` (this
/// router's own SIDs, from the config) taking part as `this router`.
/// RFC 8665 §5 and RFC 8402 §3.2: an index names one prefix in the
/// domain; RFC 8660 §2.5 leaves a clash to the operator, so it is shown,
/// not fixed.
pub fn conflicts(db: &SrDb, local: &[PrefixSid]) -> Vec<Conflict> {
    let me = db.router_id;
    // index → (prefix, router) as first seen; prefix → index.
    let mut owners: BTreeMap<u32, Vec<(Ipv4Net, String)>> = BTreeMap::new();
    for s in local.iter().filter(|s| !s.disabled) {
        owners
            .entry(s.index)
            .or_default()
            .push((s.prefix, "this router".to_owned()));
    }
    for n in &db.nodes {
        if Some(n.router_id) == me {
            continue;
        }
        let rid = Ipv4Addr::from(n.router_id).to_string();
        for p in &n.prefixes {
            let Ok(net) = Ipv4Net::new(Ipv4Addr::from(p.prefix), p.plen) else {
                continue;
            };
            owners.entry(p.sid).or_default().push((net, rid.clone()));
        }
    }
    let mut out = Vec::new();
    let mut index_of: BTreeMap<Ipv4Net, (u32, String)> = BTreeMap::new();
    for (index, list) in &owners {
        let Some((first, by)) = list.first() else {
            continue;
        };
        for (p, r) in list.iter().skip(1) {
            if p != first {
                out.push(Conflict {
                    index: *index,
                    prefix: first.to_string(),
                    router: r.clone(),
                    other_prefix: p.to_string(),
                    kind: "index",
                    detail: format!(
                        "index {index} is {first} on {by} and {p} on {r}: traffic for one goes to the other"
                    ),
                });
            }
        }
        for (p, r) in list {
            match index_of.get(p) {
                Some((i, by)) if i != index => out.push(Conflict {
                    index: *index,
                    prefix: p.to_string(),
                    router: r.clone(),
                    other_prefix: p.to_string(),
                    kind: "prefix",
                    detail: format!("{p} has index {i} on {by} and {index} on {r}"),
                }),
                Some(_) => {}
                None => {
                    index_of.insert(*p, (*index, r.clone()));
                }
            }
        }
    }
    out
}

/// The index a loopback gets when none is given: its last octet when that
/// is free here and in the network and inside the SRGB (operators read it
/// back from the address), else the lowest free one from 1.
pub fn propose_index(
    prefix: Ipv4Net,
    srgb: LabelBlock,
    local: &[PrefixSid],
    db: &SrDb,
) -> Option<u32> {
    let mut used: HashSet<u32> = local
        .iter()
        .filter(|s| s.prefix != prefix)
        .map(|s| s.index)
        .collect();
    for n in db
        .nodes
        .iter()
        .filter(|n| Some(n.router_id) != db.router_id)
    {
        for p in &n.prefixes {
            if Ipv4Net::new(Ipv4Addr::from(p.prefix), p.plen).ok() == Some(prefix) {
                // Another router already announces this prefix (anycast):
                // take its index.
                return Some(p.sid);
            }
            used.insert(p.sid);
        }
    }
    let limit = srgb.size().min(MAX_INDEX + 1);
    let last = u32::from(prefix.addr().octets()[3]);
    if last > 0 && last < limit && !used.contains(&last) {
        return Some(last);
    }
    (1..limit).find(|i| !used.contains(i))
}

/// An interface whose MTU is too small for the labels.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MtuIssue {
    pub interface: String,
    pub mtu: u16,
    pub needed: u32,
}

/// What switching SR on (or changing it) does, before the commit.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct Preview {
    /// OSPF routes that start going by label: /32s other routers announce
    /// with a SID (`by_label`), and /32s that will once their router has a
    /// SID (`maybe`, when the SR database is not known yet).
    pub by_label: Vec<String>,
    pub maybe: Vec<String>,
    /// This router's SIDs and their label on a router with the same SRGB.
    pub own: Vec<(String, u32, u32)>,
    pub mtu: Vec<MtuIssue>,
    /// OSPF interfaces where the kernel does not take labeled packets.
    pub no_mpls_input: Vec<String>,
    pub conflicts: Vec<Conflict>,
    /// The LDP block narrowed to stay out of the SR blocks.
    pub ldp_block: Option<String>,
    /// Whether the change switches SR on or off (the forwarding changes:
    /// Safe Mode is suggested).
    pub switches: Option<&'static str>,
}

/// The preview of `cfg` (the candidate) against `running`, with the SR
/// database and routes read last (`None`: not known).
pub fn preview(
    cfg: &Config,
    running: &Config,
    db: Option<&SrDb>,
    routes: &[OspfRoute],
    labels: u32,
) -> Preview {
    let mut p = Preview::default();
    let now = active(&cfg.routing.ospf);
    let before = active(&running.routing.ospf);
    p.switches = match (before.is_some(), now.is_some()) {
        (false, true) => Some("on"),
        (true, false) => Some("off"),
        _ => None,
    };
    let Some(sr) = now else {
        return p;
    };
    let own: HashSet<Ipv4Net> = cfg
        .routing
        .ospf
        .prefix_sids
        .iter()
        .filter(|s| !s.disabled)
        .map(|s| {
            p.own.push((
                s.prefix.to_string(),
                s.index,
                sr.srgb.label(s.index).unwrap_or(0),
            ));
            s.prefix
        })
        .collect();
    let with_sid: HashSet<Ipv4Net> = db
        .map(|d| {
            d.nodes
                .iter()
                .filter(|n| Some(n.router_id) != d.router_id)
                .flat_map(|n| n.prefixes.iter())
                .filter_map(|x| Ipv4Net::new(Ipv4Addr::from(x.prefix), x.plen).ok())
                .collect()
        })
        .unwrap_or_default();
    for r in routes {
        let Ok(net) = r.prefix.parse::<Ipv4Net>() else {
            continue;
        };
        if net.prefix_len() != 32 || own.contains(&net) {
            continue;
        }
        if with_sid.contains(&net) {
            p.by_label.push(r.prefix.clone());
        } else if db.is_none_or(|d| d.nodes.is_empty()) {
            p.maybe.push(r.prefix.clone());
        }
    }
    let needed = cfg.routing.mpls.settings.payload_mtu + LABEL_BYTES * labels.max(SR_LABELS);
    let mut seen = HashSet::new();
    for b in bindings(cfg)
        .into_iter()
        .filter(|b| b.instance.name == sr.instance && !b.template.passive)
    {
        if !seen.insert(b.interface.clone()) {
            continue;
        }
        let Some(i) = cfg.interfaces.get(&b.interface) else {
            continue;
        };
        if matches!(i.kind, InterfaceKind::Loopback) {
            continue;
        }
        if u32::from(i.mtu) < needed {
            p.mtu.push(MtuIssue {
                interface: b.interface.to_string(),
                mtu: i.mtu,
                needed,
            });
        }
        if !cfg.routing.mpls.input_on(&b.interface) {
            p.no_mpls_input.push(b.interface.to_string());
        }
    }
    if let Some(d) = db {
        p.conflicts = conflicts(d, &cfg.routing.ospf.prefix_sids);
    }
    p.ldp_block = dynamic_block(cfg).map(|b| b.to_string());
    p
}

#[cfg(test)]
pub(crate) mod tests;
