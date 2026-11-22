//! The egress / transit side of LSP ping (RFC 8029 §4.4, §4.5): what an
//! LSR answers to an MPLS echo request, without I/O.
//!
//! The request comes from the data plane ([`Heard`]: the frame was copied
//! to a packet socket because its destination is in 127/8 or its label TTL
//! expired); what the LSR knows comes from an [`LsrView`] (its label table,
//! the routes of the FECs, its addresses). The same code answers for the
//! Linux backend and for every hop of the lab's simulated LSPs.
//!
//! Only LDP and generic (static) prefix FECs and the Nil FEC are checked;
//! any other FEC type answers "no mapping" at its depth.

use std::net::{IpAddr, SocketAddr};

use corerouter_model::IfName;
use ipnet::IpNet;

use super::wire::{
    self, Ddmap, DsAddress, DsLabel, Echo, Fec, IfLabelStack, LABEL_EXPLICIT_NULL_V4,
    LABEL_EXPLICIT_NULL_V6, LABEL_IMPLICIT_NULL, LABEL_ROUTER_ALERT, code,
};
use crate::mpls::{MplsNexthop, MplsRoute, Origin};
use crate::probe::MplsLabel;

/// A request as the data plane delivered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    /// Interface-I: where it came in.
    pub interface: IfName,
    /// Stack-R: the labels it came with, top first (empty: unlabeled).
    pub stack: Vec<MplsLabel>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// The UDP payload.
    pub payload: Vec<u8>,
}

/// What the LSR knows, read by the responder. Implementations cache: a
/// request costs a few lookups, never a dump of the label table.
pub trait LsrView {
    /// The Incoming Label Map entry of `label`.
    fn label_entry(&self, label: u32) -> Option<MplsRoute>;
    /// How this LSR forwards the FEC `prefix` (its FTN: next hops with the
    /// labels pushed). `None`: no route for it.
    fn fec_route(&self, prefix: IpNet) -> Option<Vec<MplsNexthop>>;
    /// Whether `prefix` is one of this LSR's own addresses (it is the
    /// egress of the FEC).
    fn is_local(&self, prefix: IpNet) -> bool;
    /// The addresses of `interface`.
    fn interface_addrs(&self, interface: &IfName) -> Vec<IpAddr>;
    /// The MTU of `interface`, when known.
    fn mtu(&self, interface: &IfName) -> Option<u16>;
    /// A routable address of this LSR to answer from (`None`: the kernel
    /// picks one).
    fn source_for(&self, to: IpAddr) -> Option<IpAddr> {
        let _ = to;
        None
    }
}

/// What to do with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Send `payload` from UDP port 3503 to `to` (IP TTL 255, §4.5).
    Reply {
        to: SocketAddr,
        from: Option<IpAddr>,
        tos: Option<u8>,
        payload: Vec<u8>,
        /// For the log and the counters.
        return_code: u8,
    },
    /// Nothing is sent; why (for the counters).
    Drop(&'static str),
}

/// Largest reply, whatever the request asked (a copied Pad TLV
/// included): the responder must never answer with more than it got,
/// plus the mappings it adds.
pub const MAX_REPLY: usize = 1500;

fn is_reserved(label: u32) -> bool {
    label < 16
}

/// Pop-and-continue labels (§4.4 step 4): explicit null and router alert.
fn pops_and_continues(label: u32) -> bool {
    matches!(
        label,
        LABEL_EXPLICIT_NULL_V4 | LABEL_EXPLICIT_NULL_V6 | LABEL_ROUTER_ALERT
    )
}

fn protocol(origin: Origin) -> u8 {
    match origin {
        Origin::Static => wire::PROTO_STATIC,
        Origin::Ldp => wire::PROTO_LDP,
        Origin::Bgp => wire::PROTO_BGP,
        Origin::Other => wire::PROTO_UNKNOWN,
    }
}

/// The DDMAP of one way out of a label entry (§3.4): the next router, the
/// labels it will see (implicit null when popped).
pub fn ddmap_of(nh: &MplsNexthop, origin: Origin, mtu: Option<u16>, v6: bool) -> Ddmap {
    let address = nh
        .via
        .map_or_else(|| DsAddress::unknown(v6), DsAddress::numbered);
    let proto = protocol(origin);
    let mut labels: Vec<DsLabel> = nh
        .out_labels
        .iter()
        .map(|l| DsLabel {
            label: *l,
            tc: 0,
            bottom: false,
            protocol: proto,
        })
        .collect();
    if labels.is_empty() {
        labels.push(DsLabel {
            label: LABEL_IMPLICIT_NULL,
            tc: 0,
            bottom: false,
            protocol: proto,
        });
    }
    if let Some(last) = labels.last_mut() {
        last.bottom = true;
    }
    Ddmap {
        mtu: mtu.unwrap_or(0),
        address,
        flags: 0,
        return_code: 0,
        return_subcode: 0,
        labels,
        other: Vec::new(),
    }
}

/// Does the sender's DDMAP (what it expects us to receive) match what we
/// received (§4.4 step 4, step 5)? Implicit nulls never reach the wire,
/// so they are left out of the comparison; TC, S and protocol are
/// informational (§3.4.1.2 "MAY choose to ignore").
fn ddmap_matches(d: &Ddmap, heard: &Heard, addrs: &[IpAddr]) -> bool {
    if d.address.is_all_routers() {
        return true;
    }
    if !d.address.is_unknown() {
        let iface_ok = match d.address {
            DsAddress::V4 { .. } | DsAddress::V6 { .. } => {
                d.address.iface().is_some_and(|a| addrs.contains(&a))
                    || d.address.addr().is_some_and(|a| addrs.contains(&a))
            }
            // An unnumbered link: the index is the upstream's; the router
            // id is ours if it is any of our addresses (not checked here).
            _ => true,
        };
        if !iface_ok {
            return false;
        }
    }
    let expected: Vec<u32> = d
        .labels
        .iter()
        .map(|l| l.label)
        .filter(|l| *l != LABEL_IMPLICIT_NULL)
        .collect();
    let got: Vec<u32> = heard.stack.iter().map(|l| l.label).collect();
    expected == got
}

fn if_label_stack(heard: &Heard, addrs: &[IpAddr], v6: bool) -> IfLabelStack {
    let address = addrs
        .iter()
        .find(|a| a.is_ipv6() == v6)
        .map_or_else(|| DsAddress::unknown(v6), |a| DsAddress::numbered(*a));
    IfLabelStack {
        address,
        stack: heard.stack.clone(),
    }
}

/// §4.4.1 for one FEC at a transit LSR that switched `label` with
/// `entry`: `None` if it checks out, else the FEC return code.
fn transit_fec_check(fec: &Fec, label: u32, entry: &MplsRoute, view: &dyn LsrView) -> Option<u8> {
    let prefix = match fec {
        // §4.4.1 step 2: a Nil FEC matches explicit null / router alert only.
        Fec::Nil { .. } => {
            return (!pops_and_continues(label)).then_some(code::WRONG_LABEL);
        }
        f => match f.prefix() {
            Some(p) => p,
            None => return Some(code::NO_MAPPING),
        },
    };
    // Step 3: how this LSR switches traffic of the FEC.
    let Some(route) = view.fec_route(prefix) else {
        return Some(code::NO_MAPPING);
    };
    if route.iter().all(|nh| nh.out_labels.is_empty()) && route.iter().all(|nh| nh.via.is_none()) {
        return Some(code::NO_MAPPING);
    }
    // Step 4: the label must be the one this LSR bound to the FEC. The
    // kernel does not keep the binding itself, but zebra installs both
    // from it: the label's entry and the FEC's route leave by the same
    // next hops with the same labels. A label switched elsewhere is
    // someone else's mapping.
    let same = |a: &MplsNexthop| {
        route
            .iter()
            .any(|b| a.via == b.via && a.out_labels == b.out_labels)
    };
    if !entry.nexthops.iter().any(same) {
        return Some(code::WRONG_LABEL);
    }
    None
}

/// The answer to one request. `now` is the NTP time it was received.
pub fn respond(heard: &Heard, view: &dyn LsrView, now: (u32, u32)) -> Verdict {
    if heard.dst_port != wire::PORT {
        return Verdict::Drop("not port 3503");
    }
    // RFC 8029 §2.1: 127/8 (IPv4); RFC 9570 §4: ::1 or ::ffff:127.0.0.0/104.
    let dst_ok = match heard.dst {
        IpAddr::V4(a) => a.is_loopback(),
        IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    };
    // A labeled request whose TTL expired here may carry any destination
    // only if it is in that range too: anything else is user traffic.
    if !dst_ok {
        return Verdict::Drop("destination outside 127/8");
    }
    if heard.src_port == 0 || !unicast(heard.src) {
        return Verdict::Drop("source not a unicast address");
    }
    let to = SocketAddr::new(heard.src, heard.src_port);
    let v6 = heard.src.is_ipv6();
    let Some((handle, seq)) = wire::ids(&heard.payload) else {
        return Verdict::Drop("shorter than the header");
    };
    let req = match wire::parse(&heard.payload) {
        Ok(r) => r,
        Err(wire::WireError::Short) => return Verdict::Drop("shorter than the header"),
        // §4.4 step 1: malformed → code 1, with handle, sequence and
        // timestamp copied.
        Err(_) => {
            let mut e = Echo {
                msg_type: wire::MSG_REPLY,
                reply_mode: wire::REPLY_UDP,
                return_code: code::MALFORMED,
                handle,
                seq,
                received: now,
                ..Echo::default()
            };
            if let (Some(a), Some(b)) = (
                heard
                    .payload
                    .get(16..20)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok()),
                heard
                    .payload
                    .get(20..24)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok()),
            ) {
                e.sent = (u32::from_be_bytes(a), u32::from_be_bytes(b));
            }
            return reply(to, view, None, e);
        }
    };
    if req.msg_type != wire::MSG_REQUEST {
        return Verdict::Drop("not an echo request");
    }
    match req.reply_mode {
        wire::REPLY_UDP | wire::REPLY_UDP_ROUTER_ALERT => {}
        wire::REPLY_NONE => return Verdict::Drop("reply mode: do not reply"),
        _ => return Verdict::Drop("reply mode not supported"),
    }
    // §3: T flag: answer only where the TTL expired.
    if req.flags & wire::FLAG_TTL_EXPIRED_ONLY != 0
        && heard.stack.first().is_some_and(|l| l.ttl > 1)
    {
        return Verdict::Drop("T flag and the TTL did not expire");
    }
    let mut out = Echo {
        msg_type: wire::MSG_REPLY,
        reply_mode: req.reply_mode,
        handle: req.handle,
        seq: req.seq,
        sent: req.sent,
        received: now,
        ..Echo::default()
    };
    // §3.5: Pad TLV, first octet 2: copy it.
    if let Some(pad) = &req.pad
        && pad.first() == Some(&2)
        && heard.payload.len() <= MAX_REPLY
    {
        out.pad = Some(pad.clone());
    }
    if !req.unknown.is_empty() {
        out.return_code = code::TLV_NOT_UNDERSTOOD;
        out.errored = Some(req.unknown.clone());
        return reply(to, view, req.reply_tos, out);
    }
    let Some(fecs) = req.fec_stack.as_ref().filter(|f| !f.is_empty()) else {
        // §4.3: "An MPLS echo request MUST have a FEC Stack TLV."
        out.return_code = code::MALFORMED;
        return reply(to, view, req.reply_tos, out);
    };
    let addrs = view.interface_addrs(&heard.interface);
    let ddmap = req.ddmaps.first();
    let wants_if_stack = ddmap.is_some_and(|d| d.flags & wire::DS_FLAG_IF_LABEL_STACK != 0);
    let (rc, rsc) = classify(heard, &req, fecs, view, &addrs, &mut out, v6);
    out.return_code = rc;
    out.return_subcode = rsc;
    if wants_if_stack && out.if_label_stack.is_none() {
        out.if_label_stack = Some(if_label_stack(heard, &addrs, v6));
    }
    reply(to, view, req.reply_tos, out)
}

/// The FEC at depth `d` (bottom = 1) of a stack of `fecs`.
fn fec_at(fecs: &[Fec], d: usize) -> Option<&Fec> {
    fecs.len().checked_sub(d).and_then(|i| fecs.get(i))
}

/// The return code and subcode (§4.4 steps 3–6), filling `out`'s DDMAPs
/// and Interface and Label Stack.
fn classify(
    heard: &Heard,
    req: &Echo,
    fecs: &[Fec],
    view: &dyn LsrView,
    addrs: &[IpAddr],
    out: &mut Echo,
    v6: bool,
) -> (u8, u8) {
    let depth_byte = |d: usize| u8::try_from(d).unwrap_or(u8::MAX);
    let ddmap = req.ddmaps.first();
    // Step 3: from the top (depth = number of labels) down.
    let mut depth = heard.stack.len();
    while depth > 0 {
        let Some(label) = heard.stack.get(heard.stack.len() - depth).map(|l| l.label) else {
            break;
        };
        if pops_and_continues(label) {
            depth -= 1;
            continue;
        }
        let entry = if is_reserved(label) {
            None
        } else {
            view.label_entry(label)
        };
        let Some(entry) = entry else {
            return (code::NO_LABEL_ENTRY, depth_byte(depth));
        };
        // Step 4: swap, or pop and switch on the popped label.
        let mut rc = code::LABEL_SWITCHED;
        if let Some(d) = ddmap {
            if d.address.is_unknown() {
                rc = code::UPSTREAM_IF_UNKNOWN;
                out.if_label_stack = Some(if_label_stack(heard, addrs, v6));
            } else if !ddmap_matches(d, heard, addrs) {
                out.if_label_stack = Some(if_label_stack(heard, addrs, v6));
                return (code::DS_MISMATCH, depth_byte(depth));
            }
            for nh in entry.nexthops.iter().take(16) {
                let mtu = nh.interface.as_ref().and_then(|i| view.mtu(i));
                out.ddmaps.push(ddmap_of(nh, entry.origin, mtu, v6));
            }
        }
        // §4.4 step 4: the FEC is checked only against a DDMAP that is not
        // the all-routers one (this LSR always checks then, as if
        // "configured to perform FEC checking by default").
        if rc == code::LABEL_SWITCHED
            && let Some(d) = ddmap.filter(|d| !d.address.is_all_routers())
        {
            // FEC-stack-depth from Stack-D: walk the downstream labels
            // from the bottom, implicit nulls not counted as labels. Past
            // the end of Stack-D every step counts, so it ends after at
            // most len + depth steps.
            let mut fec_depth = 0usize;
            let mut i = depth;
            while i > 0 {
                fec_depth += 1;
                let at = d.labels.len().checked_sub(fec_depth);
                let l = at.and_then(|a| d.labels.get(a)).map(|l| l.label);
                if l != Some(LABEL_IMPLICIT_NULL) {
                    i -= 1;
                }
            }
            if fec_depth <= fecs.len()
                && fec_depth <= fecs.len()
                && !matches!(fecs.first(), Some(Fec::Nil { .. }))
                && let Some(fec) = fec_at(fecs, fec_depth)
                && let Some(fc) = transit_fec_check(fec, label, &entry, view)
            {
                return (fc, depth_byte(fec_depth));
            }
        }
        return (rc, depth_byte(depth));
    }
    // Step 5: egress (every label popped or none at all).
    if let Some(d) = ddmap
        && !d.address.is_unknown()
        && !ddmap_matches(d, heard, addrs)
    {
        out.if_label_stack = Some(if_label_stack(heard, addrs, v6));
        return (code::DS_MISMATCH, 0);
    }
    // Step 6: egress FEC validation, from the bottom FEC.
    if matches!(fecs.first(), Some(Fec::Nil { .. })) {
        return (code::EGRESS, 1);
    }
    for d in 1..=fecs.len() {
        let Some(fec) = fec_at(fecs, d) else { break };
        match fec {
            Fec::Nil { .. } => continue,
            f => match f.prefix() {
                Some(p) if view.is_local(p) => return (code::EGRESS, depth_byte(d)),
                _ => return (code::NO_MAPPING, depth_byte(d)),
            },
        }
    }
    (code::EGRESS, 1)
}

fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_broadcast()
                || a.octets().first() == Some(&0))
        }
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_loopback() || a.is_multicast()),
    }
}

fn reply(to: SocketAddr, view: &dyn LsrView, tos: Option<u8>, mut e: Echo) -> Verdict {
    let mut payload = wire::encode(&e);
    if payload.len() > MAX_REPLY {
        e.pad = None;
        e.ddmaps.truncate(4);
        payload = wire::encode(&e);
    }
    Verdict::Reply {
        to,
        from: view.source_for(to.ip()),
        tos,
        return_code: e.return_code,
        payload,
    }
}

#[cfg(test)]
mod tests;
