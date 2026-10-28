//! L2 — MPLS/LDP (G3.5): validation of `/mpls`, the FRR `ldpd` render, the
//! LDP-IGP sync lines for the IGP, and the forwarding-table view: each FEC
//! with its labels and, when it has no outgoing label, why.
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use std::fmt::Write as _;
use std::net::IpAddr;

use corerouter_hal::mpls::MplsRoute;
use corerouter_model::mpls::{
    Afi, FIRST_UNRESERVED, IMPLICIT_NULL, IPV4_EXPLICIT_NULL, IPV6_EXPLICIT_NULL, LABEL_BYTES,
    MAX_LABEL, MAX_PUSH, Mpls,
};
use corerouter_model::mpls_state::{LdpBinding, LdpState};
use corerouter_model::sealed::Sealed;
use corerouter_model::{Config, IfName, Issue};
use serde::Serialize;

/// Opens a sealed TCP MD5 key for the render (`None`: it cannot be opened).
pub type Opener<'a> = &'a dyn Fn(&Sealed) -> Option<String>;

/// Shortest and longest Hello timers FRR takes (seconds).
pub const TIMER_RANGE: (u16, u16) = (1, 65_535);

/// Validate this subsystem's part of the candidate.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    let m = &cfg.routing.mpls;
    let mut out = Vec::new();
    let (lo, hi) = m.settings.dynamic_label_range;
    if lo < FIRST_UNRESERVED || lo > hi || hi > MAX_LABEL {
        out.push(Issue::new(
            "routing.mpls.settings.dynamic_label_range",
            format!("{lo}-{hi}: must be within {FIRST_UNRESERVED}-{MAX_LABEL} (RFC 3032 §2.1: 0-15 are reserved), start ≤ end"),
        ));
    }
    if !(576..=65_535).contains(&m.settings.payload_mtu) {
        out.push(Issue::new(
            "routing.mpls.settings.payload_mtu",
            "must be 576..65535 bytes",
        ));
    }
    for name in m.interfaces.keys() {
        if name != corerouter_model::mpls::ALL
            && !name.parse::<IfName>().is_ok_and(|n| cfg.interfaces.contains_key(&n))
        {
            out.push(Issue::new(
                format!("routing.mpls.interfaces.{name}"),
                format!("no interface '{name}' (see interface.list)"),
            ));
        }
    }
    if let Some(l) = &m.ldp {
        let p = "routing.mpls.ldp";
        if l.lsr_id.is_unspecified() || l.lsr_id.is_broadcast() || l.lsr_id.is_multicast() {
            out.push(Issue::new(
                format!("{p}.lsr_id"),
                format!("{} is not a usable LSR id (use the loopback address)", l.lsr_id),
            ));
        }
        if l.afi.is_empty() {
            out.push(Issue::new(format!("{p}.afi"), "at least one of ip, ipv6"));
        }
        for v4 in [true, false] {
            if l.transport_addresses.iter().filter(|a| a.is_ipv4() == v4).count() > 1 {
                out.push(Issue::new(
                    format!("{p}.transport_addresses"),
                    "one transport address per family (RFC 5036 §2.5.2)",
                ));
            }
        }
        if l.runs(Afi::Ipv6) {
            match l.transport(Afi::Ipv6) {
                None => out.push(Issue::new(
                    format!("{p}.transport_addresses"),
                    "LDP over IPv6 needs an IPv6 transport address (RFC 7552 §6.1: a global one, e.g. the loopback's)",
                )),
                Some(IpAddr::V6(a)) if (a.segments()[0] & 0xffc0) == 0xfe80 || a.is_loopback() => out.push(Issue::new(
                    format!("{p}.transport_addresses"),
                    format!("{a}: the IPv6 transport address must be global unicast (RFC 7552 §6.1)"),
                )),
                _ => {}
            }
        }
        if l.igp_sync_holddown == Some(0) {
            out.push(Issue::new(
                format!("{p}.igp_sync_holddown"),
                "1..10000 seconds, or unset to wait for LDP as long as it takes",
            ));
        }
    }
    for (name, i) in &m.ldp_interfaces {
        let p = format!("routing.mpls.ldp_interfaces.{name}");
        if !cfg.interfaces.contains_key(name) {
            out.push(Issue::new(&p, format!("no interface '{name}' (see interface.list)")));
        }
        if i.hello_interval == 0 || i.hold_time == 0 || i.hello_interval >= i.hold_time {
            out.push(Issue::new(
                &p,
                format!(
                    "hello-interval {} must be under hold-time {} (RFC 5036 §3.5.2.1: Hellos at most every third of the hold time)",
                    i.hello_interval, i.hold_time
                ),
            ));
        }
        if let Some(l) = &m.ldp
            && let Some(a) = i.afi.iter().find(|a| !l.runs(**a))
        {
            out.push(Issue::new(
                &p,
                format!("afi {}: the LDP instance does not run it", a.name()),
            ));
        }
    }
    for (label, s) in &m.statics {
        let p = format!("routing.mpls.statics.{label}");
        if *label < FIRST_UNRESERVED || *label > MAX_LABEL {
            out.push(Issue::new(
                &p,
                format!("incoming label {label}: {FIRST_UNRESERVED}..{MAX_LABEL} (RFC 3032 §2.1)"),
            ));
        } else if (lo..=hi).contains(label) {
            out.push(Issue::new(
                &p,
                format!(
                    "label {label} is inside the dynamic range {lo}-{hi} that LDP hands out; \
                     shrink it (mpls.settings.set dynamic_label_range=16-99999) and use labels above"
                ),
            ));
        }
        if s.out_labels.len() > MAX_PUSH {
            out.push(Issue::new(&p, format!("at most {MAX_PUSH} outgoing labels")));
        }
        if let Some(bad) = s.out_labels.iter().find(|l| !out_label_ok(**l)) {
            out.push(Issue::new(
                &p,
                format!("outgoing label {bad}: use 0, 2 or {FIRST_UNRESERVED}..{MAX_LABEL} (an empty stack pops; 3 is implicit NULL, never on the wire)"),
            ));
        }
        if let Some(i) = &s.interface
            && !cfg.interfaces.contains_key(i)
        {
            out.push(Issue::new(&p, format!("no interface '{i}' (see interface.list)")));
        }
    }
    out
}

/// A label a packet may carry out (RFC 3032 §2.1; Linux refuses the rest).
pub fn out_label_ok(l: u32) -> bool {
    l == IPV4_EXPLICIT_NULL || l == IPV6_EXPLICIT_NULL || (FIRST_UNRESERVED..=MAX_LABEL).contains(&l)
}

fn afi_name(a: Afi) -> &'static str {
    match a {
        Afi::Ip => "ipv4",
        Afi::Ipv6 => "ipv6",
    }
}

/// FRR's `ldpd` configuration for `mpls` (empty without a running LDP),
/// plus zebra's dynamic label block when the range is not the default.
pub fn render_frr(mpls: &Mpls, open: Opener<'_>) -> Result<String, String> {
    let mut s = String::new();
    let (lo, hi) = mpls.settings.dynamic_label_range;
    if mpls.settings.dynamic_label_range != corerouter_model::mpls::MplsSettings::default().dynamic_label_range {
        // zebra's label manager hands LDP labels from this block only
        // (FRR 9.1+), so they never collide with `/mpls static`.
        let _ = writeln!(s, "mpls label dynamic-block {lo} {hi}");
    }
    let Some(l) = mpls.ldp_running() else {
        return Ok(s);
    };
    let _ = writeln!(s, "mpls ldp");
    let _ = writeln!(s, " router-id {}", l.lsr_id);
    if l.runs(Afi::Ip) && l.runs(Afi::Ipv6) && l.preferred_afi == Some(Afi::Ip) {
        // RFC 7552 §6.1.1: IPv6 is preferred unless configured otherwise.
        let _ = writeln!(s, " dual-stack transport-connection prefer ipv4");
    }
    for (id, n) in mpls.ldp_neighbors.iter().filter(|(_, n)| !n.disabled) {
        if let Some(key) = n.password.as_ref().filter(|k| !k.is_empty()) {
            let clear = open(key).ok_or_else(|| {
                format!("LDP neighbor {id}: its password cannot be opened (sealed on another router?)")
            })?;
            if clear.chars().any(|c| c.is_whitespace() || c.is_control()) || clear.len() > 80 {
                return Err(format!("LDP neighbor {id}: the password must be 1..80 characters without spaces"));
            }
            let _ = writeln!(s, " neighbor {id} password {clear}");
        }
        if let Some(h) = n.keepalive_hold {
            let _ = writeln!(s, " neighbor {id} session holdtime {h}");
        }
    }
    for afi in [Afi::Ip, Afi::Ipv6].into_iter().filter(|a| l.runs(*a)) {
        let _ = writeln!(s, " address-family {}", afi_name(afi));
        if let Some(t) = l.transport(afi) {
            let _ = writeln!(s, "  discovery transport-address {t}");
        }
        let targets: Vec<IpAddr> = mpls
            .ldp_neighbors
            .values()
            .filter(|n| !n.disabled)
            .filter_map(|n| n.targeted)
            .filter(|t| t.is_ipv4() == (afi == Afi::Ip))
            .collect();
        if !targets.is_empty() {
            let _ = writeln!(s, "  discovery targeted-hello accept");
        }
        if l.use_explicit_null {
            let _ = writeln!(s, "  label local advertise explicit-null");
        }
        // RFC 6720 for IPv4 (FRR's default is on); RFC 7552 §9 makes it
        // mandatory for IPv6, so there is nothing to turn off there.
        if afi == Afi::Ip && !l.gtsm {
            let _ = writeln!(s, "  ttl-security disable");
        }
        for t in targets {
            let _ = writeln!(s, "  neighbor {t} targeted");
        }
        for (name, i) in &mpls.ldp_interfaces {
            if i.disabled || !(i.afi.is_empty() || i.afi.contains(&afi)) {
                continue;
            }
            let _ = writeln!(s, "  interface {name}");
            if i.hello_interval != corerouter_model::mpls::DEFAULT_HELLO_INTERVAL {
                let _ = writeln!(s, "   discovery hello interval {}", i.hello_interval);
            }
            if i.hold_time != corerouter_model::mpls::DEFAULT_HOLD_TIME {
                let _ = writeln!(s, "   discovery hello holdtime {}", i.hold_time);
            }
        }
        let _ = writeln!(s, " exit-address-family");
    }
    Ok(s)
}

/// The lines LDP-IGP synchronization (RFC 5443) adds under `router ospf`:
/// the IGP keeps an interface at LSInfinity until LDP is up on it.
pub fn igp_sync_lines(mpls: &Mpls) -> Vec<String> {
    let Some(l) = mpls.ldp_running().filter(|l| l.igp_sync && l.runs(Afi::Ip)) else {
        return Vec::new();
    };
    match l.igp_sync_holddown {
        Some(h) => vec!["mpls ldp-sync".into(), format!("mpls ldp-sync holddown {h}")],
        None => vec!["mpls ldp-sync".into()],
    }
}

/// One line of `/mpls forwarding-table`: a FEC, its labels and the way out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FecRow {
    /// `None` for a static entry (it has no FEC).
    pub fec: Option<String>,
    pub in_label: Option<u32>,
    /// RouterOS text: `implicit-null (pop)`, `16 17`, or `-`.
    pub out_label: String,
    pub out_labels: Vec<u32>,
    pub nexthop: Option<IpAddr>,
    pub interface: Option<String>,
    pub peer: Option<String>,
    /// `ldp`, `static`, `bgp`, `other`.
    pub origin: &'static str,
    /// Installed in the kernel's label table.
    pub installed: bool,
    /// RFC 5443 on the way out: `achieved`, `waiting`, or `None` (no IGP
    /// sync there).
    pub igp_sync: Option<String>,
    /// Why there is no outgoing label (or what is wrong), in words.
    pub reason: Option<String>,
    /// An MTU warning on the way out.
    pub mtu: Option<String>,
}

/// Why `b` has no label to send with (`None`: it has one, or it ends here).
pub fn why_no_label(b: &LdpBinding, state: &LdpState) -> Option<String> {
    if b.in_use().is_some() {
        return None;
    }
    if matches!(b.local_label, Some(IMPLICIT_NULL | IPV4_EXPLICIT_NULL | IPV6_EXPLICIT_NULL)) {
        return Some("egress: the FEC is this router's own (connected or loopback); it advertises NULL and the LSP ends here".into());
    }
    if b.local_label.is_none() {
        return Some("no local label: the FEC is not an IGP, connected or static route here (FRR labels only those)".into());
    }
    if !state.neighbors.iter().any(|n| n.operational()) {
        return Some("no LDP neighbor is operational (see the Neighbors tab)".into());
    }
    if b.remote.is_empty() {
        return Some("no neighbor advertised a label for it (not in its IGP, or filtered there)".into());
    }
    let from: Vec<String> = b.remote.iter().map(|r| r.neighbor.to_string()).collect();
    Some(format!(
        "labels came from {} but none is the IGP next hop: the route leaves on a link without an LDP session (check LDP on that interface, or IGP sync)",
        from.join(", ")
    ))
}

/// The bytes a packet with `labels` labels needs, and the text of the
/// warning when the link's `mtu` is smaller (RFC 3032 §3: every label
/// adds 4 bytes; a full-size packet that does not fit is dropped or
/// fragmented).
pub fn mtu_warning(payload: u32, labels: usize, mtu: u32) -> Option<String> {
    // Popped (no label left): the packet leaves as plain IP.
    if labels == 0 {
        return None;
    }
    let n = u32::try_from(labels).unwrap_or(u32::MAX);
    let need = payload.saturating_add(LABEL_BYTES.saturating_mul(n));
    (mtu < need).then(|| {
        format!(
            "MTU {mtu} < {need}: a {payload}-byte IP packet with {n} label{} does not fit; raise the link MTU to {need}",
            if n == 1 { "" } else { "s" }
        )
    })
}

/// The forwarding table: LDP's FECs joined with the kernel's label table
/// (by incoming label), then the label entries no FEC explains (static
/// ones, other programs'). `mtu_of` gives a link's MTU.
pub fn forwarding_rows(
    mpls: &Mpls,
    state: Option<&LdpState>,
    kernel: &[MplsRoute],
    mtu_of: &dyn Fn(&str) -> Option<u32>,
) -> Vec<FecRow> {
    // The readers hand the table sorted by label: a binary search per FEC,
    // no map (a 100 k-entry map was a third of the time, **medido**).
    let sorted = kernel.windows(2).all(|w| w.first().map(|a| a.label) < w.get(1).map(|b| b.label));
    let owned: Vec<&MplsRoute>;
    let by_label: Vec<&MplsRoute> = if sorted {
        kernel.iter().collect()
    } else {
        let mut v: Vec<&MplsRoute> = kernel.iter().collect();
        v.sort_by_key(|r| r.label);
        owned = v;
        owned
    };
    let find = |l: u32| by_label.binary_search_by_key(&l, |r| r.label).ok().and_then(|i| by_label.get(i).copied());
    let payload = mpls.settings.payload_mtu;
    let sync_of = |ifname: &Option<String>| -> Option<String> {
        let st = state?;
        let name = ifname.as_deref()?;
        st.igp_sync.iter().find(|s| s.interface == name).map(|s| {
            if s.achieved { "achieved".to_owned() } else { "waiting".to_owned() }
        })
    };
    let mtu_note = |ifname: &Option<String>, labels: usize| -> Option<String> {
        mtu_warning(payload, labels, mtu_of(ifname.as_deref()?)?)
    };
    let mut rows = Vec::with_capacity(kernel.len() + state.map_or(0, |s| s.bindings.len()));
    let mut used = std::collections::HashSet::with_capacity(state.map_or(0, |s| s.bindings.len()));
    if let Some(st) = state {
        for b in &st.bindings {
            let local = b.local_label.filter(|l| *l >= FIRST_UNRESERVED);
            let k = local.and_then(find);
            if let Some(l) = local {
                used.insert(l);
            }
            let nh = k.and_then(|r| r.nexthops.first());
            let remote = b.in_use();
            let out_labels: Vec<u32> = match (nh, remote) {
                (Some(n), _) => n.out_labels.clone(),
                (None, Some(r)) if r.label != IMPLICIT_NULL => vec![r.label],
                _ => Vec::new(),
            };
            let has_out = remote.is_some();
            let interface = nh.and_then(|n| n.interface.as_ref()).map(|i| i.to_string());
            let reason = why_no_label(b, st).or_else(|| {
                (has_out && local.is_some() && k.is_none())
                    .then(|| "not in the kernel's label table yet (zebra has not installed it)".to_owned())
            });
            rows.push(FecRow {
                fec: Some(b.prefix.to_string()),
                in_label: b.local_label,
                out_label: if has_out {
                    corerouter_model::mpls::stack_text(&out_labels)
                } else {
                    "-".to_owned()
                },
                out_labels: out_labels.clone(),
                nexthop: nh.and_then(|n| n.via),
                igp_sync: sync_of(&interface),
                mtu: if has_out { mtu_note(&interface, out_labels.len()) } else { None },
                interface,
                peer: remote.map(|r| r.neighbor.to_string()),
                origin: "ldp",
                installed: k.is_some(),
                reason,
            });
        }
    }
    for r in kernel.iter().filter(|r| !used.contains(&r.label)) {
        for nh in &r.nexthops {
            let interface = nh.interface.as_ref().map(|i| i.to_string());
            rows.push(FecRow {
                fec: None,
                in_label: Some(r.label),
                out_label: corerouter_model::mpls::stack_text(&nh.out_labels),
                out_labels: nh.out_labels.clone(),
                nexthop: nh.via,
                igp_sync: sync_of(&interface),
                mtu: mtu_note(&interface, nh.out_labels.len()),
                interface,
                peer: None,
                origin: r.origin.name(),
                installed: true,
                reason: None,
            });
        }
    }
    rows
}

/// The forwarding table ready to page: the lines, their counts and each
/// line's search text (lowercase FEC, labels, next hop, interface), built
/// once per read of the table so a page and a search allocate nothing per
/// line (a search that formatted each line took 25 ms for 100 k,
/// **medido**).
#[derive(Debug, Default)]
pub struct Lines {
    pub rows: Vec<FecRow>,
    pub hay: Vec<String>,
    pub counts: Counts,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub rows: usize,
    pub fecs: usize,
    pub labeled: usize,
    pub unlabeled: usize,
    pub egress: usize,
    #[serde(rename = "static")]
    pub statics: usize,
    pub mtu_warnings: usize,
    /// Entries of the kernel's label table.
    pub labels: usize,
}

impl FecRow {
    /// A FEC LDP gives no outgoing label (the "without label" filter).
    pub fn unlabeled(&self) -> bool {
        self.fec.is_some() && self.out_label == "-"
    }
}

/// [`forwarding_rows`] with the counts and the search texts.
pub fn lines(
    mpls: &Mpls,
    state: Option<&LdpState>,
    kernel: &[MplsRoute],
    mtu_of: &dyn Fn(&str) -> Option<u32>,
) -> Lines {
    let rows = forwarding_rows(mpls, state, kernel, mtu_of);
    let mut c = Counts {
        rows: rows.len(),
        labels: kernel.len(),
        ..Counts::default()
    };
    let mut hay = Vec::with_capacity(rows.len());
    for r in &rows {
        c.fecs += usize::from(r.fec.is_some());
        c.labeled += usize::from(r.fec.is_some() && r.out_label != "-");
        c.unlabeled += usize::from(r.unlabeled());
        c.egress += usize::from(r.reason.as_deref().is_some_and(|x| x.starts_with("egress")));
        c.statics += usize::from(r.origin == "static");
        c.mtu_warnings += usize::from(r.mtu.is_some());
        let mut h = String::with_capacity(48);
        for part in [r.fec.as_deref(), r.interface.as_deref()].into_iter().flatten() {
            h.push_str(part);
            h.push(' ');
        }
        if let Some(l) = r.in_label {
            let _ = write!(h, " {l} ");
        }
        h.push_str(&r.out_label);
        if let Some(n) = r.nexthop {
            let _ = write!(h, " {n}");
        }
        h.push(' ');
        hay.push(h.to_ascii_lowercase());
    }
    Lines { rows, hay, counts: c }
}

#[cfg(test)]
mod tests;
