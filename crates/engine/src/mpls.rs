//! MPLS runtime state (G3.5): the kernel's label table and LDP's state,
//! kept in the session (`ext`) by the daemon's threads, read by
//! `mpls.forwarding-table.page` and the LDP lists.
//!
//! The label table of a full LSR is 10⁵ entries: the daemon's `mpls`
//! service dumps it on its own thread, only while someone looks (a page
//! asked in the last [`WANTED_SECS`]), and stores the result here under the
//! lock (a pointer swap). Without that service (the virtual lab, a CLI
//! without a daemon) the page reads the backend directly: the lab's table
//! is in memory.

use std::sync::Arc;

use corerouter_hal::HalError;
use corerouter_hal::mpls::{MplsReader, MplsRoute};
use corerouter_model::mpls_state::LdpState;

use crate::Session;

/// A page keeps the service dumping for this long after it was asked.
pub const WANTED_SECS: u64 = 10;

/// The label table as last read.
#[derive(Debug, Default)]
pub struct KernelLabels {
    pub routes: Arc<Vec<MplsRoute>>,
    /// Session clock of the read.
    pub updated: Option<u64>,
    pub error: Option<String>,
    /// A service keeps it: never read under the lock.
    pub service: bool,
    /// Session clock until which the service should keep reading.
    pub wanted_until: u64,
    /// The service's lines of `routes` (built on its thread).
    pub lines: Option<Arc<corerouter_proto_mpls::Lines>>,
}

/// LDP as the routing service last read it.
#[derive(Debug, Default, Clone)]
pub struct LdpStatus {
    /// `None`: no routing daemon reported (the lab, no `--frr`). Shared:
    /// a list copies the pointer, not 10⁴ bindings.
    pub state: Option<Arc<LdpState>>,
    pub updated: Option<u64>,
    pub error: Option<String>,
}

/// A reader for the service's thread (taken once, under the lock).
pub fn reader(s: &mut Session) -> Result<Box<dyn MplsReader>, HalError> {
    let r = s.hal().mpls_reader()?;
    if let Some(k) = s.ext_mut::<KernelLabels>() {
        k.service = true;
    }
    Ok(r)
}

/// Whether a page asked recently (the service dumps only then).
pub fn wanted(s: &Session) -> bool {
    let now = s.hal_now().unwrap_or(0);
    s.ext::<KernelLabels>().is_some_and(|k| k.wanted_until >= now)
}

/// Store a read of the service.
pub fn set_kernel(s: &mut Session, read: Result<Vec<MplsRoute>, String>) {
    let now = s.hal_now();
    if let Some(k) = s.ext_mut::<KernelLabels>() {
        match read {
            Ok(r) => {
                k.routes = Arc::new(r);
                k.error = None;
            }
            Err(e) => k.error = Some(e),
        }
        k.updated = now;
    }
}

/// Store LDP's state (the routing service, every tick).
pub fn set_ldp(s: &mut Session, read: Result<Option<LdpState>, String>) {
    let now = s.hal_now();
    if let Some(l) = s.ext_mut::<LdpStatus>() {
        match read {
            Ok(st) => {
                l.state = st.map(Arc::new);
                l.error = None;
            }
            Err(e) => l.error = Some(e),
        }
        l.updated = now;
    }
}

/// The label table for a page: the service's copy (asking it to go on
/// reading), or a direct read without a service.
pub fn labels(s: &mut Session) -> (Arc<Vec<MplsRoute>>, Option<String>) {
    let now = s.hal_now().unwrap_or(0);
    let service = s.ext::<KernelLabels>().is_some_and(|k| k.service);
    if service && let Some(k) = s.ext_mut::<KernelLabels>() {
        k.wanted_until = now.saturating_add(WANTED_SECS);
        let note = match (&k.error, k.updated) {
            (Some(e), _) => Some(e.clone()),
            (None, None) => Some("reading the label table…".to_owned()),
            (None, Some(_)) => None,
        };
        return (k.routes.clone(), note);
    }
    match s.hal_mut().mpls_routes() {
        Ok(r) => (Arc::new(r), None),
        Err(e) => (Arc::new(Vec::new()), Some(e.to_string())),
    }
}

/// LDP's state now (a copy of what the routing service stored).
pub fn ldp(s: &Session) -> LdpStatus {
    s.ext::<LdpStatus>().cloned().unwrap_or_default()
}

/// G3.5: the LDP labels of route rows (`ip.route.list`/`page`): a row
/// whose `dst_address` is a FEC with labels gets `mpls_in` (the label this
/// router gave it) and `mpls_out` (the next hop's, RouterOS text). One
/// pass over the bindings per call, then a lookup per row.
pub fn annotate_routes(s: &Session, rows: &mut [serde_json::Value]) {
    annotate_rows(ldp_state(s).as_deref(), rows);
}

/// The LDP state the routing service stored: a pointer, read under the
/// lock; [`annotate_rows`] runs outside it (G0.31b).
pub fn ldp_state(s: &Session) -> Option<Arc<LdpState>> {
    s.ext::<LdpStatus>().and_then(|l| l.state.clone())
}

/// [`annotate_routes`] with the state already taken.
pub fn annotate_rows(st: Option<&LdpState>, rows: &mut [serde_json::Value]) {
    let Some(st) = st else {
        return;
    };
    if st.bindings.is_empty() {
        return;
    }
    let by: std::collections::HashMap<ipnet::IpNet, &corerouter_model::mpls_state::LdpBinding> =
        st.bindings.iter().map(|b| (b.prefix, b)).collect();
    for r in rows.iter_mut() {
        let Some(dst) = r.get("dst_address").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(b) = dst.parse::<ipnet::IpNet>().ok().and_then(|d| by.get(&d)) else {
            continue;
        };
        let out = b.in_use().map(|x| {
            if x.label == corerouter_model::mpls::IMPLICIT_NULL {
                "implicit-null (pop)".to_owned()
            } else {
                corerouter_model::mpls::label_text(x.label)
            }
        });
        if let Some(o) = r.as_object_mut() {
            o.insert("mpls_in".into(), serde_json::json!(b.local_label));
            o.insert("mpls_out".into(), serde_json::json!(out));
        }
    }
}

/// The forwarding table's lines (`corerouter_proto_mpls::Lines`):
/// building them for 100 000 labels takes ~22 ms (**medido**,
/// `benches/forwarding.rs`), so they are built once per input.
/// - With the `mpls` service, it builds them on its thread after each read
///   ([`build_lines`], off the lock) and the page uses them as they are
///   (at most one tick old: the view is a 2 s sample anyway).
/// - Without it (the lab), here, kept while the inputs stay the same; the
///   cache holds the inputs it was built from, so a new table is never
///   taken for the old one.
#[derive(Default)]
struct LinesCache {
    kernel: Option<Arc<Vec<MplsRoute>>>,
    ldp: Option<Arc<LdpState>>,
    revision: u32,
    lines: Arc<corerouter_proto_mpls::Lines>,
}

/// What [`build_lines`] needs, copied under the lock (pointers and the
/// copy-on-write config).
pub struct LineInputs {
    cfg: corerouter_model::Config,
    ldp: Option<Arc<LdpState>>,
}

pub fn line_inputs(s: &Session) -> LineInputs {
    LineInputs {
        cfg: s.store().running().clone(),
        ldp: s.ext::<LdpStatus>().and_then(|l| l.state.clone()),
    }
}

/// The lines for `kernel` (no lock needed).
pub fn build_lines(i: &LineInputs, kernel: &[MplsRoute]) -> corerouter_proto_mpls::Lines {
    let mtu_of = |name: &str| -> Option<u32> {
        let n: corerouter_model::IfName = name.parse().ok()?;
        i.cfg.interfaces.get(&n).map(|x| u32::from(x.mtu))
    };
    corerouter_proto_mpls::lines(&i.cfg.routing.mpls, i.ldp.as_deref(), kernel, &mtu_of)
}

/// The service's read with its lines.
pub fn set_kernel_lines(s: &mut Session, routes: Vec<MplsRoute>, lines: corerouter_proto_mpls::Lines) {
    let now = s.hal_now();
    if let Some(k) = s.ext_mut::<KernelLabels>() {
        k.routes = Arc::new(routes);
        k.lines = Some(Arc::new(lines));
        k.error = None;
        k.updated = now;
    }
}

/// The lines for a page (see [`LinesCache`]).
pub fn lines(s: &mut Session, kernel: &Arc<Vec<MplsRoute>>) -> Arc<corerouter_proto_mpls::Lines> {
    if let Some(l) = s.ext::<KernelLabels>().filter(|k| k.service).and_then(|k| k.lines.clone()) {
        return l;
    }
    let ldp = s.ext::<LdpStatus>().and_then(|l| l.state.clone());
    let revision = s.store().current_revision();
    if let Some(c) = s.ext::<LinesCache>()
        && c.kernel.as_ref().is_some_and(|k| Arc::ptr_eq(k, kernel))
        && match (&c.ldp, &ldp) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
        && c.revision == revision
    {
        return c.lines.clone();
    }
    let lines = Arc::new(build_lines(&line_inputs(s), kernel));
    if let Some(c) = s.ext_mut::<LinesCache>() {
        c.kernel = Some(kernel.clone());
        c.ldp = ldp;
        c.revision = revision;
        c.lines = lines.clone();
    }
    lines
}
