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
}

/// LDP as the routing service last read it.
#[derive(Debug, Default, Clone)]
pub struct LdpStatus {
    /// `None`: no routing daemon reported (the lab, no `--frr`).
    pub state: Option<LdpState>,
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
                l.state = st;
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
    if service {
        if let Some(k) = s.ext_mut::<KernelLabels>() {
            k.wanted_until = now.saturating_add(WANTED_SECS);
            let note = match (&k.error, k.updated) {
                (Some(e), _) => Some(e.clone()),
                (None, None) => Some("reading the label table…".to_owned()),
                (None, Some(_)) => None,
            };
            return (k.routes.clone(), note);
        }
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
