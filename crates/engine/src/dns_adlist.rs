//! The adlist loader (G4.1d) as the engine sees it. The daemon downloads
//! the lists and holds their names (threads, sockets, memory the session
//! must not hold under its lock) and registers itself here with
//! [`Session::set_adlist_backend`]; `ip.dns.adlist.print` reads the counts
//! and `ip.dns.adlist.reload` asks for a new download. Without a daemon
//! (headless lab, WASM, tests) nothing is loaded and the counts stay empty.

use std::sync::Arc;

use corerouter_model::ItemId;
use serde::Serialize;

use crate::Session;

/// How one list is doing, as the loader knows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdlistStatus {
    #[serde(skip)]
    pub id: Option<ItemId>,
    /// `loading`, `loaded`, `failed` (the last good names are kept) or
    /// `waiting` (not tried yet).
    pub state: &'static str,
    /// Names loaded from the list (RouterOS `name-count`).
    pub name_count: u64,
    /// Queries it blocked since it loaded (RouterOS `match-count`).
    pub match_count: u64,
    /// Lines that held no usable name.
    pub skipped: u64,
    /// Seconds since the last successful load.
    pub loaded_secs_ago: Option<u64>,
    /// Why the last attempt failed.
    pub error: Option<String>,
}

/// What the daemon's loader offers. Implementations never lock the session.
pub trait AdlistBackend: Send + Sync {
    fn status(&self) -> Vec<AdlistStatus>;
    /// Download `id` again (every list with `None`), in the background.
    fn reload(&self, id: Option<ItemId>);
}

#[derive(Default)]
struct AdlistRuntime {
    backend: Option<Arc<dyn AdlistBackend>>,
}

impl Session {
    pub fn set_adlist_backend(&mut self, backend: Arc<dyn AdlistBackend>) {
        if let Some(rt) = self.ext_mut::<AdlistRuntime>() {
            rt.backend = Some(backend);
        }
    }

    pub fn adlist_backend(&self) -> Option<Arc<dyn AdlistBackend>> {
        self.ext::<AdlistRuntime>()?.backend.clone()
    }
}
