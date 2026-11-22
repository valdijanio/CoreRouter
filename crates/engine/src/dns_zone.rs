//! Authoritative zones (G4.1c) as seen by the engine. The config is the
//! engine's (`/ip dns zone`, `cmd/dns_zone.rs`); what happens at run time
//! (secondaries transferred, NOTIFY sent) is the daemon's, which registers
//! a [`ZoneBackend`] here. Without a daemon (headless lab, WASM, tests)
//! nothing is registered: the zones are config only.

use std::sync::Arc;

use corerouter_model::dns_zone::ZoneStatus;

use crate::Session;

/// What the daemon's zone service offers. Never locks the session.
pub trait ZoneBackend: Send + Sync {
    /// The zones the daemon serves or transfers.
    fn status(&self) -> Vec<ZoneStatus>;
    /// A secondary's transferred copy as a zone file.
    fn file(&self, zone: &str) -> Option<String>;
    /// Check secondary `zone` against its primaries now.
    fn refresh(&self, zone: &str) -> Result<(), String>;
}

#[derive(Default)]
struct ZoneRuntime {
    backend: Option<Arc<dyn ZoneBackend>>,
}

impl Session {
    pub fn set_zone_backend(&mut self, backend: Arc<dyn ZoneBackend>) {
        if let Some(rt) = self.ext_mut::<ZoneRuntime>() {
            rt.backend = Some(backend);
        }
    }

    pub fn zone_backend(&self) -> Option<Arc<dyn ZoneBackend>> {
        self.ext::<ZoneRuntime>()?.backend.clone()
    }
}
