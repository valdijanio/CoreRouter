//! The vendor table in use (G1.27d): the one built into the program
//! (`corerouter_model::oui::BUILTIN`), or a newer one the router
//! downloaded (`ip.arp.vendors.update`), which wins.
//!
//! The engine has no network (it runs in wasm): `update` only asks; the
//! daemon's `oui` service downloads, checks and builds the table with no
//! lock held, keeps it on disk and hands it over here in one swap.

use std::sync::{Arc, OnceLock};

use corerouter_model::oui::{BUILTIN, Meta, Table};
use serde_json::{Value, json};

/// The built-in table, checked once on first use (~0.2 ms).
fn builtin() -> Option<&'static Table<'static>> {
    static T: OnceLock<Option<Table<'static>>> = OnceLock::new();
    T.get_or_init(|| Table::new(BUILTIN).ok()).as_ref()
}

/// An update asked of the daemon, and how the last one went.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Update {
    pub requested: bool,
    pub running: bool,
    pub error: Option<String>,
    /// Session clock of the last result.
    pub at: Option<u64>,
}

#[derive(Debug, Default)]
pub struct Vendors {
    /// A downloaded table (checked when installed).
    downloaded: Option<Arc<Vec<u8>>>,
    pub update: Update,
    /// A thread of the app can download (the daemon's `oui` service).
    pub updater: bool,
}

impl Vendors {
    /// The organization of `mac`'s OUI, from the table in use.
    pub fn vendor(&self, mac: [u8; 6]) -> Option<String> {
        if let Some(b) = &self.downloaded
            && let Ok(t) = Table::new_unchecked(b)
        {
            return t.vendor(mac).map(str::to_owned);
        }
        builtin().and_then(|t| t.vendor(mac)).map(str::to_owned)
    }

    /// Which table is in use and what it says of itself.
    pub fn status(&self) -> Value {
        let (source, meta): (&str, Option<Meta>) = match &self.downloaded {
            Some(b) => ("downloaded", Table::new_unchecked(b).ok().map(|t| t.meta())),
            None => ("built-in", builtin().map(Table::meta)),
        };
        json!({
            "source": source,
            "date": meta.as_ref().map(|m| m.date.clone()),
            "entries": meta.as_ref().map(|m| m.entries),
            "sha256": meta.as_ref().map(Meta::sha256_hex),
            "source_size": meta.as_ref().map(|m| m.source_size),
            "url": "https://standards-oui.ieee.org/oui/oui.csv",
            "updater": self.updater,
            "update": {
                "requested": self.update.requested,
                "running": self.update.running,
                "error": self.update.error,
                "at": self.update.at,
            },
        })
    }
}

impl crate::Session {
    /// The daemon's `oui` service is there to download.
    pub fn vendors_updater(&mut self, on: bool) {
        if let Some(v) = self.ext_mut::<Vendors>() {
            v.updater = on;
        }
    }

    /// An update was asked: take it (the service then downloads).
    pub fn vendors_take_request(&mut self) -> bool {
        let Some(v) = self.ext_mut::<Vendors>() else {
            return false;
        };
        let asked = v.update.requested;
        if asked {
            v.update.requested = false;
            v.update.running = true;
        }
        asked
    }

    /// Install a table (checked whole here); the result of an update.
    pub fn vendors_install(&mut self, bytes: Vec<u8>) -> Result<Meta, String> {
        let meta = Table::new(&bytes)?.meta();
        let now = self.now();
        if let Some(v) = self.ext_mut::<Vendors>() {
            v.downloaded = Some(Arc::new(bytes));
            v.update.running = false;
            v.update.error = None;
            v.update.at = now;
        }
        Ok(meta)
    }

    /// The update failed: say why; the table in use stays.
    pub fn vendors_failed(&mut self, why: String) {
        let now = self.now();
        if let Some(v) = self.ext_mut::<Vendors>() {
            v.update.running = false;
            v.update.error = Some(why);
            v.update.at = now;
        }
    }
}

/// The vendor of `mac` from the table in use (`v`: the session's, if
/// any; else the built-in one).
pub fn vendor_of(v: Option<&Vendors>, mac: [u8; 6]) -> Option<String> {
    match v {
        Some(v) => v.vendor(mac),
        None => builtin().and_then(|t| t.vendor(mac)).map(str::to_owned),
    }
}
