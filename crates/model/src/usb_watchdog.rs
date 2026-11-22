//! The USB adapter watchdog (G1.29d): what an operator sets per adapter.
//! On by default for every USB Ethernet adapter; an entry here exists only
//! for an adapter whose settings differ from the default.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IfName;

/// Seconds a link may stay up sending without receiving before it counts
/// as stalled.
pub const DEFAULT_STALL_SECS: u32 = 30;
pub const MIN_STALL_SECS: u32 = 10;
pub const MAX_STALL_SECS: u32 = 3600;
/// Adapters with their own settings at most.
pub const MAX_ENTRIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UsbWatchdogPort {
    pub enabled: bool,
    pub stall_secs: u32,
}

impl Default for UsbWatchdogPort {
    fn default() -> Self {
        Self {
            enabled: true,
            stall_secs: DEFAULT_STALL_SECS,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UsbWatchdog {
    pub ports: BTreeMap<IfName, UsbWatchdogPort>,
}

impl UsbWatchdog {
    pub fn is_default(&self) -> bool {
        self.ports.is_empty()
    }

    /// The settings of `name` (the default when it has none).
    pub fn port(&self, name: &IfName) -> UsbWatchdogPort {
        self.ports.get(name).cloned().unwrap_or_default()
    }
}
