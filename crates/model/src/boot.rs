//! `/system boot` (G1.6zn): what the next boot does with the system.
//!
//! The root is the slot's squashfs on dm-verity, read from the disk as it is
//! needed. With `to_ram` the init copies it to RAM at boot (checked by the
//! same dm-verity) and runs from there, so the system disk can go away with
//! the router running (`corerouter_sysupdate::system_disk`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Boot {
    /// Copy the root to RAM at boot (off: read from the disk).
    pub to_ram: bool,
}

impl Boot {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
