//! What the RPKI side knows right now (G3.2c): the state of each RTR
//! session and the VRP table built from the validators in sync, set by the
//! daemon's `rpki` service (outside the session lock: it builds the table
//! on its own thread and only swaps an `Arc` here). Empty in the virtual
//! lab: route badges are then `unverified`.

use std::sync::Arc;

use corerouter_model::rpki::RpkiStatus;
use corerouter_proto_bgp::rpki::VrpTable;

use crate::Session;

#[derive(Default)]
pub struct RpkiLive {
    pub status: RpkiStatus,
    /// The VRPs of every validator in sync; `None`: none is.
    pub table: Option<Arc<VrpTable>>,
    /// Goes up with every new table (route lists validated with an older
    /// one say so).
    pub generation: u64,
}

impl Session {
    pub fn set_rpki_status(&mut self, status: RpkiStatus) {
        if let Some(l) = self.ext_mut::<RpkiLive>() {
            l.status = status;
        }
    }

    /// A new VRP table (`None`: no validator in sync any more).
    pub fn set_rpki_table(&mut self, table: Option<Arc<VrpTable>>) {
        if let Some(l) = self.ext_mut::<RpkiLive>() {
            l.table = table;
            l.generation = l.generation.wrapping_add(1);
        }
    }

    pub fn rpki_status(&self) -> Option<&RpkiStatus> {
        self.ext::<RpkiLive>().map(|l| &l.status)
    }

    pub(crate) fn rpki_table(&self) -> (Option<Arc<VrpTable>>, u64) {
        self.ext::<RpkiLive>()
            .map_or((None, 0), |l| (l.table.clone(), l.generation))
    }
}
