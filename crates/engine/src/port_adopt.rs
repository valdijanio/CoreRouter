//! A physical port that shows up with the router running joins the
//! configuration (G1.6t), as RouterOS lists a new card under
//! `/interface ethernet` by itself. Before this, only the first boot
//! seeded the ports (`discovered` in `session.rs`): a USB adapter, a
//! hot-plug PCIe card or a virtio card added to a running VM stayed
//! "not in the configuration" and nothing could be set on it.
//!
//! The tick decides; `interface.ethernet.adopt` does it (journal, log).
//! A link is adopted only after it kept its name for [`STABLE_POLLS`]
//! polls: PID 1 renames a new card from `ethN` to `etherN` within
//! ~100 ms (G1.6n), and the kernel name must not be adopted. With pending
//! changes in the candidate (transactional mode) the adoption waits: it
//! never mixes into an operator's unfinished edit.

use std::collections::BTreeMap;

use corerouter_hal::LinkState;
use corerouter_model::IfName;
use serde_json::json;

use crate::auth::Principal;
use crate::{Caller, Session};

/// Polls (one a second from the tick) a new link must keep its name.
pub const STABLE_POLLS: u32 = 3;
/// Ports followed at most before adoption (hostile platform).
const MAX_FOLLOWED: usize = 256;
/// Polls before an adoption that failed is tried again.
const RETRY_POLLS: u32 = 60;

/// New links seen and for how many polls (`Session::ext`).
#[derive(Default)]
pub struct PortAdoption {
    seen: BTreeMap<IfName, u32>,
    /// Adoptions that failed: polls left before the next try.
    backoff: BTreeMap<IfName, u32>,
}

impl Session {
    /// From `poll_links`: adopt the Ethernet links of `live` that are not
    /// in the configuration and kept their name long enough.
    pub(crate) fn adopt_new_ports(&mut self, live: &[LinkState]) {
        let new: Vec<&LinkState> = live
            .iter()
            .filter(|l| l.kind == "ether" && l.unmanaged.is_none())
            .filter(|l| {
                !self.store().candidate().interfaces.contains_key(&l.name)
                    && !self.store().running().interfaces.contains_key(&l.name)
            })
            .take(MAX_FOLLOWED)
            .collect();
        let Some(a) = self.ext_mut::<PortAdoption>() else {
            return;
        };
        if new.is_empty() && a.seen.is_empty() {
            return;
        }
        a.seen.retain(|n, _| new.iter().any(|l| &l.name == n));
        a.backoff.retain(|n, _| new.iter().any(|l| &l.name == n));
        let mut due = Vec::new();
        for l in &new {
            if let Some(left) = a.backoff.get_mut(&l.name) {
                *left = left.saturating_sub(1);
                if *left > 0 {
                    continue;
                }
            }
            let n = a.seen.entry(l.name.clone()).or_default();
            *n = n.saturating_add(1);
            if *n >= STABLE_POLLS {
                due.push(l.name.clone());
            }
        }
        if due.is_empty() || self.store().is_dirty() {
            return;
        }
        let caller = Caller::new(Caller::LOCAL_ID, "router: new port").with_principal(Principal::Local);
        for name in due {
            let r = self.execute_as(&caller, "interface.ethernet.adopt", &json!({ "name": name }));
            // The command commits in immediate mode; in transactional mode
            // the candidate was clean, so committing takes only this port.
            let r = r.and_then(|v| {
                if self.store().is_dirty() {
                    self.commit_candidate("interface.ethernet.adopt")?;
                }
                Ok(v)
            });
            if let Some(a) = self.ext_mut::<PortAdoption>() {
                a.seen.remove(&name);
                if r.is_err() {
                    a.backoff.insert(name.clone(), RETRY_POLLS);
                }
            }
            if let Err(e) = r {
                log::warn!("adopting new port {name}: {e}");
            }
        }
    }
}
