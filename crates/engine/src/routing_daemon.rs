//! The routing daemons behind the session (G3.1): the backend that every
//! commit touching `routing` goes through (see `commit_counted`), and the
//! state its reader brings back for `routing.bgp.session.list`.
//!
//! The virtual lab has no backend: commits only change the config and the
//! session list is empty. The daemon attaches FRR (`service/frr.rs`).

use std::sync::Arc;

use corerouter_hal::routing::{BgpClear, RoutingDaemon, RoutingReader};
use corerouter_model::Config;
use corerouter_model::routing_state::RoutingStatus;

use crate::{EngineError, Result, Session};

/// The attached backend, if any (a [`Session`] extension).
#[derive(Default)]
pub struct RoutingBackend(pub(crate) Option<Box<dyn RoutingDaemon>>);

impl Session {
    /// Attach the routing daemons and install the running config on them
    /// (what they hold is diffed, so a restart of theirs is a resync too).
    /// Returns a reader for a thread of the caller's, and the resync's
    /// error, if any: the backend stays attached either way, and the next
    /// commit or [`Session::routing_resync`] tries again.
    pub fn attach_routing(
        &mut self,
        mut daemon: Box<dyn RoutingDaemon>,
    ) -> (Box<dyn RoutingReader>, Result<()>) {
        // The render opens the sealed TCP MD5 keys (G3.2a) with the
        // session's key; without it a sealed key refuses the commit.
        match crate::sealing::key(self) {
            Ok(key) => daemon.set_secrets(Arc::new(move |s| key.open(s))),
            Err(e) => log::error!("routing: sealed BGP keys cannot be opened: {e}"),
        }
        let reader = daemon.reader();
        if let Some(slot) = self.ext_mut::<RoutingBackend>() {
            *slot = RoutingBackend(Some(daemon));
        }
        let synced = self.routing_resync();
        (reader, synced)
    }

    /// Install the running config on the routing daemons again (after they
    /// restarted). Nothing without a backend.
    pub fn routing_resync(&mut self) -> Result<()> {
        let running: Config = self.effective(self.store().running()).into_owned();
        match self.ext_mut::<RoutingBackend>() {
            Some(RoutingBackend(Some(d))) => d
                .apply(&running, &running)
                .map_err(|e| EngineError::Hal(format!("routing: {e}"))),
            _ => Ok(()),
        }
    }

    /// Reset or refresh a BGP session on the routing daemons (a running
    /// action; one vty command, ~1 ms, under the lock like a commit).
    pub fn routing_bgp_clear(&mut self, instance: &str, neighbor: &str, how: BgpClear) -> Result<()> {
        match self.ext_mut::<RoutingBackend>() {
            Some(RoutingBackend(Some(d))) => d
                .bgp_clear(instance, neighbor, how)
                .map_err(|e| EngineError::Hal(format!("routing: {e}"))),
            _ => Err(EngineError::Hal(
                "routing: no routing daemon is attached (virtual lab, or the daemon runs without --frr)".into(),
            )),
        }
    }

    /// Whether a routing backend is attached.
    pub fn has_routing(&self) -> bool {
        matches!(self.ext::<RoutingBackend>(), Some(RoutingBackend(Some(_))))
    }

    /// What the routing reader saw last (set by the daemon's thread).
    pub fn set_routing_status(&mut self, status: RoutingStatus) {
        if let Some(slot) = self.ext_mut::<RoutingStatus>() {
            *slot = status;
        }
    }

    pub fn routing_status(&self) -> Option<&RoutingStatus> {
        self.ext::<RoutingStatus>()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use corerouter_hal::HalError;
    use corerouter_model::routing_state::BgpSession;
    use serde_json::json;

    use super::*;

    /// A backend that records what it was asked and refuses on demand.
    #[derive(Clone, Default)]
    struct Fake {
        applied: Arc<Mutex<Vec<usize>>>,
        refuse: Arc<Mutex<bool>>,
    }

    impl RoutingDaemon for Fake {
        fn describe(&self) -> String {
            "fake".into()
        }
        fn apply(&mut self, _from: &Config, to: &Config) -> std::result::Result<(), HalError> {
            if *self.refuse.lock().unwrap() {
                return Err(HalError::Rejected("bgpd refused `router bgp 1`".into()));
            }
            self.applied.lock().unwrap().push(to.routing.bgp.len());
            Ok(())
        }
        fn reader(&self) -> Box<dyn RoutingReader> {
            Box::new(self.clone())
        }
    }

    impl RoutingReader for Fake {
        fn bgp_sessions(&mut self, _: &Config) -> std::result::Result<Vec<BgpSession>, HalError> {
            Ok(Vec::new())
        }
        fn version(&mut self) -> std::result::Result<String, HalError> {
            Ok("fake 1".into())
        }
    }

    fn bgp() -> serde_json::Value {
        json!({"asn": 65000, "router_id": "10.0.0.1"})
    }

    #[test]
    fn routing_commits_reach_the_backend_and_a_refusal_rolls_back() {
        let mut s = Session::new(Box::new(corerouter_hal::VirtualHal::default()));
        let fake = Fake::default();
        let (_reader, synced) = s.attach_routing(Box::new(fake.clone()));
        assert!(synced.is_ok());
        assert!(s.has_routing());
        // The resync at attach, then the commit.
        s.execute("routing.bgp.instance.set", &bgp()).unwrap();
        assert_eq!(*fake.applied.lock().unwrap(), [0, 1]);
        // A commit that does not touch routing does not call it.
        s.execute("system.identity.set", &json!({"name": "r1"})).unwrap();
        assert_eq!(fake.applied.lock().unwrap().len(), 2);
        // Refused: the commit fails and the config stays as it was.
        *fake.refuse.lock().unwrap() = true;
        let e = s
            .execute(
                "routing.bgp.instance.set",
                &json!({"asn": 65001, "router_id": "10.0.0.1"}),
            )
            .unwrap_err();
        assert!(e.to_string().contains("bgpd refused"), "{e}");
        let asn = s.store().running().routing.bgp.get("default").map(|b| b.asn.0);
        assert_eq!(asn, Some(65000));
        assert!(s.routing_resync().is_err());
    }

    #[test]
    fn without_a_backend_nothing_changes() {
        let mut s = Session::new(Box::new(corerouter_hal::VirtualHal::default()));
        assert!(!s.has_routing());
        assert!(s.routing_resync().is_ok());
        s.execute("routing.bgp.instance.set", &bgp()).unwrap();
        assert_eq!(s.routing_status(), None);
    }
}
