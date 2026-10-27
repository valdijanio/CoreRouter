//! The routing daemons (G3.1): BGP, OSPF, LDP and BFD run in an external
//! suite (FRR today, perhaps holo later: G3.8) that CoreRouter configures
//! on every commit and reads state from. Each suite is one backend of
//! [`RoutingDaemon`]; the engine only sees the trait, as with [`crate::Hal`].
//!
//! The backend gets whole configs and renders them itself (FRR text, YANG
//! for holo), so a second backend needs no change in the engine, the
//! commands, the UI or MCP.

use corerouter_model::Config;
use corerouter_model::routing_state::BgpSession;

use crate::HalError;

pub trait RoutingDaemon: Send {
    /// "frr 10.7.1 (vty)".
    fn describe(&self) -> String;

    /// Make the routing daemons run what `to` says. All-or-nothing: on
    /// `Err` they are left as they were. Only the difference is applied:
    /// sessions that `to` does not change stay up. `from` is the config
    /// believed to be running (a backend may diff against the daemons' own
    /// running config instead, which survives their restart).
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError>;

    /// A handle that reads state on another thread, without this backend
    /// (and the session lock around it).
    fn reader(&self) -> Box<dyn RoutingReader>;
}

/// Reads the routing daemons' state; owned by a thread of its own.
pub trait RoutingReader: Send {
    /// The BGP sessions of the instances of `cfg`.
    fn bgp_sessions(&mut self, cfg: &Config) -> Result<Vec<BgpSession>, HalError>;

    /// The backend's version line, e.g. "frr 10.7.1"; `Err` while it is down.
    fn version(&mut self) -> Result<String, HalError>;

    /// A value that changes whenever the daemons restart (their PIDs), so
    /// a restart quicker than one poll is still seen and the config put
    /// back. `None`: the backend cannot tell.
    fn incarnation(&mut self) -> Option<String> {
        None
    }
}
