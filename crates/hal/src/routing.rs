//! The routing daemons (G3.1): BGP, OSPF, LDP and BFD run in an external
//! suite (FRR today, perhaps holo later: G3.8) that CoreRouter configures
//! on every commit and reads state from. Each suite is one backend of
//! [`RoutingDaemon`]; the engine only sees the trait, as with [`crate::Hal`].
//!
//! The backend gets whole configs and renders them itself (FRR text, YANG
//! for holo), so a second backend needs no change in the engine, the
//! commands, the UI or MCP.

use std::sync::Arc;

use corerouter_model::Config;
use corerouter_model::bgp_rib::{BgpPrefix, BgpRib, Direction};
use corerouter_model::ospf_state::{Lsdb, OspfIfState, OspfNeighbor, OspfRoute};
use corerouter_model::routing_state::BgpSession;
use corerouter_model::sealed::Sealed;

use crate::HalError;

/// Opens a sealed secret (a BGP TCP MD5 key, G3.2a) for the render; the
/// engine holds the key and hands this to the backend. `None`: it cannot
/// be opened (no key file, another router's box).
pub type SecretOpener = Arc<dyn Fn(&Sealed) -> Option<String> + Send + Sync>;

/// What `routing.bgp.session.clear`/`refresh`/`resend` ask of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpClear {
    /// Close it and open it again (NOTIFICATION Cease, RFC 4486
    /// subcode 4, administrative reset).
    Hard,
    /// Ask the neighbor to send its routes again (ROUTE-REFRESH, RFC 2918):
    /// new inbound policy without a reset.
    SoftIn,
    /// Send ours again: new outbound policy without a reset.
    SoftOut,
}

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

    /// How the backend opens sealed secrets for its render (set once when
    /// the engine attaches it). Without it only clear values open.
    fn set_secrets(&mut self, open: SecretOpener) {
        let _ = open;
    }

    /// Reset or refresh the session with `neighbor` of BGP instance
    /// `instance` (a running-state action, not configuration).
    fn bgp_clear(&mut self, instance: &str, neighbor: &str, how: BgpClear) -> Result<(), HalError> {
        let _ = (instance, neighbor, how);
        Err(HalError::Unsupported("BGP session actions".into()))
    }
}

/// Reads the routing daemons' state; owned by a thread of its own.
pub trait RoutingReader: Send {
    /// The BGP sessions of the instances of `cfg`.
    fn bgp_sessions(&mut self, cfg: &Config) -> Result<Vec<BgpSession>, HalError>;

    /// The routes of BGP neighbor `neighbor` of instance `instance` for the
    /// policy preview (G3.2b): `received` those it sent, before the input
    /// chain; otherwise this router's best routes, before the output chain.
    fn bgp_filter_routes(
        &mut self,
        cfg: &Config,
        instance: &str,
        neighbor: &str,
        received: bool,
    ) -> Result<Vec<corerouter_model::bgp_route::BgpRouteEntry>, HalError> {
        let _ = (cfg, instance, neighbor, received);
        Err(HalError::Unsupported("BGP routes".into()))
    }

    /// The backend's version line, e.g. "frr 10.7.1"; `Err` while it is down.
    fn version(&mut self) -> Result<String, HalError>;

    /// A value that changes whenever the daemons restart (their PIDs), so
    /// a restart quicker than one poll is still seen and the config put
    /// back. `None`: the backend cannot tell.
    fn incarnation(&mut self) -> Option<String> {
        None
    }

    /// G3.2c: the routes of neighbor `neighbor` of instance `instance`,
    /// one way, both families. A full table is ~1 M routes: read it
    /// streaming, never as one buffer.
    fn bgp_routes(
        &mut self,
        instance: &str,
        neighbor: &str,
        direction: Direction,
    ) -> Result<BgpRib, HalError> {
        let _ = (instance, neighbor, direction);
        Err(HalError::Unsupported("BGP route lists".into()))
    }

    /// G3.2c: every path the daemon holds for `prefix` (an address: the
    /// longest match), for "Why this route?".
    fn bgp_prefix(&mut self, instance: &str, prefix: &str) -> Result<BgpPrefix, HalError> {
        let _ = (instance, prefix);
        Err(HalError::Unsupported("BGP prefix detail".into()))
    }

    /// G3.2c: the daemon's own view of its RTR validators, one line
    /// (`None`: it does not validate).
    fn rpki_state(&mut self) -> Option<String> {
        None
    }

    /// G3.4b: the OSPF neighbors and interfaces of `cfg`'s instances
    /// (cheap: read every poll).
    fn ospf_state(
        &mut self,
        cfg: &Config,
    ) -> Result<(Vec<OspfNeighbor>, Vec<OspfIfState>), HalError> {
        let _ = cfg;
        Ok((Vec::new(), Vec::new()))
    }

    /// G3.4b: the link-state database and the routes of OSPF instance
    /// `instance` (tens of thousands of LSAs: read streaming, on demand).
    fn ospf_lsdb(
        &mut self,
        cfg: &Config,
        instance: &str,
    ) -> Result<(Lsdb, Vec<OspfRoute>), HalError> {
        let _ = (cfg, instance);
        Err(HalError::Unsupported("OSPF database".into()))
    }
}
