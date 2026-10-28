//! FRR (G3.1): with `--frr <dir>`, the routing daemons of the FRR suite
//! whose vty sockets are in `<dir>` take the routing part of every commit
//! (`hal-frr`: only the difference, no restart, rollback on a refusal), and
//! this thread reads their state for `routing.bgp.session.list`.
//!
//! The read runs here, on its own connections, never under the session
//! lock: the lock is taken only to read the config (a clone of the routing
//! part) and to store the sample. When FRR comes back after being down
//! (restart, upgrade), the running config is installed again
//! (`Session::routing_resync`, under the lock: a commit cannot interleave).
//!
//! Without the flag nothing changes: the virtual lab and a router without
//! FRR keep the routing config and list no session.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};
use corerouter_hal::routing::RoutingReader;
use corerouter_hal_frr::Frr;
use corerouter_model::Config;
use corerouter_model::routing_state::RoutingStatus;

/// How often the sessions are read (RouterOS refreshes `session print`
/// on demand; a 2 s sample keeps the UI live and costs ~1 ms of bgpd's
/// time for 100 sessions, see docs/architecture.md).
const TICK: Duration = Duration::from_secs(2);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "frr",
    flags: &[super::Flag {
        name: "--frr",
        value: Some("<dir>"),
        help: "drive FRR through the vty sockets in <dir> (FRR's default is\n/var/run/frr): \
               routing commits and routing.bgp.session.list",
    }],
    topic: "route",
    enable: "--frr /var/run/frr",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let dir = ctx.flag("--frr").map(str::to_owned);
    if dir.as_deref() == Some("") {
        return Err("--frr needs the directory of FRR's vty sockets".into());
    }
    Ok(Box::new(move |health: &super::Health| {
        let Some(dir) = &dir else {
            health.disabled(Some("no --frr <dir>"));
            while health.sleep(Duration::from_secs(60)) {
                health.beat();
            }
            return Ok(());
        };
        let frr = Frr::new(dir);
        let (reader, synced) = lock(&session).attach_routing(Box::new(frr));
        match &synced {
            Ok(()) => health.event(format!("attached to FRR in {dir}")),
            Err(e) => health.error(e.to_string()),
        }
        run(&session, reader, synced.is_ok(), health);
        Ok(())
    }))
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn run(session: &Shared, mut reader: Box<dyn RoutingReader>, synced: bool, health: &super::Health) {
    // Whether the running config is known to be on FRR.
    let mut in_sync = synced;
    let mut status = RoutingStatus::default();
    let mut seen = reader.incarnation();
    loop {
        health.beat();
        match reader.version() {
            Ok(v) => {
                // Restarted between two polls: up both times, other PIDs.
                let now = reader.incarnation();
                if now != seen {
                    if seen.is_some() && in_sync {
                        log::warn!("FRR restarted ({now:?}); installing the running config again");
                    }
                    in_sync = false;
                    seen = now;
                }
                if !in_sync {
                    match lock(session).routing_resync() {
                        Ok(()) => {
                            log::info!("FRR is up ({v}); running config installed");
                            health.event(format!("{v}: running config installed"));
                            in_sync = true;
                        }
                        Err(e) => health.error(e.to_string()),
                    }
                }
                status.backend = v;
                let cfg = routing_only(session);
                match reader.bgp_sessions(&cfg) {
                    Ok(s) => {
                        status.bgp_sessions = s;
                        status.updated = unix_now();
                        status.error = None;
                        if in_sync {
                            health.clear_error();
                        }
                    }
                    Err(e) => {
                        status.error = Some(e.to_string());
                        health.error(e.to_string());
                    }
                }
                // G3.4b: OSPF neighbors and interfaces, every poll (two
                // small JSON answers per instance).
                if !cfg.routing.ospf.instances.is_empty() {
                    match reader.ospf_state(&cfg) {
                        Ok((n, i)) => {
                            status.ospf_neighbors = n;
                            status.ospf_interfaces = i;
                        }
                        Err(e) => {
                            status.error = Some(e.to_string());
                            health.error(e.to_string());
                        }
                    }
                } else {
                    status.ospf_neighbors.clear();
                    status.ospf_interfaces.clear();
                }
            }
            Err(e) => {
                if in_sync {
                    log::warn!("FRR is down: {e}");
                }
                in_sync = false;
                status.error = Some(e.to_string());
                status.bgp_sessions.clear();
                status.ospf_neighbors.clear();
                status.ospf_interfaces.clear();
                health.error(e.to_string());
            }
        }
        // Copied before the lock is taken (126 µs for 1 000 sessions,
        // **medido**): under it only the move.
        let sample = status.clone();
        let (wanted, ospf_wanted) = {
            let mut s = lock(session);
            s.set_routing_status(sample);
            (s.bgp_routes_wanted(), s.ospf_db_wanted())
        };
        // G3.4b: the OSPF databases a window asked for, streamed here
        // (10 000 LSAs: see docs/ospf.md) and handed back under the lock.
        if !ospf_wanted.is_empty() {
            let cfg = routing_only(session);
            for inst in ospf_wanted {
                let got = reader.ospf_lsdb(&cfg, &inst).map_err(|e| e.to_string());
                lock(session).set_ospf_db(inst, got);
            }
        }
        // G3.2b: the tables the filter preview asked for, read here (a
        // full table takes seconds) and handed back under the lock.
        for key in wanted {
            let got = reader
                .bgp_filter_routes(&Config::default(), &key.instance, &key.neighbor, key.received)
                .map(corerouter_engine::bgp_routes::to_routes)
                .map_err(|e| e.to_string());
            lock(session).set_bgp_routes(key, got);
        }
        if !health.sleep(TICK) {
            return;
        }
    }
}

/// The running config's routing part (all the reader needs), copied under
/// the lock so the read itself runs outside it.
fn routing_only(session: &Shared) -> Config {
    let routing = lock(session).store().running().routing.clone();
    Config {
        routing,
        ..Config::default()
    }
}
