//! The DHCPv4 server (G4.2a) as a service: one loop that runs the
//! engine's server round (`Session::dhcp_server_poll`) every few
//! milliseconds — [`STORM`] apart while messages keep coming (a storm after
//! a power cut), 5 ms apart when the link is quiet — under the supervisor
//! (heartbeat, the sockets it listens on, its errors). From its first run
//! the session clock stops driving the server, so `system.service.stop
//! dhcp-server` stops serving.
//!
//! The sockets, the journal and the leases are the engine's (through the
//! HAL and the config storage): a restart of this service loses nothing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_model::service::Listen;

/// Rest between rounds when nothing was heard.
const QUIET: Duration = Duration::from_millis(5);
/// Rest between rounds in a storm. Never zero: the session lock is a
/// plain mutex (not fair), and a loop that takes it again at once starves
/// the control channel, the GUI and the other services — the operator
/// could not log in to stop the storm. Each round is bounded too (the
/// engine's `ROUND_BUDGET_US`).
const STORM: Duration = Duration::from_millis(1);
/// Rest while idle (no server configured).
const IDLE: Duration = Duration::from_millis(500);

/// The service's monotonic clock: one origin for every run, so the
/// engine's probe deadlines survive a restart of the loop.
fn origin() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dhcp-server",
    flags: &[],
    topic: "dhcp",
    enable: "ip.dhcp-server.add interface=… address_pool=…",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

fn run(session: &Shared, health: &super::Health) {
    let start = origin();
    lock(session).dhcp_server_driven(true);
    let clock = move || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let mut rest = QUIET;
    while health.sleep(rest) {
        health.beat();
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (heard, ports, configured, journal) = {
            let mut s = lock(session);
            let heard = s.dhcp_server_poll(ms, &clock);
            let d = &s.store().running().ip.dhcp_server;
            let configured = d.servers.iter().any(|x| !x.disabled)
                || d.alerts.iter().any(|a| !a.disabled)
                || s.store().running().ip.dhcp_relays.relays.iter().any(|r| !r.disabled)
                || s.store().running().ipv6.dhcp_server.servers.iter().any(|x| !x.disabled)
                || s.store().running().ipv6.dhcp_server.relays.iter().any(|r| !r.disabled);
            (heard, s.dhcp_server_ports(), configured, s.dhcp_server_journal_error())
        };
        if !configured {
            health.disabled(Some("no enabled DHCP server nor relay (ip.dhcp-server.add, ip.dhcp-relay.add)"));
            health.listen(Vec::new());
            rest = IDLE;
            continue;
        }
        health.disabled(None);
        let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 67));
        health.listen(
            ports
                .iter()
                .filter(|p| p.listening.is_some())
                .map(|p| {
                    let mut l = Listen::new("udp", any);
                    l.address = format!("{any} on {}", p.interface);
                    l
                })
                .collect(),
        );
        let errors: Vec<String> = ports
            .iter()
            .filter_map(|p| p.error.as_ref().map(|e| format!("{}: {e}", p.interface)))
            .chain(journal.map(|e| format!("leases not saved: {e}")))
            .collect();
        if errors.is_empty() {
            health.clear_error();
        } else {
            health.error(errors.join("; "));
        }
        rest = rest_after(heard);
    }
}

/// How long to rest after a round that heard something (`heard`) or not.
fn rest_after(heard: bool) -> Duration {
    if heard { STORM } else { QUIET }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Between two rounds the lock is always let go for a while, storm or
    /// not (others get their turn).
    #[test]
    fn the_loop_always_rests() {
        assert!(rest_after(true) >= Duration::from_millis(1));
        assert!(rest_after(false) >= rest_after(true));
    }
    use corerouter_control::Shutdown;
    use corerouter_engine::{Session, shared};
    use serde_json::json;

    /// The service runs the lab's server: its hosts get leases, and the
    /// row says where it listens.
    #[test]
    fn the_service_serves_the_lab() {
        let session = shared(Session::virtual_lab());
        {
            let mut s = lock(&session);
            s.tick(1_700_000_000);
            for (id, p) in [
                ("ip.address.add", json!({"address": "192.168.88.1/24", "interface": "ether2"})),
                ("ip.pool.add", json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.50"})),
                ("ip.dhcp-server.add", json!({"interface": "ether2", "address_pool": "lan"})),
                ("ip.dhcp-server.network.add", json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1"})),
            ] {
                s.execute(id, &p).unwrap();
            }
        }
        let health = super::super::Health::new(Shutdown::default());
        let h2 = health.clone();
        let s2 = session.clone();
        let t = std::thread::spawn(move || run(&s2, &h2));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let bound = lock(&session)
                .execute("ip.dhcp-server.lease.print", &json!({"status": "bound"}))
                .unwrap()
                .as_array()
                .map_or(0, Vec::len);
            if bound == 4 {
                break;
            }
            assert!(Instant::now() < deadline, "the lab hosts got {bound} leases");
            std::thread::sleep(Duration::from_millis(50));
        }
        let r = health.snapshot();
        assert_eq!(r.listen.len(), 1);
        assert!(r.listen[0].address.contains("ether2"));
        assert!(r.beat.is_some());
        health.stop();
        t.join().unwrap();
    }
}
