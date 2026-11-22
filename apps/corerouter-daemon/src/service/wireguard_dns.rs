//! WireGuard endpoints by DNS name (G1.31b): the names are resolved on
//! this service's thread, through the router's own resolver, outside the
//! session lock.
//!
//! Every [`TICK`] the engine says which names are due
//! (`Session::wireguard_names_due`: never answered, or a peer without a
//! handshake for 180 s whose name was asked 30 s ago or more — the rule
//! of OpenWrt's `wireguard_watchdog` and RouterOS), the thread asks the
//! resolver, and `Session::wireguard_resolved` keeps the answer and sends
//! a changed address to the kernel.
//!
//! One thread: a peer needs its name at most every 30 s, and a lookup
//! waits on the network, not on a core; a router with hundreds of named
//! endpoints still asks a handful a second (**estimado**).

use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};

pub(crate) const SERVICE: super::Service = super::Service {
    name: "wireguard-dns",
    flags: &[],
    topic: "interface",
    enable: "interface.wireguard.peers.add endpoint_address=<name>",
    depends: &[],
    start,
};

/// How often the engine is asked for the names due.
const TICK: Duration = if cfg!(test) { Duration::from_millis(50) } else { Duration::from_secs(5) };
/// Names resolved per tick (a burst after a restart spreads out).
const PER_TICK: usize = 32;

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

fn run(session: &Shared, health: &super::Health) {
    let start = Instant::now();
    loop {
        let now_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        round(session, now_ms);
        if !health.sleep(TICK) {
            return;
        }
    }
}

/// One round: the names due, resolved off the lock, handed back.
pub(crate) fn round(session: &Shared, now_ms: u64) -> usize {
    let due = lock(session).wireguard_names_due(now_ms);
    let mut answers = Vec::new();
    for host in due.into_iter().take(PER_TICK) {
        let r = super::dns::resolve(session, &host);
        answers.push((host, r));
    }
    let n = answers.len();
    let mut s = lock(session);
    for (host, r) in answers {
        s.wireguard_resolved(&host, r, now_ms);
    }
    n
}

#[cfg(test)]
mod tests {
    use corerouter_engine::{Session, shared};
    use serde_json::json;

    #[test]
    fn a_name_endpoint_gets_its_address_and_the_tunnel_comes_up() {
        let mut s = Session::virtual_lab();
        s.execute("interface.wireguard.add", &json!({"name": "wg0"})).unwrap();
        s.execute("interface.wireguard.add", &json!({"name": "wg1"})).unwrap();
        let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
        let (k0, k1) = (l[0]["public_key"].clone(), l[1]["public_key"].clone());
        s.execute("interface.wireguard.peers.add", &json!({"interface": "wg0", "public_key": k1, "allowed_address": "10.99.0.2/32",
            "endpoint_address": "localhost", "endpoint_port": 13232, "persistent_keepalive": 25})).unwrap();
        s.execute("interface.wireguard.peers.add", &json!({"interface": "wg1", "public_key": k0, "allowed_address": "10.99.0.1/32"})).unwrap();
        let session = shared(s);
        // The router's resolver, with no server configured: localhost is
        // answered by the resolver itself (RFC 6761).
        super::super::dns::register(&session, &std::sync::Arc::new(super::super::dns::RouterDns::new()));
        assert_eq!(super::round(&session, 0), 1);
        let p = corerouter_engine::lock(&session).execute("interface.wireguard.peers.list", &json!({"interface": "wg0"})).unwrap();
        assert_eq!(p[0]["endpoint_resolved"], "127.0.0.1", "{p}");
        assert!(p[0]["resolve_error"].is_null(), "{p}");
        assert_eq!(p[0]["state"], "up");
        assert_eq!(super::round(&session, 1_000), 0, "nothing due while the handshake is fresh");
    }
}
