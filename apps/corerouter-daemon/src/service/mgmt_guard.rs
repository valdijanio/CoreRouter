//! Management guard (G3.4z): once a second, which FIB entry the replies to
//! each open management session take (`corerouter_engine::mgmt_guard`).
//!
//! The session lock is held twice per tick, to copy the (peer, local) pairs
//! and to hand the answers back; the kernel is asked in between, with no
//! lock, one `RTM_GETROUTE` per distinct pair on one netlink socket
//! (11,5 µs each in a debug build, **medido**, `docs/changes/G3.4z.md`). The
//! kernel's trie does the longest match: the cost grows with the sessions,
//! never with the routes (a full table or 200 000 OSPF LSAs cost the same).
//! One thread: 1 000 sessions are ~12 ms a second (**estimado** from the
//! measure), so a second thread would only add a lock to the feed.

use std::time::Duration;

#[cfg(target_os = "linux")]
use corerouter_engine::lock;
use corerouter_engine::Shared;

/// How often the sessions are looked at.
#[cfg(target_os = "linux")]
const TICK: Duration = Duration::from_secs(1);
const IDLE: Duration = super::IDLE_BEAT;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "mgmt-guard",
    flags: &[],
    topic: "route",
    enable: "always on (--backend linux)",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| run(&session, health)))
}

fn idle(health: &super::Health, why: &str) -> Result<(), String> {
    health.disabled(Some(why));
    while health.sleep(IDLE) {
        health.beat();
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run(session: &Shared, health: &super::Health) -> Result<(), String> {
    let _ = session;
    idle(health, "no kernel FIB to ask on this platform")
}

#[cfg(target_os = "linux")]
fn run(session: &Shared, health: &super::Health) -> Result<(), String> {
    if !lock(session).backend().starts_with("linux") {
        return idle(health, "the virtual lab has no kernel routes");
    }
    health.event("watching the routes of the management sessions");
    let mut last = (usize::MAX, usize::MAX);
    while !health.stopping() {
        health.beat();
        let probes = lock(session).mgmt_guard_probes();
        // G3.4za: a session in a VRF is looked up in its table.
        let asks: Vec<_> = probes.iter().map(|p| (p.peer, Some(p.local), p.vrf.clone())).collect();
        let answers = match corerouter_hal_linux::fib_match::lookup_in(&asks) {
            Ok(a) => a,
            Err(e) => {
                health.error(format!("route lookup: {e}"));
                Vec::new()
            }
        };
        let fed: Vec<_> = probes.iter().map(|p| p.pair()).zip(answers).collect();
        let now = {
            let mut s = lock(session);
            s.mgmt_guard_feed(fed);
            (s.mgmt_guard_sessions().len(), s.mgmt_guard_findings().len())
        };
        if now != last {
            health.event(format!("{} management session(s), {} covered by a learned route", now.0, now.1));
            last = now;
        }
        if !health.sleep(TICK) {
            break;
        }
    }
    Ok(())
}
