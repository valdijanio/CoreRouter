//! The CGNAT queue (G2.3c) as a service: serves the netfilter queue where
//! a blocks-mode pool holds the first packet of a subscriber without a
//! block. Each packet waits here, outside the session lock, until the
//! engine allocated the block (`Session::cgnat_block_for`, which puts it
//! in the kernel's map); then the packet goes on to the NAT. No block left
//! (or the most blocks a subscriber may hold): the packet is dropped
//! (RFC 6888 REQ-11). What waits is served in batches: one session lock
//! and one sync of the block journal per batch (G4.4j). The periodic work (growing, releasing, alerts) is
//! the session tick's.
//!
//! Only with a blocks-mode pool, and on a backend with a queue (Linux);
//! the lab hands blocks to its pretend subscribers from the tick.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};

/// How long `recv` waits before the loop looks at the config again.
const WAIT: Duration = Duration::from_millis(250);
/// First packets served in one batch at most (a storm: every subscriber
/// back after a reboot).
const BATCH: usize = 1024;
/// Rest while there is no blocks-mode pool, or no queue to serve.
const IDLE: Duration = Duration::from_secs(2);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "cgnat",
    flags: &[],
    topic: "cgnat",
    enable: "ip.firewall.cgnat.pool.add mode=blocks …",
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn run(session: &Shared, health: &super::Health) {
    let mut queue = None;
    let mut warned = false;
    while health.sleep(if queue.is_some() { Duration::ZERO } else { IDLE }) {
        health.beat();
        if !lock(session).cgnat_has_blocks() {
            queue = None;
            health.disabled(Some("no blocks-mode CGNAT pool (ip.firewall.cgnat.pool.add mode=blocks)"));
            continue;
        }
        health.disabled(None);
        let Some(q) = queue.as_mut() else {
            match lock(session).cgnat_queue() {
                Ok(q) => {
                    queue = Some(q);
                    health.clear_error();
                    warned = false;
                }
                Err(e) => {
                    // The lab, or a kernel without nfnetlink_queue: no
                    // queue to serve (the lab's tick allocates).
                    if !warned {
                        log::info!("cgnat: no packet queue: {e}");
                        warned = true;
                    }
                    health.error(format!("no packet queue: {e}"));
                }
            }
            continue;
        };
        // The packets waiting now, served as one batch: one lock and one
        // journal sync for all of them (G4.4j).
        let mut batch = Vec::new();
        let mut failed = None;
        loop {
            let wait = if batch.is_empty() { WAIT } else { Duration::ZERO };
            match q.recv(wait) {
                Ok(Some(p)) => {
                    batch.push(p);
                    if batch.len() >= BATCH {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if !batch.is_empty() {
            let subs: Vec<_> = batch.iter().map(|p| p.subscriber).collect();
            let got = lock(session).cgnat_blocks_for(&subs, unix_now());
            for (p, got) in batch.iter().zip(got) {
                // A 1:1 subscriber is translated by its exception rule; one
                // without a block left is refused, with the ICMP of RFC 6888
                // REQ-11b (G2.7).
                let done = match &got {
                    Ok(_) => q.verdict(p.id, true),
                    Err(e) if e.contains("1:1 exception") => q.verdict(p.id, true),
                    Err(e) => {
                        log::debug!("cgnat: {}: {e}", p.subscriber);
                        q.refuse(p.id).map(|_| ())
                    }
                };
                if let Err(e) = done {
                    failed = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = failed {
            health.error(format!("queue: {e}"));
            queue = None;
        }
    }
}
