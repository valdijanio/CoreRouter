//! The CGNAT exhaustion queues (G2.7) as a service: one thread per queue
//! (`cgnat-icmp-<n>`), each with its own queue, conntrack and ICMP sockets,
//! never the session lock. The kernel spreads the queues by flow hash; a
//! packet in them is a new connection of a nearly full subscriber, whose
//! tuple the thread checks (`hal-linux::cgnat_icmp`): taken, it is dropped
//! and the subscriber gets an ICMP host unreachable (RFC 6888 REQ-11);
//! free, it goes on. The rule has `bypass`: while nobody serves, the kernel
//! decides as before. The engine's tick keeps the set of nearly full
//! subscribers and reads what the threads counted.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use corerouter_engine::{Shared, lock};
use corerouter_hal::cgnat::EXHAUSTED_QUEUES;

/// How long a queue thread waits for packets before it looks at its flag.
const WAIT: Duration = Duration::from_millis(250);
/// How often the service looks at the config.
const LOOK: Duration = Duration::from_secs(2);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "cgnat-icmp",
    flags: &[],
    topic: "cgnat",
    enable: "ip.firewall.cgnat.set icmp_unreachable=yes (with a pool)",
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

/// Open every queue and start its thread; the flag stops them all.
fn serve_all(session: &Shared, health: &super::Health) -> Result<Arc<AtomicBool>, String> {
    let mut queues = Vec::new();
    for i in 0..EXHAUSTED_QUEUES {
        queues.push(lock(session).cgnat_exhaustion_queue(i)?);
    }
    let on = Arc::new(AtomicBool::new(true));
    for (i, mut q) in queues.into_iter().enumerate() {
        let (on, h) = (on.clone(), health.clone());
        health
            .spawn(&format!("cgnat-icmp-{i}"), move || {
                while on.load(Ordering::Acquire) && !h.stopping() {
                    if let Err(e) = q.serve(WAIT) {
                        h.error(format!("exhaustion queue {i}: {e}"));
                        on.store(false, Ordering::Release);
                    }
                }
            })
            .map_err(|e| format!("thread: {e}"))?;
    }
    Ok(on)
}

fn run(session: &Shared, health: &super::Health) {
    let mut running: Option<Arc<AtomicBool>> = None;
    let mut warned = false;
    loop {
        health.beat();
        let wanted = lock(session).cgnat_exhaustion_wanted();
        if !wanted {
            if let Some(on) = running.take() {
                on.store(false, Ordering::Release);
            }
            health.disabled(Some("no CGNAT pool, or icmp_unreachable off (ip.firewall.cgnat.set)"));
        } else {
            health.disabled(None);
            // A thread that failed turned its flag off: start them again.
            if running.as_ref().is_some_and(|on| !on.load(Ordering::Acquire)) {
                running = None;
            }
            if running.is_none() {
                match serve_all(session, health) {
                    Ok(on) => {
                        running = Some(on);
                        health.clear_error();
                        warned = false;
                    }
                    Err(e) => {
                        // The lab, or a kernel without nfnetlink_queue.
                        if !warned {
                            log::info!("cgnat-icmp: no exhaustion queues: {e}");
                            warned = true;
                        }
                        health.error(format!("no exhaustion queues: {e}"));
                    }
                }
            }
        }
        if !health.sleep(LOOK) {
            break;
        }
    }
    if let Some(on) = running {
        on.store(false, Ordering::Release);
    }
}
