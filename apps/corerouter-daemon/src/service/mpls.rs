//! MPLS label table (G3.5): reads the kernel's labels for
//! `mpls.forwarding-table.page` on this service's own thread, never under
//! the session lock, and only while someone looks (a page asked in the
//! last 10 s, `corerouter_engine::mpls::WANTED_SECS`).
//!
//! Why one thread: the dump is one netlink request the kernel answers in
//! order (100 000 labels in ~tens of ms, **medido**, docs/changes/G3.5.md);
//! splitting it would need several dumps of the same table. The lock is
//! taken to ask whether to read and to swap the result in (a pointer).

use std::time::Duration;

use corerouter_engine::{Shared, lock};

/// How often the table is read while wanted (the window refreshes each
/// second; LDP changes it at most a few times a second).
const TICK: Duration = Duration::from_secs(2);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "mpls",
    flags: &[],
    topic: "route",
    enable: "always on (reads only while the forwarding table is open)",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| run(&session, health)))
}

fn run(session: &Shared, health: &super::Health) -> Result<(), String> {
    let reader = corerouter_engine::mpls::reader(&mut lock(session));
    let mut reader = match reader {
        Ok(r) => r,
        Err(e) => {
            // The lab reads its table in memory, under the page itself.
            health.disabled(Some(&e.to_string()));
            while health.sleep(Duration::from_secs(60)) {
                health.beat();
            }
            return Ok(());
        }
    };
    loop {
        health.beat();
        if corerouter_engine::mpls::wanted(&lock(session)) {
            let read = reader.routes().map_err(|e| e.to_string());
            match &read {
                Ok(_) => health.clear_error(),
                Err(e) => health.error(e),
            }
            corerouter_engine::mpls::set_kernel(&mut lock(session), read);
        }
        if !health.sleep(TICK) {
            return Ok(());
        }
    }
}
