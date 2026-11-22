//! MPLS label table (G3.5): reads the kernel's labels for
//! `mpls.forwarding-table.page` on this service's own thread, never under
//! the session lock, and only while someone looks (a page asked in the
//! last 10 s, `corerouter_engine::mpls::WANTED_SECS`).
//!
//! It also builds the forwarding table's lines from the read (FEC joins,
//! reasons, MTU check, search text: ~22 ms for 100 000 labels, **medido**)
//! so a page under the lock only filters and cuts (~2 ms).
//!
//! Why one thread: the dump is one netlink request the kernel answers in
//! order; splitting it would need several dumps of the same table, and
//! one read every 2 s is far from a core. The lock is taken to ask whether
//! to read, to copy the inputs (pointers) and to swap the result in.

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
            health.idle_until_shutdown();
            return Ok(());
        }
    };
    loop {
        health.beat();
        if corerouter_engine::mpls::wanted(&lock(session)) {
            match reader.routes() {
                Ok(routes) => {
                    health.clear_error();
                    // The lines too, here: ~22 ms for 100 k labels that
                    // the page would otherwise spend under the lock.
                    let inputs = corerouter_engine::mpls::line_inputs(&lock(session));
                    let lines = corerouter_engine::mpls::build_lines(&inputs, &routes);
                    corerouter_engine::mpls::set_kernel_lines(&mut lock(session), routes, lines);
                }
                Err(e) => {
                    health.error(e.to_string());
                    corerouter_engine::mpls::set_kernel(&mut lock(session), Err(e.to_string()));
                }
            }
        }
        if !health.sleep(TICK) {
            return Ok(());
        }
    }
}
