//! G4.3hh: the slow path's routes to `bng0`, one thread for the whole
//! `pppoe` service.
//!
//! The kernel adds an IPv4 route in ≈ 1,3 µs under the namespace's RTNL
//! lock, one at a time. Eight workers each sending their own batches were
//! slower than one (100 000 routes: 221 ms against 132 ms, **medido**,
//! `hal-linux/tests/netns_routes_batch.rs`), and a worker that waited for
//! its share of a takeover stopped reading its subscribers' frames for
//! that long. So the workers queue their round's routes here and go on;
//! this thread merges what is queued into big batches.
//!
//! The queue holds [`QUEUE`] rounds. Full ("busy"), a worker keeps its
//! routes and offers them again next round, in order (see
//! `pppoe.rs::flush`). The routes of one worker stay in its order; two
//! workers never touch one address at the same time (an address is held
//! by one session).
#![cfg(target_os = "linux")]

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use corerouter_engine::{Shared, lock};
use corerouter_hal_linux::pppoe_io::{RouteOp, SlowTx};
use serde_json::json;

/// Rounds of routes waiting at most (each a worker's round).
pub(crate) const QUEUE: usize = 1024;
/// Routes in one merged apply at most (≈ 130 ms of kernel work).
const MERGE: usize = 100_000;

/// One worker's round of routes.
pub(crate) struct Job {
    pub ops: Vec<RouteOp>,
    /// They are a takeover's (its timeline marks when they are in).
    pub takeover: bool,
}

/// Start the thread; it ends when every sender is gone.
pub(crate) fn spawn(
    tx: SlowTx,
    session: Shared,
    one_by_one: bool,
) -> std::io::Result<SyncSender<Job>> {
    let (send, recv) = sync_channel::<Job>(QUEUE);
    std::thread::Builder::new()
        .name("pppoe-routes".into())
        .spawn(move || run(tx, &recv, &session, one_by_one))?;
    Ok(send)
}

fn run(mut tx: SlowTx, recv: &Receiver<Job>, session: &Shared, one_by_one: bool) {
    let mut ops: Vec<RouteOp> = Vec::new();
    // (end of the job's ops in `ops`, takeover)
    let mut jobs: Vec<(usize, bool)> = Vec::new();
    while let Ok(first) = recv.recv() {
        ops.clear();
        jobs.clear();
        let mut next = Some(first);
        while let Some(j) = next.take() {
            ops.extend(j.ops);
            jobs.push((ops.len(), j.takeover));
            if ops.len() < MERGE {
                next = recv.try_recv().ok();
            }
        }
        let n = ops.len();
        let (done, refused) = match tx.apply_routes(&ops, one_by_one) {
            Ok(a) => (a.done, a.refused),
            Err(e) => {
                log(session, format!("PPPoE: rotas para bng0 ({n}): {e}"));
                (0, Vec::new())
            }
        };
        if let Some(&(i, code)) = refused.first() {
            let what = ops.get(i).map(|r| format!("{}/{}", r.dst, r.len)).unwrap_or_default();
            log(
                session,
                format!(
                    "PPPoE: {} de {n} rotas para bng0 recusadas pelo kernel (a primeira, {what}: {})",
                    refused.len(),
                    std::io::Error::from_raw_os_error(code)
                ),
            );
        }
        if done == 0 && refused.is_empty() && n > 0 {
            continue;
        }
        // A takeover's jobs: their routes in, the ones still refused.
        let mut start = 0;
        for &(end, takeover) in &jobs {
            if takeover {
                let bad = refused.iter().filter(|(i, _)| (start..end).contains(i)).count();
                super::ppp_ha::routes_installed(end - start - bad, bad);
            }
            start = end;
        }
    }
}

fn log(session: &Shared, text: String) {
    lock(session).log_event(&["ppp", "warning"], "pppoe", text, json!({}));
}
