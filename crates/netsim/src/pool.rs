//! Worker threads that run routers in parallel inside a window (native
//! targets only). They live as long as the simulation: starting threads
//! for every window cost more than the window's work (**medido**: 500
//! routers took 11.3 s with a scope per window against 4.9 s on one
//! thread). A batch of routers moves to a worker (`mem::take`: a copy of
//! the struct, no allocation) and comes back at the barrier, so nothing is
//! shared and no lock is held while routers run.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use crate::Time;
use crate::node::Node;

type Batch = Vec<(usize, Node)>;

pub(crate) struct Pool {
    jobs: Vec<Sender<(Batch, Time)>>,
    done: Receiver<Batch>,
    _threads: Vec<JoinHandle<()>>,
}

impl Pool {
    /// `n` workers, or `None` if not even one could start.
    pub(crate) fn new(n: usize) -> Option<Pool> {
        let (done_tx, done) = channel::<Batch>();
        let mut jobs = Vec::new();
        let mut threads = Vec::new();
        for k in 0..n {
            let (tx, rx) = channel::<(Batch, Time)>();
            let back = done_tx.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("netsim-{k}"))
                .spawn(move || work(&rx, &back));
            if let Ok(h) = spawned {
                jobs.push(tx);
                threads.push(h);
            }
        }
        (!jobs.is_empty()).then_some(Pool {
            jobs,
            done,
            _threads: threads,
        })
    }

    pub(crate) fn size(&self) -> usize {
        self.jobs.len()
    }

    /// Run every batch to `end` (one per worker); the routers come back in
    /// any order, with their index.
    pub(crate) fn run(&self, batches: Vec<Batch>, end: Time) -> Batch {
        let mut out = Vec::new();
        let mut sent = 0;
        for (batch, tx) in batches.into_iter().zip(&self.jobs) {
            if batch.is_empty() {
                continue;
            }
            match tx.send((batch, end)) {
                Ok(()) => sent += 1,
                // The worker is gone: run them here.
                Err(std::sync::mpsc::SendError((mut batch, _))) => {
                    for (_, n) in &mut batch {
                        n.run(end);
                    }
                    out.append(&mut batch);
                }
            }
        }
        for _ in 0..sent {
            match self.done.recv() {
                Ok(mut b) => out.append(&mut b),
                Err(_) => break,
            }
        }
        out
    }
}

fn work(rx: &Receiver<(Batch, Time)>, back: &Sender<Batch>) {
    while let Ok((mut batch, end)) = rx.recv() {
        // Node::run never panics (no panics in production code); were one
        // to, the batch still goes back so the barrier does not wait forever.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for (_, n) in &mut batch {
                n.run(end);
            }
        }));
        if back.send(batch).is_err() {
            break;
        }
    }
}
