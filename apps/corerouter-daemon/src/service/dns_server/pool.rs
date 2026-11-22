//! The workers of the cache misses (G4.1r): a miss waits on the network in
//! a thread of its own, at most `max_concurrent_queries` of them, as
//! before; the threads now stay for the next miss instead of being created
//! and torn down for each one.
//!
//! Why: with a fast upstream a thread per miss cost ~210 µs of CPU per
//! answer (lab VM; ~67 µs with the pool) and capped the misses at ~13 000/s on 4 CPUs; `pthread_create`,
//! the guard page and stack (`mmap`/`mprotect`/`munmap`) and the thread's
//! malloc arena were ~60 % of the profile, the exchange with the server
//! ~13 % (`docs/dns-stress.md`, **medido**).
//!
//! A job goes to an idle worker; with none idle, a new worker starts (the
//! caller's gate keeps them at most `max_concurrent_queries`). A worker
//! idle for [`IDLE_EXIT`] ends, so a burst does not keep a thousand threads
//! for the daemon's life. Invariant: a queued job always has an idle
//! worker woken for it or a new worker started for it (jobs ≤ idle,
//! counting the ones woken that have not taken a job yet).

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

/// An idle worker ends after this long without a job.
const IDLE_EXIT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(10)
};

pub(super) type Job = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct State {
    jobs: VecDeque<Job>,
    /// Workers waiting for a job (woken ones included until they look).
    idle: usize,
    /// Workers alive.
    live: usize,
}

#[derive(Default)]
pub(super) struct Pool {
    state: Mutex<State>,
    wake: Condvar,
}

impl Pool {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `job` on a worker. `Err` when no thread could start: the job
    /// stays queued for a worker that is alive (if none is, the queue is
    /// dropped and those clients time out); the caller answers SERVFAIL
    /// now so its client tries another server at once.
    pub(super) fn submit(self: &Arc<Self>, job: Job) -> Result<(), ()> {
        let mut st = self.lock();
        st.jobs.push_back(job);
        if st.jobs.len() <= st.idle {
            drop(st);
            self.wake.notify_one();
            return Ok(());
        }
        st.live += 1;
        drop(st);
        let pool = self.clone();
        match thread::Builder::new()
            .name("dns-query".into())
            .spawn(move || pool.work())
        {
            Ok(_) => Ok(()),
            Err(e) => {
                log::warn!("DNS: no thread for a query: {e}");
                let mut st = self.lock();
                st.live = st.live.saturating_sub(1);
                if st.live == 0 {
                    st.jobs.clear();
                }
                Err(())
            }
        }
    }

    fn work(&self) {
        let mut st = self.lock();
        loop {
            if let Some(job) = st.jobs.pop_front() {
                drop(st);
                job();
                st = self.lock();
                continue;
            }
            st.idle += 1;
            let (back, waited) = self
                .wake
                .wait_timeout(st, IDLE_EXIT)
                .unwrap_or_else(PoisonError::into_inner);
            st = back;
            st.idle = st.idle.saturating_sub(1);
            if waited.timed_out() && st.jobs.is_empty() {
                st.live = st.live.saturating_sub(1);
                return;
            }
        }
    }

    /// Workers alive and idle (tests, and the thread count it explains).
    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize) {
        let st = self.lock();
        (st.live, st.idle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::channel;
    use std::time::Instant;

    fn until(what: &str, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < end, "{what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn workers_are_reused_not_one_per_job() {
        let pool = Arc::new(Pool::default());
        let (tx, rx) = channel();
        for i in 0..200 {
            let tx = tx.clone();
            pool.submit(Box::new(move || tx.send(i).unwrap())).unwrap();
            // One at a time: the same worker takes each next job.
            assert_eq!(rx.recv().unwrap(), i);
            until("the worker is idle again", || pool.counts().1 == 1);
        }
        assert_eq!(pool.counts().0, 1, "one thread did all 200 jobs");
    }

    #[test]
    fn concurrent_jobs_get_their_own_workers() {
        let pool = Arc::new(Pool::default());
        let n = 16;
        let gate = Arc::new(Barrier::new(n + 1));
        let ran = Arc::new(AtomicUsize::new(0));
        for _ in 0..n {
            let (gate, ran) = (gate.clone(), ran.clone());
            pool.submit(Box::new(move || {
                // Every job waits for all the others: they must run at once.
                gate.wait();
                ran.fetch_add(1, Ordering::SeqCst);
            }))
            .ok()
            .unwrap();
        }
        gate.wait();
        until("all ran", || ran.load(Ordering::SeqCst) == n);
        assert_eq!(pool.counts().0, n);
        // A second wave reuses them.
        let gate = Arc::new(Barrier::new(n + 1));
        until("all idle", || pool.counts().1 == n);
        for _ in 0..n {
            let gate = gate.clone();
            pool.submit(Box::new(move || {
                gate.wait();
            }))
            .ok()
            .unwrap();
        }
        gate.wait();
        assert_eq!(pool.counts().0, n, "no new thread for the second wave");
    }

    #[test]
    fn idle_workers_end() {
        let pool = Arc::new(Pool::default());
        let (tx, rx) = channel();
        pool.submit(Box::new(move || tx.send(()).unwrap())).unwrap();
        rx.recv().unwrap();
        until("the idle worker ended", || pool.counts() == (0, 0));
        // And the pool still works.
        let (tx, rx) = channel();
        pool.submit(Box::new(move || tx.send(()).unwrap())).unwrap();
        rx.recv().unwrap();
    }
}
