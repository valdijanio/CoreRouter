//! XDP CGNAT fast path (G2.5b): keeps the XDP flow map in step with
//! conntrack. The kernel's CGNAT (nftables, G2.3) NATs the first packets
//! of every connection; when conntrack says a connection is established
//! (both directions seen), its two directions go into the map and XDP
//! translates and forwards the rest. Destroyed connections leave the map;
//! connections whose packets XDP carried get their conntrack timeout
//! renewed (conntrack sees none of those packets). After lost events, or a
//! new map (XDP reloaded), the whole table is read again.
//!
//! Outside the session lock except to read the config and store the
//! status once a second.

use std::time::{Duration, Instant};

use corerouter_engine::xdp::XdpNatStatus;
use corerouter_engine::{Shared, lock};
use corerouter_hal::conntrack::Event;
use corerouter_hal::xdp_nat::{Action, Book, MAX_CARRIED, NatLink};

/// How long one wait for conntrack events lasts.
const WAIT_MS: u32 = 100;
/// Events taken per wait.
const BATCH: usize = 4096;
/// How often carried connections get their conntrack timeout renewed.
const RENEW: Duration = Duration::from_secs(2);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "xdp-nat",
    flags: &[],
    topic: "firewall",
    enable: "ip.firewall.xdp.set fast_nat=yes",
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

/// The service's state while the fast path is on.
struct Sync {
    link: Box<dyn NatLink>,
    book: Book,
    /// The map generation and lost-event count the book matches.
    seen: Option<(u64, u64)>,
    last_renew: Instant,
    st: XdpNatStatus,
}

impl Sync {
    fn apply(&mut self, a: &Action) {
        let r = match a {
            Action::Install(f) => self.link.install(f).map(|()| self.st.installed += 1),
            Action::Remove(f) => self.link.remove(f).map(|()| self.st.removed += 1),
        };
        if let Err(e) = r {
            self.st.last_error = Some(e.to_string());
        }
    }

    /// One round: resync when needed, events, renewals.
    fn step(&mut self, generation: u64) {
        let lost = self.link.lost();
        if self.seen != Some((generation, lost)) {
            self.book.clear();
            match self.link.table() {
                Ok(table) => {
                    for a in self.book.resync(&table) {
                        self.apply(&a);
                    }
                    self.st.resyncs += 1;
                    self.seen = Some((generation, lost));
                }
                Err(e) => self.st.last_error = Some(e.to_string()),
            }
        }
        let mut events: Vec<Event> = Vec::new();
        match self.link.events(WAIT_MS, BATCH, &mut events) {
            Ok(()) => {
                for e in &events {
                    if let Some(a) = self.book.event(e) {
                        self.apply(&a);
                    }
                }
            }
            Err(e) => self.st.last_error = Some(e.to_string()),
        }
        if self.last_renew.elapsed() >= RENEW {
            self.last_renew = Instant::now();
            let link = &self.link;
            let due = self.book.due(&|f| link.used(f));
            if !due.is_empty() {
                match self.link.refresh(&due) {
                    Ok(n) => self.st.renewed += n as u64,
                    Err(e) => self.st.last_error = Some(e.to_string()),
                }
            }
        }
        self.st.carried = self.book.len();
        self.st.lost = lost;
    }
}

fn run(session: &Shared, health: &super::Health) {
    let mut sync: Option<Sync> = None;
    let mut cache: Option<(u32, bool)> = None;
    let mut last_status = Instant::now();
    let mut retry = Instant::now();
    while !health.stopping() {
        health.beat();
        {
            let s = lock(session);
            let rev = s.store().current_revision();
            if cache.is_none_or(|c| c.0 != rev) {
                cache = Some((rev, s.store().running().ip.xdp.fast_nat));
            }
        }
        let on = cache.is_some_and(|c| c.1);
        if !on {
            if sync.take().is_some() {
                health.event("stopped");
            }
            health.disabled(Some("the CGNAT fast path is off (ip.firewall.xdp.set fast_nat=yes)"));
            lock(session).xdp_nat_set_status(XdpNatStatus {
                idle: Some("off".into()),
                ..XdpNatStatus::default()
            });
            if !health.sleep(Duration::from_secs(1)) {
                break;
            }
            continue;
        }
        health.disabled(None);
        if sync.is_none() && Instant::now() >= retry {
            let link = lock(session).xdp_nat_link();
            match link {
                Ok(link) => {
                    health.clear_error();
                    health.event("following conntrack");
                    sync = Some(Sync {
                        link,
                        book: Book::new(MAX_CARRIED),
                        seen: None,
                        last_renew: Instant::now(),
                        st: XdpNatStatus::default(),
                    });
                }
                Err(e) => {
                    retry = Instant::now() + Duration::from_secs(10);
                    health.error(&e);
                    lock(session).xdp_nat_set_status(XdpNatStatus {
                        last_error: Some(e),
                        ..XdpNatStatus::default()
                    });
                }
            }
        }
        let Some(sy) = sync.as_mut() else {
            if !health.sleep(Duration::from_secs(1)) {
                break;
            }
            continue;
        };
        match sy.link.generation() {
            None => {
                // XDP is not loaded (no interface yet): nothing to fill.
                sy.book.clear();
                sy.seen = None;
                sy.st.carried = 0;
                sy.st.idle =
                    Some("XDP is not attached anywhere (ip.firewall.xdp.interface.add)".into());
                if !health.sleep(Duration::from_secs(1)) {
                    break;
                }
            }
            Some(g) => {
                sy.st.idle = None;
                sy.step(g);
            }
        }
        if last_status.elapsed() >= Duration::from_secs(1) {
            last_status = Instant::now();
            let st = sy.st.clone();
            if let Some(e) = &st.last_error {
                health.error(e);
            }
            lock(session).xdp_nat_set_status(st);
        }
    }
}
