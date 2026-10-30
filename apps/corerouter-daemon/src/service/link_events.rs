//! Link events (G1.3d): the kernel's `RTM_NEWLINK`/`RTM_DELLINK`, so a
//! port gone and back between two of the clock's polls (a fast replug, a
//! USB driver reset, ~1.7 s **medido**) gets its configuration back at once
//! instead of never: the poll saw the same name both times. The engine's
//! poll tells a replug by the new link index; this only makes it look now.
//!
//! The socket is read with no lock held. Events that come together (a
//! commit that touches many links, a card and its VLANs) are gathered for
//! [`SETTLE`] and handed over in one call, so the session lock is taken once
//! per burst, not once per event. One thread: the kernel queues the events
//! in order on one socket, and reading one costs microseconds (**medido**,
//! 3.4 µs per drain); the work is the engine's poll, whose kernel dump is
//! read with the lock released too (G1.3f): the lock is held only to fold
//! the links in.

use std::time::Duration;

#[cfg(target_os = "linux")]
use corerouter_engine::lock;
use corerouter_engine::Shared;

/// How long one read waits (the heartbeat in between).
#[cfg(target_os = "linux")]
const WAIT_MS: u16 = 1000;
/// Events of one burst are gathered this long before the engine looks.
#[cfg(target_os = "linux")]
const SETTLE: Duration = Duration::from_millis(50);
const IDLE: Duration = super::IDLE_BEAT;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "link-events",
    flags: &[],
    topic: "interface",
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
    idle(health, "no link events on this platform (the 1 s poll looks)")
}

#[cfg(target_os = "linux")]
fn run(session: &Shared, health: &super::Health) -> Result<(), String> {
    use corerouter_hal_linux::link_events::{Events, LinkEvents, MAX_NAMES};
    if !lock(session).backend().starts_with("linux") {
        return idle(health, "the virtual lab has no kernel links");
    }
    let mut feed = LinkEvents::open().map_err(|e| e.to_string())?;
    health.event("listening for link changes");
    let mut lost = 0u64;
    let mut handled = 0u64;
    while !health.stopping() {
        health.beat();
        let first = feed.wait(WAIT_MS).map_err(|e| e.to_string())?;
        if first == Events::None {
            continue;
        }
        // The rest of the burst, still with no lock.
        let mut all = first;
        let until = std::time::Instant::now() + SETTLE;
        while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
            let ms = u16::try_from(left.as_millis()).unwrap_or(0).max(1);
            all = match (feed.wait(ms).map_err(|e| e.to_string())?, all) {
                (Events::None, a) => {
                    all = a;
                    break;
                }
                (Events::Names(more), Events::Names(mut names)) => {
                    names.extend(more);
                    if names.len() > MAX_NAMES { Events::Lost } else { Events::Names(names) }
                }
                (Events::Names(more), Events::None) => Events::Names(more),
                _ => Events::Lost,
            };
        }
        match all {
            Events::Names(names) => {
                let names: Vec<String> = names.into_iter().collect();
                look(session, Some(&names));
                // `system.service.print`: what the feed last handled (the
                // netns test waits for its port here, not on a clock).
                handled = handled.saturating_add(1);
                let shown: Vec<&str> = names.iter().take(8).map(String::as_str).collect();
                health.event(format!("link changes handled: {handled} (last: {})", shown.join(", ")));
            }
            Events::Lost => {
                lost = lost.saturating_add(1);
                health.error(format!("the kernel dropped link events ({lost} times): looked at every port"));
                look(session, None);
            }
            Events::None => {}
        }
    }
    Ok(())
}

/// `Session::link_events`, with the links read while the session is
/// unlocked (G1.3f): the lock is held for the check and the fold, not for
/// the kernel dump.
#[cfg(target_os = "linux")]
fn look(session: &Shared, names: Option<&[String]>) {
    let reader = {
        let s = lock(session);
        if !s.link_events_wanted(names) {
            return;
        }
        s.link_reader()
    };
    let links = reader.map(|mut r| r.read());
    lock(session).link_events_sampled(links);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};

    #[test]
    fn idles_on_the_virtual_lab() {
        let session = shared(Session::virtual_lab());
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        health.stop();
        assert!(run(&session, &health).is_ok());
        assert!(health.snapshot().disabled.is_some_and(|d| d.contains("virtual lab")));
    }
}
