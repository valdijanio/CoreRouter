//! System › Resources and health (G4.8a): reads the machine every 5 s —
//! every second while someone looks at it (a GUI window, the top bar's
//! readout, a command in the last 15 s) — with its own sampler, **outside**
//! the session lock (`/proc` and `/sys` reads take ~0,5 ms, the sensors
//! ~30 ms every 10 s and the process list ~5 ms, **medido**), then hands
//! the reading to the engine under the lock, which only does arithmetic:
//! loads, rates, the 10-minute history of the sparklines and the health
//! checks, whose changes go to the router's log (the path of the G4.5
//! bandwidth alerts: syslog and ClickHouse through the logging rules).

use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_hal::system_resource::{ResourceSampler, Want};

pub(crate) const SERVICE: super::Service = super::Service {
    name: "health",
    flags: &[],
    topic: "system",
    enable: "always on",
    depends: &[],
    start,
};

/// Between two readings when nobody looks, and when someone does.
const SLOW: Duration = Duration::from_secs(5);
const FAST: Duration = Duration::from_secs(1);
const SLICE: Duration = Duration::from_millis(250);

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        let sampler = lock(&session).resource_sampler();
        let mut sampler = match sampler {
            Ok(s) => s,
            Err(why) => {
                health.disabled(Some(&why));
                while health.sleep(SLOW) {
                    health.beat();
                }
                return Ok(());
            }
        };
        let t0 = Instant::now();
        let mut last: Option<Instant> = None;
        while health.sleep(SLICE) {
            health.beat();
            let wanted = lock(&session).resource_wanted();
            let every = if wanted.fast { FAST } else { SLOW };
            if last.is_some_and(|l| l.elapsed() < every) {
                continue;
            }
            last = Some(Instant::now());
            let checks = once(&session, sampler.as_mut(), wanted.processes, t0);
            health.event(format!("{} checks, {} not ok", checks.0, checks.1));
        }
        Ok(())
    }))
}

/// One reading: sampled without the lock, ingested and judged with it.
/// Returns (checks, checks not ok).
fn once(session: &Shared, sampler: &mut dyn ResourceSampler, processes: bool, t0: Instant) -> (usize, usize) {
    let now_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let sample = sampler.sample(Want {
        processes,
        now_ms: Some(now_ms),
    });
    let mut s = lock(session);
    s.resource_ingest(sample);
    let checks = s.health_alerts();
    let bad = checks
        .iter()
        .filter(|c| c.severity.as_str() == "warning" || c.severity.as_str() == "error")
        .count();
    (checks.len(), bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use serde_json::json;

    #[test]
    fn readings_reach_the_commands_and_alerts_reach_the_log() {
        let s = shared(Session::virtual_lab());
        let mut sampler = lock(&s).resource_sampler().unwrap();
        let t0 = Instant::now() - Duration::from_secs(3600);
        // Two minutes of readings, 5 s apart, on the lab's clock.
        for i in 0..24u64 {
            let sample = sampler.sample(Want { processes: i % 2 == 0, now_ms: Some(i * 5000) });
            let mut g = lock(&s);
            g.resource_ingest(sample);
            g.health_alerts();
        }
        let _ = once(&s, sampler.as_mut(), true, t0);
        let v = lock(&s).execute("system.resource.print", &json!({})).unwrap();
        assert!(v["cpu_load"].as_f64().is_some(), "{v}");
        assert!(v["history"].as_array().unwrap().len() >= 20);
        let c = lock(&s).execute("system.health.check", &json!({})).unwrap();
        let nic = c["checks"].as_array().unwrap().iter().find(|c| c["key"] == "nic.errors").unwrap().clone();
        assert_eq!(nic["severity"], "warning", "the lab's ether4 has a bad cable: {nic}");
        let log = lock(&s).execute("log.print", &json!({})).unwrap();
        let text = log.to_string();
        assert!(text.contains("Saúde: NIC errors"), "{text}");
    }

    #[test]
    fn the_service_reads_fast_only_while_someone_looks() {
        let s = shared(Session::virtual_lab());
        assert!(!lock(&s).resource_wanted().fast);
        lock(&s).tick(1_800_000_000);
        lock(&s).execute("system.resource.print", &json!({})).unwrap();
        assert!(lock(&s).resource_wanted().fast);
        assert!(!lock(&s).resource_wanted().processes);
        lock(&s).execute("system.resource.process.print", &json!({})).unwrap();
        assert!(lock(&s).resource_wanted().processes);
        lock(&s).tick(1_800_000_000 + 60);
        assert!(!lock(&s).resource_wanted().fast, "15 s later nobody looks");
    }
}
