//! The CGNAT usage scan (G2.7b) as a service: every
//! [`SCAN_SECS`](corerouter_engine::cgnat_blocks::SCAN_SECS) it reads the
//! conntrack table **outside the session lock**, one connection at a time,
//! into a compact [`Usage`](corerouter_engine::cgnat_blocks::Usage) (12
//! bytes per CGNAT connection, sorted), and only then takes the lock to
//! hand it over: growing and releasing blocks, alerts, the set of nearly
//! full subscribers (G2.7) and the capacity peaks are O(subscribers)
//! there. Without this service (the lab) the session tick reads by itself.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_engine::cgnat_blocks::{SCAN_SECS, UsageBuilder};
use corerouter_engine::{Shared, lock};

pub(crate) const SERVICE: super::Service = super::Service {
    name: "cgnat-scan",
    flags: &[],
    topic: "cgnat",
    enable: "ip.firewall.cgnat.pool.add …",
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
    let mut warned = false;
    loop {
        health.beat();
        let scanner = {
            let s = lock(session);
            if s.cgnat_scan_wanted() {
                Some(s.conntrack_scanner())
            } else {
                None
            }
        };
        match scanner {
            None => health.disabled(Some("no CGNAT pool (ip.firewall.cgnat.pool.add)")),
            Some(Err(e)) => {
                // The lab: its tick reads for itself.
                if !warned {
                    log::info!("cgnat-scan: no conntrack scanner: {e}");
                    warned = true;
                }
                health.disabled(Some("no conntrack scanner on this backend (the tick reads)"));
            }
            Some(Ok(mut scanner)) => {
                health.disabled(None);
                let mut b = UsageBuilder::default();
                match scanner.scan(&mut |c| b.add(c)) {
                    Ok(stats) => {
                        let usage = b.finish(stats);
                        lock(session).cgnat_scan_feed(unix_now(), usage);
                        health.clear_error();
                    }
                    Err(e) => health.error(format!("conntrack read: {e}")),
                }
            }
        }
        if !health.sleep(Duration::from_secs(SCAN_SECS)) {
            break;
        }
    }
}
