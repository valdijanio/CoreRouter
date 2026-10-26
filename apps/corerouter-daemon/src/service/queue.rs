//! Queues (G4.9b) as a service: once a second, the plan of the running
//! config and the bound DHCP leases goes to the data plane when it changed
//! (`Session::queue_sync`: the tc programs, `fq`, the queue maps), and the
//! counters come back for `queue.simple.list`. The sessions' queues ride
//! on their session entries (the `pppoe` and `ipoe` services, with
//! `corerouter_engine::queue::shape_of`).

use std::time::Duration;

use corerouter_engine::{Shared, lock};

const TICK: Duration = Duration::from_secs(1);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "queue",
    flags: &[],
    topic: "system",
    enable: "queue.simple.add …, ip.dhcp-server.network.set rate_limit=…, or a shaped ppp profile",
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

fn run(session: &Shared, health: &super::Health) {
    let mut reported: Option<String> = None;
    while health.sleep(TICK) {
        health.beat();
        let mut s = lock(session);
        if s.queue_sync() {
            let (n, err) = {
                let rt = s.ext::<corerouter_engine::queue::ShaperRuntime>();
                (
                    rt.and_then(|r| r.applied.as_ref()).map_or(0, |p| p.queues.len()),
                    rt.and_then(|r| r.error.clone()),
                )
            };
            match &err {
                Some(e) => health.error(format!("shaper: {e}")),
                None => {
                    health.clear_error();
                    health.event(format!("{n} queue(s) in the data plane"));
                }
            }
            // Say a new failure once in the router's log.
            if err.is_some() && err != reported {
                s.log_event(
                    &["system", "warning"],
                    "queue",
                    format!("Filas: o plano de dados recusou: {}", err.clone().unwrap_or_default()),
                    serde_json::json!({}),
                );
            }
            reported = err;
        }
    }
}

#[cfg(test)]
mod tests {
    use corerouter_engine::queue::shape_of;
    use corerouter_model::ppp::Effective;
    use corerouter_model::queue::{DownloadMode, Queues};

    #[test]
    fn profiles_choose_their_queue() {
        let q = Queues::default();
        let mut e = Effective {
            queue_type: "cake-default".into(),
            ..Effective::default()
        };
        assert!(matches!(shape_of(&q, &e), Some(corerouter_hal::queue::Kind::Codel { interval_us: 100_000, .. })));
        e.queue_type = "default-small".into();
        assert_eq!(shape_of(&q, &e), Some(corerouter_hal::queue::Kind::Fifo { limit_bytes: 10 * 1514 }));
        e.download_mode = DownloadMode::Policer;
        assert_eq!(shape_of(&q, &e), None);
    }
}
