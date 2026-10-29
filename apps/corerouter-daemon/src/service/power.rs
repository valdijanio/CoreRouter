//! `system.reboot` / `system.shutdown` (G1.6qa): carries out the request
//! the engine recorded (`corerouter_engine::power`).
//!
//! At start it decides whether this daemon may stop the machine: only on
//! the CoreRouter image, where PID 1 is corerouter-init and our parent.
//! Anywhere else (a developer's machine, a container, systemd) the
//! commands stay disabled with the reason: a signal to another PID 1 would
//! mean something else, or stop the host.
//!
//! Every [`TICK`] the body takes the request under the lock (a field read)
//! and, outside it, waits [`PAUSE`] so the client reads its answer, then
//! signals init: SIGTERM reboots, SIGUSR2 powers off (`corerouter-init`,
//! `pid1.rs`). Init stops this daemon with SIGTERM, which writes the
//! config checkpoint (G0.27), then FRR, syncs and unmounts `/config`.
//!
//! One thread, idle almost always: the work is one request in a lifetime.

use std::time::Duration;

use corerouter_engine::power::{self, Action};
use corerouter_engine::{Shared, lock};

pub(crate) const SERVICE: super::Service = super::Service {
    name: "power",
    flags: &[],
    topic: "system",
    enable: "system.reboot / system.shutdown (on the image)",
    depends: &[],
    start,
};

const TICK: Duration = Duration::from_millis(200);
/// For whoever asked to read the result before the connection goes (as
/// the package service's reboot).
const PAUSE: Duration = Duration::from_secs(1);
/// `comm` of PID 1 on the image (15 bytes: the kernel's limit, whole).
const INIT: &str = "corerouter-init";

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let support = support(
        std::fs::read_to_string("/proc/1/comm").ok().as_deref(),
        std::os::unix::process::parent_id(),
    );
    if let Err(why) = &support {
        log::info!("power: system.reboot and system.shutdown disabled: {why}");
    }
    power::set_support(&mut lock(&session), support.clone());
    Ok(Box::new(move |health: &super::Health| {
        if support.is_err() {
            health.disabled(Some("not on the CoreRouter image"));
        }
        health.beat();
        while health.sleep(if support.is_ok() { TICK } else { super::IDLE_BEAT }) {
            health.beat();
            if support.is_err() {
                continue;
            }
            let Some(req) = power::take_request(&mut lock(&session)) else {
                continue;
            };
            carry_out(&session, health, &req);
        }
        Ok(())
    }))
}

/// Whether PID 1 is corerouter-init and our parent (it restarts us and
/// stops us cleanly); else why not.
fn support(pid1_comm: Option<&str>, parent: u32) -> Result<(), String> {
    let comm = pid1_comm.map(str::trim).unwrap_or("?");
    if comm != INIT {
        return Err(format!("PID 1 is {comm}, not {INIT}: stop this machine with its own tools"));
    }
    if parent != 1 {
        return Err(format!("this daemon was not started by {INIT} (parent PID {parent})"));
    }
    Ok(())
}

fn carry_out(session: &Shared, health: &super::Health, req: &power::Request) {
    let what = req.action.as_str();
    log::warn!("power: {what} asked by {}", req.by);
    health.event(format!("{what} asked by {}", req.by));
    std::thread::sleep(PAUSE);
    if let Err(e) = signal_init(req.action) {
        let msg = format!("{what}: cannot ask init: {e}");
        log::error!("power: {msg}");
        health.error(&msg);
        lock(session).log_event(&["system", "error"], "power", msg, serde_json::Value::Null);
    }
}

#[cfg(target_os = "linux")]
fn signal_init(action: Action) -> Result<(), String> {
    use rustix::process::{Pid, Signal, kill_process};
    let sig = match action {
        Action::Reboot => Signal::TERM,
        Action::Shutdown => Signal::USR2,
    };
    kill_process(Pid::INIT, sig).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn signal_init(_: Action) -> Result<(), String> {
    Err("only on the CoreRouter image (Linux)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_under_corerouter_init_as_parent() {
        assert!(support(Some("corerouter-init\n"), 1).is_ok());
        let e = support(Some("systemd\n"), 1).unwrap_err();
        assert!(e.contains("systemd"), "{e}");
        assert!(support(Some("corerouter-init\n"), 4242).unwrap_err().contains("4242"));
        assert!(support(None, 1).is_err());
    }
}
