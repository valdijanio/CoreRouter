//! System › Install to disk (G1.6y): `--live` tells the daemon it runs from
//! the ISO, not installed (`corerouter_engine::live`). This service reads the
//! disks and writes the image for `system.install.*`.
//!
//! The body only ticks: reads and writes run on one worker thread at a time,
//! outside the session lock, so `print` answers and the health beats while a
//! spinning disk takes minutes. One install per machine: nothing to divide
//! here, and `corerouter_sysupdate::install` already reads, hashes and writes
//! on separate threads.

//!
//! The work is in `install/linux.rs`: the disks, `/proc` and `O_EXCL` are
//! Linux's, and only the image runs live. Elsewhere the row says so.

pub(crate) const SERVICE: super::Service = super::Service {
    name: "install",
    flags: &[super::Flag {
        name: "--live",
        value: None,
        help: "The image runs live from the installer ISO, not installed (corerouter-init passes it)",
    }],
    topic: "system",
    enable: "always on in the live image (System › Install to disk)",
    depends: &[],
    start,
};

#[cfg(target_os = "linux")]
#[path = "install/linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
use linux::start;

#[cfg(not(target_os = "linux"))]
fn start(_ctx: &super::Ctx) -> Result<super::Run, String> {
    Ok(Box::new(|health: &super::Health| {
        health.disabled(Some("the live image runs on Linux only"));
        health.beat();
        while health.sleep(super::IDLE_BEAT) {
            health.beat();
        }
        Ok(())
    }))
}
