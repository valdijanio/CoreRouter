//! System › Install to disk (G1.6y): `--live` tells the daemon it runs from
//! the ISO, not installed (`corerouter_engine::live`).

use corerouter_engine::{Shared, lock};
use std::time::Duration;

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

const TICK: Duration = Duration::from_secs(10);

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session: Shared = ctx.session.clone();
    let live = ctx.flag("--live").is_some();
    if live {
        corerouter_engine::live::set(&mut lock(&session));
        log::warn!("live image: not installed; only the network test and the install can change anything");
    }
    Ok(Box::new(move |health: &super::Health| {
        if !live {
            health.disabled(Some("this router is installed"));
        }
        health.beat();
        while health.sleep(TICK) {
            health.beat();
        }
        Ok(())
    }))
}
