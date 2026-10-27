//! `/radius` (G4.3j): the AAA service, under the supervisor. At start it
//! registers the driver's handle (`radius_aaa::Aaa`) in the session as the
//! engine's `AaaBackend`: `radius.monitor` and `radius.test` read and use
//! it, and so will PPP (G4.3d), IPoE (G4.3f) and the router's login.
//!
//! The body runs the driver on a helper thread and, every tick, hands it the
//! running `/radius`, `/radius incoming` and `/ppp aaa` (the driver keeps
//! what did not change) and writes its log lines to the router's log (topic
//! `radius`). The session is locked only for those two short steps, never
//! while the network is waited on.

use std::sync::Arc;
use std::time::Duration;

use corerouter_engine::{Shared, lock};
use corerouter_model::service::Listen;
use serde_json::json;

use super::radius_aaa::{self, AaaConfig, Aaa, Inbox};

const TICK: Duration = Duration::from_millis(250);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "radius",
    flags: &[],
    topic: "radius",
    enable: "radius.add address=… service=ppp secret=…",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let (aaa, inbox) = radius_aaa::channel();
    lock(&session).set_aaa_backend(Arc::new(aaa.clone()));
    // G4.3hb: unclaimed CoA/DM to the other BNG of a pair, and its to ours.
    aaa.set_forward(Some(Arc::new(super::ppp_ha::PeerForward)));
    super::ppp_ha::set_aaa(Some(aaa.clone()));
    Ok(Box::new(move |health: &super::Health| {
        run(&session, &aaa, &inbox, health)
    }))
}

fn config(session: &Shared) -> AaaConfig {
    let s = lock(session);
    let cfg = s.store().running();
    AaaConfig {
        servers: cfg.radius.servers.clone(),
        incoming: cfg.radius.incoming.clone(),
        ppp: cfg.ppp.aaa.clone(),
        nas_identifier: cfg.system.identity.clone(),
    }
}

fn run(session: &Shared, aaa: &Aaa, inbox: &Arc<Inbox>, health: &super::Health) -> Result<(), String> {
    let me = aaa.clone();
    let rx = inbox.clone();
    let stop = health.clone();
    let driver = health
        .spawn("radius-aaa", move || {
            radius_aaa::run(&me, &rx, &|| stop.stopping());
        })
        .map_err(|e| format!("cannot start the RADIUS driver: {e}"))?;
    let mut last: Option<AaaConfig> = None;
    let result = loop {
        health.beat();
        let cfg = config(session);
        if last.as_ref() != Some(&cfg) {
            aaa.reload(cfg.clone());
            last = Some(cfg.clone());
        }
        let logs = aaa.take_logs();
        if !logs.is_empty() {
            let mut s = lock(session);
            for l in logs {
                s.log_event(
                    &["radius", l.level],
                    corerouter_engine::logging::DAEMON,
                    l.message,
                    json!({}),
                );
            }
        }
        if let Some(b) = radius_aaa::rcvbuf() {
            let mut s = lock(session);
            if let Some(t) = s.ext_mut::<corerouter_engine::health_check::SocketBuffers>() {
                t.sockets.insert("radius".into(), b);
            }
        }
        let st = corerouter_engine::radius::AaaBackend::status(aaa);
        match &st.incoming.last_error {
            Some(e) => health.error(e),
            None => health.clear_error(),
        }
        health.listen(
            st.incoming
                .listening
                .as_deref()
                .and_then(|l| l.strip_prefix("udp "))
                .and_then(|a| a.parse().ok())
                .map(|a| vec![Listen::new("udp", a)])
                .unwrap_or_default(),
        );
        let used = cfg.servers.iter().any(|e| !e.disabled && !e.service.is_empty());
        health.disabled((!used).then_some("no enabled /radius entry"));
        if driver.is_finished() {
            break Err("the RADIUS driver ended".to_owned());
        }
        if !health.sleep(TICK) {
            break Ok(());
        }
    };
    aaa.stop();
    let _ = driver.join();
    result
}
