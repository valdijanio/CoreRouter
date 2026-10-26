//! IPoE subscribers (G4.3f) as a service: the owner of the sessions the
//! DHCP server's leases become (`ipoe_bng.rs`). At start it registers in
//! the session as the engine's `IpoeBackend` (the DHCP server asks it about
//! clients and tells it about leases) and as the IPoE half of `ppp.active`;
//! RADIUS CoA/Disconnect reach it as a session owner.
//!
//! Its thread, a few times a second: the running config into the core;
//! the XDP data plane switched on for the IPoE access ports (when the HAL
//! has it: else the sessions exist without the policer, and the row says
//! why); the core's map changes applied, with the ports' index and MAC;
//! once a second the XDP counters (accounting, the PPP window) and the
//! keepalive. The session lock is taken only for those short steps, never
//! while the core's own lock is held.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_hal::pppoe::PppoeOp;
use corerouter_model::IfName;

use super::ipoe_bng::{Backend, Core, Owner, Sessions, XdpOp, xdp_session};

const TICK: Duration = Duration::from_millis(100);
const SECOND: Duration = Duration::from_secs(1);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "ipoe",
    flags: &[],
    topic: "ppp",
    enable: "ip.dhcp-server.set … ipoe=yes (or use_radius=yes)",
    depends: &["radius"],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let core = Core::new();
    {
        let mut s = lock(&session);
        s.set_ipoe_backend(Arc::new(Backend(core.clone())));
        s.set_ipoe_sessions(Arc::new(Sessions(core.clone())));
    }
    Ok(Box::new(move |health: &super::Health| run(&session, &core, health)))
}

/// The index and MAC of an access port.
#[cfg(target_os = "linux")]
fn port_info(name: &IfName) -> Result<(u32, [u8; 6]), String> {
    corerouter_hal_linux::pppoe_io::port_info(name).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn port_info(name: &IfName) -> Result<(u32, [u8; 6]), String> {
    Err(format!("{name}: no access port outside Linux"))
}

struct Driver {
    ports: Vec<IfName>,
    info: HashMap<IfName, (u32, [u8; 6])>,
    plane: Option<Result<(), String>>,
    /// When the data plane was last tried (an `Err` is tried again: XDP
    /// may be attached to the ports later).
    tried: Option<Instant>,
    owner_of: Option<usize>,
}

/// How often a data plane that was refused is asked for again.
const RETRY: Duration = Duration::from_secs(30);

fn run(session: &Shared, core: &Arc<Core>, health: &super::Health) -> Result<(), String> {
    let owner = Arc::new(Owner(core.clone()));
    let mut d = Driver { ports: Vec::new(), info: HashMap::new(), plane: None, tried: None, owner_of: None };
    let mut last: Option<Instant> = None;
    while health.sleep(TICK) {
        health.beat();
        if last.is_none_or(|t| t.elapsed() >= SECOND) {
            let secs = last.map_or(1, |t| t.elapsed().as_secs().max(1));
            last = Some(Instant::now());
            d.second(session, core, &owner, health, secs);
        }
        d.apply(session, core);
    }
    Ok(())
}

impl Driver {
    fn second(&mut self, session: &Shared, core: &Arc<Core>, owner: &Arc<Owner>, health: &super::Health, secs: u64) {
        let (cfg, aaa) = {
            let s = lock(session);
            (s.store().running().clone(), s.aaa_backend())
        };
        if let Some(a) = &aaa {
            let key = Arc::as_ptr(a) as *const () as usize;
            if self.owner_of != Some(key) {
                a.register_owner(owner.clone());
                self.owner_of = Some(key);
            }
        }
        core.configure(&cfg, aaa);
        let ports = core.ports();
        if ports.is_empty() {
            health.disabled(Some("no DHCP server with ipoe=yes or use_radius (ip.dhcp-server.set … ipoe=yes)"));
        } else {
            health.disabled(None);
        }
        let retry = matches!(self.plane, Some(Err(_))) && self.tried.is_none_or(|t| t.elapsed() >= RETRY);
        if ports != self.ports || self.plane.is_none() || retry {
            self.tried = Some(Instant::now());
            self.info.clear();
            for p in &ports {
                if let Ok(i) = port_info(p) {
                    self.info.insert(p.clone(), i);
                }
            }
            let r = if ports.is_empty() {
                let _ = lock(session).ipoe_dataplane(false, &[]);
                Err("no ports".into())
            } else {
                lock(session).ipoe_dataplane(true, &ports)
            };
            core.set_xdp(r.is_ok());
            self.plane = Some(r);
            self.ports = ports;
        }
        match &self.plane {
            Some(Err(why)) if !self.ports.is_empty() => {
                health.event(format!("no XDP data plane ({why}): sessions without the policer"));
            }
            _ => health.clear_error(),
        }
        let slots = core.slots();
        if matches!(self.plane, Some(Ok(()))) && !slots.is_empty() {
            let c = lock(session).pppoe_counters(&slots);
            core.counters(&c, secs);
        }
        core.keepalive();
    }

    /// The core's XDP map changes, with the ports' index and MAC.
    fn apply(&mut self, session: &Shared, core: &Arc<Core>) {
        let ops = core.take_ops();
        if ops.is_empty() || !matches!(self.plane, Some(Ok(()))) {
            return;
        }
        let ops: Vec<PppoeOp> = ops
            .into_iter()
            .filter_map(|op| match op {
                XdpOp::Remove(slot) => Some(PppoeOp::Remove(slot)),
                XdpOp::Upsert { slot, interface, client_mac, ip, up, down, shape } => {
                    let (ifindex, mac) = *self.info.get(&interface)?;
                    Some(PppoeOp::Upsert(slot, xdp_session(ifindex, mac, client_mac, ip, up, down, shape)))
                }
            })
            .collect();
        let mut s = lock(session);
        if let Err(e) = s.pppoe_apply(&ops) {
            s.log_event(&["ppp", "error"], "ipoe", format!("IPoE: mapa XDP: {e}"), serde_json::json!({}));
        }
    }
}
