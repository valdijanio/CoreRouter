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
//!
//! G4.3hd, every tick: in a redundant pair, the takeover's IPoE sessions
//! adopted before this node answers DHCP, the sessions ended quietly when
//! the role goes to the peer, and the changes published (hot standby).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_hal::pppoe::PppoeOp;
use corerouter_model::IfName;

use super::ipoe_bng::{Backend, Core, KernelRoute, Owner, Sessions, XdpOp, xdp_session};

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
        core.set_framed(corerouter_engine::framed::FramedTable::of(&mut s));
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

/// G4.3cd: the kernel routes of blocks routed to subscribers (`dst via
/// subscriber`): the kernel forwards IPoE downstream itself.
#[cfg(target_os = "linux")]
fn kernel_routes(ops: &[KernelRoute]) -> Result<(), String> {
    let ops: Vec<_> = ops.iter().map(|k| (k.dst.network(), k.dst.prefix_len(), k.via, k.add)).collect();
    corerouter_hal_linux::pppoe_io::gateway_routes(&ops).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn kernel_routes(ops: &[KernelRoute]) -> Result<(), String> {
    if ops.is_empty() { Ok(()) } else { Err("routed blocks need Linux".into()) }
}

/// G4.3hd: no ARP replies on an IPoE port of a pair's standby (it has the
/// gateway's address too).
#[cfg(target_os = "linux")]
fn arp_quiet(name: &IfName, quiet: bool) -> Result<(), String> {
    corerouter_hal_linux::ha_io::arp_quiet(name, quiet).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn arp_quiet(_: &IfName, _: bool) -> Result<(), String> {
    Ok(())
}

struct Driver {
    ports: Vec<IfName>,
    info: HashMap<IfName, (u32, [u8; 6])>,
    plane: Option<Result<(), String>>,
    /// When the data plane was last tried (an `Err` is tried again: XDP
    /// may be attached to the ports later).
    tried: Option<Instant>,
    owner_of: Option<usize>,
    /// G4.3hd: this node was the pair's active one at the last tick; the
    /// ports' ARP state set last (quiet, for these ports).
    was_active: bool,
    arp: Option<(bool, Vec<IfName>)>,
}

/// How often a data plane that was refused is asked for again.
const RETRY: Duration = Duration::from_secs(30);

fn run(session: &Shared, core: &Arc<Core>, health: &super::Health) -> Result<(), String> {
    let owner = Arc::new(Owner(core.clone()));
    let mut d = Driver { ports: Vec::new(), info: HashMap::new(), plane: None, tried: None, owner_of: None, was_active: false, arp: None };
    let mut last: Option<Instant> = None;
    while health.sleep(TICK) {
        health.beat();
        if last.is_none_or(|t| t.elapsed() >= SECOND) {
            let secs = last.map_or(1, |t| t.elapsed().as_secs().max(1));
            last = Some(Instant::now());
            d.second(session, core, &owner, health, secs);
        }
        d.pair(core);
        d.apply(session, core);
    }
    Ok(())
}

impl Driver {
    /// G4.3hd: the redundant pair's side of the IPoE sessions.
    fn pair(&mut self, core: &Arc<Core>) {
        use std::sync::atomic::Ordering;
        use super::pppoe_bng::ha::{HaChange, TAKEOVER, TAKEOVER_GEN};
        use super::ipoe_bng::ha::IpoeHaChange;
        // The role first: `ppp-ha` raises the takeover's number before it
        // lets this node answer, so an active node sees its takeover.
        let active = super::pppoe_bng::HA_ACTIVE.load(Ordering::Acquire);
        let gen_ = TAKEOVER_GEN.load(Ordering::Acquire);
        if gen_ > core.ha_gen() {
            let records = TAKEOVER.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            let done = core.adopt(gen_, records.as_deref().map_or(&[], Vec::as_slice));
            super::ppp_ha::adopted(done.sessions, done.skipped);
        }
        if self.was_active && !active && core.ha_enabled() {
            core.abandon();
        }
        self.was_active = active;
        let answering = active && core.ha_gen() >= gen_;
        core.set_answering(answering);
        // G4.3hk: quiet also while the pair and this service's config
        // disagree (one has the pair, the other not yet).
        let paired = super::pppoe_bng::HA_PAIRED.load(Ordering::Acquire);
        core.set_paired(paired);
        let quiet = !super::pppoe_bng::may_answer(core.ha_enabled(), paired, answering);
        let ports = core.ports();
        // A router without a pair keeps whatever it had.
        let untouched = !core.ha_enabled() && !paired && self.arp.is_none();
        if !untouched && self.arp.as_ref() != Some(&(quiet, ports.clone())) {
            for p in &ports {
                if let Err(e) = arp_quiet(p, quiet) {
                    log::warn!("ipoe: arp_ignore on {p}: {e}");
                }
            }
            self.arp = Some((quiet, ports));
        }
        let changes = core.ha_take();
        if changes.is_empty() {
            return;
        }
        let out: Vec<HaChange> = changes
            .into_iter()
            .map(|c| match c {
                IpoeHaChange::Up(k, v) => HaChange::Up(k, v),
                IpoeHaChange::Gone(k) => HaChange::Gone(k),
                IpoeHaChange::Counters(k, c) => HaChange::Counters(k, c),
            })
            .collect();
        if let Some(back) = super::ppp_ha::publish(out) {
            core.ha_requeue(
                back.into_iter()
                    .map(|c| match c {
                        HaChange::Up(k, v) => IpoeHaChange::Up(k, v),
                        HaChange::Gone(k) => IpoeHaChange::Gone(k),
                        HaChange::Counters(k, c) => IpoeHaChange::Counters(k, c),
                    })
                    .collect(),
            );
        }
    }

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
        // G4.3cd: kernel routes of routed blocks (with or without XDP) and
        // the core's log lines, before the map changes.
        let mut logs = core.take_logs();
        if let Err(e) = kernel_routes(&core.take_kernel_routes()) {
            logs.push((true, format!("IPoE: rota de bloco roteado: {e}")));
        }
        if !logs.is_empty() {
            let mut s = lock(session);
            for (error, text) in logs {
                let level = if error { "error" } else { "info" };
                s.log_event(&["ppp", level], "ipoe", text, serde_json::json!({}));
            }
        }
        let ops = core.take_ops();
        if ops.is_empty() || !matches!(self.plane, Some(Ok(()))) {
            return;
        }
        let ops: Vec<PppoeOp> = ops
            .into_iter()
            .filter_map(|op| match op {
                XdpOp::Remove(slot) => Some(PppoeOp::Remove(slot)),
                XdpOp::Route { dst, slot, add } => Some(PppoeOp::Route { dst, idx: slot, add }),
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
