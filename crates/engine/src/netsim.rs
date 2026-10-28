//! G3.7: the lab behind Tools › Network Simulator. Every virtual router is
//! a CoreRouter of its own — a [`Session`] on the virtual backend, with the
//! same commands and validations as the real one — and the simulator
//! (`corerouter-netsim`) runs simplified OSPF, BGP and BFD between them on a
//! virtual clock. A command typed into a virtual router (`tool.netsim.node.run`)
//! goes through that router's `Session::execute`; the simulator then reads
//! its running configuration again ([`node_config`]).
//!
//! Runtime state only (`Session::ext`): never saved, gone on restart, never
//! applied to the real router. Design: `docs/netsim.md`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use corerouter_hal::VirtualHal;
use corerouter_model::Config;
use corerouter_model::bgp::{NexthopChoice, resolve_templates};
use corerouter_model::ospf::Version;
use corerouter_netsim::preset::{self, ACCEPT_CHAIN, Plan, Scenario};
use corerouter_netsim::{
    BgpConfig, Endpoint, Fault, IfAddr, Link, LinkId, MS, Neighbor, NodeConfig, NodeId, OspfIface, SEC,
    Simulation, Time, Timers,
};
use corerouter_proto_bgp::filter::eval::Policy;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Session;

/// Set `key` in a JSON object (no-op on anything else: never panics).
pub(crate) fn put(v: &mut Value, key: &str, x: Value) {
    if let Some(m) = v.as_object_mut() {
        m.insert(key.to_owned(), x);
    }
}

/// The badge every view of the simulator carries.
pub const BADGE: &str = "simulation — not the real network";

/// Most routers the engine builds (each is a whole `Session`).
pub const MAX_LAB_NODES: usize = 500;

/// Events one command may run before it returns (the session lock is held
/// meanwhile); the caller asks again for the rest.
pub const EVENT_BUDGET: u64 = 400_000;

/// One virtual router.
pub struct LabNode {
    pub session: Session,
    pub pos: [f32; 2],
    /// Prefixes it originates in BGP (RouterOS `output.network` is not in
    /// the model yet: the simulator keeps them).
    pub networks: Vec<Ipv4Net>,
    /// The commands typed into it, in order (the scenario export replays them).
    pub commands: Vec<(String, Value)>,
    /// A copy of this router's own configuration ("what if").
    pub imported: bool,
}

/// One fault, as injected (kept for the scenario export).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Injected {
    pub at_ms: u64,
    #[serde(flatten)]
    pub fault: Fault,
}

pub struct Lab {
    pub name: String,
    pub seed: u64,
    pub sim: Simulation,
    pub nodes: Vec<LabNode>,
    pub faults: Vec<Injected>,
    pub playing: bool,
    /// Virtual seconds per wall-clock second.
    pub speed: u32,
    /// A virtual router's `Session` and its config view, built once each.
    pub timers: Timers,
}

/// The simulator of this session (`s.ext_mut::<NetSim>()`).
#[derive(Default)]
pub struct NetSim {
    pub lab: Option<Box<Lab>>,
}

fn run(s: &mut Session, node: &str, id: &str, params: Value) -> Result<(), String> {
    s.execute(id, &params)
        .map(|_| ())
        .map_err(|e| format!("{node}: {id}: {e}"))
}

/// Threads a window may use here.
fn threads() -> usize {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::thread::available_parallelism().map_or(1, |c| c.get().min(8))
    }
    #[cfg(target_arch = "wasm32")]
    {
        1
    }
}

/// What the simulator reads from a virtual router's running configuration:
/// its IPv4 addresses, the BGP instance `default`, its connections (with
/// the templates applied) and its `/routing filter`.
pub fn node_config(name: &str, cfg: &Config, networks: &[Ipv4Net], timers: Timers) -> NodeConfig {
    let addresses: Vec<IfAddr> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && a.from_pool.is_none())
        .filter_map(|a| match a.address {
            IpNet::V4(net) => Some(IfAddr {
                iface: a.interface.to_string(),
                net,
            }),
            IpNet::V6(_) => None,
        })
        .collect();
    let routing = &cfg.routing;
    let instance = routing.bgp.get("default").filter(|i| !i.disabled);
    let router_id = instance.map(|i| i.router_id).unwrap_or_else(|| {
        addresses
            .iter()
            .find(|a| a.net.prefix_len() == 32)
            .or(addresses.first())
            .map_or(Ipv4Addr::UNSPECIFIED, |a| a.net.addr())
    });
    let bgp = instance.map(|i| {
        let resolved = resolve_templates(&routing.bgp_templates);
        let neighbors = routing
            .bgp_connections
            .values()
            .filter(|c| c.instance == i.name)
            .filter_map(|c| {
                let IpAddr::V4(remote) = c.remote_address else { return None };
                let p = c.effective(&resolved).ok()?;
                let hold = match p.hold_time.unwrap_or(180) {
                    0 => Time::MAX / 4,
                    h => Time::from(h) * SEC,
                };
                let keepalive = p
                    .keepalive_time
                    .map_or(hold / 3, |k| Time::from(k.max(1)) * SEC);
                Some(Neighbor {
                    name: c.name.clone(),
                    remote,
                    remote_as: p.remote_as.map(|a| a.0),
                    local: p.update_source.as_deref().and_then(|u| u.parse().ok()),
                    hold,
                    keepalive,
                    input: p.input_filter.clone(),
                    output: p.output_filter.clone(),
                    // G3.6b: a BFD profile on the connection (RouterOS
                    // `use-bfd`) drops the session with BFD.
                    bfd: p.bfd.is_some(),
                    next_hop_self: p.nexthop_choice == Some(NexthopChoice::ForceSelf),
                    disabled: c.disabled,
                })
            })
            .collect();
        BgpConfig {
            asn: i.asn.0,
            networks: networks.to_vec(),
            neighbors,
            policy: Arc::new(Policy::build(&routing.filter).0),
        }
    });
    let (ospf, ospf_ifaces) = ospf_of(cfg);
    NodeConfig {
        name: name.to_owned(),
        router_id,
        addresses,
        ospf,
        ospf_ifaces: Some(ospf_ifaces),
        bgp,
        timers,
    }
}

/// G3.7d: the router's OSPFv2 as the simulator runs it — the first enabled
/// v2 instance, on the interfaces its templates match (the same matching
/// `proto_ospf::bind` does for the FRR render), with each template's cost,
/// hello and dead intervals, passive flag and BFD profile. No instance: no
/// OSPF.
fn ospf_of(cfg: &Config) -> (bool, Vec<OspfIface>) {
    let Some(inst) = cfg
        .routing
        .ospf
        .instances
        .values()
        .find(|i| !i.disabled && i.version == Version::V2)
    else {
        return (false, Vec::new());
    };
    let secs = |s: Option<u16>| s.map(|s| Time::from(s.max(1)) * SEC);
    let ifaces = corerouter_proto_ospf::bind::bindings(cfg)
        .into_iter()
        .filter(|b| b.instance.name == inst.name)
        .map(|b| OspfIface {
            iface: b.interface.to_string(),
            cost: b.template.cost.map(u32::from),
            hello: secs(b.template.hello_interval),
            dead: secs(b.template.dead_interval),
            passive: b.template.passive,
            bfd: b.template.bfd.is_some(),
        })
        .collect();
    (true, ifaces)
}

/// Type the OSPF of a virtual router: instance `default`, the backbone,
/// a point-to-point template for `ifaces` and the loopback as passive.
fn ospf_commands(node: &mut LabNode, name: &str, rid: Ipv4Addr, ifaces: &[String]) -> Result<(), String> {
    let running = node.session.store().running();
    let has = !running.routing.ospf.instances.is_empty()
        || node.commands.iter().any(|(id, _)| id == "routing.ospf.instance.add");
    if !has {
        node.exec(name, "routing.ospf.instance.add", json!({"name": "default", "router_id": rid.to_string()}))?;
        node.exec(
            name,
            "routing.ospf.area.add",
            json!({"name": "backbone", "instance": "default", "area_id": "0.0.0.0"}),
        )?;
        node.exec(
            name,
            "routing.ospf.interface-template.add",
            json!({"area": "backbone", "interfaces": ["lo"], "passive": true, "comment": "loopback"}),
        )?;
    }
    if !ifaces.is_empty() {
        node.exec(
            name,
            "routing.ospf.interface-template.add",
            json!({"area": "backbone", "interfaces": ifaces, "type": "ptp"}),
        )?;
    }
    Ok(())
}

impl LabNode {
    fn new(ports: usize, pos: [f32; 2], networks: Vec<Ipv4Net>) -> LabNode {
        let ports = u8::try_from(ports.clamp(8, 255)).unwrap_or(255);
        LabNode {
            session: Session::new(Box::new(VirtualHal::new(ports))),
            pos,
            networks,
            commands: Vec::new(),
            imported: false,
        }
    }

    /// Type a command into this router, remembering it for the export.
    pub fn exec(&mut self, name: &str, id: &str, params: Value) -> Result<Value, String> {
        let out = self
            .session
            .execute(id, &params)
            .map_err(|e| format!("{name}: {id}: {e}"))?;
        self.commands.push((id.to_owned(), params));
        Ok(out)
    }

    /// Make sure `iface` exists (a virtual router has `ether1..N`; any other
    /// name becomes a loopback-type interface).
    fn ensure_iface(&mut self, name: &str, iface: &str) -> Result<(), String> {
        let exists = iface
            .parse()
            .ok()
            .is_some_and(|i| self.session.store().running().interfaces.contains_key(&i));
        if !exists {
            self.exec(name, "interface.loopback.add", json!({"name": iface}))?;
        }
        Ok(())
    }
}

impl Lab {
    /// A lab of the planned routers, each built by commands.
    pub fn from_scenario(scn: &Scenario, seed: u64) -> Result<Lab, String> {
        if scn.nodes.len() > MAX_LAB_NODES {
            return Err(format!("at most {MAX_LAB_NODES} routers"));
        }
        let plan = scn.plan()?;
        let mut lab = Lab {
            name: scn.name.clone(),
            seed,
            sim: Simulation::new(seed),
            nodes: Vec::with_capacity(plan.nodes.len()),
            faults: Vec::new(),
            playing: false,
            speed: 1,
            timers: Timers::default(),
        };
        lab.sim.set_threads(threads());
        lab.build(&plan)?;
        Ok(lab)
    }

    fn build(&mut self, plan: &Plan) -> Result<(), String> {
        for p in &plan.nodes {
            let ports = p.addresses.iter().filter(|a| a.iface.starts_with("ether")).count();
            let mut node = LabNode::new(ports, p.pos, p.networks.clone());
            let name = p.name.as_str();
            // One commit per router, as an operator pasting a script would
            // in transactional mode.
            run(&mut node.session, name, "config.mode.set", json!({"mode": "transactional"}))?;
            node.exec(name, "system.identity.set", json!({"name": name}))?;
            for a in &p.addresses {
                node.ensure_iface(name, &a.iface)?;
                node.exec(
                    name,
                    "ip.address.add",
                    json!({"address": a.net.to_string(), "interface": a.iface}),
                )?;
            }
            if !p.neighbors.is_empty() || !p.networks.is_empty() {
                if p.neighbors.iter().any(|n| n.input.is_some() || n.output.is_some()) {
                    node.exec(
                        name,
                        "routing.filter.rule.add",
                        json!({"chain": ACCEPT_CHAIN, "rule": "accept", "comment": "simulator: eBGP needs a policy (RFC 8212)"}),
                    )?;
                }
                node.exec(
                    name,
                    "routing.bgp.instance.set",
                    json!({"asn": p.asn, "router_id": p.router_id.to_string()}),
                )?;
                for n in &p.neighbors {
                    let mut params = json!({
                        "name": n.name,
                        "remote_address": n.remote.to_string(),
                        "remote_as": n.remote_as,
                    });
                    if let Some(l) = n.local {
                        put(&mut params, "update_source", json!(l.to_string()));
                    }
                    if let Some(c) = &n.input {
                        put(&mut params, "input_filter", json!(c));
                    }
                    if let Some(c) = &n.output {
                        put(&mut params, "output_filter", json!(c));
                    }
                    if n.bfd {
                        put(&mut params, "bfd", json!(corerouter_model::bfd::PROFILE_DEFAULT));
                    }
                    if n.next_hop_self {
                        put(&mut params, "nexthop_choice", json!("force-self"));
                    }
                    node.exec(name, "routing.bgp.connection.add", params)?;
                }
            }
            // OSPF on the router's ends of the links that run it.
            let i = self.nodes.len();
            let ospf_ifaces: Vec<String> = plan
                .links
                .iter()
                .filter(|l| l.ospf)
                .filter_map(|l| {
                    let ix = u32::try_from(i).ok()?;
                    [&l.a, &l.b].into_iter().find(|e| e.node.0 == ix).map(|e| e.iface.clone())
                })
                .collect();
            if !ospf_ifaces.is_empty() {
                ospf_commands(&mut node, name, p.router_id, &ospf_ifaces)?;
            }
            run(&mut node.session, name, "config.commit", json!({}))?;
            run(&mut node.session, name, "config.mode.set", json!({"mode": "immediate"}))?;
            let cfg = node_config(name, node.session.store().running(), &node.networks, self.timers);
            self.sim.add_node(cfg)?;
            self.nodes.push(node);
        }
        for l in &plan.links {
            self.sim.add_link(l.clone())?;
        }
        Ok(())
    }

    fn node_name(&self, i: usize) -> String {
        self.sim
            .config(NodeId(u32::try_from(i).unwrap_or(u32::MAX)))
            .map(|c| c.name.clone())
            .unwrap_or_default()
    }

    /// The router named `name` (or by its index).
    pub fn find(&self, name: &str) -> Result<usize, String> {
        if let Some(id) = self.sim.node_by_name(name) {
            return Ok(id.0 as usize);
        }
        let names: Vec<String> = self.sim.nodes().into_iter().map(|n| n.name).collect();
        let hint = crate::error::suggest(name, names.iter().map(String::as_str))
            .map(|s| format!(" (did you mean {s:?}?)"))
            .unwrap_or_default();
        Err(format!(
            "no virtual router {:?}{hint}",
            name.chars().take(64).collect::<String>()
        ))
    }

    /// Read router `i`'s running configuration into the simulator again.
    pub fn refresh(&mut self, i: usize) -> Result<(), String> {
        let name = self.node_name(i);
        let node = self.nodes.get(i).ok_or("no such router")?;
        let identity = node.session.store().running().system.identity.clone();
        let name = if identity.trim().is_empty() { name } else { identity };
        let cfg = node_config(&name, node.session.store().running(), &node.networks, self.timers);
        self.sim
            .set_config(NodeId(u32::try_from(i).map_err(|_| "router index")?), cfg)
    }

    /// Run a command inside virtual router `i`.
    pub fn run_on(&mut self, i: usize, id: &str, params: Value) -> Result<Value, String> {
        if id.starts_with("tool.netsim.") {
            return Err("a virtual router has no simulator of its own".into());
        }
        let name = self.node_name(i);
        let node = self.nodes.get_mut(i).ok_or("no such router")?;
        let out = node.exec(&name, id, params)?;
        self.refresh(i)?;
        Ok(out)
    }

    /// Add a router at run time: a loopback, a BGP instance.
    pub fn add_node(&mut self, name: Option<&str>, asn: u32, pos: [f32; 2]) -> Result<usize, String> {
        if self.nodes.len() >= MAX_LAB_NODES {
            return Err(format!("at most {MAX_LAB_NODES} routers"));
        }
        let i = self.nodes.len();
        let name = name.map_or_else(|| format!("R{}", i + 1), str::to_owned);
        if self.sim.node_by_name(&name).is_some() {
            return Err(format!("a virtual router named {name:?} exists"));
        }
        let lo = (0..=MAX_LAB_NODES * 4)
            .map(preset::loopback)
            .find(|a| !self.address_used(*a))
            .ok_or("no loopback address left")?;
        let mut node = LabNode::new(8, pos, Vec::new());
        node.exec(&name, "system.identity.set", json!({"name": name}))?;
        node.ensure_iface(&name, "lo")?;
        node.exec(&name, "ip.address.add", json!({"address": format!("{lo}/32"), "interface": "lo"}))?;
        node.exec(
            &name,
            "routing.filter.rule.add",
            json!({"chain": ACCEPT_CHAIN, "rule": "accept", "comment": "simulator: eBGP needs a policy (RFC 8212)"}),
        )?;
        node.exec(&name, "routing.bgp.instance.set", json!({"asn": asn, "router_id": lo.to_string()}))?;
        ospf_commands(&mut node, &name, lo, &[])?;
        let cfg = node_config(&name, node.session.store().running(), &node.networks, self.timers);
        self.sim.add_node(cfg)?;
        self.nodes.push(node);
        Ok(i)
    }

    fn address_used(&self, a: Ipv4Addr) -> bool {
        self.nodes.iter().any(|n| {
            n.session
                .store()
                .running()
                .ip
                .addresses
                .iter()
                .any(|x| x.address.addr() == IpAddr::V4(a))
        })
    }

    /// A free /30 for a new link (10.0.0.0/9, the presets' space).
    fn free_link_net(&self) -> Option<(Ipv4Net, Ipv4Net)> {
        let base = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        (0u32..1 << 21).find_map(|k| {
            let a = Ipv4Addr::from(base + (k << 2) + 1);
            let b = Ipv4Addr::from(base + (k << 2) + 2);
            (!self.address_used(a) && !self.address_used(b))
                .then(|| Some((Ipv4Net::new(a, 30).ok()?, Ipv4Net::new(b, 30).ok()?)))
                .flatten()
        })
    }

    fn free_port(&self, i: usize) -> Option<String> {
        let node = self.nodes.get(i)?;
        let used: Vec<String> = self
            .sim
            .links()
            .into_iter()
            .flat_map(|l| {
                let mut v = Vec::new();
                if l.a.0 as usize == i {
                    v.push(l.a_iface);
                }
                if l.b.0 as usize == i {
                    v.push(l.b_iface);
                }
                v
            })
            .collect();
        node.session
            .store()
            .running()
            .interfaces
            .keys()
            .map(ToString::to_string)
            .filter(|n| n.starts_with("ether") && !used.contains(n))
            .min_by_key(|n| n.trim_start_matches("ether").parse::<u32>().unwrap_or(u32::MAX))
    }

    /// Connect two routers: a free port on each, a /30 typed into both,
    /// OSPF on it, and eBGP between them when their ASes differ.
    pub fn add_link(&mut self, a: usize, b: usize, cost: u32, latency: Time, bfd: bool, ospf: bool) -> Result<LinkId, String> {
        if a == b {
            return Err("a link joins two different routers".into());
        }
        let (na, nb) = self.free_link_net().ok_or("no /30 left")?;
        let mut ifaces = Vec::new();
        for (i, net) in [(a, na), (b, nb)] {
            let name = self.node_name(i);
            let port = self
                .free_port(i)
                .ok_or_else(|| format!("{name} has no free port"))?;
            let node = self.nodes.get_mut(i).ok_or("no such router")?;
            node.exec(&name, "ip.address.add", json!({"address": net.to_string(), "interface": port}))?;
            ifaces.push(port);
        }
        let (Some(ia), Some(ib)) = (ifaces.first(), ifaces.get(1)) else {
            return Err("no port".into());
        };
        let mut link = Link::new(
            Endpoint { node: NodeId(u32::try_from(a).map_err(|_| "index")?), iface: ia.clone() },
            Endpoint { node: NodeId(u32::try_from(b).map_err(|_| "index")?), iface: ib.clone() },
        );
        link.cost_a = cost.clamp(1, 65535);
        link.cost_b = link.cost_a;
        link.latency = latency.max(1);
        link.bfd = bfd;
        link.ospf = ospf;
        let id = self.sim.add_link(link)?;
        if ospf {
            for (i, port) in [(a, ia.clone()), (b, ib.clone())] {
                let name = self.node_name(i);
                let rid = self.sim.config(NodeId(u32::try_from(i).map_err(|_| "index")?)).map(|c| c.router_id);
                if let (Some(node), Some(rid)) = (self.nodes.get_mut(i), rid) {
                    ospf_commands(node, &name, rid, &[port])?;
                }
            }
        }
        let asn = |i: usize| {
            self.nodes
                .get(i)
                .and_then(|n| n.session.store().running().routing.bgp.get("default").map(|x| x.asn.0))
        };
        if let (Some(xa), Some(xb)) = (asn(a), asn(b))
            && xa != xb
        {
            for (me, other, remote, other_as) in [(a, b, nb.addr(), xb), (b, a, na.addr(), xa)] {
                let peer = self.node_name(other).to_lowercase();
                let name = self.node_name(me);
                if let Some(node) = self.nodes.get_mut(me) {
                    node.exec(
                        &name,
                        "routing.bgp.connection.add",
                        json!({"name": peer, "remote_address": remote.to_string(), "remote_as": other_as,
                               "input_filter": ACCEPT_CHAIN, "output_filter": ACCEPT_CHAIN,
                               "bfd": corerouter_model::bfd::PROFILE_DEFAULT}),
                    )?;
                }
            }
        }
        self.refresh(a)?;
        self.refresh(b)?;
        Ok(id)
    }

    /// "What if": a virtual router with this router's own addresses, BGP
    /// instance, templates, connections and `/routing filter`, typed in as
    /// commands. Commands the virtual router refuses are listed, not fatal.
    pub fn import(&mut self, name: &str, real: &Config, pos: [f32; 2]) -> Result<(usize, Vec<String>), String> {
        if self.nodes.len() >= MAX_LAB_NODES {
            return Err(format!("at most {MAX_LAB_NODES} routers"));
        }
        if self.sim.node_by_name(name).is_some() {
            return Err(format!("a virtual router named {name:?} exists"));
        }
        let mut node = LabNode::new(8, pos, Vec::new());
        node.imported = true;
        let mut refused = Vec::new();
        let try_exec = |node: &mut LabNode, refused: &mut Vec<String>, id: &str, params: Value| {
            if let Err(e) = node.exec(name, id, params) {
                refused.push(e);
            }
        };
        try_exec(&mut node, &mut refused, "system.identity.set", json!({"name": name}));
        for a in real.ip.addresses.iter().filter(|a| a.from_pool.is_none() && a.address.addr().is_ipv4()) {
            let iface = a.interface.to_string();
            if let Err(e) = node.ensure_iface(name, &iface) {
                refused.push(e);
                continue;
            }
            try_exec(&mut node, &mut refused, "ip.address.add", json!({"address": a.address.to_string(), "interface": iface}));
        }
        let f = &real.routing.filter;
        for l in f.prefix_lists.values() {
            let entries: Vec<String> = l.entries.iter().map(ToString::to_string).collect();
            try_exec(&mut node, &mut refused, "routing.filter.prefix-list.add", json!({"name": l.name, "entries": entries}));
        }
        for l in f.community_lists.values() {
            try_exec(&mut node, &mut refused, "routing.filter.community-list.add", json!({"name": l.name, "communities": l.communities}));
        }
        for r in &f.rules {
            try_exec(&mut node, &mut refused, "routing.filter.rule.add", json!({"chain": r.chain, "rule": r.rule, "disabled": r.disabled}));
        }
        // G3.6 BFD profiles the connections and templates name (the built-in
        // ones exist already; keys stay sealed on the real router).
        for b in real.routing.bfd.profiles.values() {
            let p = json!({"name": b.name, "min_tx": b.min_tx, "min_rx": b.min_rx, "multiplier": b.multiplier, "passive": b.passive});
            let builtin = corerouter_model::bfd::builtin_profiles().iter().any(|x| x.name == b.name);
            let id = if builtin { "routing.bfd.profile.set" } else { "routing.bfd.profile.add" };
            let p = if builtin { json!({"id": b.name, "min_tx": b.min_tx, "min_rx": b.min_rx, "multiplier": b.multiplier}) } else { p };
            try_exec(&mut node, &mut refused, id, p);
        }
        if let Some(i) = real.routing.bgp.get("default") {
            try_exec(&mut node, &mut refused, "routing.bgp.instance.set", json!({"asn": i.asn.0, "router_id": i.router_id.to_string()}));
        }
        let params_of = |p: &corerouter_model::bgp::BgpParams| {
            let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
            if let Some(m) = v.as_object_mut() {
                // The key stays sealed on the real router; RPKI has no
                // validator in the lab.
                m.remove("tcp_md5_key");
                m.remove("rpki_invalid");
            }
            v
        };
        // Parents first: a template lists templates added before it.
        let mut pending: Vec<_> = real.routing.bgp_templates.values().collect();
        for _ in 0..corerouter_model::bgp::MAX_TEMPLATE_DEPTH + 1 {
            pending.retain(|t| {
                let ready = t.templates.iter().all(|p| {
                    node.session.store().running().routing.bgp_templates.contains_key(p)
                });
                if !ready {
                    return true;
                }
                let mut p = params_of(&t.params);
                put(&mut p, "name", json!(t.name));
                put(&mut p, "templates", json!(t.templates));
                try_exec(&mut node, &mut refused, "routing.bgp.template.add", p);
                false
            });
        }
        for c in real.routing.bgp_connections.values() {
            let mut p = params_of(&c.params);
            put(&mut p, "name", json!(c.name));
            put(&mut p, "remote_address", json!(c.remote_address.to_string()));
            put(&mut p, "instance", json!(c.instance));
            put(&mut p, "templates", json!(c.templates));
            put(&mut p, "disabled", json!(c.disabled));
            try_exec(&mut node, &mut refused, "routing.bgp.connection.add", p);
        }
        // G3.7d: the OSPF too (authentication keys stay sealed on the real
        // router: a keyed template is copied without its key).
        let ospf = &real.routing.ospf;
        for i in ospf.instances.values() {
            let mut p = json!({"name": i.name, "version": if i.version == Version::V3 { 3 } else { 2 }, "disabled": i.disabled});
            if let Some(r) = i.router_id {
                put(&mut p, "router_id", json!(r.to_string()));
            }
            try_exec(&mut node, &mut refused, "routing.ospf.instance.add", p);
        }
        for a in ospf.areas.values() {
            try_exec(
                &mut node,
                &mut refused,
                "routing.ospf.area.add",
                json!({"name": a.name, "instance": a.instance, "area_id": a.area_id.to_string(),
                       "type": a.kind.name(), "no_summaries": a.no_summaries, "disabled": a.disabled}),
            );
        }
        for t in &ospf.templates {
            let mut p = json!({"area": t.area, "interfaces": t.interfaces,
                "networks": t.networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "type": t.kind.name(), "passive": t.passive, "disabled": t.disabled});
            for (k, v) in [("cost", t.cost), ("hello_interval", t.hello_interval), ("dead_interval", t.dead_interval)] {
                if let Some(v) = v {
                    put(&mut p, k, json!(v));
                }
            }
            if let Some(b) = &t.bfd {
                put(&mut p, "bfd", json!(b));
            }
            try_exec(&mut node, &mut refused, "routing.ospf.interface-template.add", p);
        }
        let cfg = node_config(name, node.session.store().running(), &node.networks, self.timers);
        self.sim.add_node(cfg)?;
        self.nodes.push(node);
        Ok((self.nodes.len() - 1, refused))
    }

    pub fn inject(&mut self, at: Time, fault: Fault) -> Result<(), String> {
        self.sim.schedule(at, fault)?;
        if self.faults.len() < 10_000 {
            self.faults.push(Injected { at_ms: at.max(self.sim.now()) / MS, fault });
        }
        Ok(())
    }

    /// The whole picture for the window.
    pub fn view(&self) -> Value {
        let nodes: Vec<Value> = self
            .sim
            .nodes()
            .into_iter()
            .zip(&self.nodes)
            .map(|(v, n)| {
                let mut o = serde_json::to_value(&v).unwrap_or(Value::Null);
                put(&mut o, "pos", json!(n.pos));
                put(&mut o, "imported", json!(n.imported));
                o
            })
            .collect();
        let links: Vec<Value> = self
            .sim
            .links()
            .into_iter()
            .map(|l| {
                let mut o = serde_json::to_value(&l).unwrap_or(Value::Null);
                put(&mut o, "latency_ms", json!(l.latency as f64 / MS as f64));
                o
            })
            .collect();
        let conv = self.sim.convergence().map(|c| {
            json!({
                "fault": c.fault,
                "fault_at_ms": c.fault_at / MS,
                "detected_after_ms": c.detected_after.map(|t| t as f64 / MS as f64),
                "igp_after_ms": c.igp_after.map(|t| t as f64 / MS as f64),
                "bgp_after_ms": c.bgp_after.map(|t| t as f64 / MS as f64),
                "bgp_prefixes_before": c.bgp_prefixes_before,
                "bgp_prefixes_now": c.bgp_prefixes_now,
                "quiet_for_ms": c.quiet_for / MS,
            })
        });
        let now = self.sim.now();
        json!({
            "loaded": true,
            "badge": BADGE,
            "name": self.name,
            "seed": self.seed,
            "now_ms": now / MS,
            "playing": self.playing,
            "speed": self.speed,
            "threads": self.sim.threads(),
            "nodes": nodes,
            "links": links,
            "stats": self.sim.stats(),
            "convergence": conv,
            "last_change_ms": self.sim.last_change().map(|t| t / MS),
            "next_event_ms": self.sim.next_event().map(|t| t / MS),
            "records": self.sim.records().len(),
        })
    }

    /// The scenario as a file: routers (and the commands typed into them),
    /// links, faults, and — for a test — what each router has at the end.
    pub fn export(&self, expect: bool) -> Value {
        let nodes: Vec<Value> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let commands: Vec<Value> = n
                    .commands
                    .iter()
                    .map(|(id, p)| json!({"command": id, "params": p}))
                    .collect();
                json!({
                    "name": self.node_name(i),
                    "pos": n.pos,
                    "networks": n.networks,
                    "ports": n.session.store().running().interfaces.keys().filter(|k| k.to_string().starts_with("ether")).count(),
                    "commands": commands,
                })
            })
            .collect();
        let links: Vec<Value> = self
            .sim
            .links()
            .into_iter()
            .map(|l| {
                json!({"a": self.node_name(l.a.0 as usize), "a_iface": l.a_iface,
                       "b": self.node_name(l.b.0 as usize), "b_iface": l.b_iface,
                       "cost_a": l.cost_a, "cost_b": l.cost_b, "latency_us": l.latency,
                       "ospf": l.ospf, "bfd": l.bfd})
            })
            .collect();
        let mut out = json!({
            "format": "corerouter-netsim/2",
            "name": self.name,
            "seed": self.seed,
            "nodes": nodes,
            "links": links,
            "faults": self.faults,
            "run_ms": self.sim.now() / MS,
        });
        if expect {
            let per: Vec<Value> = (0..self.nodes.len())
                .map(|i| {
                    let id = NodeId(u32::try_from(i).unwrap_or(u32::MAX));
                    let mut prefixes: Vec<String> = self
                        .sim
                        .routes(id)
                        .into_iter()
                        .filter(|r| r.via.is_some())
                        .map(|r| r.prefix.to_string())
                        .collect();
                    prefixes.sort();
                    let est = self
                        .sim
                        .bgp_peers(id)
                        .iter()
                        .filter(|p| p.state == "established")
                        .count();
                    json!({"node": self.node_name(i), "bgp_routes": prefixes, "bgp_established": est})
                })
                .collect();
            put(&mut out, "expect", Value::Array(per));
        }
        out
    }

    /// Rebuild a lab from [`Lab::export`]'s file, replaying every command
    /// and fault (the clock stays at 0: advance to `run_ms`).
    pub fn load(file: &Value) -> Result<Lab, String> {
        let f: ScenarioFile = serde_json::from_value(file.clone()).map_err(|e| format!("scenario: {e}"))?;
        if f.format == "corerouter-netsim/1" {
            return Err("scenario: format 1 is from before the routers typed their own OSPF (G3.7d); export it again".into());
        }
        if f.format != "corerouter-netsim/2" {
            return Err(format!("scenario: unknown format {:?}", f.format.chars().take(40).collect::<String>()));
        }
        if f.nodes.len() > MAX_LAB_NODES || f.links.len() > corerouter_netsim::MAX_LINKS {
            return Err("scenario: too many routers or links".into());
        }
        let mut lab = Lab {
            name: f.name.chars().take(64).collect(),
            seed: f.seed,
            sim: Simulation::new(f.seed),
            nodes: Vec::new(),
            faults: Vec::new(),
            playing: false,
            speed: 1,
            timers: Timers::default(),
        };
        lab.sim.set_threads(threads());
        for n in &f.nodes {
            let mut node = LabNode::new(n.ports, n.pos, n.networks.clone());
            for c in n.commands.iter().take(100_000) {
                node.exec(&n.name, &c.command, c.params.clone())?;
            }
            let cfg = node_config(&n.name, node.session.store().running(), &node.networks, lab.timers);
            lab.sim.add_node(cfg)?;
            lab.nodes.push(node);
        }
        for l in &f.links {
            let a = lab.find(&l.a)?;
            let b = lab.find(&l.b)?;
            let mut link = Link::new(
                Endpoint { node: NodeId(u32::try_from(a).map_err(|_| "index")?), iface: l.a_iface.clone() },
                Endpoint { node: NodeId(u32::try_from(b).map_err(|_| "index")?), iface: l.b_iface.clone() },
            );
            link.cost_a = l.cost_a.clamp(1, 65535);
            link.cost_b = l.cost_b.clamp(1, 65535);
            link.latency = l.latency_us.clamp(1, 10 * SEC);
            link.ospf = l.ospf;
            link.bfd = l.bfd;
            lab.sim.add_link(link)?;
        }
        for i in f.faults.iter().take(10_000) {
            lab.inject(i.at_ms.saturating_mul(MS), i.fault)?;
        }
        Ok(lab)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioFile {
    format: String,
    #[serde(default)]
    name: String,
    seed: u64,
    nodes: Vec<FileNode>,
    links: Vec<FileLink>,
    #[serde(default)]
    faults: Vec<Injected>,
    #[serde(default)]
    #[allow(dead_code)]
    run_ms: u64,
    #[serde(default)]
    #[allow(dead_code)]
    expect: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileNode {
    name: String,
    #[serde(default)]
    pos: [f32; 2],
    #[serde(default)]
    networks: Vec<Ipv4Net>,
    #[serde(default)]
    ports: usize,
    commands: Vec<FileCommand>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCommand {
    command: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLink {
    a: String,
    a_iface: String,
    b: String,
    b_iface: String,
    cost_a: u32,
    cost_b: u32,
    latency_us: u64,
    ospf: bool,
    bfd: bool,
}
