//! Tools › Network Simulator (G3.7): virtual routers running simplified
//! OSPF, BGP and BFD on a virtual clock (`crate::netsim`). Nothing here
//! touches the real router: every view carries the badge
//! "simulation — not the real network".

use corerouter_netsim::preset::{self, BgpMode};
use corerouter_netsim::{Fault, LinkId, MS, NodeId, Time};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::netsim::{EVENT_BUDGET, Lab, NetSim, put};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.netsim.get", "Network Simulator", ["Tools", "Network Simulator"], None,
        "{} → {loaded, badge, name?, seed?, now_ms?, playing?, speed?, threads?, nodes?: [{id, name, router_id, up, asn, ospf_neighbors, bgp_established, bgp_peers, bgp_prefixes, routes, lsdb, pending_events, pos, imported}], links?: [{id, a, a_iface, b, b_iface, state: up|cut|down, latency, latency_ms, loss_pct, cost_a, cost_b, ospf, bfd, ospf_full}], stats?, convergence?: {fault, fault_at_ms, detected_after_ms, igp_after_ms, bgp_after_ms, bgp_prefixes_before, bgp_prefixes_now, quiet_for_ms}, last_change_ms?, next_event_ms?, records?}",
        always, get),
    cmd!(query "tool.netsim.new", "New Simulation", [], None,
        "{preset?: square|ring|mesh|star|grid (default square), nodes?: int 2..500 (default 6; square is always 4), bgp?: none|ebgp|ibgp (default ebgp; ibgp is a full mesh, up to 30 routers), seed?: u64} → {name, nodes, links}",
        always, new),
    cmd!(query "tool.netsim.load", "Load Simulation", [], None,
        "{scenario: object (from tool.netsim.export)} → {name, nodes, links, run_ms}",
        always, load),
    cmd!(query "tool.netsim.export", "Export Simulation", [], None,
        "{expect?: bool (add what every router has now: the scenario becomes a test)} → {format, name, seed, nodes, links, faults, run_ms, expect?}",
        has_lab, export),
    cmd!(query "tool.netsim.clear", "Close Simulation", [], None,
        "{} → {cleared}",
        always, clear),
    cmd!(query "tool.netsim.clock", "Simulation Clock", [], None,
        "{action: play|pause|step, speed?: int 1..3600 (virtual seconds per second)} → {now_ms, playing, speed}",
        has_lab, clock),
    cmd!(query "tool.netsim.tick", "Simulation Tick", [], None,
        "{wall_ms: int 1..10000 (wall-clock time since the last tick; advances wall_ms × speed when playing)} → {now_ms, done}",
        has_lab, tick),
    cmd!(query "tool.netsim.advance", "Advance Simulation", [], None,
        "{ms: int 1..86400000 (virtual time)} → {now_ms, done (false: the event budget ran out; ask again)}",
        has_lab, advance),
    cmd!(query "tool.netsim.fault", "Inject Fault", [], None,
        "{kind: link-cut|link-down|link-restore|node-down|node-up|latency|loss, link?: int (for the link kinds), node?: string (for the node kinds), latency_ms?: number 0.001..10000, loss?: int 0..100, at_ms?: int (virtual time; default now)} → {at_ms}",
        has_lab, fault),
    cmd!(query "tool.netsim.timeline", "Simulation Timeline", [], None,
        "{after?: int (records already seen), limit?: int 1..1000 (default 200), node?: string} → {records: [{seq, at_ms, node?, layer: fault|bfd|ospf|bgp, type, …}], next, total}",
        has_lab, timeline),
    cmd!(query "tool.netsim.node.get", "Virtual Router", [], None,
        "{node: string, routes_limit?: int 1..5000 (default 500)} → {node, routes: [{prefix, proto, metric, links, via?}], ospf_neighbors, bgp_peers, bgp_routes, lsdb}",
        has_lab, node_get),
    cmd!(query "tool.netsim.node.add", "Add Virtual Router", [], None,
        "{name?: string, asn?: u32 (default 65000), x?: number 0..1, y?: number 0..1} → {node}",
        has_lab, node_add),
    cmd!(query "tool.netsim.node.run", "Run on Virtual Router", [], None,
        "{node: string, id: string (any command but tool.netsim.*), params?: object} → {node, result}",
        has_lab, node_run),
    cmd!(query "tool.netsim.link.add", "Add Virtual Link", [], None,
        "{a: string, b: string, cost?: int 1..65535 (default 10), latency_ms?: number 0.001..10000 (default 1), bfd?: bool (default true), ospf?: bool (default true; eBGP is added when the ASes differ)} → {link}",
        has_lab, link_add),
    cmd!(query "tool.netsim.link.set", "Set Virtual Link", [], None,
        "{link: int, cost?: int 1..65535 (both ends), cost_a?: int 1..65535, cost_b?: int 1..65535, bfd?: bool, latency_ms?: number 0.001..10000, loss?: int 0..100} → {link}",
        has_lab, link_set),
    cmd!(query "tool.netsim.import", "What If (import this router)", [], None,
        "{name?: string (default \"this-router\"), x?: number 0..1, y?: number 0..1} → {node, refused: [string] (commands the virtual router refused)}",
        has_lab, import),
];

const NO_LAB: &str = "no simulation: start one with tool.netsim.new";

/// Enabled when a simulation is loaded.
fn has_lab(s: &Session) -> std::result::Result<(), String> {
    match s.ext::<NetSim>().and_then(|n| n.lab.as_deref()) {
        Some(_) => Ok(()),
        None => Err(NO_LAB.into()),
    }
}

fn lab(s: &mut Session) -> Result<&mut Lab> {
    s.ext_mut::<NetSim>()
        .and_then(|n| n.lab.as_deref_mut())
        .ok_or_else(|| EngineError::bad("simulation", NO_LAB))
}

/// A refusal from the simulation, blamed on the parameter that caused it.
fn on(param: &'static str) -> impl Fn(String) -> EngineError {
    move |e| EngineError::bad(param, e)
}

fn opt_f64(p: &Value, key: &str, lo: f64, hi: f64) -> Result<Option<f64>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_f64() {
            Some(x) if (lo..=hi).contains(&x) => Ok(Some(x)),
            _ => Err(EngineError::bad(key, format!("must be a number {lo}..{hi}"))),
        },
    }
}

fn opt_u64(p: &Value, key: &str) -> Result<Option<u64>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "must be a non-negative integer")),
    }
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => Err(EngineError::bad(key, format!("must be {lo}..{hi}"))),
        v => Ok(v),
    }
}

fn pos(p: &Value) -> Result<[f32; 2]> {
    let x = opt_f64(p, "x", 0.0, 1.0)?.unwrap_or(0.5);
    let y = opt_f64(p, "y", 0.0, 1.0)?.unwrap_or(0.5);
    Ok([x as f32, y as f32])
}

fn ms_of(t: Time) -> u64 {
    t / MS
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(match s.ext_mut::<NetSim>().and_then(|n| n.lab.as_deref()) {
        Some(lab) => lab.view(),
        None => json!({"loaded": false, "badge": crate::netsim::BADGE}),
    })
}

fn summary(lab: &Lab) -> Value {
    json!({"name": lab.name, "nodes": lab.nodes.len(), "links": lab.sim.link_count()})
}

fn new(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_str(p, "preset")?.unwrap_or("square");
    let n = ranged(p, "nodes", 2, 500)?.unwrap_or(6) as usize;
    let mode = match opt_str(p, "bgp")?.unwrap_or("ebgp") {
        "none" => BgpMode::None,
        "ebgp" => BgpMode::Ebgp,
        "ibgp" => BgpMode::Ibgp,
        other => {
            return Err(EngineError::bad(
                "bgp",
                format!("{:?}: none, ebgp or ibgp", other.chars().take(16).collect::<String>()),
            ));
        }
    };
    if mode == BgpMode::Ibgp && n > 30 && name != "square" {
        return Err(EngineError::bad("nodes", "an iBGP full mesh goes up to 30 routers"));
    }
    let seed = opt_u64(p, "seed")?.unwrap_or(1);
    let scn = preset::by_name(name, n, mode).ok_or_else(|| {
        let hint = crate::error::suggest(name, preset::NAMES.iter().copied())
            .map(|s| format!(" (did you mean {s:?}?)"))
            .unwrap_or_default();
        EngineError::bad("preset", format!("{}: {}{hint}", name.chars().take(16).collect::<String>(), preset::NAMES.join(", ")))
    })?;
    let lab = Lab::from_scenario(&scn, seed).map_err(on("preset"))?;
    let out = summary(&lab);
    if let Some(ns) = s.ext_mut::<NetSim>() {
        ns.lab = Some(Box::new(lab));
    }
    Ok(out)
}

fn load(s: &mut Session, p: &Value) -> Result<Value> {
    let file = p
        .get("scenario")
        .filter(|v| v.is_object())
        .ok_or_else(|| EngineError::bad("scenario", "must be the object tool.netsim.export returns"))?;
    let lab = Lab::load(file).map_err(on("scenario"))?;
    let mut out = summary(&lab);
    put(&mut out, "run_ms", file.get("run_ms").cloned().unwrap_or(json!(0)));
    if let Some(ns) = s.ext_mut::<NetSim>() {
        ns.lab = Some(Box::new(lab));
    }
    Ok(out)
}

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let expect = opt_bool(p, "expect")?.unwrap_or(false);
    Ok(lab(s)?.export(expect))
}

fn clear(s: &mut Session, _: &Value) -> Result<Value> {
    let had = s.ext_mut::<NetSim>().and_then(|n| n.lab.take()).is_some();
    Ok(json!({"cleared": had}))
}

fn clock(s: &mut Session, p: &Value) -> Result<Value> {
    let action = req_str(p, "action")?;
    let speed = ranged(p, "speed", 1, 3600)?;
    let lab = lab(s)?;
    if let Some(v) = speed {
        lab.speed = v;
    }
    match action {
        "play" => lab.playing = true,
        "pause" => lab.playing = false,
        "step" => {
            lab.playing = false;
            lab.sim.step();
        }
        other => {
            return Err(EngineError::bad(
                "action",
                format!("{:?}: play, pause or step", other.chars().take(16).collect::<String>()),
            ));
        }
    }
    Ok(json!({"now_ms": ms_of(lab.sim.now()), "playing": lab.playing, "speed": lab.speed}))
}

fn advance_by(lab: &mut Lab, d: Time) -> Value {
    let until = lab.sim.now().saturating_add(d);
    let done = lab.sim.advance(until, EVENT_BUDGET);
    json!({"now_ms": ms_of(lab.sim.now()), "done": done})
}

fn tick(s: &mut Session, p: &Value) -> Result<Value> {
    let wall = ranged(p, "wall_ms", 1, 10_000)?
        .ok_or_else(|| EngineError::bad("wall_ms", "is required"))?;
    let lab = lab(s)?;
    if !lab.playing {
        return Ok(json!({"now_ms": ms_of(lab.sim.now()), "done": true}));
    }
    let d = Time::from(wall) * MS * Time::from(lab.speed);
    Ok(advance_by(lab, d))
}

fn advance(s: &mut Session, p: &Value) -> Result<Value> {
    let ms = opt_u64(p, "ms")?
        .filter(|m| (1..=86_400_000).contains(m))
        .ok_or_else(|| EngineError::bad("ms", "must be 1..86400000"))?;
    Ok(advance_by(lab(s)?, ms * MS))
}

fn link_id(lab: &Lab, p: &Value) -> Result<LinkId> {
    let l = opt_u32(p, "link")?.ok_or_else(|| EngineError::bad("link", "is required"))?;
    lab.sim
        .link(LinkId(l))
        .map(|_| LinkId(l))
        .ok_or_else(|| EngineError::bad("link", format!("no link {l} (there are {})", lab.sim.link_count())))
}

fn node_id(lab: &Lab, p: &Value) -> Result<NodeId> {
    let name = req_str(p, "node")?;
    let i = lab.find(name).map_err(|e| EngineError::bad("node", e))?;
    Ok(NodeId(u32::try_from(i).unwrap_or(u32::MAX)))
}

fn latency(p: &Value) -> Result<Option<Time>> {
    Ok(opt_f64(p, "latency_ms", 0.001, 10_000.0)?.map(|ms| ((ms * MS as f64) as Time).max(1)))
}

fn fault(s: &mut Session, p: &Value) -> Result<Value> {
    let kind = req_str(p, "kind")?.to_owned();
    let at = opt_u64(p, "at_ms")?.map(|m| m.saturating_mul(MS));
    let lat = latency(p)?;
    let loss = ranged(p, "loss", 0, 100)?;
    let lab = lab(s)?;
    let f = match kind.as_str() {
        "link-cut" => Fault::LinkCut { link: link_id(lab, p)? },
        "link-down" => Fault::LinkDown { link: link_id(lab, p)? },
        "link-restore" => Fault::LinkRestore { link: link_id(lab, p)? },
        "node-down" => Fault::NodeDown { node: node_id(lab, p)? },
        "node-up" => Fault::NodeUp { node: node_id(lab, p)? },
        "latency" => Fault::Latency {
            link: link_id(lab, p)?,
            latency: lat.ok_or_else(|| EngineError::bad("latency_ms", "is required"))?,
        },
        "loss" => Fault::Loss {
            link: link_id(lab, p)?,
            loss_pct: u8::try_from(loss.ok_or_else(|| EngineError::bad("loss", "is required"))?).unwrap_or(100),
        },
        other => {
            return Err(EngineError::bad(
                "kind",
                format!(
                    "{:?}: link-cut, link-down, link-restore, node-down, node-up, latency or loss",
                    other.chars().take(16).collect::<String>()
                ),
            ));
        }
    };
    let at = at.unwrap_or(lab.sim.now()).max(lab.sim.now());
    lab.inject(at, f).map_err(on("kind"))?;
    Ok(json!({"at_ms": ms_of(at)}))
}

fn timeline(s: &mut Session, p: &Value) -> Result<Value> {
    let after = opt_u64(p, "after")?.unwrap_or(0) as usize;
    let limit = ranged(p, "limit", 1, 1000)?.unwrap_or(200) as usize;
    let lab = lab(s)?;
    let node = match opt_str(p, "node")? {
        Some(n) => Some(NodeId(u32::try_from(lab.find(n).map_err(|e| EngineError::bad("node", e))?).unwrap_or(u32::MAX))),
        None => None,
    };
    let names: Vec<String> = lab.sim.nodes().into_iter().map(|n| n.name).collect();
    let total = lab.sim.records().len();
    let mut records = Vec::new();
    let mut next = after;
    for (seq, r) in lab.sim.records().enumerate().skip(after) {
        next = seq + 1;
        if node.is_some_and(|n| r.node != Some(n) && r.node.is_some()) {
            continue;
        }
        let mut o = serde_json::to_value(r).unwrap_or(Value::Null);
        put(&mut o, "seq", json!(seq));
        put(&mut o, "at_ms", json!(r.at as f64 / MS as f64));
        put(&mut o, "layer", json!(r.kind.layer()));
        if let Some(n) = r.node {
            put(&mut o, "node", json!(names.get(n.0 as usize)));
        }
        records.push(o);
        if records.len() >= limit {
            break;
        }
    }
    Ok(json!({"records": records, "next": next, "total": total}))
}

fn node_get(s: &mut Session, p: &Value) -> Result<Value> {
    let limit = ranged(p, "routes_limit", 1, 5000)?.unwrap_or(500) as usize;
    let lab = lab(s)?;
    let id = node_id(lab, p)?;
    let view = lab.sim.nodes().into_iter().nth(id.0 as usize);
    let mut routes = lab.sim.routes(id);
    routes.truncate(limit);
    Ok(json!({
        "node": view,
        "routes": routes,
        "ospf_neighbors": lab.sim.ospf_neighbors(id),
        "bgp_peers": lab.sim.bgp_peers(id),
        "bgp_routes": lab.sim.bgp_routes(id, limit),
        "lsdb": lab.sim.lsdb(id),
    }))
}

fn node_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = super::args::opt_text(p, "name", 32)?;
    let asn = opt_u32(p, "asn")?.unwrap_or(65000);
    let at = pos(p)?;
    let lab = lab(s)?;
    let i = lab.add_node(name.as_deref(), asn, at).map_err(on("name"))?;
    Ok(json!({"node": lab.sim.nodes().into_iter().nth(i).map(|n| n.name)}))
}

fn node_run(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let params = p.get("params").cloned().unwrap_or_else(|| json!({}));
    let lab = lab(s)?;
    let node = node_id(lab, p)?;
    let result = lab.run_on(node.0 as usize, &id, params).map_err(on("id"))?;
    Ok(json!({"node": lab.sim.config(node).map(|c| c.name.clone()), "result": result}))
}

fn link_add(s: &mut Session, p: &Value) -> Result<Value> {
    let (a, b) = (req_str(p, "a")?.to_owned(), req_str(p, "b")?.to_owned());
    let cost = ranged(p, "cost", 1, 65535)?.unwrap_or(10);
    let lat = latency(p)?.unwrap_or(MS);
    let bfd = opt_bool(p, "bfd")?.unwrap_or(true);
    let ospf = opt_bool(p, "ospf")?.unwrap_or(true);
    let lab = lab(s)?;
    let ia = lab.find(&a).map_err(|e| EngineError::bad("a", e))?;
    let ib = lab.find(&b).map_err(|e| EngineError::bad("b", e))?;
    let id = lab.add_link(ia, ib, cost, lat, bfd, ospf).map_err(on("b"))?;
    Ok(json!({"link": id.0}))
}

fn link_set(s: &mut Session, p: &Value) -> Result<Value> {
    let cost = ranged(p, "cost", 1, 65535)?;
    let cost_a = ranged(p, "cost_a", 1, 65535)?.or(cost);
    let cost_b = ranged(p, "cost_b", 1, 65535)?.or(cost);
    let bfd = opt_bool(p, "bfd")?;
    let lat = latency(p)?;
    let loss = ranged(p, "loss", 0, 100)?;
    let lab = lab(s)?;
    let id = link_id(lab, p)?;
    lab.sim.set_link(id, cost_a, cost_b, bfd).map_err(on("link"))?;
    let now = lab.sim.now();
    if let Some(latency) = lat {
        lab.inject(now, Fault::Latency { link: id, latency }).map_err(on("latency_ms"))?;
    }
    if let Some(l) = loss {
        lab.inject(now, Fault::Loss { link: id, loss_pct: u8::try_from(l).unwrap_or(100) })
            .map_err(on("loss"))?;
    }
    Ok(json!({"link": id.0}))
}

fn import(s: &mut Session, p: &Value) -> Result<Value> {
    let name = super::args::opt_text(p, "name", 32)?.unwrap_or_else(|| "this-router".into());
    let at = pos(p)?;
    let real = s.store().running().clone();
    let lab = lab(s)?;
    let (i, refused) = lab.import(&name, &real, at).map_err(on("name"))?;
    Ok(json!({"node": lab.sim.nodes().into_iter().nth(i).map(|n| n.name), "refused": refused}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab_session() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("tool.netsim.new", &json!({})).unwrap();
        s
    }

    fn run_for(s: &mut Session, ms: u64) {
        loop {
            let r = s.execute("tool.netsim.advance", &json!({"ms": ms})).unwrap();
            if r["done"] == true {
                break;
            }
        }
    }

    #[test]
    fn the_square_converges_through_commands() {
        let mut s = lab_session();
        let v = s.execute("tool.netsim.get", &json!({})).unwrap();
        assert_eq!(v["badge"], crate::netsim::BADGE);
        assert_eq!(v["nodes"].as_array().unwrap().len(), 4);
        run_for(&mut s, 60_000);
        let v = s.execute("tool.netsim.get", &json!({})).unwrap();
        for n in v["nodes"].as_array().unwrap() {
            assert_eq!(n["bgp_established"], n["bgp_peers"], "{n}");
        }
        let r2 = s.execute("tool.netsim.node.get", &json!({"node": "R2"})).unwrap();
        let routes = r2["routes"].to_string();
        assert!(routes.contains("198.51.100.0/24"), "{routes}");
        // Each virtual router is a CoreRouter: its own config, by command.
        let addr = s
            .execute("tool.netsim.node.run", &json!({"node": "R2", "id": "ip.address.list"}))
            .unwrap();
        assert!(addr["result"].to_string().contains("10.255.0.2/32"), "{addr}");
    }

    #[test]
    fn a_fault_shows_on_the_timeline_and_the_convergence() {
        let mut s = lab_session();
        run_for(&mut s, 60_000);
        s.execute("tool.netsim.fault", &json!({"kind": "link-cut", "link": 0})).unwrap();
        run_for(&mut s, 5_000);
        let v = s.execute("tool.netsim.get", &json!({})).unwrap();
        let c = &v["convergence"];
        assert_eq!(c["fault"]["kind"], "link-cut", "{c}");
        assert!(c["detected_after_ms"].as_f64().unwrap() <= 900.0, "{c}");
        assert_eq!(v["links"][0]["state"], "cut");
        let t = s.execute("tool.netsim.timeline", &json!({"limit": 1000})).unwrap();
        let layers: Vec<&str> = t["records"].as_array().unwrap().iter().filter_map(|r| r["layer"].as_str()).collect();
        assert!(layers.contains(&"fault") && layers.contains(&"bfd") && layers.contains(&"ospf"), "{layers:?}");
        let r = s.execute("tool.netsim.timeline", &json!({"after": t["next"], "limit": 10})).unwrap();
        assert_eq!(r["records"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn a_command_on_a_virtual_router_changes_the_simulation() {
        let mut s = lab_session();
        run_for(&mut s, 60_000);
        // R4 stops sending to R1 (an output chain that rejects): R1 moves
        // to the path through R3.
        s.execute("tool.netsim.node.run", &json!({"node": "R4", "id": "routing.filter.rule.add", "params": {"chain": "to-r1", "rule": "reject"}})).unwrap();
        s.execute("tool.netsim.node.run", &json!({"node": "R4", "id": "routing.bgp.connection.set", "params": {"id": "r1", "output_filter": "to-r1"}})).unwrap();
        run_for(&mut s, 30_000);
        let r1 = s.execute("tool.netsim.node.get", &json!({"node": "R1"})).unwrap();
        let route = r1["routes"].as_array().unwrap().iter().find(|r| r["prefix"] == "198.51.100.0/24").cloned().unwrap();
        assert_eq!(route["proto"], "ibgp", "{route}");
        // A bad command is refused by the virtual router's own validation.
        let e = s.execute("tool.netsim.node.run", &json!({"node": "R4", "id": "routing.bgp.connection.set", "params": {"id": "r1", "output_filter": "nope"}})).unwrap_err();
        assert!(e.to_string().contains("R4"), "{e}");
        let e = s.execute("tool.netsim.node.run", &json!({"node": "R4", "id": "tool.netsim.clear"})).unwrap_err();
        assert!(e.to_string().contains("no simulator"), "{e}");
    }

    #[test]
    fn the_clock_plays_pauses_and_steps() {
        let mut s = lab_session();
        let r = s.execute("tool.netsim.tick", &json!({"wall_ms": 1000})).unwrap();
        assert_eq!(r["now_ms"], 0, "paused: nothing moves");
        s.execute("tool.netsim.clock", &json!({"action": "play", "speed": 60})).unwrap();
        let r = s.execute("tool.netsim.tick", &json!({"wall_ms": 500})).unwrap();
        assert_eq!(r["now_ms"], 30_000);
        let a = s.execute("tool.netsim.clock", &json!({"action": "step"})).unwrap();
        assert_eq!(a["playing"], false);
        assert!(a["now_ms"].as_u64().unwrap() >= 30_000);
        assert!(s.execute("tool.netsim.clock", &json!({"action": "rewind"})).is_err());
    }

    #[test]
    fn editing_the_topology() {
        let mut s = lab_session();
        let r = s.execute("tool.netsim.node.add", &json!({"name": "R5", "asn": 65200, "x": 0.5, "y": 0.9})).unwrap();
        assert_eq!(r["node"], "R5");
        let l = s.execute("tool.netsim.link.add", &json!({"a": "R5", "b": "R4", "latency_ms": 2})).unwrap();
        run_for(&mut s, 60_000);
        // eBGP came with the link (different ASes): R5 learns the ISP's /16.
        let r5 = s.execute("tool.netsim.node.get", &json!({"node": "R5"})).unwrap();
        assert!(r5["routes"].to_string().contains("100.64.0.0/16"), "{r5}");
        s.execute("tool.netsim.link.set", &json!({"link": l["link"], "cost": 50, "loss": 10})).unwrap();
        let v = s.execute("tool.netsim.get", &json!({})).unwrap();
        let link = &v["links"][l["link"].as_u64().unwrap() as usize];
        assert_eq!(link["cost_a"], 50);
        assert!(s.execute("tool.netsim.link.add", &json!({"a": "R5", "b": "R55"})).unwrap_err().to_string().contains("did you mean"));
        assert!(s.execute("tool.netsim.fault", &json!({"kind": "link-cut", "link": 99})).is_err());
    }

    #[test]
    fn export_and_load_replay_the_same_run() {
        let mut s = lab_session();
        run_for(&mut s, 30_000);
        s.execute("tool.netsim.fault", &json!({"kind": "node-down", "node": "R2"})).unwrap();
        run_for(&mut s, 30_000);
        let file = s.execute("tool.netsim.export", &json!({"expect": true})).unwrap();
        let mut t = Session::virtual_lab();
        let r = t.execute("tool.netsim.load", &json!({"scenario": file})).unwrap();
        assert_eq!(r["run_ms"], 60_000);
        run_for(&mut t, 60_000);
        let again = t.execute("tool.netsim.export", &json!({"expect": true})).unwrap();
        assert_eq!(file["expect"], again["expect"]);
        assert!(t.execute("tool.netsim.load", &json!({"scenario": {"format": "x"}})).is_err());
    }

    #[test]
    fn what_if_imports_this_router() {
        let mut s = lab_session();
        s.execute("interface.loopback.add", &json!({"name": "lo0"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "10.255.9.9/32", "interface": "lo0"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "192.0.2.1/30", "interface": "ether1"})).unwrap();
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.255.9.9"})).unwrap();
        s.execute("routing.filter.rule.add", &json!({"chain": "up-in", "rule": "accept"})).unwrap();
        s.execute("routing.bgp.template.add", &json!({"name": "up", "hold_time": 90, "input_filter": "up-in", "output_filter": "up-in"})).unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "upstream", "remote_address": "192.0.2.2", "remote_as": 64999, "templates": "up"})).unwrap();
        s.execute("routing.ospf.instance.add", &json!({"name": "core", "router_id": "10.255.9.9"})).unwrap();
        s.execute("routing.ospf.area.add", &json!({"name": "bb", "instance": "core", "area_id": "0.0.0.0"})).unwrap();
        s.execute("routing.ospf.interface-template.add", &json!({"area": "bb", "interfaces": ["ether1"], "type": "ptp", "cost": 30})).unwrap();
        let r = s.execute("tool.netsim.import", &json!({})).unwrap();
        assert_eq!(r["node"], "this-router");
        assert_eq!(r["refused"], json!([]), "{r}");
        let n = s.execute("tool.netsim.node.get", &json!({"node": "this-router"})).unwrap();
        assert_eq!(n["bgp_peers"][0]["name"], "upstream", "{n}");
        let t = s.execute("tool.netsim.node.run", &json!({"node": "this-router", "id": "routing.ospf.interface-template.list"})).unwrap();
        assert_eq!(t["result"][0]["cost"], 30, "{t}");
        // The real router is untouched.
        assert!(s.store().running().routing.bgp_connections.contains_key("upstream"));
        assert_eq!(s.store().running().ip.addresses.len(), 2);
    }

    #[test]
    fn without_a_simulation_commands_say_so() {
        let mut s = Session::virtual_lab();
        assert_eq!(s.execute("tool.netsim.get", &json!({})).unwrap()["loaded"], false);
        let e = s.execute("tool.netsim.advance", &json!({"ms": 10})).unwrap_err();
        assert!(e.to_string().contains("tool.netsim.new") && e.to_string().contains("disabled"), "{e}");
        assert!(s.execute("tool.netsim.new", &json!({"preset": "rnig"})).unwrap_err().to_string().contains("ring"));
        assert!(s.execute("tool.netsim.new", &json!({"preset": "ring", "nodes": 40, "bgp": "ibgp"})).is_err());
        assert_eq!(s.execute("tool.netsim.clear", &json!({})).unwrap()["cleared"], false);
    }

    fn route(s: &mut Session, node: &str, prefix: &str) -> Option<Value> {
        let n = s.execute("tool.netsim.node.get", &json!({"node": node})).unwrap();
        n["routes"].as_array().unwrap().iter().find(|r| r["prefix"] == prefix).cloned()
    }

    #[test]
    fn each_virtual_router_runs_its_own_ospf_config() {
        // G3.7d: the presets type OSPF in each router (instance, backbone,
        // point-to-point template, passive loopback); the simulator reads it.
        let mut s = lab_session();
        let t = s.execute("tool.netsim.node.run", &json!({"node": "R1", "id": "routing.ospf.interface-template.list"})).unwrap();
        let rows = t["result"].as_array().unwrap().clone();
        assert!(rows.iter().any(|r| r["passive"] == true && r["interfaces"] == json!(["lo"])), "{t}");
        let ptp = rows.iter().find(|r| r["type"] == "ptp").unwrap()["id"].clone();
        run_for(&mut s, 60_000);
        assert_eq!(route(&mut s, "R1", "10.255.0.2/32").unwrap()["metric"], 10);
        // A template before it makes ether1 (to R2) cost 100: R1 goes round by R3.
        s.execute("tool.netsim.node.run", &json!({"node": "R1", "id": "routing.ospf.interface-template.add",
            "params": {"area": "backbone", "interfaces": ["ether1"], "type": "ptp", "cost": 100, "place_before": ptp}})).unwrap();
        run_for(&mut s, 30_000);
        assert_eq!(route(&mut s, "R1", "10.255.0.2/32").unwrap()["metric"], 20);
        // R2 turns its OSPF off: its loopback leaves the other routers.
        s.execute("tool.netsim.node.run", &json!({"node": "R2", "id": "routing.ospf.instance.set",
            "params": {"id": "default", "disabled": true}})).unwrap();
        run_for(&mut s, 60_000);
        assert!(route(&mut s, "R1", "10.255.0.2/32").is_none());
        // The upstream (R4) has no OSPF at all.
        let r4 = s.execute("tool.netsim.node.run", &json!({"node": "R4", "id": "routing.ospf.instance.list"})).unwrap();
        assert_eq!(r4["result"], json!([]));
    }

    #[test]
    fn a_new_link_joins_ospf_by_command() {
        let mut s = lab_session();
        s.execute("tool.netsim.node.add", &json!({"name": "R5", "asn": 65000})).unwrap();
        s.execute("tool.netsim.link.add", &json!({"a": "R5", "b": "R2"})).unwrap();
        run_for(&mut s, 60_000);
        // R5's loopback reaches R1 through OSPF (R5 typed its template).
        let r = route(&mut s, "R1", "10.255.0.5/32").unwrap();
        assert_eq!(r["proto"], "ospf", "{r}");
    }

    #[test]
    fn bgp_bfd_comes_from_the_connection() {
        // G3.6b: the presets put the `default` BFD profile on eBGP; without
        // it a silent cut waits for the hold timer.
        let peers = |s: &mut Session| {
            s.execute("tool.netsim.node.get", &json!({"node": "R1"})).unwrap()["bgp_peers"].clone()
        };
        for with_bfd in [true, false] {
            let mut s = lab_session();
            if !with_bfd {
                for (node, conn) in [("R1", "r4"), ("R4", "r1")] {
                    s.execute("tool.netsim.node.run", &json!({"node": node, "id": "routing.bgp.connection.set",
                        "params": {"id": conn, "bfd": null}})).unwrap();
                }
            }
            run_for(&mut s, 60_000);
            let v = s.execute("tool.netsim.get", &json!({})).unwrap();
            let up = v["links"].as_array().unwrap().iter().find(|l| l["ospf"] == false && (l["a"] == 0 || l["b"] == 0)).unwrap()["id"].clone();
            s.execute("tool.netsim.fault", &json!({"kind": "link-cut", "link": up})).unwrap();
            run_for(&mut s, 5_000);
            let r4 = peers(&mut s).as_array().unwrap().iter().find(|p| p["name"] == "r4").cloned().unwrap();
            assert_eq!(r4["state"] != "established", with_bfd, "bfd {with_bfd}: {r4}");
        }
    }
}