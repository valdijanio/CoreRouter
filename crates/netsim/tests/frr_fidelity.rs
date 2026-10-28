//! G3.7c: the simulator against a real FRR. The same scenario runs in the
//! simulator and as one FRR instance (zebra, ospfd, bgpd) per router, each
//! in its own network namespace, one veth per link; after both converge,
//! every router must have the same best routes: prefix, protocol, OSPF
//! metric and the interfaces packets leave by (ECMP included), and the same
//! BGP sessions up.
//!
//! Root and FRR: the lab VM only (`scripts/frr-netsim-fidelity.sh`). Without
//! `NETSIM_FRR_LIVE=1` the test returns at once.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_netsim::preset::{BgpMode, Plan, Scenario, ring, square};
use corerouter_netsim::{NodeId, Proto, SEC, Simulation};
use serde_json::Value;

/// One best route as both sides can say it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Best {
    proto: &'static str,
    /// OSPF only (BGP's MED/IGP cost is not comparable as a number).
    metric: Option<u32>,
    ifaces: Vec<String>,
}

type Table = BTreeMap<String, Best>;

fn ns(scenario: &str, node: &str) -> String {
    format!("crs{}{}", &scenario[..2], node.to_lowercase())
}

fn sh(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{cmd} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn quiet(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

/// The simulator's view: run until nothing changes for 30 virtual s.
fn simulated(s: &Scenario, plan: &Plan) -> (Vec<Table>, Vec<usize>) {
    let mut sim: Simulation = s.build(7).unwrap();
    sim.advance(180 * SEC, u64::MAX);
    let mut tables = Vec::new();
    let mut up = Vec::new();
    for (i, n) in plan.nodes.iter().enumerate() {
        let id = NodeId(i as u32);
        let mut t = Table::new();
        for r in sim.routes(id) {
            let proto = match r.proto {
                Proto::Connected => continue,
                Proto::Ospf => "ospf",
                Proto::Ebgp | Proto::Ibgp => "bgp",
            };
            if r.links.is_empty() {
                continue; // its own loopback or network
            }
            let mut ifaces: Vec<String> = r
                .links
                .iter()
                .filter_map(|l| sim.link(*l))
                .map(|l| {
                    if l.a.node == id {
                        l.a.iface.clone()
                    } else {
                        l.b.iface.clone()
                    }
                })
                .collect();
            ifaces.sort();
            ifaces.dedup();
            t.insert(
                r.prefix.to_string(),
                Best {
                    proto,
                    metric: (proto == "ospf").then_some(r.metric),
                    ifaces,
                },
            );
        }
        tables.push(t);
        up.push(
            sim.bgp_peers(id)
                .iter()
                .filter(|p| p.state == "established")
                .count(),
        );
        let _ = n;
    }
    (tables, up)
}

/// FRR's configuration for one router of the plan: ospfd's and bgpd's.
fn frr_conf(plan: &Plan, i: usize) -> (String, String) {
    let n = &plan.nodes[i];
    let mut c = String::new();
    // Interfaces in OSPF: the loopback (passive) and the links with ospf.
    let ospf_ifaces: Vec<(String, u32)> = plan
        .links
        .iter()
        .filter(|l| l.ospf)
        .filter_map(|l| {
            if l.a.node.0 as usize == i {
                Some((l.a.iface.clone(), l.cost_a))
            } else if l.b.node.0 as usize == i {
                Some((l.b.iface.clone(), l.cost_b))
            } else {
                None
            }
        })
        .collect();
    for (iface, cost) in &ospf_ifaces {
        let _ = writeln!(
            c,
            "interface {iface}\n ip ospf network point-to-point\n ip ospf cost {cost}\n ip ospf hello-interval 1\n ip ospf dead-interval 4\n ip ospf area 0.0.0.0\nexit"
        );
    }
    let _ = writeln!(
        c,
        "interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit"
    );
    let _ = writeln!(c, "router ospf\n ospf router-id {}\nexit", n.router_id);
    let ospf = std::mem::take(&mut c);
    if !n.neighbors.is_empty() || !n.networks.is_empty() {
        let _ = writeln!(c, "router bgp {}", n.asn);
        let _ = writeln!(c, " bgp router-id {}", n.router_id);
        let _ = writeln!(
            c,
            " no bgp ebgp-requires-policy\n no bgp network import-check"
        );
        let _ = writeln!(c, " timers bgp 3 9");
        for nb in &n.neighbors {
            let asn = nb.remote_as.unwrap_or(n.asn);
            let _ = writeln!(c, " neighbor {} remote-as {asn}", nb.remote);
            let _ = writeln!(c, " neighbor {} advertisement-interval 0", nb.remote);
            if let Some(l) = nb.local {
                let _ = writeln!(c, " neighbor {} update-source {l}", nb.remote);
            }
        }
        let _ = writeln!(c, " address-family ipv4 unicast");
        for p in &n.networks {
            let _ = writeln!(c, "  network {p}");
        }
        for nb in &n.neighbors {
            if nb.next_hop_self {
                let _ = writeln!(c, "  neighbor {} next-hop-self", nb.remote);
            }
        }
        let _ = writeln!(c, " exit-address-family\nexit");
    }
    (ospf, c)
}

fn teardown(s: &Scenario, plan: &Plan) {
    for n in &plan.nodes {
        let name = ns(&s.name, &n.name);
        quiet("pkill", &["-f", "--", &format!("-N {name}( |$)")]);
        quiet("ip", &["netns", "del", &name]);
    }
}

fn frr_up(s: &Scenario, plan: &Plan) {
    teardown(s, plan);
    std::thread::sleep(Duration::from_millis(300));
    for n in &plan.nodes {
        let name = ns(&s.name, &n.name);
        sh("ip", &["netns", "add", &name]);
        sh("ip", &["-n", &name, "link", "set", "lo", "up"]);
    }
    for l in &plan.links {
        let (a, b) = (
            &plan.nodes[l.a.node.0 as usize],
            &plan.nodes[l.b.node.0 as usize],
        );
        let (na, nb) = (ns(&s.name, &a.name), ns(&s.name, &b.name));
        sh(
            "ip",
            &[
                "-n", &na, "link", "add", &l.a.iface, "type", "veth", "peer", "name", &l.b.iface,
                "netns", &nb,
            ],
        );
    }
    for (i, n) in plan.nodes.iter().enumerate() {
        let name = ns(&s.name, &n.name);
        for a in &n.addresses {
            sh(
                "ip",
                &[
                    "-n",
                    &name,
                    "addr",
                    "add",
                    &a.net.to_string(),
                    "dev",
                    &a.iface,
                ],
            );
            sh("ip", &["-n", &name, "link", "set", &a.iface, "up"]);
        }
        let dir = format!("/etc/frr/{name}");
        sh(
            "install",
            &[
                "-d",
                "-o",
                "frr",
                "-g",
                "frr",
                &dir,
                &format!("/var/run/frr/{name}"),
            ],
        );
        let (ospf, bgp) = frr_conf(plan, i);
        std::fs::write(format!("{dir}/zebra.conf"), "").unwrap();
        std::fs::write(format!("{dir}/ospfd.conf"), ospf).unwrap();
        std::fs::write(format!("{dir}/bgpd.conf"), bgp).unwrap();
        std::fs::write(format!("{dir}/vtysh.conf"), "").unwrap();
        sh("chown", &["-R", "frr:frr", &dir]);
        for d in ["zebra", "ospfd", "bgpd"] {
            // A daemon keeps the pipes `output()` would wait on: no pipes.
            let ok = Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    &name,
                    &format!("/usr/lib/frr/{d}"),
                    "-N",
                    &name,
                    "-d",
                ])
                .args(["-f", &format!("{dir}/{d}.conf")])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success();
            assert!(ok, "{d} of {name} did not start");
            if d == "zebra" {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn frr_table(name: &str) -> Table {
    let v: Value = serde_json::from_str(&sh("vtysh", &["-N", name, "-c", "show ip route json"]))
        .unwrap_or(Value::Null);
    let mut t = Table::new();
    let Some(m) = v.as_object() else { return t };
    for (prefix, entries) in m {
        let Some(e) = entries
            .as_array()
            .and_then(|a| a.iter().find(|e| e["selected"] == true))
        else {
            continue;
        };
        let proto = match e["protocol"].as_str() {
            Some("ospf") => "ospf",
            Some("bgp") => "bgp",
            _ => continue,
        };
        let mut ifaces: Vec<String> = e["nexthops"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|h| h["fib"] == true)
            .filter_map(|h| h["interfaceName"].as_str().map(str::to_owned))
            .collect();
        ifaces.sort();
        ifaces.dedup();
        if ifaces.is_empty() {
            continue; // not installed (its own network, a loopback)
        }
        t.insert(
            prefix.clone(),
            Best {
                proto,
                metric: (proto == "ospf").then(|| e["metric"].as_u64().unwrap_or(0) as u32),
                ifaces,
            },
        );
    }
    t
}

fn frr_established(name: &str) -> usize {
    let v: Value = serde_json::from_str(&sh(
        "vtysh",
        &["-N", name, "-c", "show bgp ipv4 unicast summary json"],
    ))
    .unwrap_or(Value::Null);
    v["peers"]
        .as_object()
        .map(|p| p.values().filter(|p| p["state"] == "Established").count())
        .unwrap_or(0)
}

fn compare(s: &Scenario) {
    let plan = s.plan().unwrap();
    let (want, want_up) = simulated(s, &plan);
    let started = Instant::now();
    frr_up(s, &plan);
    let names: Vec<String> = plan.nodes.iter().map(|n| ns(&s.name, &n.name)).collect();
    // Converged: every table as the simulator's, for 5 s in a row.
    let mut same_since: Option<Instant> = None;
    let mut last = Vec::new();
    while started.elapsed() < Duration::from_secs(120) {
        last = names.iter().map(|n| frr_table(n)).collect::<Vec<_>>();
        let up: Vec<usize> = names.iter().map(|n| frr_established(n)).collect();
        if last == want && up == want_up {
            let since = *same_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(5) {
                break;
            }
        } else {
            same_since = None;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let routes: usize = want.iter().map(BTreeMap::len).sum();
    if same_since.is_none_or(|s| s.elapsed() < Duration::from_secs(5)) {
        let mut diff = String::new();
        for (i, (w, g)) in want.iter().zip(&last).enumerate() {
            for p in w
                .keys()
                .chain(g.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                if w.get(p) != g.get(p) {
                    let _ = writeln!(
                        diff,
                        "{} {p}: simulator {:?}, FRR {:?}",
                        plan.nodes[i].name,
                        w.get(p),
                        g.get(p)
                    );
                }
            }
        }
        let up: Vec<usize> = names.iter().map(|n| frr_established(n)).collect();
        teardown(s, &plan);
        panic!(
            "{}: FRR differs from the simulator\nBGP sessions up: simulator {want_up:?}, FRR {up:?}\n{diff}",
            s.name
        );
    }
    eprintln!(
        "{}: {} routers, {routes} best routes and {} BGP sessions the same in FRR (converged in {:.1} s)",
        s.name,
        plan.nodes.len(),
        want_up.iter().sum::<usize>() / 2,
        started.elapsed().as_secs_f64() - 5.0
    );
    teardown(s, &plan);
}

#[test]
fn simulator_matches_frr() {
    if std::env::var("NETSIM_FRR_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: NETSIM_FRR_LIVE=1 only in the lab VM (scripts/frr-netsim-fidelity.sh)");
        return;
    }
    // The square: OSPF triangle, iBGP full mesh with next-hop-self, an
    // upstream with eBGP to two borders. A 5-ring with eBGP everywhere
    // (shortest AS path, no ties). A 4-ring with OSPF only (ECMP across).
    let mut failures = Vec::new();
    for s in [square(), ring(5, BgpMode::Ebgp), ring(4, BgpMode::None)] {
        if let Err(e) = std::panic::catch_unwind(|| compare(&s)) {
            failures.push(
                e.downcast_ref::<String>()
                    .cloned()
                    .unwrap_or_else(|| "panic".into()),
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
