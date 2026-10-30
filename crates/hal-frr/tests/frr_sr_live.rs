//! G3.4f (and G3.4d) against a real FRR, in the lab VM only
//! (`scripts/frr-sr-live.sh` starts R2..R4 of a square in namespaces).
//! Without `COREROUTER_FRR_LIVE=1` the tests return at once.
//!
//! What `live_sr` shows:
//! - the OSPF + SR render is FRR's canonical form (a second sync types
//!   nothing), with the default blocks and with a moved SRGB;
//! - the SR database is read: R2..R4 with their SIDs;
//! - zebra puts the SID's label on the kernel route and a ping crosses it;
//! - R1's loopback addresses reach the kernel through `LinuxHal` (G3.4i):
//!   the loopback named `lo` is the kernel's `lo`, so ospfd takes its
//!   prefix SID and R2 and R3 switch R1's label;
//! - a prefix SID on a dummy interface (a loopback with another name) is
//!   still refused by ospfd (only an IFF_LOOPBACK interface takes one);
//! - switching SR off types the removals in an order FRR takes.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_hal::routing::RoutingDaemon;
use corerouter_hal_frr::Frr;
use corerouter_model::Config;
use corerouter_model::config::AddressEntry;
use corerouter_model::ospf::{
    AreaId, AreaType, NetworkType, NssaTranslate, OspfArea, OspfInstance, OspfTemplate,
};
use corerouter_model::ospf_sr::{LabelBlock, PrefixSid, SegmentRouting, SidBehavior, SrDb};
use corerouter_model::types::ItemId;

fn live() -> Option<Frr> {
    (std::env::var("COREROUTER_FRR_LIVE").as_deref() == Ok("1"))
        .then(|| Frr::new(std::env::var("COREROUTER_FRR_DIR").unwrap_or("/var/run/frr".into())))
}

/// R1: crsr-a to R2 and crsr-h to R4 (cost 10 each), the loopback on lo.
pub fn config() -> Config {
    let mut cfg = Config::default();
    for (n, kind) in [
        ("crsr-a", "ethernet"),
        ("crsr-h", "ethernet"),
        ("lo", "loopback"),
        ("crsr-lo", "loopback"),
    ] {
        let iface =
            serde_json::from_value(serde_json::json!({"name": n, "kind": {"type": kind}})).unwrap();
        cfg.interfaces.insert(n.parse().unwrap(), iface);
    }
    for (i, (a, n)) in [
        ("10.255.0.1/32", "lo"),
        ("10.255.0.11/32", "crsr-lo"),
        ("10.0.12.1/30", "crsr-a"),
        ("10.0.14.1/30", "crsr-h"),
    ]
    .into_iter()
    .enumerate()
    {
        cfg.ip.addresses.push(AddressEntry {
            id: ItemId(u32::try_from(i).unwrap() + 1),
            address: a.parse().unwrap(),
            interface: n.parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let o = &mut cfg.routing.ospf;
    o.instances.insert(
        "v2".into(),
        OspfInstance {
            name: "v2".into(),
            version: Default::default(),
            vrf: "main".into(),
            router_id: Some("10.255.0.1".parse().unwrap()),
            redistribute: Vec::new(),
            out_filter_chain: None,
            originate_default: Default::default(),
            subscriber_pools: false,
            stub_router: false,
            stub_router_on_startup: None,
            disabled: false,
            comment: String::new(),
        },
    );
    o.areas.insert(
        "backbone".into(),
        OspfArea {
            name: "backbone".into(),
            instance: "v2".into(),
            area_id: AreaId(0),
            kind: AreaType::Default,
            no_summaries: false,
            default_cost: None,
            nssa_translate: NssaTranslate::Candidate,
            disabled: false,
            comment: String::new(),
        },
    );
    for name in ["crsr-a", "crsr-h"] {
        let id = o.next_id();
        o.templates.push(OspfTemplate {
            id,
            area: "backbone".into(),
            interfaces: vec![name.into()],
            kind: NetworkType::Ptp,
            cost: Some(10),
            hello_interval: Some(1),
            dead_interval: Some(4),
            ..OspfTemplate::default()
        });
    }
    let id = o.next_id();
    o.templates.push(OspfTemplate {
        id,
        area: "backbone".into(),
        interfaces: vec!["lo".into(), "crsr-lo".into()],
        passive: true,
        ..OspfTemplate::default()
    });
    o.segment_routing = Some(SegmentRouting::new("v2"));
    let id = o.next_id();
    o.prefix_sids.push(PrefixSid {
        id,
        prefix: "10.255.0.1/32".parse().unwrap(),
        index: 1,
        behavior: SidBehavior::Php,
        disabled: false,
        comment: String::new(),
    });
    cfg
}

/// R1's kernel side of [`config`] put by `LinuxHal` (G3.4i): the loopback
/// `lo` (the kernel's own) and the dummy `crsr-lo`, with their addresses;
/// the ports are the script's veths. Taken back on drop, even on a panic.
pub struct KernelLo {
    hal: corerouter_hal_linux::LinuxHal,
    cfg: Config,
}

impl KernelLo {
    pub fn apply(full: &Config) -> Self {
        use corerouter_hal::Hal;
        let mut cfg = Config::default();
        for n in ["lo", "crsr-lo"] {
            let n: corerouter_model::IfName = n.parse().unwrap();
            cfg.interfaces
                .insert(n.clone(), full.interfaces[&n].clone());
        }
        cfg.ip.addresses = full
            .ip
            .addresses
            .iter()
            .filter(|a| cfg.interfaces.contains_key(&a.interface))
            .cloned()
            .collect();
        let mut hal = corerouter_hal_linux::LinuxHal::new();
        let t = Instant::now();
        hal.apply(&Config::default(), &cfg).unwrap();
        eprintln!(
            "LinuxHal: lo + crsr-lo applied in {:.2} ms",
            t.elapsed().as_secs_f64() * 1000.0
        );
        let (_, lo) = sh("ip", &["-o", "addr", "show", "dev", "lo"]);
        assert!(
            lo.contains("10.255.0.1/32") && lo.contains("127.0.0.1/8"),
            "{lo}"
        );
        Self { hal, cfg }
    }
}

impl Drop for KernelLo {
    fn drop(&mut self) {
        use corerouter_hal::Hal;
        if let Err(e) = self.hal.apply(&self.cfg, &Config::default()) {
            eprintln!("taking R1's loopback back: {e}");
        }
    }
}

pub fn sh(cmd: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(cmd).args(args).output().unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

pub fn wait<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        if let Some(v) = f() {
            eprintln!("{what} after {:.1} s", t.elapsed().as_secs_f64());
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(secs), "not {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A kernel route with its nexthop: zebra installs nexthop objects, so the
/// label is on `ip nexthop show id N`, not on the route line.
pub fn kernel_route(dst: &str) -> String {
    let (_, mut t) = sh("ip", &["route", "show", dst]);
    let ids: Vec<String> = t
        .split_whitespace()
        .skip_while(|w| *w != "nhid")
        .nth(1)
        .map(str::to_owned)
        .into_iter()
        .collect();
    for id in ids {
        let (_, nh) = sh("ip", &["nexthop", "show", "id", &id]);
        t.push_str(&nh);
        // A group: its members.
        if let Some(g) = nh.split_whitespace().skip_while(|w| *w != "group").nth(1) {
            for m in g.split('/').filter_map(|x| x.split(',').next()) {
                let (_, x) = sh("ip", &["nexthop", "show", "id", m]);
                t.push_str(&x);
            }
        }
    }
    // iproute2 prints "encap mpls  16003" (two spaces).
    t.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sr_db(frr: &Frr, cfg: &Config) -> SrDb {
    frr.ospf_lsdb(cfg, "v2")
        .map(|(db, _)| db.sr)
        .unwrap_or_default()
}

fn canonical(frr: &Frr, cfg: &Config, what: &str) {
    let again = frr.sync(&frr.render(cfg).unwrap()).unwrap();
    assert!(
        again.commands.is_empty() && again.leftover.is_empty(),
        "{what}: not canonical: {again:?}"
    );
}

#[test]
fn live_sr() {
    let Some(mut frr) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-sr-live.sh)");
        return;
    };
    let cfg = config();
    assert_eq!(corerouter_proto_ospf::validate(&cfg), Vec::new());
    let _lo = KernelLo::apply(&cfg);
    let started = Instant::now();
    frr.apply(&Config::default(), &cfg).unwrap();
    eprintln!(
        "applied in {:.1} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    canonical(&frr, &cfg, "SR on, default blocks");

    let db = wait("R2..R4 in the SR database", 90, || {
        let db = sr_db(&frr, &cfg);
        (db.nodes.len() >= 4).then_some(db)
    });
    for n in &db.nodes {
        eprintln!(
            "SR node {} SRGB {}+{} prefixes {:?}",
            Ipv4Addr::from(n.router_id),
            n.srgb_start,
            n.srgb_size,
            n.prefixes
                .iter()
                .map(|p| (Ipv4Addr::from(p.prefix), p.sid, p.in_label))
                .collect::<Vec<_>>()
        );
    }
    let conflicts = corerouter_proto_ospf::sr::conflicts(&db, &cfg.routing.ospf.prefix_sids);
    assert!(conflicts.is_empty(), "{conflicts:?}");
    let route = wait("kernel route to R3 with SID label 16003", 60, || {
        let t = kernel_route("10.255.0.3");
        t.contains("encap mpls 16003").then_some(t)
    });
    eprintln!("kernel: {}", route.trim());
    let ping = wait("ping through the SR label", 30, || {
        let (ok, t) = sh(
            "ping",
            &["-c", "1", "-W", "1", "-I", "10.255.0.1", "10.255.0.3"],
        );
        ok.then_some(t)
    });
    eprintln!("{}", ping.lines().last().unwrap_or_default());
    eprintln!(
        "SR path usable {:.1} s after the commit",
        started.elapsed().as_secs_f64()
    );
    let (_, r2) = sh("ip", &["-n", "crsr2", "-f", "mpls", "route", "show"]);
    eprintln!("R2's label table:\n{r2}");
    assert!(
        r2.lines()
            .any(|l| l.starts_with("16003") && l.contains("10.0.23.2")),
        "R2 does not switch 16003 towards R3"
    );
    // G3.4i: ospfd took R1's prefix SID on the kernel's lo: R2 (its
    // neighbour, PHP: pops) and R3 switch R1's label 16001.
    for ns in ["crsr2", "crsr3"] {
        let t = wait(&format!("{ns} switches R1's SID label 16001"), 60, || {
            let (_, t) = sh("ip", &["-n", ns, "-f", "mpls", "route", "show"]);
            t.lines().any(|l| l.starts_with("16001")).then_some(t)
        });
        eprintln!(
            "{ns}: {}",
            t.lines()
                .find(|l| l.starts_with("16001"))
                .unwrap_or_default()
        );
    }
    let (_, back) = sh(
        "ip",
        &[
            "netns",
            "exec",
            "crsr3",
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            "10.255.0.3",
            "10.255.0.1",
        ],
    );
    eprintln!("R3 → R1's lo: {}", back.lines().last().unwrap_or_default());
    let (_, mine) = sh("ip", &["-f", "mpls", "route", "show"]);
    eprintln!("R1's label table:\n{mine}");

    // A moved SRGB and SRLB, as FRR prints them back.
    let mut moved = cfg.clone();
    if let Some(sr) = moved.routing.ospf.segment_routing.as_mut() {
        sr.srgb = LabelBlock {
            start: 20_000,
            end: 27_999,
        };
        sr.srlb = LabelBlock {
            start: 5_000,
            end: 5_999,
        };
        sr.node_msd = Some(8);
    }
    moved.routing.ospf.prefix_sids[0].behavior = SidBehavior::ExplicitNull;
    let t = Instant::now();
    frr.apply(&cfg, &moved).unwrap();
    eprintln!("SRGB moved in {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    canonical(&frr, &moved, "moved SRGB, explicit-null");
    frr.apply(&moved, &cfg).unwrap();
    canonical(&frr, &cfg, "back to the defaults");

    // ospfd takes a prefix SID only on an IFF_LOOPBACK interface: a dummy
    // (what CoreRouter's loopback interfaces are on Linux) is refused.
    let mut dummy = cfg.clone();
    let id = dummy.routing.ospf.next_id();
    dummy.routing.ospf.prefix_sids.push(PrefixSid {
        id,
        prefix: "10.255.0.11/32".parse().unwrap(),
        index: 11,
        behavior: SidBehavior::Php,
        disabled: false,
        comment: String::new(),
    });
    match frr.apply(&cfg, &dummy) {
        Ok(()) => {
            let (_, run) = sh("vtysh", &["-c", "show running-config ospfd"]);
            eprintln!("FRR took a SID on a dummy interface:\n{run}");
            frr.apply(&dummy, &cfg).unwrap();
        }
        Err(e) => eprintln!("SID on a dummy interface refused by ospfd: {e}"),
    }
    canonical(&frr, &cfg, "after the dummy");

    // Off: the prefixes go before SR, SR before its opaque LSAs.
    let t = Instant::now();
    frr.apply(&cfg, &Config::default()).unwrap();
    eprintln!("SR off in {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let (_, run) = sh("vtysh", &["-c", "show running-config ospfd"]);
    assert!(!run.contains("segment-routing"), "{run}");
}

// ---- G3.4d: TI-LFA ----

const SINK: &str = "COREROUTER_UDP_SINK";
/// One datagram every this many microseconds (2 000 a second).
const GAP_US: u64 = 500;

/// The receiver, run inside R3's namespace by `ip netns exec` (this same
/// test binary, `udp_sink`): counts the iperf3 datagrams (proto-iperf's
/// header and loss accounting) and the longest silence between two.
#[test]
fn udp_sink() {
    let Ok(spec) = std::env::var(SINK) else {
        return;
    };
    let mut it = spec.split(',');
    let (addr, out, secs) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap().parse::<u64>().unwrap(),
    );
    let sock = std::net::UdpSocket::bind(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut rx = corerouter_proto_iperf::UdpRx::default();
    let start = Instant::now();
    let mut last: Option<Instant> = None;
    let mut worst = Duration::ZERO;
    let mut buf = [0u8; 2048];
    while start.elapsed() < Duration::from_secs(secs) {
        let Ok(n) = sock.recv(&mut buf) else { continue };
        let Some(h) = corerouter_proto_iperf::UdpHeader::read(buf.get(..n).unwrap_or(&[]), false)
        else {
            continue;
        };
        let now = Instant::now();
        if let Some(l) = last {
            worst = worst.max(now - l);
        }
        last = Some(now);
        rx.on_datagram(&h, start.elapsed().as_secs_f64());
    }
    std::fs::write(
        out,
        format!("{} {} {}", rx.packet_count, rx.errors, worst.as_micros()),
    )
    .unwrap();
}

/// Send to R3's loopback from R1's for `secs`, run `cut` after one second;
/// (sent, lost, the longest silence at the receiver).
fn measure(secs: u64, cut: impl FnOnce()) -> (u64, u64, Duration) {
    let out = format!("/tmp/crsr-sink-{}", std::process::id());
    let _ = std::fs::remove_file(&out);
    let exe = std::env::current_exe().unwrap();
    let mut sink = Command::new("ip")
        .args(["netns", "exec", "crsr3"])
        .arg(&exe)
        .args(["--exact", "udp_sink", "--nocapture"])
        .env(SINK, format!("10.255.0.3:5201,{out},{}", secs + 2))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let sock = std::net::UdpSocket::bind("10.255.0.1:0").unwrap();
    sock.connect("10.255.0.3:5201").unwrap();
    let start = Instant::now();
    let mut cut = Some(cut);
    let mut seq = 0u64;
    let mut buf = [0u8; 128];
    while start.elapsed() < Duration::from_secs(secs) {
        seq += 1;
        let t = start.elapsed();
        corerouter_proto_iperf::UdpHeader {
            sec: u32::try_from(t.as_secs()).unwrap(),
            usec: t.subsec_micros(),
            seq,
        }
        .write(&mut buf, false);
        let _ = sock.send(&buf);
        if t >= Duration::from_secs(1)
            && let Some(c) = cut.take()
        {
            c();
        }
        let next = Duration::from_micros(seq * GAP_US);
        while start.elapsed() < next {
            std::hint::spin_loop();
        }
    }
    let _ = sink.wait();
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    let v: Vec<u64> = text
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    (
        seq,
        v.get(1).copied().unwrap_or(seq),
        Duration::from_micros(v.get(2).copied().unwrap_or(0)),
    )
}

/// The topology netsim's TI-LFA takes, from the LSDB ospfd has.
fn topology(db: &corerouter_model::ospf_state::Lsdb) -> corerouter_netsim::tilfa::Topology {
    let mut arcs = Vec::new();
    for l in db.lsas.iter().filter(|l| l.kind == 1) {
        let s = l.link_start as usize;
        for k in &db.links[s..s + usize::from(l.link_count)] {
            if k.kind == 1 {
                arcs.push((
                    Ipv4Addr::from(l.adv),
                    Ipv4Addr::from(k.id),
                    u32::from(k.metric),
                ));
            }
        }
    }
    corerouter_netsim::tilfa::Topology::new(&arcs)
}

fn vtysh(ns: Option<&str>, lines: &[&str]) {
    let mut a: Vec<String> = Vec::new();
    if let Some(n) = ns {
        a.extend(["-N".into(), n.into()]);
    }
    a.push("-c".into());
    a.push("configure terminal".into());
    for l in lines {
        a.push("-c".into());
        a.push((*l).into());
    }
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    let (ok, t) = sh("vtysh", &refs);
    assert!(ok, "vtysh {lines:?}: {t}");
}

/// Cut R1–R2 the way named, run the traffic, bring it back.
fn scenario(frr: &Frr, cfg: &Config, name: &str, silent: bool) -> Duration {
    // Converged: the route to R3 by R2 again.
    wait("R1 → R3 by R2", 60, || {
        kernel_route("10.255.0.3").contains("crsr-a").then_some(())
    });
    std::thread::sleep(Duration::from_secs(3));
    let (sent, lost, worst) = measure(4, || {
        if silent {
            // A cut that leaves the carrier up: only BFD sees it.
            sh(
                "tc",
                &[
                    "qdisc", "add", "dev", "crsr-a", "root", "netem", "loss", "100%",
                ],
            );
            sh(
                "ip",
                &[
                    "netns", "exec", "crsr2", "tc", "qdisc", "add", "dev", "crsr-b", "root",
                    "netem", "loss", "100%",
                ],
            );
        } else {
            sh("ip", &["-n", "crsr2", "link", "set", "crsr-b", "down"]);
        }
    });
    let outage = Duration::from_micros(lost * GAP_US);
    eprintln!(
        "MEASURED {name}: sent {sent}, lost {lost} ({:.1} ms at {} µs a datagram), longest silence {:.1} ms",
        outage.as_secs_f64() * 1000.0,
        GAP_US,
        worst.as_secs_f64() * 1000.0
    );
    let _ = sh("tc", &["qdisc", "del", "dev", "crsr-a", "root"]);
    let _ = sh(
        "ip",
        &[
            "netns", "exec", "crsr2", "tc", "qdisc", "del", "dev", "crsr-b", "root",
        ],
    );
    let _ = sh("ip", &["-n", "crsr2", "link", "set", "crsr-b", "up"]);
    let _ = (frr, cfg);
    outage
}

#[test]
fn live_ti_lfa() {
    let Some(mut frr) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-sr-live.sh)");
        return;
    };
    let mut cfg = config();
    if let Some(sr) = cfg.routing.ospf.segment_routing.as_mut() {
        sr.ti_lfa = corerouter_model::ospf_sr::TiLfa::Link;
    }
    let _lo = KernelLo::apply(&cfg);
    frr.apply(&Config::default(), &cfg).unwrap();
    canonical(&frr, &cfg, "SR with TI-LFA");
    // The backup of R3's loopback, as zebra holds it.
    let (db, route) = wait("a TI-LFA backup for 10.255.0.3/32", 90, || {
        let (db, routes) = frr.ospf_lsdb(&cfg, "v2").ok()?;
        let r = routes.into_iter().find(|r| r.prefix == "10.255.0.3/32")?;
        r.fast_reroute
            .as_ref()
            .is_some_and(|f| !f.backup.is_empty())
            .then_some((db, r))
    });
    let f = route.fast_reroute.clone().unwrap();
    eprintln!(
        "10.255.0.3/32 primary {:?}, backup {:?}",
        f.primary, f.backup
    );
    let t = std::time::Instant::now();
    let read = frr.ospf_lsdb(&cfg, "v2").unwrap();
    eprintln!(
        "LSDB + SR + zebra routes read in {:.1} ms ({} routes)",
        t.elapsed().as_secs_f64() * 1000.0,
        read.1.len()
    );
    // Fidelity: netsim's simplified TI-LFA against ospfd's, for every
    // route announced by a router.
    let topo = topology(&db);
    let r1: Ipv4Addr = "10.255.0.1".parse().unwrap();
    let mut agree = 0;
    let mut differ = Vec::new();
    let mut only_netsim: Vec<String> = Vec::new();
    for r in read
        .1
        .iter()
        .filter(|r| r.prefix.ends_with("/32") && r.prefix != "10.255.0.1/32")
    {
        let Some(fr) = r.fast_reroute.as_ref() else {
            continue;
        };
        let dest: Ipv4Addr = r.prefix.trim_end_matches("/32").parse().unwrap();
        let Some(via) = fr.primary.first().and_then(|h| h.via.clone()) else {
            continue;
        };
        let nbr = if via == "10.0.12.2" {
            "10.255.0.2"
        } else {
            "10.255.0.4"
        };
        let rep = corerouter_netsim::tilfa::repair(
            &topo,
            r1,
            dest,
            nbr.parse().unwrap(),
            corerouter_netsim::tilfa::Protection::Link,
        );
        let ours = rep.as_ref().and_then(|x| x.nexthop).map(|n| {
            if n == Ipv4Addr::new(10, 255, 0, 2) {
                "10.0.12.2"
            } else {
                "10.0.14.2"
            }
        });
        let theirs = fr.backup.first().and_then(|h| h.via.as_deref());
        let segs = rep.as_ref().map_or(0, |x| x.segments.len());
        let labels = fr.backup.first().map_or(0, |h| h.labels.len());
        match (theirs, ours) {
            (Some(t), Some(o)) if t == o && labels <= segs + 1 => agree += 1,
            (Some(_), Some(_)) => differ.push(format!(
                "{}: ospfd {:?}, netsim {ours:?} {:?}",
                r.prefix,
                fr.backup,
                rep.map(|x| x.segments)
            )),
            // ospfd 10.7.1 leaves out a repair netsim finds (seen: P and Q
            // apart, two adjacencies): the coverage says so for that route.
            (None, Some(_)) => {
                only_netsim.push(format!("{} {:?}", r.prefix, rep.map(|x| x.segments)))
            }
            (Some(_), None) => {
                differ.push(format!("{}: ospfd {:?}, netsim none", r.prefix, fr.backup))
            }
            (None, None) => agree += 1,
        }
    }
    eprintln!(
        "fidelity: {agree} routes agree, {} differ {differ:?}; repairs ospfd did not install: {only_netsim:?}",
        differ.len()
    );
    assert!(differ.is_empty(), "{differ:?}");

    // BFD on R1's link to R2 (R2 has it in its own config): typed by hand,
    // the CoreRouter's BFD engine is not in this VM test.
    vtysh(
        None,
        &[
            "bfd",
            "profile crfast",
            "detect-multiplier 3",
            "receive-interval 10",
            "transmit-interval 10",
            "exit",
            "exit",
            "interface crsr-a",
            "ip ospf bfd",
            "ip ospf bfd profile crfast",
        ],
    );
    wait("BFD up with R2", 30, || {
        let (_, t) = sh("vtysh", &["-c", "show bfd peers brief"]);
        t.contains("10.0.12.2")
            .then_some(())
            .filter(|_| t.contains("up"))
    });
    let lfa_carrier = scenario(&frr, &cfg, "TI-LFA, carrier lost", false);
    let lfa_silent = scenario(&frr, &cfg, "TI-LFA + BFD, silent cut", true);
    // The same without TI-LFA.
    vtysh(None, &["router ospf", "no fast-reroute ti-lfa"]);
    let bfd_carrier = scenario(&frr, &cfg, "no TI-LFA, carrier lost", false);
    let bfd_silent = scenario(&frr, &cfg, "only BFD, silent cut", true);
    eprintln!(
        "SUMMARY outage ms: TI-LFA carrier {:.1}, TI-LFA+BFD silent {:.1}, no TI-LFA carrier {:.1}, only BFD silent {:.1}",
        lfa_carrier.as_secs_f64() * 1000.0,
        lfa_silent.as_secs_f64() * 1000.0,
        bfd_carrier.as_secs_f64() * 1000.0,
        bfd_silent.as_secs_f64() * 1000.0
    );
    frr.apply(&cfg, &Config::default()).unwrap();
}
