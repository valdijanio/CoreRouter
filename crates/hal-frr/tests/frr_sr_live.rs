//! G3.4f (and G3.4d) against a real FRR, in the lab VM only
//! (`scripts/frr-sr-live.sh` starts R2..R4 of a square in namespaces).
//! Without `COREROUTER_FRR_LIVE=1` the tests return at once.
//!
//! What `live_sr` shows:
//! - the OSPF + SR render is FRR's canonical form (a second sync types
//!   nothing), with the default blocks and with a moved SRGB;
//! - the SR database is read: R2..R4 with their SIDs;
//! - zebra puts the SID's label on the kernel route and a ping crosses it;
//! - a prefix SID on a dummy interface is refused by ospfd (only an
//!   IFF_LOOPBACK interface takes one): the gap the docs name;
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
