//! G3.2b against a real FRR, in the lab VM only (`scripts/frr-policy-live.sh`
//! starts FRR and two peers: `crpol`, eBGP AS 65200 at 198.51.100.34,
//! sending 203.0.113.0/24 (65200:100 65200:200, large 65200:1:2),
//! 198.18.0.0/15, 10.66.0.0/16 (65200:666) and 192.0.2.128/25; `crpol2`,
//! iBGP AS 65000 at 198.51.100.38, sending 10.30.1..5.0/24). Without
//! `COREROUTER_FRR_LIVE=1` every test returns at once.
//!
//! What it shows:
//! - RFC 8212: the eBGP session comes up but nothing passes either way
//!   until it has chains; the routes it sent are kept (`keep_received`);
//! - an input chain drops a prefix by list, one by community and one by
//!   length, and sets LOCAL_PREF on the rest;
//! - an output chain prepends our AS twice and marks a community: the
//!   peer sees both;
//! - the render is FRR's canonical form (a second sync types nothing),
//!   and changing one rule types only its route-map entries;
//! - the preview, run on the routes read from bgpd, says what bgpd did.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_hal::routing::RoutingDaemon;
use corerouter_hal_frr::Frr;
use corerouter_hal_frr::conf::diff;
use corerouter_hal_frr::render::Daemon;
use corerouter_model::bgp::{BgpConnection, BgpParams, LocalRole};
use corerouter_model::routing_filter::{FilterRule, PrefixList};
use corerouter_model::{Asn, BgpInstance, Config};
use corerouter_proto_bgp::filter::Route;
use corerouter_proto_bgp::filter::eval::{Policy, Side, preview};
use serde_json::Value;

fn live() -> Option<Frr> {
    (std::env::var("COREROUTER_FRR_LIVE").as_deref() == Ok("1"))
        .then(|| Frr::new(std::env::var("COREROUTER_FRR_DIR").unwrap_or("/var/run/frr".into())))
}

fn conn(name: &str, addr: &str, params: BgpParams) -> BgpConnection {
    BgpConnection {
        name: name.into(),
        instance: "default".into(),
        remote_address: addr.parse().unwrap(),
        templates: Vec::new(),
        params,
        disabled: false,
        comment: String::new(),
    }
}

fn base() -> Config {
    let mut cfg = Config::default();
    cfg.routing.bgp.insert(
        "default".into(),
        BgpInstance {
            name: "default".into(),
            asn: Asn(65000),
            router_id: "198.51.100.33".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        },
    );
    for c in [
        conn(
            "pol",
            "198.51.100.34",
            BgpParams {
                remote_as: Some(Asn(65200)),
                ..Default::default()
            },
        ),
        conn(
            "pol2",
            "198.51.100.38",
            BgpParams {
                local_role: Some(LocalRole::Ibgp),
                ..Default::default()
            },
        ),
    ] {
        cfg.routing.bgp_connections.insert(c.name.clone(), c);
    }
    cfg
}

fn rule(cfg: &mut Config, chain: &str, text: &str) {
    let f = &mut cfg.routing.filter;
    let id = f.next_id();
    f.rules.push(FilterRule {
        id,
        chain: chain.into(),
        rule: text.into(),
        disabled: false,
        comment: String::new(),
    });
}

fn with_policy() -> Config {
    let mut cfg = base();
    cfg.routing.filter.prefix_lists.insert(
        "bogons".into(),
        PrefixList {
            name: "bogons".into(),
            entries: vec![
                "10.0.0.0/8 le 32".parse().unwrap(),
                "198.18.0.0/15 le 32".parse().unwrap(),
            ],
            comment: String::new(),
        },
    );
    rule(
        &mut cfg,
        "pol-in",
        "if (dst in bogons && not dst in 198.18.0.0/15) { reject }",
    );
    rule(
        &mut cfg,
        "pol-in",
        "if (bgp-communities includes 65200:666) { reject }",
    );
    rule(&mut cfg, "pol-in", "if (dst-len > 24) { reject }");
    rule(&mut cfg, "pol-in", "set bgp-local-pref 150; accept");
    rule(
        &mut cfg,
        "pol-out",
        "if (dst in 10.30.0.0/16) { set bgp-path-prepend 2; append bgp-communities 65000:10; accept }",
    );
    if let Some(c) = cfg.routing.bgp_connections.get_mut("pol") {
        c.params.input_filter = Some("pol-in".into());
        c.params.output_filter = Some("pol-out".into());
    }
    cfg
}

/// bgpd's JSON for `cmd`, in our namespace or in the peer's.
fn json(peer: bool, cmd: &str) -> Value {
    let out = if peer {
        Command::new("ip")
            .args([
                "netns", "exec", "crfrrpol", "vtysh", "-N", "crpol", "-c", cmd,
            ])
            .output()
            .unwrap()
    } else {
        Command::new("vtysh").args(["-c", cmd]).output().unwrap()
    };
    serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
}

fn routes(peer: bool) -> Vec<String> {
    let v = json(peer, "show bgp ipv4 unicast json");
    let mut out: Vec<String> = v["routes"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    out.sort();
    out
}

fn wait_for(what: &str, ok: impl Fn() -> bool) {
    let t = Instant::now();
    while !ok() {
        assert!(
            t.elapsed() < Duration::from_secs(90),
            "not {what} after 90 s"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!("{what} after {:.1} s", t.elapsed().as_secs_f64());
}

#[test]
fn live_bgp_policy() {
    let Some(mut frr) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-policy-live.sh)");
        return;
    };
    frr.apply(&Config::default(), &Config::default()).unwrap();

    // 1. RFC 8212: no chain, nothing passes; the routes are kept.
    let cfg = base();
    frr.apply(&Config::default(), &cfg).unwrap();
    wait_for("pol established", || {
        frr.bgp_sessions(&cfg)
            .unwrap()
            .iter()
            .any(|s| s.connection.as_deref() == Some("pol") && s.established)
    });
    wait_for("pol2's 5 routes in", || {
        routes(false)
            .iter()
            .filter(|r| r.starts_with("10.30."))
            .count()
            == 5
    });
    let received = frr
        .bgp_filter_routes("default", "198.51.100.34", true)
        .unwrap();
    if received.len() != 4 {
        let raw = Command::new("vtysh")
            .args([
                "-c",
                "show bgp ipv4 unicast neighbors 198.51.100.34 received-routes detail",
            ])
            .output()
            .unwrap();
        let run = Command::new("vtysh")
            .args(["-c", "show running-config"])
            .output()
            .unwrap();
        eprintln!(
            "received {}:\n{}\nrunning:\n{}",
            received.len(),
            String::from_utf8_lossy(&raw.stdout),
            String::from_utf8_lossy(&run.stdout)
        );
    }
    wait_for("4 routes kept from pol", || {
        frr.bgp_filter_routes("default", "198.51.100.34", true)
            .unwrap()
            .len()
            == 4
    });
    std::thread::sleep(Duration::from_secs(3));
    let ours = routes(false);
    assert!(
        !ours.iter().any(|r| r == "203.0.113.0/24"),
        "RFC 8212: eBGP routes accepted without a policy: {ours:?}"
    );
    let theirs = routes(true);
    assert!(
        !theirs.iter().any(|r| r.starts_with("10.30.")),
        "RFC 8212: routes sent without a policy: {theirs:?}"
    );
    let s = frr
        .bgp_sessions(&cfg)
        .unwrap()
        .into_iter()
        .find(|s| s.connection.as_deref() == Some("pol"))
        .unwrap();
    eprintln!(
        "RFC 8212 session: {s:?}; kept {} received routes",
        received.len()
    );

    // 2. The chains: canonical render, then the routes they let through.
    let cfg2 = with_policy();
    let want = frr.render(&cfg2).unwrap();
    let synced = frr.sync(&want).unwrap();
    assert!(
        synced.leftover.is_empty(),
        "not canonical: {:?}",
        synced.leftover
    );
    let mut v = frr.connect(Daemon::Bgpd).unwrap();
    assert_eq!(
        diff(&frr.running(&mut v, Daemon::Bgpd).unwrap(), &want),
        Vec::<String>::new()
    );
    assert!(
        frr.sync(&want).unwrap().commands.is_empty(),
        "a second sync typed commands"
    );
    wait_for("203.0.113.0/24 accepted with local-pref 150", || {
        let v = json(false, "show bgp ipv4 unicast 203.0.113.0/24 json");
        v["paths"][0]["locPrf"].as_u64() == Some(150)
    });
    let ours = routes(false);
    assert!(ours.contains(&"198.18.0.0/15".to_owned()), "{ours:?}");
    assert!(
        !ours.contains(&"10.66.0.0/16".to_owned()),
        "dropped by list and community: {ours:?}"
    );
    assert!(
        !ours.contains(&"192.0.2.128/25".to_owned()),
        "dropped by length: {ours:?}"
    );
    wait_for("the peer sees 10.30.1.0/24 prepended and marked", || {
        let v = json(true, "show bgp ipv4 unicast 10.30.1.0/24 json");
        let p = &v["paths"][0];
        p["aspath"]["string"].as_str() == Some("65000 65000 65000")
            && p["community"]["string"].as_str() == Some("65000:10")
    });

    // 3. The preview on the routes read from bgpd agrees with bgpd.
    let (policy, problems) = Policy::build(&cfg2.routing.filter);
    assert!(problems.is_empty(), "{problems:?}");
    let got: Vec<Route> = frr
        .bgp_filter_routes("default", "198.51.100.34", true)
        .unwrap()
        .into_iter()
        // The peer sends our 10.30.x back (its path has our AS: bgpd drops
        // them before any policy, RFC 4271 §9.1.2).
        .filter(|e| !e.as_path.contains(&65000))
        .filter_map(|e| {
            let mut r = Route::bgp(e.prefix?, e.as_path);
            r.communities = e.communities;
            r.large = e
                .large
                .into_iter()
                .map(|(a, b, c)| corerouter_proto_bgp::filter::Large(a, b, c))
                .collect();
            Some(r)
        })
        .collect();
    let side = Side {
        policy: &policy,
        chain: policy.chain("pol-in"),
        accept_without: false,
        counted: 0,
        asn: 65000,
    };
    let pv = preview(&side, None, &got, 10, 1);
    assert_eq!((pv.total, pv.accepted, pv.rejected), (4, 2, 2), "{pv:?}");
    let mut passed: Vec<String> = pv
        .accepted_rows
        .iter()
        .map(|r| r.route.prefix.to_string())
        .collect();
    passed.sort();
    assert_eq!(passed, ["198.18.0.0/15", "203.0.113.0/24"]);
    let tagged = got
        .iter()
        .find(|r| r.prefix.to_string() == "203.0.113.0/24")
        .unwrap();
    assert_eq!(tagged.large.len(), 1, "large communities read: {tagged:?}");

    // 4. Changing one rule types only its entries; the /25 now passes.
    let mut cfg3 = cfg2.clone();
    cfg3.routing.filter.rules[2].rule = "if (dst-len > 25) { reject }".into();
    let t = Instant::now();
    let synced = frr.sync(&frr.render(&cfg3).unwrap()).unwrap();
    eprintln!(
        "one rule changed: {:?} in {:.1} ms",
        synced.commands,
        t.elapsed().as_secs_f64() * 1e3
    );
    assert!(synced.leftover.is_empty(), "{:?}", synced.leftover);
    assert!(
        synced.commands.iter().map(|(_, n)| n).sum::<usize>() <= 20,
        "{:?}",
        synced.commands
    );
    wait_for("192.0.2.128/25 accepted", || {
        routes(false).contains(&"192.0.2.128/25".to_owned())
    });

    // 5. Back to no policy: the eBGP routes go again (RFC 8212).
    frr.apply(&cfg3, &base()).unwrap();
    wait_for("RFC 8212 again", || {
        !routes(false).contains(&"203.0.113.0/24".to_owned())
    });
    let mut v = frr.connect(Daemon::Bgpd).unwrap();
    let left = frr.running(&mut v, Daemon::Bgpd).unwrap().render();
    assert!(!left.contains("CR-"), "filters left behind:\n{left}");
    frr.apply(&base(), &Config::default()).unwrap();
}
