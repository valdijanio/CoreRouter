//! G3.4 against a real FRR, in the lab VM only (`scripts/frr-ospf-live.sh`
//! starts two OSPF peers in namespaces). Without `COREROUTER_FRR_LIVE=1`
//! the test returns at once.
//!
//! What it shows:
//! - the render is FRR's canonical form (a second sync types nothing);
//! - the HMAC-SHA-256 adjacency reaches Full (RFC 5709 through a key chain);
//! - rotating the key (key 2 sent from now on, key 1 still accepted) keeps
//!   the adjacency up: the neighbor's uptime keeps growing;
//! - the peer with a smaller MTU sticks before Full and the Diagnose
//!   points at RFC 2328 §10.6;
//! - the LSDB is read streaming and the topology has the link to the peer.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use corerouter_hal::routing::RoutingDaemon;
use corerouter_hal_frr::Frr;
use corerouter_model::Config;
use corerouter_model::ospf::{
    AreaId, AreaType, AuthType, NetworkType, NssaTranslate, OspfArea, OspfInstance, OspfKey,
    OspfKeychain, OspfTemplate,
};
use corerouter_model::ospf_state::OspfNeighbor;
use corerouter_proto_ospf::diagnose::{Local, Seen, diagnose};
use corerouter_proto_ospf::topology::{Node, graphs};

fn live() -> Option<Frr> {
    (std::env::var("COREROUTER_FRR_LIVE").as_deref() == Ok("1"))
        .then(|| Frr::new(std::env::var("COREROUTER_FRR_DIR").unwrap_or("/var/run/frr".into())))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(id: u16, k: &str, send: (Option<u64>, Option<u64>)) -> OspfKey {
    OspfKey {
        id,
        algorithm: AuthType::Sha256,
        key_string: k.into(),
        send_from: send.0,
        send_until: send.1,
        accept_from: None,
        accept_until: None,
    }
}

fn config(keys: Vec<OspfKey>) -> Config {
    let mut cfg = Config::default();
    let o = &mut cfg.routing.ospf;
    o.instances.insert(
        "v2".into(),
        OspfInstance {
            name: "v2".into(),
            version: Default::default(),
            vrf: "main".into(),
            router_id: Some("192.0.2.1".parse().unwrap()),
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
    o.keychains.insert(
        "k".into(),
        OspfKeychain {
            name: "k".into(),
            keys,
            comment: String::new(),
        },
    );
    for (name, auth) in [("crospf-a", true), ("crospf-c", false)] {
        let id = o.next_id();
        o.templates.push(OspfTemplate {
            id,
            area: "backbone".into(),
            interfaces: vec![name.into()],
            kind: NetworkType::Ptp,
            hello_interval: Some(2),
            dead_interval: Some(8),
            auth: auth.then_some(AuthType::Sha256),
            keychain: auth.then(|| "k".to_owned()),
            ..OspfTemplate::default()
        });
    }
    // The interfaces exist in the kernel; the config only needs their names.
    for n in ["crospf-a", "crospf-c"] {
        let iface =
            serde_json::from_value(serde_json::json!({"name": n, "kind": {"type": "ethernet"}}))
                .unwrap();
        cfg.interfaces.insert(n.parse().unwrap(), iface);
    }
    cfg
}

fn neighbor(frr: &Frr, cfg: &Config, id: &str) -> Option<OspfNeighbor> {
    frr.ospf_state(cfg)
        .unwrap()
        .0
        .into_iter()
        .find(|n| n.router_id == id)
}

fn wait(
    frr: &Frr,
    cfg: &Config,
    id: &str,
    what: &str,
    ok: impl Fn(&OspfNeighbor) -> bool,
) -> OspfNeighbor {
    let t = Instant::now();
    loop {
        if let Some(n) = neighbor(frr, cfg, id).filter(|n| ok(n)) {
            eprintln!("{id} {what} after {:.1} s", t.elapsed().as_secs_f64());
            return n;
        }
        assert!(
            t.elapsed() < Duration::from_secs(90),
            "{id}: not {what}: {:?}",
            neighbor(frr, cfg, id)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn live_ospf() {
    let Some(mut frr) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-ospf-live.sh)");
        return;
    };
    let cfg = config(vec![key(1, "Sup3rS3cret", (None, None))]);
    let t = Instant::now();
    frr.apply(&Config::default(), &cfg).unwrap();
    eprintln!("applied in {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let again = frr.sync(&frr.render(&cfg).unwrap()).unwrap();
    assert!(
        again.commands.is_empty() && again.leftover.is_empty(),
        "not canonical: {again:?}"
    );

    // HMAC-SHA-256 up.
    let up = wait(&frr, &cfg, "192.0.2.2", "Full with sha256", |n| {
        n.state == "Full"
    });
    assert_eq!(up.interface, "crospf-a");

    // Rotation: key 1 stops being sent now, key 2 starts; both accepted.
    let t0 = now().saturating_sub(5);
    let rotated = config(vec![
        key(1, "Sup3rS3cret", (None, Some(t0))),
        key(2, "N3wS3cret", (Some(t0), None)),
    ]);
    frr.apply(&cfg, &rotated).unwrap();
    let before = neighbor(&frr, &rotated, "192.0.2.2")
        .unwrap()
        .state_secs
        .unwrap_or(0);
    std::thread::sleep(Duration::from_secs(20)); // 2.5 dead intervals
    let after = neighbor(&frr, &rotated, "192.0.2.2").unwrap();
    assert_eq!(
        after.state, "Full",
        "dropped during the rotation: {after:?}"
    );
    assert!(
        after.state_secs.unwrap_or(0) >= before + 15,
        "the adjacency restarted: {before} → {after:?}"
    );
    eprintln!(
        "rotation to key 2 without a drop: up {} s",
        after.state_secs.unwrap_or(0)
    );

    // MTU mismatch: stuck before Full, explained.
    let stuck = wait(&frr, &rotated, "192.0.2.6", "seen", |n| !n.state.is_empty());
    std::thread::sleep(Duration::from_secs(10));
    let stuck = neighbor(&frr, &rotated, "192.0.2.6").unwrap_or(stuck);
    assert_ne!(stuck.state, "Full", "{stuck:?}");
    let local = Local {
        version: 2,
        interface: "crospf-c".into(),
        router_id: Some("192.0.2.1".parse().unwrap()),
        network_type: "ptp".into(),
        hello: 2,
        dead: 8,
        mtu: Some(1500),
        auth: "none".into(),
        ..Local::default()
    };
    let seen = [Seen {
        router_id: stuck.router_id.clone(),
        state: stuck.state.clone(),
        state_secs: stuck.state_secs,
    }];
    let f = diagnose(&local, &seen, &[]);
    eprintln!("diagnose: {f:?}");
    assert!(f.iter().any(|f| f.rfc == "RFC 2328 §10.6"), "{f:?}");

    // LSDB and topology.
    let (db, routes) = frr.ospf_lsdb(&rotated, "v2").unwrap();
    eprintln!(
        "lsdb: {} LSAs, {} links, {} routes",
        db.lsas.len(),
        db.links.len(),
        routes.len()
    );
    let g = graphs(&db);
    let area = &g[&0];
    let me = area
        .find(Node::Router(u32::from(std::net::Ipv4Addr::new(
            192, 0, 2, 1,
        ))))
        .unwrap();
    let peer = area
        .find(Node::Router(u32::from(std::net::Ipv4Addr::new(
            192, 0, 2, 2,
        ))))
        .unwrap();
    assert!(
        area.edges()
            .iter()
            .any(|e| (e.0 == me && e.1 == peer) || (e.0 == peer && e.1 == me))
    );

    frr.apply(&rotated, &Config::default()).unwrap();
}
