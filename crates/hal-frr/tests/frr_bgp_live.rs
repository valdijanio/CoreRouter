//! G3.2a against a real FRR, in the lab VM only (`scripts/frr-live.sh`
//! starts FRR and two BGP peers: `crpeer`, eBGP AS 65100 at 198.51.100.2,
//! and `crpeer2`, iBGP AS 65000 at 198.51.100.18 with a TCP MD5 key and 20
//! prefixes). Without `COREROUTER_FRR_LIVE=1` every test returns at once.
//!
//! What it shows:
//! - the render of every connection parameter is FRR's canonical form (a
//!   second sync types nothing);
//! - two sessions come up (one with the MD5 key), and changing, adding or
//!   removing one neighbor does not reset the other;
//! - `max-prefix` closes the session that goes over its limit;
//! - 1 000 connections are applied, changed by one and removed, timed.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use corerouter_hal::routing::{BgpClear, RoutingDaemon};
use corerouter_hal_frr::Frr;
use corerouter_hal_frr::conf::{Conf, diff};
use corerouter_hal_frr::render::Daemon;
use corerouter_model::bgp::{
    Afi, BgpConnection, BgpParams, BgpTemplate, LocalRole, MaxPrefixAction, NexthopChoice,
};
use corerouter_model::routing_state::BgpSession;
use corerouter_model::{Asn, BgpInstance, Config};

/// The key `crpeer2` has for us (in clear: a legacy value opens as itself).
const KEY: &str = "Sup3rS3cret";

fn live() -> Option<Frr> {
    (std::env::var("COREROUTER_FRR_LIVE").as_deref() == Ok("1"))
        .then(|| Frr::new(std::env::var("COREROUTER_FRR_DIR").unwrap_or("/var/run/frr".into())))
}

fn running(frr: &Frr) -> Conf {
    let mut v = frr.connect(Daemon::Bgpd).unwrap();
    frr.running(&mut v, Daemon::Bgpd).unwrap()
}

fn base_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.routing.bgp.insert(
        "default".into(),
        BgpInstance {
            name: "default".into(),
            asn: Asn(65000),
            router_id: "198.51.100.1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            graceful_restart_time: None,
            graceful_stale_time: None,
            graceful_defer_time: None,
            graceful_notification: None,
            hard_admin_reset: None,
        },
    );
    cfg
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

fn add(cfg: &mut Config, c: BgpConnection) {
    cfg.routing.bgp_connections.insert(c.name.clone(), c);
}

/// The two real neighbors.
fn peers(limit2: u32) -> Config {
    let mut cfg = base_cfg();
    add(
        &mut cfg,
        conn(
            "up1",
            "198.51.100.2",
            BgpParams {
                remote_as: Some(Asn(65100)),
                ..Default::default()
            },
        ),
    );
    add(
        &mut cfg,
        conn(
            "ibgp2",
            "198.51.100.18",
            BgpParams {
                local_role: Some(LocalRole::Ibgp),
                tcp_md5_key: Some(KEY.into()),
                max_prefix_ipv4: Some(limit2),
                ..Default::default()
            },
        ),
    );
    cfg
}

fn sessions(frr: &Frr, cfg: &Config) -> Vec<BgpSession> {
    frr.bgp_sessions(cfg).unwrap()
}

fn session(frr: &Frr, cfg: &Config, name: &str) -> Option<BgpSession> {
    sessions(frr, cfg)
        .into_iter()
        .find(|s| s.connection.as_deref() == Some(name))
}

fn wait(
    frr: &Frr,
    cfg: &Config,
    name: &str,
    what: &str,
    ok: impl Fn(&BgpSession) -> bool,
) -> BgpSession {
    let t = Instant::now();
    loop {
        if let Some(s) = session(frr, cfg, name).filter(|s| ok(s)) {
            eprintln!("{name} {what} after {:.1} s", t.elapsed().as_secs_f64());
            return s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(90),
            "{name}: not {what}: {:?}",
            session(frr, cfg, name)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn live_bgp_connections() {
    let Some(frr) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-live.sh)");
        return;
    };
    let mut frr = frr;
    frr.apply(&Config::default(), &Config::default()).unwrap();

    // 1. Every parameter, on neighbors that never come up: FRR prints the
    //    render back as it is (no leftover), and a second sync is empty.
    let mut cfg = base_cfg();
    cfg.routing.bgp_templates.insert(
        "transit".into(),
        BgpTemplate {
            name: "transit".into(),
            templates: Vec::new(),
            params: BgpParams {
                local_role: Some(LocalRole::EbgpProvider),
                hold_time: Some(90),
                multihop: Some(true),
                afi: Some(vec![Afi::Ip, Afi::Ipv6]),
                max_prefix_ipv4: Some(1000),
                max_prefix_ipv6: Some(500),
                max_prefix_action: Some(MaxPrefixAction::Restart),
                max_prefix_restart: Some(7),
                ..Default::default()
            },
            comment: String::new(),
        },
    );
    add(
        &mut cfg,
        BgpConnection {
            templates: vec!["transit".into()],
            ..conn(
                "t1",
                "192.0.2.21",
                BgpParams {
                    remote_as: Some(Asn(64500)),
                    keepalive_time: Some(20),
                    tcp_md5_key: Some("abc".into()),
                    update_source: Some("198.51.100.1".into()),
                    nexthop_choice: Some(NexthopChoice::ForceSelf),
                    ..Default::default()
                },
            )
        },
    );
    add(
        &mut cfg,
        BgpConnection {
            disabled: true,
            ..conn(
                "t2",
                "2001:db8::21",
                BgpParams {
                    local_role: Some(LocalRole::EbgpCustomer),
                    afi: Some(vec![Afi::Ipv6]),
                    max_prefix_ipv6: Some(10),
                    max_prefix_action: Some(MaxPrefixAction::Warning),
                    nexthop_choice: Some(NexthopChoice::Propagate),
                    ..Default::default()
                },
            )
        },
    );
    add(
        &mut cfg,
        conn(
            "t3",
            "192.0.2.23",
            BgpParams {
                local_role: Some(LocalRole::Ibgp),
                hold_time: Some(0),
                ..Default::default()
            },
        ),
    );
    let want = frr.render(&cfg).unwrap();
    let synced = frr.sync(&want).unwrap();
    assert!(
        synced.leftover.is_empty(),
        "not canonical: {:?}",
        synced.leftover
    );
    assert_eq!(diff(&running(&frr), &want), Vec::<String>::new());
    assert!(frr.sync(&want).unwrap().commands.is_empty());
    // Removing them: one `no neighbor X remote-as` each, accepted.
    frr.sync(&frr.render(&base_cfg()).unwrap()).unwrap();
    assert_eq!(
        diff(&running(&frr), &frr.render(&base_cfg()).unwrap()),
        Vec::<String>::new()
    );

    // 2. The two real peers come up; the iBGP one only with the MD5 key.
    let cfg = peers(100);
    frr.apply(&base_cfg(), &cfg).unwrap();
    let up1 = wait(&frr, &cfg, "up1", "established", |s| s.established);
    let ib = wait(&frr, &cfg, "ibgp2", "established with 20 prefixes", |s| {
        s.established && s.prefix_count == Some(20)
    });
    eprintln!("up1: {up1:?}\nibgp2: {ib:?}");
    assert_eq!(ib.hold_time, Some(180));

    // 3. Changing one neighbor (hold time, key off/on) and adding and
    //    removing a third does not reset the other.
    std::thread::sleep(Duration::from_secs(3));
    let before = session(&frr, &cfg, "up1").unwrap();
    let mut changed = cfg.clone();
    if let Some(c) = changed.routing.bgp_connections.get_mut("ibgp2") {
        c.params.hold_time = Some(30);
    }
    add(
        &mut changed,
        conn(
            "extra",
            "192.0.2.99",
            BgpParams {
                remote_as: Some(Asn(64999)),
                ..Default::default()
            },
        ),
    );
    let t = Instant::now();
    frr.apply(&cfg, &changed).unwrap();
    eprintln!(
        "one neighbor changed and one added: {:.1} ms",
        t.elapsed().as_secs_f64() * 1e3
    );
    frr.apply(&changed, &cfg).unwrap();
    let after = session(&frr, &cfg, "up1").unwrap();
    assert!(after.established, "{after:?}");
    assert!(
        after.uptime_secs >= before.uptime_secs && after.flaps == before.flaps,
        "up1 was reset by a change to another neighbor: {before:?} → {after:?}"
    );

    // 4. Soft reset keeps the session up; a hard clear restarts it.
    frr.bgp_clear("default", "198.51.100.2", BgpClear::SoftIn)
        .unwrap();
    frr.bgp_clear("default", "198.51.100.2", BgpClear::SoftOut)
        .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let soft = session(&frr, &cfg, "up1").unwrap();
    assert!(soft.established && soft.flaps == before.flaps, "{soft:?}");
    assert!(
        frr.bgp_clear("default", "192.0.2.250", BgpClear::Hard)
            .is_err()
    );

    // 5. max-prefix: 20 prefixes against a limit of 10 closes ibgp2; up1
    //    stays up.
    let tight = peers(10);
    frr.apply(&cfg, &tight).unwrap();
    let down = wait(&frr, &tight, "ibgp2", "closed by max-prefix", |s| {
        !s.established
    });
    eprintln!("ibgp2 over its limit: {down:?}");
    let why = format!("{:?} {:?}", down.reason, down.last_error);
    assert!(
        why.to_lowercase().contains("prefix") || why.contains("PfxCt"),
        "{why}"
    );
    assert!(session(&frr, &tight, "up1").unwrap().established);

    // 6. 1 000 connections: apply, change one, remove them all.
    let mut big = base_cfg();
    for i in 0..1000u32 {
        add(
            &mut big,
            conn(
                &format!("n{i}"),
                &format!("10.{}.{}.{}", 100 + i / 65536, (i / 256) % 256, i % 256),
                BgpParams {
                    remote_as: Some(Asn(64512 + i % 1000)),
                    hold_time: Some(90),
                    max_prefix_ipv4: Some(1000),
                    ..Default::default()
                },
            ),
        );
    }
    let t = Instant::now();
    let s = frr.sync(&frr.render(&big).unwrap()).unwrap();
    let apply = t.elapsed();
    assert!(
        s.leftover.is_empty(),
        "{:?}",
        &s.leftover[..s.leftover.len().min(5)]
    );
    let mut one = big.clone();
    if let Some(c) = one.routing.bgp_connections.get_mut("n500") {
        c.params.hold_time = Some(30);
    }
    let t = Instant::now();
    let s1 = frr.sync(&frr.render(&one).unwrap()).unwrap();
    let change = t.elapsed();
    let t = Instant::now();
    let n = sessions(&frr, &big).len();
    let read = t.elapsed();
    let t = Instant::now();
    frr.sync(&frr.render(&base_cfg()).unwrap()).unwrap();
    let remove = t.elapsed();
    eprintln!(
        "PERF 1000 connections: apply {:.0} ms ({:?}), change one {:.0} ms ({:?}), remove all {:.0} ms; \
         session read with {n} neighbors {:.1} ms",
        apply.as_secs_f64() * 1e3,
        s.commands,
        change.as_secs_f64() * 1e3,
        s1.commands,
        remove.as_secs_f64() * 1e3,
        read.as_secs_f64() * 1e3,
    );
    assert_eq!(
        s1.commands,
        vec![(Daemon::Bgpd, 3)],
        "one neighbor's timers only"
    );

    frr.sync(&Conf::default()).unwrap();
}
