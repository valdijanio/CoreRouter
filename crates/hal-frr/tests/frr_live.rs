//! G3.1 against a real FRR, in the lab VM only (`scripts/frr-live.sh`
//! starts FRR, and a BGP peer in the namespace `crfrrpeer`, then runs this
//! with `COREROUTER_FRR_LIVE=1`). Without the variable every test returns
//! at once: CI and the host have no FRR.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use corerouter_hal::routing::RoutingDaemon;
use corerouter_hal_frr::Frr;
use corerouter_hal_frr::conf::{Conf, diff};
use corerouter_hal_frr::render::{Daemon, Owned};
use corerouter_model::routing_state::BgpSession;
use corerouter_model::{Asn, BgpInstance, Config};

const OWNED: Owned = &[
    ("router bgp ", &[Daemon::Bgpd]),
    ("ip prefix-list ", &[Daemon::Bgpd]),
];

fn live() -> Option<Frr> {
    (std::env::var("COREROUTER_FRR_LIVE").as_deref() == Ok("1"))
        .then(|| Frr::new(std::env::var("COREROUTER_FRR_DIR").unwrap_or("/var/run/frr".into())))
}

fn conf(s: &str) -> Conf {
    Conf::parse(s).unwrap()
}

fn running(frr: &Frr) -> Conf {
    let mut v = frr.connect(Daemon::Bgpd).unwrap();
    frr.running(&mut v, Daemon::Bgpd).unwrap()
}

/// Our side of the peering with the namespace's bgpd (AS 65100).
fn peering(extra: &str) -> String {
    format!(
        "router bgp 65000\n bgp router-id 198.51.100.1\n no bgp default ipv4-unicast\n \
         neighbor 198.51.100.2 remote-as 65100\n{extra} address-family ipv4 unicast\n  \
         neighbor 198.51.100.2 activate\n exit-address-family\nexit\n"
    )
}

fn peer(frr: &Frr) -> Option<BgpSession> {
    let mut cfg = Config::default();
    cfg.routing
        .bgp
        .insert("default".into(), instance(65000, "198.51.100.1"));
    frr.bgp_sessions(&cfg)
        .unwrap()
        .into_iter()
        .find(|s| s.remote_address == "198.51.100.2")
}

fn instance(asn: u32, rid: &str) -> BgpInstance {
    BgpInstance {
        name: "default".into(),
        asn: Asn(asn),
        router_id: rid.parse().unwrap(),
        disabled: false,
        comment: String::new(),
    }
}

#[test]
fn live_frr() {
    let Some(base) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-live.sh)");
        return;
    };
    let frr = base.clone().with_owned(OWNED);
    frr.sync(&Conf::default()).unwrap();

    // 1. The engine's path: a CoreRouter config, rendered; FRR prints it
    //    back the same (no leftover: the render is canonical).
    let mut cfg = Config::default();
    cfg.routing
        .bgp
        .insert("default".into(), instance(65000, "198.51.100.1"));
    let mut driver = base.clone();
    driver.apply(&Config::default(), &cfg).unwrap();
    let want = base.render(&cfg).unwrap();
    assert_eq!(diff(&running(&base), &want), Vec::<String>::new());
    let mut off = cfg.clone();
    if let Some(i) = off.routing.bgp.get_mut("default") {
        i.disabled = true;
    }
    driver.apply(&cfg, &off).unwrap();
    assert!(running(&base).render().contains(" bgp shutdown\n"));
    driver.apply(&off, &cfg).unwrap();
    let synced = base.sync(&want).unwrap();
    assert!(synced.commands.is_empty(), "{synced:?}");

    // 2. A session comes up with the peer in the namespace.
    frr.sync(&conf(&peering(""))).unwrap();
    let t = Instant::now();
    let up = loop {
        if let Some(s) = peer(&frr).filter(|s| s.established) {
            break s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "no session: {:?}",
            peer(&frr)
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    eprintln!(
        "established after {:.1} s: {up:?}",
        t.elapsed().as_secs_f64()
    );
    // RFC 8212 (FRR's ebgp-requires-policy): the peer's route is not
    // accepted without a policy.
    assert_eq!(up.prefix_count, Some(0));

    // 3. Commits that do not touch the session keep it up: a description,
    //    another neighbor, 2000 prefix-list entries, then their removal.
    std::thread::sleep(Duration::from_secs(2));
    let before = peer(&frr).unwrap();
    let mut lists = String::new();
    for i in 0..2000 {
        lists.push_str(&format!(
            "ip prefix-list L seq {} permit 10.{}.{}.0/24\n",
            (i + 1) * 5,
            i / 256,
            i % 256
        ));
    }
    let extra =
        " neighbor 198.51.100.2 description upstream\n neighbor 198.51.100.9 remote-as 65200\n";
    for step in [
        format!("{}{lists}", peering(extra)),
        peering(extra),
        peering(""),
    ] {
        let s = frr.sync(&conf(&step)).unwrap();
        assert!(s.leftover.is_empty(), "{s:?}");
        assert_eq!(diff(&running(&frr), &conf(&step)), Vec::<String>::new());
    }
    let after = peer(&frr).unwrap();
    assert!(after.established, "{after:?}");
    assert!(
        after.uptime_secs >= before.uptime_secs,
        "the session was reset: {before:?} → {after:?}"
    );

    // 4. A refused command: what was typed before it is undone and the
    //    session stays up.
    let bad = conf(&peering(
        " neighbor 198.51.100.2 description changed\n neighbor 198.51.100.7 remote-as 99999999999\n",
    ));
    let e = frr.sync(&bad).unwrap_err().to_string();
    assert!(e.contains("198.51.100.7"), "{e}");
    assert_eq!(
        diff(&running(&frr), &conf(&peering(""))),
        Vec::<String>::new()
    );
    assert!(peer(&frr).unwrap().established);

    frr.sync(&Conf::default()).unwrap();
}
