//! G3.5 against a real FRR, in the lab VM only (`scripts/frr-ldp-live.sh`
//! starts two LSRs in namespaces). Without `COREROUTER_FRR_LIVE=1` the test
//! returns at once.
//!
//! What it shows:
//! - the OSPF + LDP render is FRR's canonical form (a second sync types
//!   nothing);
//! - the LDP session with R2 comes up and the bindings are read: R3's
//!   loopback has a remote label from R2, in use;
//! - zebra puts that label on the kernel route and a ping crosses the LSP;
//! - RFC 5443 sync is read from ospfd and is achieved on the link.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_hal::routing::RoutingDaemon;
use corerouter_hal_frr::Frr;
use corerouter_model::Config;
use corerouter_model::mpls::{LdpInstance, LdpInterface};
use corerouter_model::mpls_state::LdpState;
use corerouter_model::ospf::{
    AreaId, AreaType, NetworkType, NssaTranslate, OspfArea, OspfInstance, OspfTemplate,
};

fn live() -> Option<Frr> {
    (std::env::var("COREROUTER_FRR_LIVE").as_deref() == Ok("1"))
        .then(|| Frr::new(std::env::var("COREROUTER_FRR_DIR").unwrap_or("/var/run/frr".into())))
}

fn config() -> Config {
    let mut cfg = Config::default();
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
    // The loopback in a passive point-to-point template, as operators
    // write it: the render must still get its /32 advertised (ospfd takes
    // a /32 on a ptp interface as unnumbered).
    for (name, kind, passive) in [
        ("crldp-a", NetworkType::Ptp, false),
        ("crldp-lo", NetworkType::Ptp, true),
    ] {
        let id = o.next_id();
        o.templates.push(OspfTemplate {
            id,
            area: "backbone".into(),
            interfaces: vec![name.into()],
            kind,
            hello_interval: Some(1),
            dead_interval: Some(4),
            passive,
            ..OspfTemplate::default()
        });
    }
    for n in ["crldp-a", "crldp-lo"] {
        let iface =
            serde_json::from_value(serde_json::json!({"name": n, "kind": {"type": "ethernet"}}))
                .unwrap();
        cfg.interfaces.insert(n.parse().unwrap(), iface);
    }
    let m = &mut cfg.routing.mpls;
    m.ldp = Some(LdpInstance::new([10, 255, 0, 1].into()));
    m.ldp_interfaces
        .insert("crldp-a".parse().unwrap(), LdpInterface::default());
    cfg
}

fn sh(cmd: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(cmd).args(args).output().unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn wait<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
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

fn state(frr: &Frr, cfg: &Config) -> LdpState {
    frr.ldp_state(cfg).unwrap().unwrap()
}

#[test]
fn live_ldp() {
    let Some(mut frr) = live() else {
        eprintln!("skipped: COREROUTER_FRR_LIVE=1 only in the lab VM (scripts/frr-ldp-live.sh)");
        return;
    };
    let cfg = config();
    let started = Instant::now();
    frr.apply(&Config::default(), &cfg).unwrap();
    eprintln!(
        "applied in {:.1} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    let again = frr.sync(&frr.render(&cfg).unwrap()).unwrap();
    assert!(
        again.commands.is_empty() && again.leftover.is_empty(),
        "not canonical: {again:?}"
    );

    let r2: std::net::Ipv4Addr = "10.255.0.2".parse().unwrap();
    wait("LDP session with R2 operational", 90, || {
        state(&frr, &cfg)
            .neighbors
            .into_iter()
            .find(|n| n.lsr_id == r2 && n.operational())
    });
    let r3: ipnet::IpNet = "10.255.0.3/32".parse().unwrap();
    let label = wait("R3's loopback bound to R2's label", 90, || {
        state(&frr, &cfg)
            .bindings
            .into_iter()
            .find(|b| b.prefix == r3)
            .and_then(|b| b.in_use().map(|r| r.label))
    });
    eprintln!("10.255.0.3/32 via R2 label {label}");
    assert!(label >= 16, "R2 must swap, not pop: label {label}");

    let route = wait("kernel route with the label", 30, || {
        let (_, t) = sh("ip", &["route", "show", "10.255.0.3"]);
        t.contains("encap mpls").then_some(t)
    });
    eprintln!("kernel: {}", route.trim());
    assert!(route.contains(&label.to_string()), "{route}");
    // The way back (R3 → R1 through R2's label) settles a moment later.
    let ping = wait("ping through the LSP", 30, || {
        let (ok, t) = sh(
            "ping",
            &["-c", "1", "-W", "1", "-I", "10.255.0.1", "10.255.0.3"],
        );
        ok.then_some(t)
    });
    eprintln!("{}", ping.lines().last().unwrap_or_default());
    eprintln!(
        "LSP usable {:.1} s after the commit",
        started.elapsed().as_secs_f64()
    );
    let (_, r2_table) = sh("ip", &["-n", "crldp2", "-f", "mpls", "route", "show"]);
    eprintln!("R2's label table:\n{r2_table}");
    assert!(
        r2_table
            .lines()
            .any(|l| l.starts_with(&label.to_string()) && l.contains("10.0.23.2")),
        "R2 does not switch {label} towards R3"
    );

    // RFC 5443: the link's sync, as ospfd prints it. ldpd declares the
    // initial label exchange complete 10 s after the session (its fixed
    // wait time); until then ospfd keeps the link at LSInfinity.
    let sync = wait("IGP sync achieved on crldp-a", 40, || {
        let st = state(&frr, &cfg);
        st.igp_sync
            .iter()
            .any(|s| s.interface == "crldp-a" && s.achieved)
            .then_some(st.igp_sync)
    });
    eprintln!("igp sync: {sync:?}");
    assert!(
        sync.iter().all(|s| s.interface != "crldp-lo"),
        "a loopback has no sync to wait for: {sync:?}"
    );

    frr.apply(&cfg, &Config::default()).unwrap();
}
