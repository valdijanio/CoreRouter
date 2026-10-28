//! G3.6i: our engine against FRR's `bfdd`, in the lab VM only
//! (`scripts/frr-bfd-live.sh` starts a `bfdd` of its own FRR instance in a
//! namespace and runs these in another one, joined by a veth). `#[ignore]`
//! and `BFDD_NS` unset: nothing runs.
//!
//! - `bfdd_interop`: Up; a Poll started by `bfdd` (new timers) and one
//!   started by us; SHA1 on our side only never comes up (bfdd 10.7.1 has
//!   no authentication); each side detects the other's loss.
//! - `bfdd_load`: N sessions at 50 ms × 3 between the engine and `bfdd`;
//!   bfdd's CPU from `/proc/<pid>/stat`, its transmit regularity as the gap
//!   between its packets here, false downs on both sides. The addresses
//!   are on our side: a single-hop session in bfdd is keyed by the peer
//!   (and interface), not the local address, so 1000 `peer 10.76.0.1
//!   local-address …` blocks are one session there.

// Helpers outside #[test] fns may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_model::bfd::{BfdAuth, BfdKey, BfdKeyText, BfdProfile, BfdSessionStatus};
use corerouter_proto_bfd::packet::State;
use serde_json::Value;

use super::engine::{Engine, Options, Spec};
use super::config_of;

const OURS: Ipv4Addr = Ipv4Addr::new(10, 76, 0, 1);
const THEIRS: Ipv4Addr = Ipv4Addr::new(10, 76, 0, 2);

fn ns() -> Option<String> {
    std::env::var("BFDD_NS").ok().filter(|v| !v.is_empty())
}

fn engine(threads: usize) -> Engine {
    let opts = Options {
        threads,
        bind4: Some(Ipv4Addr::UNSPECIFIED),
        bind6: None,
        ..Options::default()
    };
    let spawn = |name: String, f: Box<dyn FnOnce() + Send>| thread::Builder::new().name(name).spawn(f);
    Engine::start(&opts, &spawn).unwrap()
}

fn spec(peer: Ipv4Addr, prof: &BfdProfile) -> Spec {
    spec_from(OURS, peer, prof)
}

fn spec_from(local: Ipv4Addr, peer: Ipv4Addr, prof: &BfdProfile) -> Spec {
    Spec {
        key: BfdKey {
            peer: IpAddr::V4(peer),
            multihop: false,
            local: Some(IpAddr::V4(local)),
        },
        cfg: config_of(prof),
        // No dampening: a lab flap must show, not be held.
        damp: None,
        min_ttl: prof.min_ttl,
        users: vec!["lab".into()],
        profile: prof.name.clone(),
    }
}

fn vtysh(ns: &str, cmds: &[&str]) -> String {
    let mut c = Command::new("vtysh");
    c.args(["-N", ns]);
    for x in cmds {
        c.args(["-c", x]);
    }
    let out = c.output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// bfdd's configuration commands, through a file (1000 peers are 5000
/// lines).
fn configure(ns: &str, lines: &[String]) {
    let path = std::env::temp_dir().join(format!("bfdd-{ns}.conf"));
    // A config file: vtysh -f applies it as the daemons' configuration.
    let mut text = String::from("bfd\n");
    for l in lines {
        text.push_str(l);
        text.push('\n');
    }
    text.push_str("exit\n");
    std::fs::write(&path, text).unwrap();
    let out = Command::new("vtysh").args(["-N", ns, "-f"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// bfdd's view of the session with `peer` (its `show bfd peers json`).
fn theirs(ns: &str, peer: Ipv4Addr, local: Ipv4Addr) -> Option<Value> {
    let v: Value = serde_json::from_str(&vtysh(ns, &["show bfd peers json"])).ok()?;
    v.as_array()?
        .iter()
        .find(|p| {
            p["peer"].as_str() == Some(&peer.to_string()) && p["local"].as_str() == Some(&local.to_string())
        })
        .cloned()
}

fn ours(e: &Engine, peer: Ipv4Addr) -> Option<BfdSessionStatus> {
    e.snapshot().0.into_iter().find(|s| s.peer == Some(IpAddr::V4(peer)))
}

fn wait<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let t = Instant::now();
    loop {
        if let Some(v) = f() {
            eprintln!("{what}: {:.0} ms", t.elapsed().as_secs_f64() * 1000.0);
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(secs), "not {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// bfdd's `peer` block for a session with `ours`, from its `local`.
fn peer_lines(ours: Ipv4Addr, local: Ipv4Addr, ms: u32) -> Vec<String> {
    vec![
        format!("peer {ours} local-address {local}"),
        format!(" receive-interval {ms}"),
        format!(" transmit-interval {ms}"),
        " detect-multiplier 3".into(),
        " exit".into(),
    ]
}

#[test]
#[ignore = "lab VM only: scripts/frr-bfd-live.sh"]
fn bfdd_interop() {
    let Some(ns) = ns() else { return };
    // bfdd starts slow (300 ms); we ask for 50 ms.
    configure(&ns, &peer_lines(OURS, THEIRS, 300));
    let mut e = engine(2);
    let fast = BfdProfile::new("fast", 50, 3);
    let discr = e.add(spec(THEIRS, &fast), None);
    let up = wait("Up on both sides", 10, || {
        let o = ours(&e, THEIRS)?;
        let t = theirs(&ns, OURS, THEIRS)?;
        (o.state == "up" && t["status"] == "up").then_some((o, t))
    });
    eprintln!("ours: tx {} µs; bfdd: {}", up.0.tx_interval_us, up.1);
    // We send at bfdd's 300 ms receive interval (RFC 5880 §6.8.7).
    assert_eq!(up.0.tx_interval_us, 300_000);
    while e.events.try_recv().is_ok() {}

    // A Poll from bfdd: its timers go to 50 ms; ours follow, no flap.
    configure(&ns, &peer_lines(OURS, THEIRS, 50));
    wait("bfdd's Poll: we send at 50 ms", 10, || {
        ours(&e, THEIRS).filter(|o| o.tx_interval_us == 50_000 && o.state == "up")
    });
    // A Poll from us: 200 ms; bfdd sees it, no flap.
    let slow = BfdProfile::new("slow", 200, 3);
    e.update(discr, spec(THEIRS, &slow));
    let t = wait("our Poll: bfdd sees 200 ms", 10, || {
        theirs(&ns, OURS, THEIRS).filter(|t| t["remote-transmit-interval"] == 200 && t["status"] == "up")
    });
    eprintln!("bfdd after our Poll: {t}");
    let flaps: Vec<_> = std::iter::from_fn(|| e.events.try_recv().ok()).collect();
    assert!(flaps.iter().all(|f| f.to == State::Up), "flapped during the Polls: {flaps:?}");
    e.update(discr, spec(THEIRS, &fast));

    // SHA1 on our side only: bfdd drops packets with the A bit, so the
    // session goes down and stays down (no false Up).
    let mut sha = BfdProfile::new("sha", 50, 3);
    sha.auth = BfdAuth::KeyedSha1;
    sha.auth_key_id = 1;
    sha.auth_secret = BfdKeyText("lab-secret".into());
    e.update(discr, spec(THEIRS, &sha));
    wait("SHA1 against bfdd: down", 10, || ours(&e, THEIRS).filter(|o| o.state != "up"));
    thread::sleep(Duration::from_secs(2));
    let o = ours(&e, THEIRS).unwrap();
    assert_ne!(o.state, "up", "came up with SHA1 against a bfdd without authentication: {o:?}");
    let t = theirs(&ns, OURS, THEIRS).unwrap();
    eprintln!("with SHA1: ours {} ({}), bfdd {}", o.state, o.diag, t["status"]);
    e.update(discr, spec(THEIRS, &fast));
    wait("Up again without SHA1", 10, || ours(&e, THEIRS).filter(|o| o.state == "up"));
    while e.events.try_recv().is_ok() {}

    // We go silent: bfdd detects it (3 × 50 ms).
    e.remove(discr, &spec(THEIRS, &fast).key);
    let t0 = Instant::now();
    let t = wait("bfdd detects our loss", 5, || {
        theirs(&ns, OURS, THEIRS).filter(|t| t["status"] == "down")
    });
    eprintln!("bfdd: {t}");
    assert!(t0.elapsed() < Duration::from_millis(400), "{:?}", t0.elapsed());
    assert_eq!(t["diagnostic"], "control detection time expired", "{t}");

    // Back up, then bfdd dies: we detect it.
    let discr = e.add(spec(THEIRS, &fast), None);
    // The new session, not the removed one's last snapshot.
    wait("Up again", 10, || {
        ours(&e, THEIRS).filter(|o| o.local_discr == discr && o.state == "up")
    });
    while e.events.try_recv().is_ok() {}
    let pid = std::fs::read_to_string(format!("/var/run/frr/{ns}/bfdd.pid")).unwrap();
    let t0 = Instant::now();
    assert!(Command::new("kill").args(["-9", pid.trim()]).status().unwrap().success());
    let ev = e.events.recv_timeout(Duration::from_secs(2)).unwrap();
    let took = t0.elapsed();
    eprintln!("bfdd killed: we saw {:?} (diag {:?}) after {took:?}", ev.to, ev.diag);
    assert_eq!(ev.to, State::Down);
    assert!(took <= Duration::from_millis(200), "{took:?}");
    assert_eq!(ev.discr, discr);
}

fn bfdd_cpu_ticks(ns: &str) -> u64 {
    let pid = std::fs::read_to_string(format!("/var/run/frr/{ns}/bfdd.pid")).unwrap();
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())).unwrap();
    // After the ")" of the name: field 14 (utime) and 15 (stime) are the
    // 12th and 13th.
    let rest = &stat[stat.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

fn bfdd_downs(ns: &str) -> u64 {
    let v: Value = serde_json::from_str(&vtysh(ns, &["show bfd peers counters json"])).unwrap_or(Value::Null);
    v.as_array()
        .map(|a| a.iter().filter_map(|p| p["session-down"].as_u64()).sum())
        .unwrap_or(0)
}

fn local_of(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 77, (i / 250) as u8, (i % 250 + 1) as u8)
}

fn load_run(ns: &str, sessions: usize, threads: usize, secs: u64) -> String {
    let mut lines = Vec::new();
    for i in 0..sessions {
        lines.extend(peer_lines(local_of(i), THEIRS, 50));
    }
    configure(ns, &lines);
    let fast = BfdProfile::new("fast", 50, 3);
    let mut e = engine(threads);
    for i in 0..sessions {
        e.add(spec_from(local_of(i), THEIRS, &fast), None);
    }
    let up = {
        let t = Instant::now();
        loop {
            let (s, _) = e.snapshot();
            if s.len() == sessions && s.iter().all(|x| x.state == "up" && x.tx_interval_us == 50_000) {
                break true;
            }
            if t.elapsed() > Duration::from_secs(30) {
                break false;
            }
            thread::sleep(Duration::from_millis(100));
        }
    };
    if !up {
        let (s, _) = e.snapshot();
        let n_up = s.iter().filter(|x| x.state == "up").count();
        let brief = vtysh(ns, &["show bfd peers brief"]);
        panic!(
            "{sessions} sessions did not come up: {n_up} of {} up here; first: {:?}\nbfdd:\n{}",
            s.len(),
            s.first(),
            brief.lines().take(12).collect::<Vec<_>>().join("\n")
        );
    }
    while e.events.try_recv().is_ok() {}
    thread::sleep(Duration::from_secs(1));
    let _ = e.snapshot();
    let downs0 = bfdd_downs(ns);
    let ticks0 = bfdd_cpu_ticks(ns);
    let start = Instant::now();
    let mut cpu: Vec<f32> = Vec::new();
    while start.elapsed() < Duration::from_secs(secs) {
        thread::sleep(Duration::from_secs(1));
        let (_, t) = e.snapshot();
        cpu.extend(t.iter().map(|t| t.cpu_percent));
    }
    let elapsed = start.elapsed().as_secs_f64();
    // USER_HZ is 100 on Linux.
    let bfdd_cpu = (bfdd_cpu_ticks(ns) - ticks0) as f64 / elapsed;
    let bfdd_false = bfdd_downs(ns) - downs0;
    let ours_false = std::iter::from_fn(|| e.events.try_recv().ok())
        .filter(|ev| ev.to == State::Down)
        .count();
    let (s, _) = e.snapshot();
    let mut gap: Vec<u64> = s.iter().filter_map(|x| x.rx_gap_p99_us).collect();
    gap.sort_unstable();
    let mut jit: Vec<u64> = s.iter().filter_map(|x| x.tx_jitter_p99_us).collect();
    jit.sort_unstable();
    let avg_cpu = cpu.iter().sum::<f32>() / cpu.len().max(1) as f32;
    drop(e);
    let _ = Command::new("vtysh").args(["-N", ns, "-c", "configure terminal", "-c", "no bfd"]).output();
    format!(
        "| {sessions} | {threads} | {avg_cpu:.1} | {bfdd_cpu:.1} | {} | {} | {} | {} | {ours_false} | {bfdd_false} |",
        jit.get(jit.len() / 2).copied().unwrap_or(0),
        jit.last().copied().unwrap_or(0),
        gap.get(gap.len() / 2).copied().unwrap_or(0),
        gap.last().copied().unwrap_or(0),
    )
}

#[test]
#[ignore = "lab VM only: scripts/frr-bfd-live.sh"]
fn bfdd_load() {
    let Some(ns) = ns() else { return };
    let secs = std::env::var("BFD_LOAD_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(15);
    println!(
        "| sessions | our threads | our CPU %/thread | bfdd CPU % | our tx jitter p99 median (µs) | worst | bfdd tx gap p99 median (µs) | worst | our false downs | bfdd false downs |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|");
    // BFD_THREADS=1,4: our engine's threads (bfdd has one).
    let threads: Vec<usize> = std::env::var("BFD_THREADS")
        .unwrap_or_else(|_| "1".into())
        .split(',')
        .filter_map(|t| t.trim().parse().ok())
        .collect();
    for sessions in [100, 500, 1000] {
        for t in &threads {
            println!("{}", load_run(&ns, sessions, *t, secs));
        }
    }
}
