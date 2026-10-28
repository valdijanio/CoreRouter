//! Two engines talking over the loopback (no root, no namespace: 127.0.0.1
//! and 127.0.0.2, high ports), and the load harness of docs/bfd.md
//! (`#[ignore]`, run in a throwaway namespace):
//!
//! ```sh
//! unshare --user --map-root-user --net -- sh -c 'ip link set lo up && \
//!   cargo test -p corerouter-daemon --release bfd::tests::load -- --ignored --nocapture'
//! ```

// Helpers outside #[test] fns may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_model::bfd::{BfdKey, BfdProfile};
use corerouter_proto_bfd::packet::State;

use super::engine::{Engine, Event, Options, Spec};
use super::{config_of, damp_of};

fn spawn(name: String, f: Box<dyn FnOnce() + Send>) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new().name(name).spawn(f)
}

fn engine(bind: Ipv4Addr, port: u16, peer_port: u16, threads: usize) -> Engine {
    let opts = Options {
        threads,
        bind4: Some(bind),
        bind6: None,
        port_single: port,
        port_multi: port + 1,
        peer_ports: Some((peer_port, peer_port + 1)),
    };
    Engine::start(&opts, &spawn).unwrap()
}

fn spec(peer: IpAddr, local: Option<IpAddr>, prof: &BfdProfile) -> Spec {
    Spec {
        key: BfdKey {
            peer,
            multihop: false,
            local,
        },
        cfg: config_of(prof),
        damp: damp_of(prof),
        min_ttl: prof.min_ttl,
        users: vec!["test".into()],
        profile: prof.name.clone(),
    }
}

fn ports() -> (u16, u16) {
    let base = 20_000 + (std::process::id() % 20_000) as u16 / 4 * 4;
    (base, base + 2)
}

fn wait_for(e: &Engine, until: Duration, f: impl Fn(&[corerouter_model::bfd::BfdSessionStatus]) -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < until {
        let (s, _) = e.snapshot();
        if !s.is_empty() && f(&s) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn two_engines_come_up_and_detect_the_loss() {
    let (pa, pb) = ports();
    let fast = BfdProfile::new("fast", 50, 3);
    let a_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let b_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut a = engine("127.0.0.1".parse().unwrap(), pa, pb, 2);
    let mut b = engine("127.0.0.2".parse().unwrap(), pb, pa, 2);
    let mut da = spec(b_ip, None, &fast);
    da.damp = None;
    a.add(da.clone(), Some(1));
    b.add(spec(a_ip, None, &fast), Some(0));
    assert!(
        wait_for(&a, Duration::from_secs(5), |s| s.iter().all(|x| x.state == "up" && x.tx_interval_us == 50_000)),
        "{:?}",
        a.snapshot().0
    );
    assert_eq!(a.steering, "reuseport-cbpf");
    let mut events: Vec<Event> = Vec::new();
    while let Ok(e) = a.events.try_recv() {
        events.push(e);
    }
    assert!(events.iter().any(|e| e.to == State::Up && e.client_up));
    // B goes away: A must see it within the detection time (150 ms) plus
    // its own wheel tick and the snapshot.
    let t = Instant::now();
    drop(b);
    let ev = a.events.recv_timeout(Duration::from_secs(2)).unwrap();
    let took = t.elapsed();
    assert_eq!(ev.to, State::Down);
    assert!(!ev.client_up);
    assert!(took <= Duration::from_millis(170), "{took:?}");
    assert!(took >= Duration::from_millis(90), "{took:?}");
    let (s, threads) = a.snapshot();
    assert_eq!(threads.len(), 2);
    // The peer's packets reached their thread without a hand-over,
    // but for the first ones (Your Discriminator 0, socket 0).
    let fwd: u64 = threads.iter().map(|t| t.forwarded).sum();
    let rx: u64 = s.iter().map(|x| x.packets_rx).sum();
    assert!(fwd <= 3, "forwarded {fwd} of {rx}");
    drop(a);
}

#[test]
fn ttl_below_255_is_dropped_on_single_hop() {
    // A plain UDP socket sends with TTL 64: RFC 5881 §5 says discard.
    let (pa, pb) = ports();
    let pa = pa + 1000;
    let pb = pb + 1000;
    let mut a = engine("127.0.0.1".parse().unwrap(), pa, pb, 1);
    a.add(spec("127.0.0.3".parse().unwrap(), None, &BfdProfile::new("x", 300, 3)), None);
    let s = std::net::UdpSocket::bind("127.0.0.3:0").unwrap();
    s.set_ttl(64).unwrap();
    let mut p = corerouter_proto_bfd::packet::Packet::new(99);
    let mut out = [0u8; corerouter_proto_bfd::packet::MAX_LEN];
    let n = p.encode(&mut out);
    for _ in 0..3 {
        s.send_to(&out[..n], ("127.0.0.1", pa)).unwrap();
    }
    thread::sleep(Duration::from_millis(400));
    let (sessions, _) = a.snapshot();
    assert_eq!(sessions[0].packets_rx, 0);
    assert_eq!(sessions[0].dropped, 3);
    // With TTL 255 the same packet is taken (Down → Init).
    s.set_ttl(255).unwrap();
    p.state = State::Down;
    let n = p.encode(&mut out);
    s.send_to(&out[..n], ("127.0.0.1", pa)).unwrap();
    assert!(wait_for(&a, Duration::from_secs(2), |s| s[0].state == "init"));
}

/// The load harness: `sessions` pairs at 50 ms × 3 between two engines on
/// the loopback of a namespace, `threads` per engine, for `secs`.
fn load_run(sessions: usize, threads: usize, secs: u64) -> String {
    let (pa, pb) = (30_000, 30_002);
    let fast = BfdProfile::new("fast", 50, 3);
    let a_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let mut a = engine(Ipv4Addr::UNSPECIFIED, pa, pb, threads);
    let mut b = engine(Ipv4Addr::UNSPECIFIED, pb, pa, threads);
    for i in 0..sessions {
        let peer = IpAddr::V4(Ipv4Addr::new(127, 1, (i / 250) as u8, (i % 250 + 1) as u8));
        let mut sa = spec(peer, Some(a_ip), &fast);
        sa.damp = None;
        a.add(sa, None);
        let mut sb = spec(a_ip, Some(peer), &fast);
        sb.damp = None;
        b.add(sb, None);
    }
    let up = wait_for(&a, Duration::from_secs(20), |s| {
        s.len() == sessions && s.iter().all(|x| x.state == "up" && x.tx_interval_us == 50_000)
    });
    assert!(up, "sessions did not come up");
    while a.events.try_recv().is_ok() {}
    // Steady state.
    thread::sleep(Duration::from_secs(1));
    let _ = a.snapshot();
    let start = Instant::now();
    let mut cpu: Vec<f32> = Vec::new();
    while start.elapsed() < Duration::from_secs(secs) {
        thread::sleep(Duration::from_secs(1));
        let (_, t) = a.snapshot();
        cpu.extend(t.iter().map(|t| t.cpu_percent));
    }
    let drops = std::iter::from_fn(|| a.events.try_recv().ok())
        .filter(|e| e.to == State::Down)
        .count();
    let (s, t) = a.snapshot();
    let mut jit: Vec<u64> = s.iter().filter_map(|x| x.tx_jitter_p99_us).collect();
    jit.sort_unstable();
    let mut gap: Vec<u64> = s.iter().filter_map(|x| x.rx_gap_p99_us).collect();
    gap.sort_unstable();
    let max_cpu = cpu.iter().copied().fold(0.0f32, f32::max);
    let avg_cpu = cpu.iter().sum::<f32>() / cpu.len().max(1) as f32;
    let fwd: u64 = t.iter().map(|t| t.forwarded).sum();
    drop(b);
    drop(a);
    format!(
        "| {sessions} | {threads} | {avg_cpu:.1} | {max_cpu:.1} | {} | {} | {} | {drops} | {fwd} |",
        jit.last().copied().unwrap_or(0),
        jit.get(jit.len() / 2).copied().unwrap_or(0),
        gap.last().copied().unwrap_or(0),
    )
}

#[test]
#[ignore = "load harness (docs/bfd.md): run in a namespace with --release"]
fn load() {
    let secs = std::env::var("BFD_LOAD_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(15);
    println!(
        "| sessions | threads | CPU %/thread avg | CPU %/thread max | tx jitter p99 worst (µs) | tx jitter p99 median (µs) | rx gap p99 worst (µs) | false downs | handed over |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for sessions in [100, 500, 1000] {
        for threads in [1, 2, 4, 8] {
            println!("{}", load_run(sessions, threads, secs));
        }
    }
}
