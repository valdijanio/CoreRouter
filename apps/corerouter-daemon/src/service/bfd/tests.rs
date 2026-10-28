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
        port_multi: free_port(),
        peer_ports: Some((peer_port, 0)),
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

/// A port free right now, chosen by the kernel (no fixed ranges: two
/// tests of the binary, or another test's ephemeral port, never meet). The
/// engine binds it with SO_REUSEPORT, and the kernel hands a bound port to
/// nobody else.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

fn ports() -> (u16, u16) {
    (free_port(), free_port())
}

/// Generous under a loaded CI (load ~28 on 32 cores): waits end on the
/// event or the counter, this only bounds a hang.
const PATIENCE: Duration = Duration::from_secs(10);
/// The detection tests check BFD detected the loss, not the machine's
/// speed: never before the detection time (150 ms minus one 50 ms
/// interval), and within this ceiling. The precise numbers come from the
/// load bench (`load`, docs/bfd.md).
const DETECT_CEILING: Duration = Duration::from_millis(1500)
;

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
        wait_for(&a, PATIENCE, |s| s.iter().all(|x| x.state == "up" && x.tx_interval_us == 50_000)),
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
    let ev = a.events.recv_timeout(PATIENCE).unwrap();
    let took = t.elapsed();
    assert_eq!(ev.to, State::Down);
    assert!(!ev.client_up);
    eprintln!("detected after {took:?} (detection time 150 ms)");
    assert!(took <= DETECT_CEILING, "{took:?}");
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
    let mut a = engine("127.0.0.1".parse().unwrap(), pa, pb, 1);
    a.add(spec("127.0.0.3".parse().unwrap(), None, &BfdProfile::new("x", 300, 3)), None);
    // The worker takes the session before the packets (it reads its
    // sockets first: a packet for a session not there yet is ignored).
    assert!(wait_for(&a, PATIENCE, |s| s.len() == 1));
    let s = std::net::UdpSocket::bind("127.0.0.3:0").unwrap();
    s.set_ttl(64).unwrap();
    let mut p = corerouter_proto_bfd::packet::Packet::new(99);
    let mut out = [0u8; corerouter_proto_bfd::packet::MAX_LEN];
    let n = p.encode(&mut out);
    for _ in 0..3 {
        s.send_to(&out[..n], ("127.0.0.1", pa)).unwrap();
    }
    assert!(wait_for(&a, PATIENCE, |s| s[0].dropped == 3), "{:?}", a.snapshot().0);
    let (sessions, _) = a.snapshot();
    assert_eq!(sessions[0].packets_rx, 0);
    // With TTL 255 the same packet is taken (Down → Init).
    s.set_ttl(255).unwrap();
    p.state = State::Down;
    let n = p.encode(&mut out);
    s.send_to(&out[..n], ("127.0.0.1", pa)).unwrap();
    assert!(wait_for(&a, PATIENCE, |s| s[0].state == "init"));
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

/// G3.6b: the engine as bfdd's data plane. A fake bfdd (a Unix socket)
/// hands it a session; a second engine is the peer. bfdd must hear Up,
/// then Down with Diag 1 when the peer goes, and get its counters.
#[test]
fn data_plane_for_a_fake_bfdd() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    use corerouter_proto_bfd::dplane as dp;

    use super::{Controller, dplane};

    let (pa, pb) = ports();
    let dir = std::env::temp_dir().join(format!("g36b-dplane-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bfdd_dplane.sock");
    let listener = UnixListener::bind(&path).unwrap();

    let health = crate::service::Health::new(corerouter_control::Shutdown::default());
    let (tx, rx) = std::sync::mpsc::sync_channel(dplane::QUEUE);
    let h = health.clone();
    let p = path.clone();
    thread::spawn(move || dplane::run(p, tx, h));
    let (mut bfdd, _) = listener.accept().unwrap();
    bfdd.set_read_timeout(Some(Duration::from_millis(20))).unwrap();

    let mut ctl = Controller {
        threads: Some(2),
        dplane: true,
        opts: Options {
            threads: 2,
            bind4: Some("127.0.0.1".parse().unwrap()),
            bind6: None,
            port_single: pa,
            port_multi: free_port(),
            peer_ports: Some((pb, 0)),
        },
        ..Controller::default()
    };
    let cfg = corerouter_model::Config::default();
    let mut msg = Vec::new();
    dp::encode_session(
        dp::DP_ADD_SESSION,
        &dp::DpSession {
            flags: 0,
            src: "127.0.0.1".parse().unwrap(),
            dst: "127.0.0.2".parse().unwrap(),
            lid: 0x0001_1001,
            min_tx: 50_000,
            min_rx: 50_000,
            min_echo_tx: 0,
            min_echo_rx: 0,
            hold_time: 0,
            ttl: 255,
            detect_mult: 3,
            ifindex: 0,
            ifname: String::new(),
        },
        &mut msg,
    );
    bfdd.write_all(&msg).unwrap();
    // The peer.
    let mut b = engine("127.0.0.2".parse().unwrap(), pb, pa, 1);
    let mut sb = spec("127.0.0.1".parse().unwrap(), None, &BfdProfile::new("fast", 50, 3));
    sb.damp = None;
    b.add(sb, None);

    // Pumps the controller like its loop; returns bfdd's state changes.
    let mut inbuf: Vec<u8> = Vec::new();
    let mut pump = |ctl: &mut Controller, bfdd: &mut std::os::unix::net::UnixStream| -> Vec<dp::StateChange> {
        while let Ok(m) = rx.try_recv() {
            ctl.on_bfdd(m, &cfg, &health);
        }
        let mut evs = Vec::new();
        if let Some(e) = &ctl.engine {
            while let Ok(ev) = e.events.try_recv() {
                evs.push(ev);
            }
        }
        ctl.tell_bfdd(&evs);
        let mut chunk = [0u8; 1024];
        if let Ok(n) = bfdd.read(&mut chunk) {
            inbuf.extend_from_slice(&chunk[..n]);
        }
        let mut out = Vec::new();
        while let Ok(Some(h)) = dp::header(&inbuf) {
            let len = usize::from(h.length);
            if inbuf.len() < len {
                break;
            }
            if h.kind == dp::BFD_STATE_CHANGE {
                let p = &inbuf[8..len];
                let be = |i: usize| u32::from_be_bytes(p[i..i + 4].try_into().unwrap());
                out.push(dp::StateChange {
                    lid: be(0),
                    rid: be(4),
                    remote_flags: be(8),
                    desired_tx: be(12),
                    required_rx: be(16),
                    required_echo_rx: be(20),
                    state: p[24],
                    diagnostics: p[25],
                    detect_mult: p[26],
                });
            } else if h.kind == dp::BFD_SESSION_COUNTERS {
                assert_eq!(h.id, 77);
                out.push(dp::StateChange {
                    lid: 0,
                    rid: 0,
                    remote_flags: 0,
                    desired_tx: 0,
                    required_rx: 0,
                    required_echo_rx: 0,
                    state: 99,
                    diagnostics: 0,
                    detect_mult: 0,
                });
            }
            inbuf.drain(..len);
        }
        out
    };
    let t = Instant::now();
    let mut up = None;
    while t.elapsed() < PATIENCE && up.is_none() {
        up = pump(&mut ctl, &mut bfdd).into_iter().find(|s| s.state == 3);
    }
    let up = up.expect("bfdd heard Up");
    assert_eq!(up.lid, 0x0001_1001);
    assert_ne!(up.rid, 0);
    assert_eq!(up.detect_mult, 3);
    assert_eq!(ctl.engine.as_ref().unwrap().steering, "reuseport-cbpf");
    // Counters on request, with the request's id.
    let mut req = vec![1, 0, 0, 5, 0, 77, 0, 12];
    req.extend_from_slice(&0x0001_1001u32.to_be_bytes());
    bfdd.write_all(&req).unwrap();
    let t = Instant::now();
    let mut counted = false;
    while t.elapsed() < PATIENCE && !counted {
        counted = pump(&mut ctl, &mut bfdd).iter().any(|s| s.state == 99);
    }
    assert!(counted, "no counters");
    // The peer goes: Down, Diag 1, within the detection time.
    let t = Instant::now();
    drop(b);
    let mut down = None;
    while t.elapsed() < PATIENCE && down.is_none() {
        down = pump(&mut ctl, &mut bfdd).into_iter().find(|s| s.state == 1);
    }
    let took = t.elapsed();
    let down = down.expect("bfdd heard Down");
    assert_eq!(down.diagnostics, 1);
    eprintln!("bfdd heard Down after {took:?} (detection time 150 ms)");
    assert!(took <= DETECT_CEILING, "{took:?}");
    assert!(took >= Duration::from_millis(90), "{took:?}");
    health.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
