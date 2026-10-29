//! The iperf3 protocol over the host's sockets (G6.4b): the client behind
//! `tool.bandwidth-test.start` ([`IperfClient`]) and the server of
//! `/tool bandwidth-server` ([`serve`]), interoperable with `iperf3`.
//! What the bytes mean is `corerouter_proto_iperf`; this moves them.
//!
//! Threads, blocking sockets with short timeouts (so a stop or the end of
//! the test is seen within ~200 ms), never the session lock while on the
//! network. One thread per data stream, like iperf3 ≥ 3.16. TCP senders
//! write blocks of `len` bytes, UDP senders datagrams that start with the
//! sender's clock and a sequence number; both pace to `bandwidth` when one
//! is set. Receivers count bytes and, for UDP, loss, reordering and jitter.
//!
//! The CPU reported is the whole router's (`/proc/stat`), not this
//! process': the question an operator asks is "did the test load the
//! router", and forwarding happens in the kernel.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::Shared;
use corerouter_engine::bandwidth::{BandwidthBackend, Outcome, Sample, TestRequest, Way};
use corerouter_proto_iperf::{
    self as iperf, COOKIE_SIZE, Direction, Limits, MAX_PARAMS_JSON, MAX_RESULTS_JSON, Params,
    Proto, Results, State, StreamResult, UDP_CONNECT_MSG, UDP_CONNECT_REPLY,
    UDP_CONNECT_REPLY_LEGACY, UdpHeader, UdpRx,
};
use serde_json::Value;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait for the peer on the control connection.
const CTRL_TIMEOUT: Duration = Duration::from_secs(10);
/// Socket timeouts of the data streams: how soon a stop is noticed.
const SLICE: Duration = Duration::from_millis(200);
/// How long the server waits for the client's data streams.
const STREAMS_TIMEOUT: Duration = Duration::from_secs(10);
/// A server stops a test this long past its duration (iperf3: 40 s).
const GRACE: Duration = Duration::from_secs(10);
/// Receive buffer of a stream (a TCP read, a UDP datagram).
const RX_BUF: usize = 128 * 1024;
/// Socket receive buffer asked for a UDP receiver.
const UDP_RCVBUF: usize = 4 << 20;

fn io(what: &str, e: &std::io::Error) -> String {
    format!("{what}: {e}")
}

fn timed_out(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// 36 random bytes from the OS (every `RandomState` is seeded from it),
/// made a cookie.
pub fn random_cookie() -> [u8; COOKIE_SIZE] {
    let mut r = [0u8; 36];
    for (i, chunk) in r.chunks_mut(8).enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        let bytes = h.finish().to_be_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(bytes.get(..n).unwrap_or(&[]));
    }
    iperf::cookie(&r)
}

fn read_state(ctrl: &mut TcpStream) -> Result<State, String> {
    let mut b = [0u8; 1];
    ctrl.read_exact(&mut b)
        .map_err(|e| io("reading the test state", &e))?;
    let [byte] = b;
    State::from_byte(byte).ok_or_else(|| format!("the peer sent an unknown test state {byte}"))
}

fn write_state(ctrl: &mut TcpStream, s: State) -> Result<(), String> {
    ctrl.write_all(&[s.byte()])
        .map_err(|e| io("sending the test state", &e))
}

fn write_json(ctrl: &mut TcpStream, v: &Value) -> Result<(), String> {
    ctrl.write_all(&iperf::frame(v))
        .map_err(|e| io("sending JSON", &e))
}

fn read_json(ctrl: &mut TcpStream, max: usize) -> Result<Value, String> {
    let mut h = [0u8; 4];
    ctrl.read_exact(&mut h).map_err(|e| io("reading JSON", &e))?;
    let len = iperf::frame_len(h, max).map_err(|e| e.to_string())?;
    let mut body = vec![0u8; len];
    ctrl.read_exact(&mut body)
        .map_err(|e| io("reading JSON", &e))?;
    iperf::parse(&body).map_err(|e| e.to_string())
}

/// The router's CPU (all cores) from `/proc/stat`, between two calls.
#[derive(Default)]
pub struct CpuMeter {
    last: Option<(u64, u64)>,
}

fn cpu_times() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().next()?.strip_prefix("cpu ")?;
    let v: Vec<u64> = line.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    let total: u64 = v.iter().take(8).sum();
    let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

impl CpuMeter {
    /// Percent busy since the last call (`None` the first time).
    pub fn sample(&mut self) -> Option<f64> {
        let now = cpu_times()?;
        let out = self.last.and_then(|(busy, total)| {
            let dt = now.1.saturating_sub(total);
            (dt > 0).then(|| now.0.saturating_sub(busy) as f64 / dt as f64 * 100.0)
        });
        self.last = Some(now);
        out
    }
}

/// What a stream's thread counts.
#[derive(Default)]
struct Counter {
    bytes: AtomicU64,
    packets: AtomicU64,
    udp: Mutex<UdpRx>,
}

enum Sock {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

struct Stream {
    id: u32,
    sender: bool,
    sock: Sock,
    counter: Arc<Counter>,
}

fn wall_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Sleep until `bits` are due at `rate` bit/s since `start` (at most one
/// slice, so a stop is seen).
fn pace(start: Instant, bits: u64, rate: u64) {
    if rate == 0 {
        return;
    }
    let due = Duration::from_secs_f64(bits as f64 / rate as f64);
    let ahead = due.saturating_sub(start.elapsed());
    if ahead > Duration::from_millis(1) {
        thread::sleep(ahead.min(SLICE));
    }
}

/// Start each stream's thread; they end when `stop` is set or the peer
/// closes.
fn spawn_streams(streams: &[Stream], p: &Params, stop: &Arc<AtomicBool>) -> Result<Vec<JoinHandle<()>>, String> {
    let mut out = Vec::new();
    let wide = p.udp_counters_64bit;
    for s in streams {
        let stop = Arc::clone(stop);
        let counter = Arc::clone(&s.counter);
        let (rate, len) = (p.bandwidth, usize::try_from(p.len).unwrap_or(1460));
        let sock = match &s.sock {
            Sock::Tcp(t) => Sock::Tcp(t.try_clone().map_err(|e| io("stream", &e))?),
            Sock::Udp(u) => Sock::Udp(u.try_clone().map_err(|e| io("stream", &e))?),
        };
        let sender = s.sender;
        let h = thread::Builder::new()
            .name(format!("iperf-{}", s.id))
            .spawn(move || match (sock, sender) {
                (Sock::Tcp(t), true) => tcp_send(t, len, rate, &stop, &counter),
                (Sock::Tcp(t), false) => tcp_recv(t, &stop, &counter),
                (Sock::Udp(u), true) => udp_send(&u, len, rate, wide, &stop, &counter),
                (Sock::Udp(u), false) => udp_recv(&u, wide, &stop, &counter),
            })
            .map_err(|e| io("starting a stream", &e))?;
        out.push(h);
    }
    Ok(out)
}

fn tcp_send(mut t: TcpStream, len: usize, rate: u64, stop: &AtomicBool, c: &Counter) {
    // Not all zeros: a compressing link would make the test lie.
    let buf: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let _ = t.set_write_timeout(Some(SLICE));
    let start = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match t.write(&buf) {
            Ok(0) => return,
            Ok(n) => {
                let total = c.bytes.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                pace(start, total * 8, rate);
            }
            Err(e) if timed_out(&e) || e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

fn tcp_recv(mut t: TcpStream, stop: &AtomicBool, c: &Counter) {
    let mut buf = vec![0u8; RX_BUF];
    let _ = t.set_read_timeout(Some(SLICE));
    loop {
        match t.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                c.bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) if timed_out(&e) || e.kind() == ErrorKind::Interrupted => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

fn udp_send(u: &UdpSocket, len: usize, rate: u64, wide: bool, stop: &AtomicBool, c: &Counter) {
    let mut buf: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let _ = u.set_write_timeout(Some(SLICE));
    let start = Instant::now();
    let mut seq = 1u64;
    while !stop.load(Ordering::Relaxed) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        UdpHeader {
            sec: u32::try_from(now.as_secs() & 0xFFFF_FFFF).unwrap_or(0),
            usec: now.subsec_micros(),
            seq,
        }
        .write(&mut buf, wide);
        match u.send(&buf) {
            Ok(n) => {
                seq += 1;
                c.packets.fetch_add(1, Ordering::Relaxed);
                let total = c.bytes.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                pace(start, total * 8, rate);
            }
            // ENOBUFS and friends: the queue is full; try again.
            Err(e) if timed_out(&e) || e.raw_os_error() == Some(105) => {}
            Err(_) => return,
        }
    }
}

fn udp_recv(u: &UdpSocket, wide: bool, stop: &AtomicBool, c: &Counter) {
    let mut buf = vec![0u8; 65_536];
    // A burst must not overflow the default ~200 KiB buffer between two
    // reads (the kernel caps this at net.core.rmem_max).
    let _ = socket2::SockRef::from(u).set_recv_buffer_size(UDP_RCVBUF);
    let _ = u.set_read_timeout(Some(SLICE));
    loop {
        match u.recv(&mut buf) {
            Ok(n) => {
                c.bytes.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(h) = buf.get(..n).and_then(|b| UdpHeader::read(b, wide)) {
                    c.udp.lock().unwrap_or_else(PoisonError::into_inner).on_datagram(&h, wall_secs());
                }
            }
            Err(e) if timed_out(&e) || e.kind() == ErrorKind::Interrupted => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }
            // ECONNREFUSED after the peer closed its socket: done.
            Err(_) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(SLICE);
            }
        }
    }
}

/// This side's results for the peer.
fn our_results(streams: &[Stream], cpu: f64, secs: f64) -> Results {
    let any_sender = streams.iter().any(|s| s.sender);
    Results {
        cpu_util_total: cpu,
        cpu_util_user: 0.0,
        cpu_util_system: cpu,
        sender_has_retransmits: if any_sender { 0 } else { -1 },
        streams: streams
            .iter()
            .map(|s| {
                let rx = s.counter.udp.lock().unwrap_or_else(PoisonError::into_inner).clone();
                let udp_rx = matches!(s.sock, Sock::Udp(_)) && !s.sender;
                StreamResult {
                    id: s.id,
                    bytes: s.counter.bytes.load(Ordering::Relaxed),
                    retransmits: -1,
                    jitter: if udp_rx { rx.jitter } else { 0.0 },
                    errors: if udp_rx { i64::try_from(rx.errors).unwrap_or(i64::MAX) } else { 0 },
                    packets: if udp_rx {
                        i64::try_from(rx.packet_count).unwrap_or(i64::MAX)
                    } else {
                        i64::try_from(s.counter.packets.load(Ordering::Relaxed)).unwrap_or(i64::MAX)
                    },
                    start_time: 0.0,
                    end_time: secs,
                }
            })
            .collect(),
        server_output_text: None,
    }
}

/// Which of `n` streams this side sends on, in creation order: the
/// client's senders connect first (`iperf_create_streams(test, 1)`).
fn client_roles(d: Direction, n: u32) -> Vec<bool> {
    match d {
        Direction::Send => vec![true; n as usize],
        Direction::Receive => vec![false; n as usize],
        Direction::Both => {
            let mut v = vec![true; n as usize];
            v.extend(vec![false; n as usize]);
            v
        }
    }
}

fn udp_open(to: SocketAddr, sender: bool) -> Result<UdpSocket, String> {
    let any = match to {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let u = UdpSocket::bind(any).map_err(|e| io("opening a UDP stream", &e))?;
    u.connect(to).map_err(|e| io("opening a UDP stream", &e))?;
    u.set_read_timeout(Some(CTRL_TIMEOUT))
        .map_err(|e| io("opening a UDP stream", &e))?;
    u.send(&UDP_CONNECT_MSG)
        .map_err(|e| io("opening a UDP stream", &e))?;
    // With -R data may come before the reply; skip a few datagrams.
    let mut buf = vec![0u8; 65_536];
    for _ in 0..64 {
        let n = u.recv(&mut buf).map_err(|e| io("waiting for the UDP stream's reply", &e))?;
        if n == 4 && matches!(buf.get(..4), Some(r) if r == UDP_CONNECT_REPLY || r == UDP_CONNECT_REPLY_LEGACY) {
            return Ok(u);
        }
        if sender {
            break;
        }
    }
    Err("the server did not answer the UDP stream".into())
}

fn set_tos(sock: &Sock, tos: u8, v6: bool) {
    if tos == 0 {
        return;
    }
    let s = match sock {
        Sock::Tcp(t) => socket2::SockRef::from(t),
        Sock::Udp(u) => socket2::SockRef::from(u),
    };
    if v6 {
        set_tclass(&s, tos);
    } else {
        let _ = s.set_tos_v4(u32::from(tos));
    }
}

/// The IPv6 traffic class (DSCP) of a stream.
#[cfg(unix)]
fn set_tclass(s: &socket2::SockRef<'_>, tos: u8) {
    let _ = s.set_tclass_v6(u32::from(tos));
}

/// Windows has no `IPV6_TCLASS` in socket2: IPv6 streams go unmarked.
#[cfg(not(unix))]
fn set_tclass(_: &socket2::SockRef<'_>, tos: u8) {
    log::info!("bandwidth test: DSCP {} not set on IPv6 (unsupported on this OS)", tos >> 2);
}

/// The client: `tool.bandwidth-test.start` on the daemon.
pub struct IperfClient {
    pub session: Shared,
}

impl IperfClient {
    fn address(&self, req: &TestRequest) -> Result<IpAddr, String> {
        if let Some(a) = req.addr {
            return Ok(a);
        }
        let all = super::dns::resolve(&self.session, &req.host)?;
        all.iter()
            .find(|a| a.is_ipv4())
            .or_else(|| all.first())
            .copied()
            .ok_or_else(|| format!("'{}' has no address", req.host))
    }
}

impl BandwidthBackend for IperfClient {
    fn describe(&self) -> String {
        "iperf3 (this router)".into()
    }

    fn run(
        &self,
        req: &TestRequest,
        wait: &dyn Fn(Duration) -> bool,
        on_sample: &mut dyn FnMut(Sample),
    ) -> Result<Outcome, String> {
        let addr = self.address(req)?;
        let to = SocketAddr::new(addr, req.port);
        let p = &req.params;
        let mut ctrl = TcpStream::connect_timeout(&to, CONNECT_TIMEOUT)
            .map_err(|e| format!("cannot reach {to}: {e}"))?;
        let _ = ctrl.set_nodelay(true);
        ctrl.set_read_timeout(Some(CTRL_TIMEOUT))
            .and_then(|()| ctrl.set_write_timeout(Some(CTRL_TIMEOUT)))
            .map_err(|e| io("control connection", &e))?;
        let cookie = random_cookie();
        ctrl.write_all(&cookie)
            .map_err(|e| io("sending the cookie", &e))?;
        let roles = client_roles(p.direction, p.parallel);
        let ids = iperf::stream_ids(u32::try_from(roles.len()).unwrap_or(0));
        let mut streams: Vec<Stream> = Vec::new();
        let mut theirs: Option<Results> = None;
        let mut secs = 0.0;
        let mut cpu_avg = 0.0;
        loop {
            match read_state(&mut ctrl)? {
                State::ParamExchange => write_json(&mut ctrl, &p.to_json())?,
                State::CreateStreams => {
                    for (sender, id) in roles.iter().zip(&ids) {
                        let sock = match p.proto {
                            Proto::Tcp => {
                                let mut t = TcpStream::connect_timeout(&to, CONNECT_TIMEOUT)
                                    .map_err(|e| io("opening a TCP stream", &e))?;
                                t.write_all(&cookie)
                                    .map_err(|e| io("opening a TCP stream", &e))?;
                                Sock::Tcp(t)
                            }
                            Proto::Udp => Sock::Udp(udp_open(to, *sender)?),
                        };
                        set_tos(&sock, p.tos, addr.is_ipv6());
                        streams.push(Stream {
                            id: *id,
                            sender: *sender,
                            sock,
                            counter: Arc::default(),
                        });
                    }
                }
                State::TestStart => {}
                State::TestRunning => {
                    let (s, c) = run_test(&mut ctrl, &streams, p, wait, on_sample)?;
                    secs = s;
                    cpu_avg = c;
                }
                State::ExchangeResults => {
                    write_json(&mut ctrl, &our_results(&streams, cpu_avg, secs).to_json())?;
                    let v = read_json(&mut ctrl, MAX_RESULTS_JSON)?;
                    theirs = Some(Results::from_json(&v).map_err(|e| e.to_string())?);
                }
                State::DisplayResults => {
                    let _ = write_state(&mut ctrl, State::IperfDone);
                    break;
                }
                State::AccessDenied => return Err(iperf::error_text(121)),
                State::ServerError => {
                    let mut b = [0u8; 8];
                    let code = ctrl
                        .read_exact(&mut b)
                        .ok()
                        .and_then(|()| b.get(..4)?.try_into().ok())
                        .map_or(0, i32::from_be_bytes);
                    return Err(iperf::error_text(code));
                }
                State::ServerTerminate => return Err("the server stopped the test".into()),
                other => return Err(format!("the server sent an unexpected {other:?}")),
            }
        }
        Ok(outcome(&streams, theirs.unwrap_or_default(), secs, addr, p.proto))
    }
}

/// Run the streams for the test's duration (or until stopped), sampling
/// once a second; then end it (TEST_END). Returns the seconds it ran and
/// the router's average CPU.
fn run_test(
    ctrl: &mut TcpStream,
    streams: &[Stream],
    p: &Params,
    wait: &dyn Fn(Duration) -> bool,
    on_sample: &mut dyn FnMut(Sample),
) -> Result<(f64, f64), String> {
    let stop = Arc::new(AtomicBool::new(false));
    let handles = spawn_streams(streams, p, &stop)?;
    let start = Instant::now();
    let total = Duration::from_secs(u64::from(p.time.saturating_add(p.omit)));
    let mut cpu = CpuMeter::default();
    let _ = cpu.sample();
    let (mut cpu_sum, mut cpu_n) = (0.0, 0u32);
    let mut last = (0u64, 0u64, 0u64, 0u64);
    let mut last_t = Duration::ZERO;
    let mut next = Duration::from_secs(1);
    loop {
        let now = start.elapsed();
        let step = next.min(total).saturating_sub(now);
        let alive = wait(step.min(SLICE));
        let now = start.elapsed();
        if now >= next.min(total) || !alive {
            let sum = |sender: bool| -> u64 {
                streams
                    .iter()
                    .filter(|s| s.sender == sender)
                    .map(|s| s.counter.bytes.load(Ordering::Relaxed))
                    .sum()
            };
            let (sent, received) = (sum(true), sum(false));
            let udp: Vec<UdpRx> = streams
                .iter()
                .filter(|s| !s.sender && matches!(s.sock, Sock::Udp(_)))
                .map(|s| s.counter.udp.lock().unwrap_or_else(PoisonError::into_inner).clone())
                .collect();
            let lost: u64 = udp.iter().map(|r| r.errors).sum();
            let packets: u64 = udp.iter().map(|r| r.packet_count).sum();
            let c = cpu.sample();
            if let Some(c) = c {
                cpu_sum += c;
                cpu_n += 1;
            }
            on_sample(Sample {
                t: now.as_secs_f64(),
                secs: now.saturating_sub(last_t).as_secs_f64(),
                sent: sent.saturating_sub(last.0),
                received: received.saturating_sub(last.1),
                lost: (!udp.is_empty()).then(|| lost.saturating_sub(last.2)),
                packets: (!udp.is_empty()).then(|| packets.saturating_sub(last.3)),
                jitter_ms: udp.iter().map(|r| r.jitter * 1000.0).reduce(f64::max),
                cpu: c,
            });
            last = (sent, received, lost, packets);
            last_t = now;
            next += Duration::from_secs(1);
        }
        if !alive || now >= total {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    write_state(ctrl, State::TestEnd)?;
    for h in handles {
        let _ = h.join();
    }
    let secs = start.elapsed().as_secs_f64();
    Ok((secs, if cpu_n > 0 { cpu_sum / f64::from(cpu_n) } else { 0.0 }))
}

/// Both sides' numbers, per direction.
fn outcome(streams: &[Stream], theirs: Results, secs: f64, addr: IpAddr, proto: Proto) -> Outcome {
    let peer = |id: u32| theirs.streams.iter().find(|s| s.id == id);
    let way = |sender: bool| -> Option<Way> {
        let mine: Vec<&Stream> = streams.iter().filter(|s| s.sender == sender).collect();
        if mine.is_empty() {
            return None;
        }
        let ours: u64 = mine.iter().map(|s| s.counter.bytes.load(Ordering::Relaxed)).sum();
        let peers: u64 = mine.iter().filter_map(|s| peer(s.id)).map(|r| r.bytes).sum();
        let mut w = Way {
            sent: if sender { ours } else { peers },
            received: if sender { peers } else { ours },
            secs,
            ..Way::default()
        };
        if proto == Proto::Udp {
            if sender {
                // The far end received: its loss and jitter.
                let r: Vec<&StreamResult> = mine.iter().filter_map(|s| peer(s.id)).collect();
                w.lost = Some(r.iter().map(|x| u64::try_from(x.errors).unwrap_or(0)).sum());
                w.packets = Some(r.iter().map(|x| u64::try_from(x.packets).unwrap_or(0)).sum());
                w.jitter_ms = r.iter().map(|x| x.jitter * 1000.0).reduce(f64::max);
            } else {
                let rx: Vec<UdpRx> = mine
                    .iter()
                    .map(|s| s.counter.udp.lock().unwrap_or_else(PoisonError::into_inner).clone())
                    .collect();
                w.lost = Some(rx.iter().map(|r| r.errors).sum());
                w.packets = Some(rx.iter().map(|r| r.packet_count).sum());
                w.jitter_ms = rx.iter().map(|r| r.jitter * 1000.0).reduce(f64::max);
            }
        } else if !sender {
            let r: i64 = mine
                .iter()
                .filter_map(|s| peer(s.id))
                .map(|x| x.retransmits)
                .filter(|r| *r >= 0)
                .sum();
            w.retransmits = (theirs.sender_has_retransmits == 1).then(|| u64::try_from(r).unwrap_or(0));
        }
        Some(w)
    };
    Outcome {
        upload: way(true),
        download: way(false),
        remote_cpu: Some(theirs.cpu_util_total),
        server_output: theirs.server_output_text.clone(),
        address: Some(addr.to_string()),
    }
}

/// How a served test went, for the server's status and log.
#[derive(Debug, Clone, Default)]
pub struct Served {
    pub client: String,
    pub proto: &'static str,
    pub direction: &'static str,
    pub streams: u32,
    pub secs: f64,
    pub bytes: u64,
}

/// Map a refusal to the error code iperf3 clients print.
fn refusal_code(e: &iperf::Error) -> i32 {
    let t = e.to_string();
    if t.contains("server allows at most") && t.contains(" s") && !t.contains("bit/s") {
        37
    } else if t.contains("streams") {
        6
    } else if t.contains("bit/s") {
        27
    } else {
        114
    }
}

fn server_error(ctrl: &mut TcpStream, code: i32) {
    let mut b = vec![State::ServerError.byte()];
    b.extend_from_slice(&code.to_be_bytes());
    b.extend_from_slice(&0i32.to_be_bytes());
    let _ = ctrl.write_all(&b);
}

/// Refuse a client the server will not serve now (busy, not allowed).
pub fn deny(mut c: TcpStream) {
    let _ = c.set_write_timeout(Some(SLICE));
    let _ = c.write_all(&[State::AccessDenied.byte()]);
}

/// Accept the next TCP stream with our cookie (others are denied), until
/// `deadline`.
fn accept_tcp(listener: &TcpListener, cookie: &[u8], deadline: Instant) -> Result<TcpStream, String> {
    loop {
        match listener.accept() {
            Ok((mut t, _)) => {
                let _ = t.set_nonblocking(false);
                let _ = t.set_read_timeout(Some(CONNECT_TIMEOUT));
                let mut c = [0u8; COOKIE_SIZE];
                if t.read_exact(&mut c).is_ok() && c.as_slice() == cookie {
                    return Ok(t);
                }
                deny(t);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("the client's data streams did not come".into());
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(io("accepting a data stream", &e)),
        }
    }
}

/// A UDP socket on the server port, sharing it with the ones already
/// connected to a stream (iperf3 does the same).
fn udp_listener(local: SocketAddr) -> Result<UdpSocket, String> {
    let domain = if local.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(|e| io("UDP stream socket", &e))?;
    s.set_reuse_address(true)
        .map_err(|e| io("UDP stream socket", &e))?;
    // Linux needs SO_REUSEPORT for a second socket on the port; on Windows
    // SO_REUSEADDR alone allows it (and there is no SO_REUSEPORT).
    #[cfg(unix)]
    s.set_reuse_port(true)
        .map_err(|e| io("UDP stream socket", &e))?;
    if local.is_ipv6() {
        let _ = s.set_only_v6(false);
    }
    s.bind(&local.into()).map_err(|e| io("UDP stream socket", &e))?;
    Ok(s.into())
}

/// One UDP stream on `u`, an already bound listener. With `more`, the
/// listener for the next stream is bound before the reply goes out, as
/// iperf3 does (`iperf_udp_accept`): the client sends the next stream's
/// datagram as soon as it reads the reply, and a port with no socket yet
/// answers it with ICMP port unreachable ("Connection refused").
fn accept_udp(
    u: UdpSocket,
    local: SocketAddr,
    deadline: Instant,
    more: bool,
) -> Result<(UdpSocket, Option<UdpSocket>), String> {
    let mut buf = [0u8; 64];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("the client's UDP streams did not come".into());
        }
        u.set_read_timeout(Some(left.min(SLICE)))
            .map_err(|e| io("UDP stream", &e))?;
        match u.recv_from(&mut buf) {
            // iperf3 does not look at the bytes; neither do we.
            Ok((_, peer)) => {
                u.connect(peer).map_err(|e| io("UDP stream", &e))?;
                let next = if more { Some(udp_listener(local)?) } else { None };
                u.send(&UDP_CONNECT_REPLY).map_err(|e| io("UDP stream", &e))?;
                return Ok((u, next));
            }
            Err(e) if timed_out(&e) => {}
            Err(e) => return Err(io("UDP stream", &e)),
        }
    }
}

/// Serve one test on `ctrl` (already accepted from `listener`): the
/// server half of the state machine. `alive()` is false once the service
/// is stopping; `busy` gets every other client that knocks meanwhile.
pub fn serve(
    listener: &TcpListener,
    mut ctrl: TcpStream,
    limits: &Limits,
    alive: &dyn Fn() -> bool,
    busy: &mut dyn FnMut(TcpStream),
    started: &mut dyn FnMut(&Served),
) -> Result<Served, String> {
    let peer = ctrl.peer_addr().map_err(|e| io("client", &e))?;
    let local = ctrl.local_addr().map_err(|e| io("client", &e))?;
    let _ = ctrl.set_nonblocking(false);
    let _ = ctrl.set_nodelay(true);
    ctrl.set_read_timeout(Some(CTRL_TIMEOUT))
        .and_then(|()| ctrl.set_write_timeout(Some(CTRL_TIMEOUT)))
        .map_err(|e| io("control connection", &e))?;
    let mut cookie = [0u8; COOKIE_SIZE];
    ctrl.read_exact(&mut cookie).map_err(|e| io("reading the cookie", &e))?;
    if !iperf::cookie_is_valid(&cookie) {
        return Err("the client sent no iperf3 cookie".into());
    }
    write_state(&mut ctrl, State::ParamExchange)?;
    let v = read_json(&mut ctrl, MAX_PARAMS_JSON)?;
    let p = match Params::from_json(&v, limits) {
        Ok(p) => p,
        Err(e) => {
            server_error(&mut ctrl, refusal_code(&e));
            return Err(format!("refused {peer}: {e}"));
        }
    };
    let mut served = Served {
        client: peer.ip().to_canonical().to_string(),
        proto: match p.proto { Proto::Tcp => "tcp", Proto::Udp => "udp" },
        direction: match p.direction {
            Direction::Send => "send",
            Direction::Receive => "receive",
            Direction::Both => "both",
        },
        streams: p.parallel,
        ..Served::default()
    };
    started(&served);
    // The server's roles mirror the client's.
    let roles: Vec<bool> = client_roles(p.direction, p.parallel).iter().map(|s| !s).collect();
    let ids = iperf::stream_ids(u32::try_from(roles.len()).unwrap_or(0));
    // UDP: the port must be listening before the client is told to send
    // (iperf3 binds `prot_listener` before CREATE_STREAMS too).
    let udp_local = SocketAddr::new(local.ip(), local.port());
    let mut udp_next = match p.proto {
        Proto::Udp => Some(udp_listener(udp_local)?),
        Proto::Tcp => None,
    };
    write_state(&mut ctrl, State::CreateStreams)?;
    let deadline = Instant::now() + STREAMS_TIMEOUT;
    let mut streams = Vec::with_capacity(roles.len());
    for (i, (sender, id)) in roles.iter().zip(&ids).enumerate() {
        let sock = match p.proto {
            Proto::Tcp => Sock::Tcp(accept_tcp(listener, &cookie, deadline)?),
            Proto::Udp => {
                let l = udp_next.take().ok_or("no UDP listener for the next stream")?;
                let (u, next) = accept_udp(l, udp_local, deadline, i + 1 < roles.len())?;
                udp_next = next;
                Sock::Udp(u)
            }
        };
        set_tos(&sock, p.tos, peer.is_ipv6());
        streams.push(Stream { id: *id, sender: *sender, sock, counter: Arc::default() });
    }
    write_state(&mut ctrl, State::TestStart)?;
    write_state(&mut ctrl, State::TestRunning)?;
    let stop = Arc::new(AtomicBool::new(false));
    let handles = spawn_streams(&streams, &p, &stop)?;
    let start = Instant::now();
    let limit = Duration::from_secs(u64::from(p.time.saturating_add(p.omit))) + GRACE;
    let mut cpu = CpuMeter::default();
    let _ = cpu.sample();
    ctrl.set_read_timeout(Some(SLICE)).map_err(|e| io("control connection", &e))?;
    let ended = loop {
        let mut b = [0u8; 1];
        match ctrl.read(&mut b) {
            Ok(1) => match State::from_byte(u8::from_ne_bytes(b)) {
                Some(State::TestEnd) => break Ok(()),
                Some(State::ClientTerminate | State::IperfDone) | None => break Err("the client ended the test".to_owned()),
                Some(other) => break Err(format!("the client sent an unexpected {other:?}")),
            },
            Ok(_) => break Err("the client closed the control connection".to_owned()),
            Err(e) if timed_out(&e) || e.kind() == ErrorKind::Interrupted => {}
            Err(e) => break Err(io("control connection", &e)),
        }
        if !alive() {
            let _ = write_state(&mut ctrl, State::ServerTerminate);
            break Err("the server is stopping".to_owned());
        }
        if start.elapsed() > limit {
            server_error(&mut ctrl, 160);
            break Err("the test ran past its duration".to_owned());
        }
        // Another client while busy: iperf3 answers ACCESS_DENIED.
        if let Ok((other, _)) = listener.accept() {
            busy(other);
        }
    };
    stop.store(true, Ordering::Relaxed);
    let secs = start.elapsed().as_secs_f64();
    let cpu_pct = cpu.sample().unwrap_or(0.0);
    served.secs = secs;
    served.bytes = streams.iter().map(|s| s.counter.bytes.load(Ordering::Relaxed)).sum();
    // Close the data sockets so the client's senders stop.
    for s in &streams {
        match &s.sock {
            Sock::Tcp(t) => {
                let _ = t.shutdown(std::net::Shutdown::Both);
            }
            Sock::Udp(_) => {}
        }
    }
    for h in handles {
        let _ = h.join();
    }
    ended?;
    ctrl.set_read_timeout(Some(CTRL_TIMEOUT)).map_err(|e| io("control connection", &e))?;
    write_state(&mut ctrl, State::ExchangeResults)?;
    let v = read_json(&mut ctrl, MAX_RESULTS_JSON)?;
    let _ = Results::from_json(&v).map_err(|e| e.to_string())?;
    let mut ours = our_results(&streams, cpu_pct, secs);
    if p.get_server_output {
        ours.server_output_text = Some(format!(
            "CoreRouter bandwidth server: {} {} from {}, {} stream(s), {:.1} s, {} bytes, router CPU {:.0}%\n",
            served.proto, served.direction, served.client, served.streams, secs, served.bytes, cpu_pct
        ));
    }
    write_json(&mut ctrl, &ours.to_json())?;
    write_state(&mut ctrl, State::DisplayResults)?;
    let _ = read_state(&mut ctrl);
    Ok(served)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Our server on 127.0.0.1, serving `tests` tests with `limits`.
    fn server(limits: Limits, tests: usize) -> (u16, JoinHandle<Vec<Result<Served, String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        l.set_nonblocking(true).unwrap();
        let h = thread::spawn(move || {
            let mut out = Vec::new();
            let start = Instant::now();
            while out.len() < tests && start.elapsed() < Duration::from_secs(30) {
                match l.accept() {
                    Ok((c, _)) => out.push(serve(&l, c, &limits, &|| true, &mut deny, &mut |_| {})),
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            out
        });
        (port, h)
    }

    fn client() -> IperfClient {
        IperfClient {
            session: corerouter_engine::shared(corerouter_engine::Session::virtual_lab()),
        }
    }

    fn req(port: u16, proto: Proto, direction: Direction, bandwidth: u64, parallel: u32) -> TestRequest {
        TestRequest {
            host: "127.0.0.1".into(),
            addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port,
            params: Params {
                proto,
                direction,
                time: 2,
                parallel,
                bandwidth,
                len: if proto == Proto::Udp { 1400 } else { 128 * 1024 },
                get_server_output: true,
                ..Params::default()
            },
        }
    }

    fn run(r: &TestRequest) -> (Result<Outcome, String>, Vec<Sample>) {
        let mut samples = Vec::new();
        let out = client().run(r, &|d| {
            thread::sleep(d);
            true
        }, &mut |s| samples.push(s));
        (out, samples)
    }

    #[test]
    fn tcp_both_ways_against_our_server() {
        let (port, srv) = server(Limits::default(), 1);
        let (out, samples) = run(&req(port, Proto::Tcp, Direction::Both, 200_000_000, 2));
        let o = out.unwrap();
        let up = o.upload.unwrap();
        let down = o.download.unwrap();
        // Paced at 200 Mbit/s per stream, two streams each way.
        let rate = |w: &Way| w.received as f64 * 8.0 / w.secs;
        assert!((300e6..440e6).contains(&rate(&up)), "up {}", rate(&up));
        assert!((300e6..440e6).contains(&rate(&down)), "down {}", rate(&down));
        assert!(up.received <= up.sent && up.received > up.sent * 9 / 10);
        assert!(samples.len() >= 2, "one sample a second");
        assert!(o.server_output.unwrap().contains("tcp both from 127.0.0.1, 2 stream(s)"));
        let served = srv.join().unwrap();
        assert!(served[0].is_ok(), "{served:?}");
    }

    #[test]
    fn udp_receive_counts_loss_and_jitter() {
        let (port, srv) = server(Limits::default(), 1);
        let (out, samples) = run(&req(port, Proto::Udp, Direction::Receive, 20_000_000, 1));
        let o = out.unwrap();
        let down = o.download.unwrap();
        assert!(o.upload.is_none());
        let packets = down.packets.unwrap();
        // 20 Mbit/s of 1400-byte datagrams for 2 s ≈ 3571.
        assert!((3000..4200).contains(&packets), "{packets}");
        assert!(down.lost.unwrap() < packets / 20, "loopback barely loses: {:?}", down.lost);
        assert!(down.jitter_ms.unwrap() < 5.0);
        assert!(samples.iter().all(|s| s.packets.is_some()));
        assert!(srv.join().unwrap()[0].is_ok());
    }

    #[test]
    fn udp_send_gets_the_far_ends_numbers() {
        let (port, srv) = server(Limits::default(), 1);
        let (out, _) = run(&req(port, Proto::Udp, Direction::Send, 10_000_000, 2));
        let up = out.unwrap().upload.unwrap();
        assert!(up.packets.unwrap() > 2500, "{up:?}");
        assert!(up.received > 0 && up.received <= up.sent);
        assert!(srv.join().unwrap()[0].is_ok());
    }

    /// Several UDP streams: each one's datagram comes right after the
    /// previous reply. The server binds the next listener before replying
    /// (and the first before CREATE_STREAMS); before that fix the client
    /// could hit a port with no socket and get "Connection refused" (flaky
    /// under `cargo xtask ci`, 2026-10-28).
    #[test]
    fn udp_with_several_streams_never_hits_a_closed_port() {
        for _ in 0..5 {
            let (port, srv) = server(Limits::default(), 1);
            let mut r = req(port, Proto::Udp, Direction::Send, 1_000_000, 4);
            r.params.time = 1;
            let (out, _) = run(&r);
            let up = out.unwrap().upload.unwrap();
            assert!(up.received > 0, "{up:?}");
            assert!(srv.join().unwrap()[0].is_ok());
        }
    }

    #[test]
    fn the_server_refuses_what_its_limits_forbid() {
        let limits = Limits { max_duration: 1, max_streams: 1, max_rate: Some(1_000_000) };
        let (port, srv) = server(limits, 1);
        let (out, _) = run(&req(port, Proto::Tcp, Direction::Send, 0, 1));
        let e = out.unwrap_err();
        assert!(e.contains("longer than the server allows"), "{e}");
        let served = srv.join().unwrap();
        assert!(served[0].as_ref().unwrap_err().contains("refused"));
    }

    #[test]
    fn a_busy_server_denies() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            deny(c);
        });
        let (out, _) = run(&req(port, Proto::Tcp, Direction::Send, 0, 1));
        assert!(out.unwrap_err().contains("busy"));
        t.join().unwrap();
    }

    /// The `iperf3` binary, when installed (`sudo apt install iperf3`).
    fn iperf3() -> Option<std::path::PathBuf> {
        std::env::var_os("PATH")?
            .to_str()?
            .split(':')
            .map(|d| std::path::Path::new(d).join("iperf3"))
            .find(|p| p.is_file())
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    /// Our client against `iperf3 -s`, every protocol and direction.
    #[test]
    fn interop_our_client_with_iperf3_server() {
        let Some(bin) = iperf3() else {
            eprintln!("skipped: iperf3 not installed (sudo apt install iperf3)");
            return;
        };
        for (proto, dir) in [
            (Proto::Tcp, Direction::Send),
            (Proto::Tcp, Direction::Receive),
            (Proto::Tcp, Direction::Both),
            (Proto::Udp, Direction::Send),
            (Proto::Udp, Direction::Receive),
        ] {
            let port = free_port();
            let mut srv = std::process::Command::new(&bin)
                .args(["-s", "-1", "-B", "127.0.0.1", "-p", &port.to_string()])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap();
            thread::sleep(Duration::from_millis(300));
            let (out, samples) = run(&req(port, proto, dir, 50_000_000, 2));
            let o = out.unwrap_or_else(|e| panic!("{proto:?} {dir:?}: {e}"));
            for w in [&o.upload, &o.download].into_iter().flatten() {
                assert!(w.received > 0 && w.sent > 0, "{proto:?} {dir:?}: {w:?}");
            }
            assert!(o.remote_cpu.is_some());
            assert!(!samples.is_empty());
            let _ = srv.wait();
        }
    }

    /// `iperf3 -c` against our server.
    #[test]
    fn interop_iperf3_client_with_our_server() {
        let Some(bin) = iperf3() else {
            eprintln!("skipped: iperf3 not installed (sudo apt install iperf3)");
            return;
        };
        for args in [vec!["-t", "1"], vec!["-t", "1", "-R"], vec!["-t", "1", "--bidir"], vec!["-t", "1", "-u", "-b", "20M"], vec!["-t", "1", "-u", "-b", "20M", "-R", "-P", "2"]] {
            let (port, srv) = server(Limits::default(), 1);
            let out = std::process::Command::new(&bin)
                .args(["-c", "127.0.0.1", "-p", &port.to_string(), "-J", "--get-server-output"])
                .args(&args)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "iperf3 {args:?}: {text}");
            let v: Value = serde_json::from_str(&text).unwrap();
            assert!(v.get("error").is_none(), "iperf3 {args:?}: {}", v["error"]);
            let end = &v["end"];
            let bytes = end["sum_received"]["bytes"].as_u64().or(end["sum"]["bytes"].as_u64()).unwrap_or(0);
            assert!(bytes > 0, "iperf3 {args:?}: {end}");
            assert!(srv.join().unwrap()[0].is_ok());
        }
    }

    #[test]
    fn cookies_are_random_and_valid() {
        let (a, b) = (random_cookie(), random_cookie());
        assert!(iperf::cookie_is_valid(&a) && iperf::cookie_is_valid(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn cpu_meter_reads_proc_stat() {
        let mut m = CpuMeter::default();
        assert_eq!(m.sample(), None);
        thread::sleep(Duration::from_millis(50));
        let c = m.sample().unwrap_or(0.0);
        assert!((0.0..=100.0).contains(&c));
    }
}
