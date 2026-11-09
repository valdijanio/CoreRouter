//! NTP server (G4.6c, `/system ntp server`): answers the LAN's clients (mode
//! 4) only while this router's clock is good, from the allowed networks, under
//! a per-source rate limit (`corerouter_proto_ntp::server`, docs/ntp.md).
//!
//! Off by default. What is asked of a packet, cheapest first: an address no
//! reply can go to, the allowed list (silence, also the default for a WAN
//! address), the header, the clock, the rate.
//!
//! Threads (`workers`): one `SO_REUSEPORT` socket per reader, each with its
//! rate table and counters, so a packet takes no lock and shares no cache line
//! (docs/perf.md, G4.6c). Nothing here holds the session lock per packet: the
//! main loop copies the config and the client's status once per [`TICK`] and
//! publishes a new [`View`]; a reader sees that through one relaxed atomic.

use std::collections::hash_map::RandomState;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};
use corerouter_model::ntp::{
    ClockState, NtpServer, NtpServerStats, NtpServing, NtpState, NtpStatus,
};
use corerouter_model::service::Listen;
use corerouter_proto_ntp::discipline::STEP_NANOS;
use corerouter_proto_ntp::server::{
    self, Limit, RATE_SLOTS, RateLimiter, Refused, SystemVars,
};
use ipnet::IpNet;

/// How often the main loop looks at the config and the client.
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(1)
};
/// How long a reader waits for a datagram before looking at the stop flag.
const POLL: Duration = Duration::from_millis(200);
/// Longer than a header plus any extension fields worth reading: the rest is
/// cut by the kernel and only the header is used.
const MAX_REQUEST: usize = 1024;
/// Receive buffer of each socket: a burst waits here, not in the void.
#[cfg(target_os = "linux")]
const RCVBUF: usize = 1 << 20;
/// RFC 5905 Figure 6: MINDISP = 5 ms, the least a server may claim.
const MIN_DISPERSION_NANOS: i64 = 5_000_000;
/// The precision reported: about 1 µs, what a read of the clock costs and
/// what a kernel timestamp of a packet can tell apart (**estimado**).
const PRECISION: i8 = -20;
/// Broadcast every 2^6 s, ntpd's default.
const BROADCAST_POLL: i8 = 6;
/// "LOCL": RFC 5905 Figure 12's name for an uncalibrated local clock.
const REFID_LOCAL: [u8; 4] = *b"LOCL";

/// Readers per socket family: half the cores, 1 to 4 (docs/perf.md, G4.6c).
fn default_readers() -> usize {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    (cores / 2).clamp(1, 4)
}

fn unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0)
}

/// What the readers need to decide, replaced as a whole.
#[derive(Debug, Clone, Default, PartialEq)]
struct View {
    serve: Option<SystemVars>,
    allowed: Vec<IpNet>,
    /// Never answer to these: they are configured broadcast addresses, and
    /// one socket holds `SO_BROADCAST`.
    no_reply: Vec<IpAddr>,
    rate_limit: bool,
}

impl View {
    fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allowed.iter().any(|n| n.contains(&ip))
    }
}

/// One reader's counters, on a cache line of its own.
#[derive(Default)]
#[repr(align(64))]
struct Counters {
    requests: AtomicU64,
    replies: AtomicU64,
    kisses: AtomicU64,
    denied: AtomicU64,
    limited: AtomicU64,
    malformed: AtomicU64,
    unsynchronized: AtomicU64,
}

/// What readers and the main loop share.
struct Board {
    generation: AtomicU64,
    view: Mutex<Arc<View>>,
    stop: AtomicBool,
}

impl Board {
    fn new(view: View) -> Self {
        Self {
            generation: AtomicU64::new(1),
            view: Mutex::new(Arc::new(view)),
            stop: AtomicBool::new(false),
        }
    }

    fn publish(&self, view: View) {
        *self.view.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(view);
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn read(&self) -> Arc<View> {
        self.view.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

/// The verdict on one datagram, with every outcome counted.
fn answer(
    bytes: &[u8],
    from: SocketAddr,
    view: &View,
    limiter: &mut RateLimiter<RandomState>,
    steady_ms: u64,
    rx_nanos: i128,
    now: &dyn Fn() -> i128,
    counters: &Counters,
) -> Option<[u8; corerouter_proto_ntp::HEADER_LEN]> {
    let c = |counter: &AtomicU64| {
        counter.fetch_add(1, Ordering::Relaxed);
    };
    let ip = from.ip();
    if server::bad_source(ip, from.port()) || view.no_reply.contains(&ip) {
        c(&counters.malformed);
        return None;
    }
    if !view.allows(ip) {
        c(&counters.denied);
        return None;
    }
    let request = match server::parse_request(bytes) {
        Ok(r) => r,
        Err(Refused::Malformed | Refused::NotARequest | Refused::Version | Refused::NoTimestamp) => {
            c(&counters.malformed);
            return None;
        }
    };
    c(&counters.requests);
    let tx = now();
    let Some(sys) = view.serve.as_ref().filter(|s| s.usable_at(tx)) else {
        c(&counters.unsynchronized);
        return None;
    };
    let verdict = if view.rate_limit {
        limiter.check(ip, steady_ms)
    } else {
        Limit::Allow
    };
    match verdict {
        Limit::Allow => {
            c(&counters.replies);
            Some(server::reply(&request, sys, rx_nanos, now()).encode())
        }
        Limit::Kiss => {
            c(&counters.kisses);
            Some(server::kiss(&request, b"RATE", rx_nanos, now()).encode())
        }
        Limit::Silent => {
            c(&counters.limited);
            None
        }
    }
}

fn reader(sock: Arc<sock::Udp>, board: Arc<Board>, counters: Arc<Counters>) {
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut limiter = RateLimiter::new(RATE_SLOTS, RandomState::new());
    let mut seen = 0u64;
    let mut view = Arc::new(View::default());
    // The limiter runs on this: a step of the wall clock must not limit or
    // forgive anyone.
    let start = Instant::now();
    while !board.stop.load(Ordering::Relaxed) {
        let got = sock.recv(&mut buf);
        let now_generation = board.generation.load(Ordering::Acquire);
        if now_generation != seen {
            view = board.read();
            seen = now_generation;
        }
        let (n, from, local, stamp) = match got {
            Ok(got) => got,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => {
                log::debug!("NTP server: read: {e}");
                continue;
            }
        };
        let steady_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let rx = stamp.unwrap_or_else(unix_nanos);
        let bytes = buf.get(..n).unwrap_or_default();
        if let Some(out) = answer(bytes, from, &view, &mut limiter, steady_ms, rx, &unix_nanos, &counters) {
            sock.send(&out, from, local);
        }
    }
}

/// The readers of one set of sockets, stopped as a whole.
struct Open {
    board: Arc<Board>,
    counters: Vec<Arc<Counters>>,
    /// Holds `SO_BROADCAST` when asked; source of the broadcasts.
    first_v4: Option<Arc<sock::Udp>>,
    listen: Vec<Listen>,
    vrf: String,
    broadcast_socket: bool,
}

impl Open {
    fn close(&self) {
        self.board.stop.store(true, Ordering::Relaxed);
    }
}

fn open(
    cfg: &NtpServer,
    port: u16,
    readers: usize,
    view: View,
    health: &super::Health,
) -> Result<Open, String> {
    let board = Arc::new(Board::new(view));
    let mut counters = Vec::new();
    let mut listen = Vec::new();
    let mut first_v4 = None;
    let addrs: [(IpAddr, bool); 2] = [
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), true),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), false),
    ];
    let mut opened = 0usize;
    let mut error = None;
    for (ip, is_v4) in addrs {
        let addr = SocketAddr::new(ip, port);
        for i in 0..readers {
            let udp = match sock::Udp::bind(addr, &cfg.vrf) {
                Ok(u) => Arc::new(u),
                Err(e) => {
                    if is_v4 {
                        error = Some(format!("cannot listen on {addr}: {e}"));
                    } else {
                        log::info!("NTP server: no IPv6 listener on {addr}: {e}");
                    }
                    break;
                }
            };
            if is_v4 && i == 0 {
                if cfg.broadcast
                    && let Err(e) = udp.set_broadcast()
                {
                    log::warn!("NTP server: no broadcast: {e}");
                }
                first_v4 = Some(udp.clone());
            }
            if i == 0 {
                listen.push(Listen::new("udp", addr));
            }
            let c = Arc::new(Counters::default());
            counters.push(c.clone());
            let (s, b) = (udp, board.clone());
            let spawned = health.spawn(&format!("ntp-srv-{i}"), move || reader(s, b, c));
            if let Err(e) = spawned {
                error = Some(format!("cannot start a reader: {e}"));
            }
            opened += 1;
        }
    }
    if let Some(e) = error.filter(|_| first_v4.is_none()) {
        board.stop.store(true, Ordering::Relaxed);
        return Err(e);
    }
    if opened == 0 {
        return Err("no socket opened".into());
    }
    Ok(Open {
        board,
        counters,
        first_v4,
        listen,
        vrf: cfg.vrf.clone(),
        broadcast_socket: cfg.broadcast,
    })
}

/// The system variables from a good report of the client, RFC 5905 §11.2.
/// `None` when the report says nothing good about the clock.
fn upstream_vars(st: &NtpStatus) -> Option<SystemVars> {
    let stratum = st.synced_stratum?.checked_add(1).filter(|s| *s < 16)?;
    let address: IpAddr = st.synced_address.as_deref()?.parse().ok()?;
    let reference = i128::from(st.last_sync?).saturating_mul(1_000_000_000);
    let ms = |v: Option<f64>| (v.unwrap_or(0.0) * 1e6) as i64;
    let offset = ms(st.system_offset_ms).saturating_abs();
    // A clock that was measured and not corrected is as far off as measured.
    let uncorrected = match st.clock {
        ClockState::Slewing | ClockState::NotSet => offset,
        _ => 0,
    };
    Some(SystemVars {
        leap: st.leap.unwrap_or(0) & 3,
        stratum,
        precision: PRECISION,
        root_delay_nanos: ms(st.root_delay_ms).saturating_add(ms(st.round_trip_ms).max(0)),
        root_dispersion_nanos: ms(st.root_dispersion_ms)
            .saturating_add(uncorrected)
            .saturating_add(MIN_DISPERSION_NANOS),
        reference_id: server::reference_id_of(address),
        reference_nanos: reference,
        ages: true,
    })
}

/// Which clock to serve, and how the last good one carries over. RFC 5905
/// §11.2: a client that lost its servers keeps serving as the dispersion
/// grows, until [`SystemVars::usable_at`] says no.
#[derive(Debug, Default)]
struct Holdover(Option<SystemVars>);

impl Holdover {
    fn decide(&mut self, st: &NtpStatus, cfg: &NtpServer, now: i128) -> Option<SystemVars> {
        match (st.status, st.clock) {
            (NtpState::Stopped, _) => self.0 = None,
            // A question to the operator or a refused answer: the clock is
            // not known to be good, whatever it was before.
            (_, ClockState::AwaitingConfirmation | ClockState::Refused) => self.0 = None,
            // One odd answer in a good clock: keep the old state.
            (NtpState::Synchronized, ClockState::HoldingSpike) => {}
            // Only measuring and already far off: that is not a good clock.
            (NtpState::Synchronized, ClockState::NotSet)
                if st
                    .system_offset_ms
                    .is_none_or(|o| o.abs() * 1e6 >= STEP_NANOS as f64) =>
            {
                self.0 = None;
            }
            (NtpState::Synchronized, _) => self.0 = upstream_vars(st),
            _ => {}
        }
        if let Some(v) = self.0.filter(|v| v.usable_at(now)) {
            return Some(v);
        }
        cfg.use_local_clock.then_some(SystemVars {
            leap: 0,
            stratum: cfg.local_clock_stratum.clamp(1, 15),
            precision: PRECISION,
            root_delay_nanos: 0,
            root_dispersion_nanos: MIN_DISPERSION_NANOS,
            reference_id: REFID_LOCAL,
            reference_nanos: now,
            ages: false,
        })
    }
}

fn run(session: &Shared, port: u16, readers: usize, health: &super::Health) -> Result<(), String> {
    let mut opened: Option<Open> = None;
    let mut holdover = Holdover::default();
    let mut last_view: Option<View> = None;
    let mut last_stats: Option<NtpServerStats> = None;
    let mut retry = Instant::now();
    let mut next_broadcast = Instant::now();
    loop {
        health.beat();
        if health.stopping() {
            if let Some(o) = &opened {
                o.close();
            }
            return Ok(());
        }
        let (cfg, status) = {
            let s = lock(session);
            (s.store().running().system.ntp_server.clone(), s.ntp_status())
        };
        let mut stats = NtpServerStats::default();
        if cfg.enabled {
            health.disabled(None);
            let now = unix_nanos();
            let serve = holdover.decide(&status, &cfg, now);
            let view = View {
                serve,
                allowed: cfg.allowed.clone(),
                no_reply: if cfg.broadcast {
                    cfg.broadcast_addresses.clone()
                } else {
                    Vec::new()
                },
                rate_limit: cfg.rate_limit,
            };
            // A new VRF or broadcast switch needs other sockets.
            let stale = opened
                .as_ref()
                .is_some_and(|o| o.vrf != cfg.vrf || o.broadcast_socket != cfg.broadcast);
            if stale {
                if let Some(o) = opened.take() {
                    o.close();
                }
                last_view = None;
            }
            if opened.is_none() && Instant::now() >= retry {
                match open(&cfg, port, readers, view.clone(), health) {
                    Ok(o) => {
                        health.listen(o.listen.clone());
                        health.clear_error();
                        last_view = Some(view.clone());
                        opened = Some(o);
                    }
                    Err(e) => {
                        health.error(&e);
                        stats.last_error = Some(e);
                        retry = Instant::now() + Duration::from_secs(5);
                    }
                }
            }
            if let Some(o) = &opened {
                if last_view.as_ref() != Some(&view) {
                    o.board.publish(view.clone());
                    last_view = Some(view.clone());
                }
                if cfg.broadcast
                    && Instant::now() >= next_broadcast
                    && let (Some(sys), Some(sock)) = (view.serve.as_ref(), &o.first_v4)
                {
                    next_broadcast = Instant::now() + Duration::from_secs(1 << BROADCAST_POLL);
                    let packet = server::broadcast(sys, BROADCAST_POLL, unix_nanos()).encode();
                    for ip in &cfg.broadcast_addresses {
                        sock.send(&packet, SocketAddr::new(*ip, port), None);
                    }
                }
                stats.listening = true;
                for c in &o.counters {
                    let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
                    stats.requests += n(&c.requests);
                    stats.replies += n(&c.replies);
                    stats.kisses += n(&c.kisses);
                    stats.denied += n(&c.denied);
                    stats.limited += n(&c.limited);
                    stats.malformed += n(&c.malformed);
                    stats.unsynchronized += n(&c.unsynchronized);
                }
            }
            stats.serving = match &view.serve {
                None => NtpServing::No,
                Some(v) if v.reference_id == REFID_LOCAL => NtpServing::LocalClock,
                Some(_) => NtpServing::Upstream,
            };
            stats.stratum = view.serve.map(|v| v.stratum);
        } else {
            health.disabled(Some("system.ntp.server enabled=no"));
            if let Some(o) = opened.take() {
                o.close();
                health.listen(Vec::new());
            }
            holdover = Holdover::default();
            last_view = None;
        }
        if last_stats.as_ref() != Some(&stats) {
            lock(session).set_ntp_server_stats(stats.clone());
            last_stats = Some(stats);
        }
        if !health.sleep(TICK) {
            if let Some(o) = &opened {
                o.close();
            }
            return Ok(());
        }
    }
}

/// Configured with `system.ntp.server.*`; the flag is for measuring.
pub(crate) const SERVICE: super::Service = super::Service {
    name: "ntp-server",
    flags: &[super::Flag {
        name: "--ntp-server-readers",
        value: Some("<n>"),
        help: "Threads answering NTP per address family, 1..=64\n(default half the cores, 1 to 4).",
    }],
    topic: "ntp",
    enable: "system.ntp.server.set enabled=yes",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let readers = match ctx.flag("--ntp-server-readers") {
        Some(v) => v
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=64).contains(n))
            .ok_or_else(|| format!("--ntp-server-readers {v}: expected 1..=64"))?,
        None => default_readers(),
    };
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, corerouter_proto_ntp::PORT, readers, health)
    }))
}

/// Linux: the destination address of each request (the reply goes out from
/// it, or a client that `connect`ed drops it), the kernel's receive time, a
/// socket per reader and the VRF. `nix` and `socket2`, no `unsafe`.
#[cfg(target_os = "linux")]
mod sock {
    use std::io::{IoSlice, IoSliceMut};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;

    use nix::libc;
    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage,
        recvmsg, sendmsg, setsockopt, sockopt,
    };

    use super::{POLL, RCVBUF};
    use corerouter_model::ntp::MAIN_VRF;

    pub(super) struct Udp {
        sock: UdpSocket,
        v6: bool,
    }

    fn nix_io(e: nix::Error) -> std::io::Error {
        std::io::Error::from_raw_os_error(e as i32)
    }

    impl Udp {
        pub(super) fn bind(addr: SocketAddr, vrf: &str) -> std::io::Result<Self> {
            use socket2::{Domain, Protocol, Socket, Type};
            let v6 = addr.is_ipv6();
            let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
            let s = Socket::new(domain, Type::DGRAM.cloexec(), Some(Protocol::UDP))?;
            s.set_reuse_port(true)?;
            if vrf != MAIN_VRF {
                s.bind_device(Some(vrf.as_bytes()))?;
            }
            let _ = s.set_recv_buffer_size(RCVBUF);
            if v6 {
                s.set_only_v6(true)?;
                setsockopt(&s, sockopt::Ipv6RecvPacketInfo, &true).map_err(nix_io)?;
            } else {
                setsockopt(&s, sockopt::Ipv4PacketInfo, &true).map_err(nix_io)?;
            }
            setsockopt(&s, sockopt::ReceiveTimestampns, &true).map_err(nix_io)?;
            s.bind(&addr.into())?;
            let sock: UdpSocket = s.into();
            sock.set_read_timeout(Some(POLL))?;
            Ok(Self { sock, v6 })
        }

        pub(super) fn set_broadcast(&self) -> std::io::Result<()> {
            self.sock.set_broadcast(true)
        }

        /// One datagram: length, client, the address it was sent to, and when
        /// the kernel received it.
        #[allow(clippy::type_complexity)]
        pub(super) fn recv(
            &self,
            buf: &mut [u8],
        ) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>, Option<i128>)> {
            let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo, libc::timespec);
            let mut iov = [IoSliceMut::new(buf)];
            let msg = recvmsg::<SockaddrStorage>(
                self.sock.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .map_err(nix_io)?;
            let mut local = None;
            let mut stamp = None;
            for c in msg.cmsgs().map_err(nix_io)? {
                match c {
                    ControlMessageOwned::Ipv4PacketInfo(i) => {
                        local = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(i.ipi_addr.s_addr))));
                    }
                    ControlMessageOwned::Ipv6PacketInfo(i) => {
                        local = Some(IpAddr::V6(Ipv6Addr::from(i.ipi6_addr.s6_addr)));
                    }
                    ControlMessageOwned::ScmTimestampns(t) => {
                        stamp = Some(
                            i128::from(t.tv_sec()) * 1_000_000_000 + i128::from(t.tv_nsec()),
                        );
                    }
                    _ => {}
                }
            }
            let from = msg.address.as_ref().and_then(|a| {
                a.as_sockaddr_in()
                    .map(|v4| SocketAddr::from((v4.ip(), v4.port())))
                    .or_else(|| {
                        a.as_sockaddr_in6()
                            .map(|v6| SocketAddr::from((v6.ip(), v6.port())))
                    })
            });
            let from = from.ok_or_else(|| std::io::Error::other("datagram without a source"))?;
            Ok((msg.bytes, from, local, stamp))
        }

        pub(super) fn send(&self, bytes: &[u8], to: SocketAddr, local: Option<IpAddr>) {
            let iov = [IoSlice::new(bytes)];
            let sent = match (to, local) {
                (SocketAddr::V4(dst), Some(IpAddr::V4(src))) if !self.v6 => {
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from(src).to_be(),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    sendmsg(
                        self.sock.as_raw_fd(),
                        &iov,
                        &[ControlMessage::Ipv4PacketInfo(&info)],
                        MsgFlags::empty(),
                        Some(&SockaddrIn::from(dst)),
                    )
                }
                (SocketAddr::V6(dst), Some(IpAddr::V6(src))) if self.v6 => {
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: src.octets(),
                        },
                        ipi6_ifindex: 0,
                    };
                    sendmsg(
                        self.sock.as_raw_fd(),
                        &iov,
                        &[ControlMessage::Ipv6PacketInfo(&info)],
                        MsgFlags::empty(),
                        Some(&SockaddrIn6::from(dst)),
                    )
                }
                _ => self
                    .sock
                    .send_to(bytes, to)
                    .map_err(|e| nix::Error::from_raw(e.raw_os_error().unwrap_or(0))),
            };
            if let Err(e) = sent {
                log::debug!("NTP server: reply to {to} not sent: {e}");
            }
        }
    }
}

/// Elsewhere (the daemon on macOS/Windows runs the virtual lab): plain
/// `std::net`, from whatever address the system picks, with no VRF.
#[cfg(not(target_os = "linux"))]
mod sock {
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    use super::POLL;

    pub(super) struct Udp {
        sock: UdpSocket,
    }

    impl Udp {
        pub(super) fn bind(addr: SocketAddr, _vrf: &str) -> std::io::Result<Self> {
            let sock = UdpSocket::bind(addr)?;
            sock.set_read_timeout(Some(POLL))?;
            Ok(Self { sock })
        }

        pub(super) fn set_broadcast(&self) -> std::io::Result<()> {
            self.sock.set_broadcast(true)
        }

        #[allow(clippy::type_complexity)]
        pub(super) fn recv(
            &self,
            buf: &mut [u8],
        ) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>, Option<i128>)> {
            let (n, from) = self.sock.recv_from(buf)?;
            Ok((n, from, None, None))
        }

        pub(super) fn send(&self, bytes: &[u8], to: SocketAddr, _local: Option<IpAddr>) {
            if let Err(e) = self.sock.send_to(bytes, to) {
                log::debug!("NTP server: reply to {to} not sent: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_proto_ntp::{MODE_CLIENT, MODE_SERVER, Packet, Timestamp, check_reply};
    use serde_json::json;
    use std::net::UdpSocket;

    const NANOS: i128 = 1_000_000_000;
    const T: i128 = 1_794_000_000 * NANOS;

    fn view() -> View {
        View {
            serve: Some(sys()),
            allowed: corerouter_model::ntp::default_allowed(),
            no_reply: Vec::new(),
            rate_limit: true,
        }
    }

    fn sys() -> SystemVars {
        SystemVars {
            leap: 0,
            stratum: 3,
            precision: PRECISION,
            root_delay_nanos: 1_000_000,
            root_dispersion_nanos: 1_000_000,
            reference_id: [192, 0, 2, 1],
            reference_nanos: T,
            ages: true,
        }
    }

    fn ask(
        v: &View,
        limiter: &mut RateLimiter<RandomState>,
        from: &str,
        bytes: &[u8],
    ) -> (Option<Packet>, Counters) {
        let c = Counters::default();
        let out = answer(
            bytes,
            from.parse().unwrap(),
            v,
            limiter,
            1000,
            T,
            &|| T + 1000,
            &c,
        );
        (out.map(|b| Packet::decode(&b).unwrap()), c)
    }

    fn limiter() -> RateLimiter<RandomState> {
        RateLimiter::new(64, RandomState::new())
    }

    fn request() -> [u8; 48] {
        Packet::client_request(Timestamp::from_unix_nanos(T)).encode()
    }

    #[test]
    fn allowed_source_gets_a_reply() {
        let (r, c) = ask(&view(), &mut limiter(), "192.168.88.2:40000", &request());
        let r = r.unwrap();
        assert_eq!(r.mode, MODE_SERVER);
        assert_eq!(r.stratum, 3);
        assert_eq!(c.replies.load(Ordering::Relaxed), 1);
    }

    /// RFC 8633 §5.1: a public source gets silence, by default.
    #[test]
    fn a_public_source_gets_silence() {
        let (r, c) = ask(&view(), &mut limiter(), "8.8.8.8:40000", &request());
        assert!(r.is_none());
        assert_eq!(c.denied.load(Ordering::Relaxed), 1);
        // A mapped address does not get around the list.
        let (r, _) = ask(&view(), &mut limiter(), "[::ffff:8.8.8.8]:40000", &request());
        assert!(r.is_none());
        let (r, _) = ask(&view(), &mut limiter(), "[::ffff:192.168.1.1]:40000", &request());
        assert!(r.is_some());
    }

    /// Only after synchronizing: silence, not an unsynchronized reply.
    #[test]
    fn no_clock_no_answer() {
        let v = View {
            serve: None,
            ..view()
        };
        let (r, c) = ask(&v, &mut limiter(), "192.168.88.2:40000", &request());
        assert!(r.is_none());
        assert_eq!(c.unsynchronized.load(Ordering::Relaxed), 1);
    }

    /// RFC 9327 §6: mode 6 and 7 are dropped, and answer nothing.
    #[test]
    fn control_modes_get_nothing() {
        for mode in [6u8, 7] {
            let mut p = Packet::client_request(Timestamp::from_unix_nanos(T));
            p.mode = mode;
            let (r, c) = ask(&view(), &mut limiter(), "192.168.88.2:40000", &p.encode());
            assert!(r.is_none());
            assert_eq!(c.malformed.load(Ordering::Relaxed), 1);
        }
        let (r, _) = ask(&view(), &mut limiter(), "192.168.88.2:0", &request());
        assert!(r.is_none(), "port 0");
    }

    #[test]
    fn a_configured_broadcast_address_is_never_answered() {
        let v = View {
            no_reply: vec!["192.168.88.255".parse().unwrap()],
            ..view()
        };
        let (r, _) = ask(&v, &mut limiter(), "192.168.88.255:40000", &request());
        assert!(r.is_none());
    }

    #[test]
    fn a_flood_ends_in_a_kiss_and_silence_and_the_switch_turns_it_off() {
        let v = view();
        let mut l = limiter();
        let mut kisses = 0;
        let mut replies = 0;
        let mut silence = 0;
        for _ in 0..50 {
            match ask(&v, &mut l, "192.168.88.2:40000", &request()).0 {
                Some(p) if p.stratum == 0 => {
                    assert_eq!(p.kiss_code().as_deref(), Some("RATE"));
                    kisses += 1;
                }
                Some(_) => replies += 1,
                None => silence += 1,
            }
        }
        assert_eq!((replies, kisses, silence), (16, 1, 33));
        let free = View {
            rate_limit: false,
            ..view()
        };
        let mut l = limiter();
        for _ in 0..50 {
            let p = ask(&free, &mut l, "192.168.88.2:40000", &request()).0.unwrap();
            assert_eq!(p.stratum, 3);
        }
    }

    fn status() -> NtpStatus {
        NtpStatus {
            status: NtpState::Synchronized,
            synced_stratum: Some(2),
            synced_address: Some("192.0.2.9".into()),
            synced_server: Some("s".into()),
            last_sync: Some(1_794_000_000),
            system_offset_ms: Some(1.0),
            round_trip_ms: Some(10.0),
            root_delay_ms: Some(20.0),
            root_dispersion_ms: Some(3.0),
            clock: ClockState::Slewing,
            ..NtpStatus::default()
        }
    }

    /// RFC 5905 §11.2: stratum + 1, delays add up, the source is the refid.
    #[test]
    fn the_header_comes_from_the_source() {
        let v = upstream_vars(&status()).unwrap();
        assert_eq!(v.stratum, 3);
        assert_eq!(v.reference_id, [192, 0, 2, 9]);
        assert_eq!(v.root_delay_nanos, 30_000_000);
        assert_eq!(v.root_dispersion_nanos, 3_000_000 + 1_000_000 + 5_000_000);
        // Stratum 15 upstream: we would be 16, which is nobody.
        let far = NtpStatus {
            synced_stratum: Some(15),
            ..status()
        };
        assert!(upstream_vars(&far).is_none());
    }

    #[test]
    fn serving_follows_the_clock() {
        let cfg = NtpServer::default();
        let mut h = Holdover::default();
        // Never synchronized: silence.
        let waiting = NtpStatus {
            status: NtpState::Waiting,
            ..NtpStatus::default()
        };
        assert!(h.decide(&waiting, &cfg, T).is_none());
        // Synchronized: serves.
        assert_eq!(h.decide(&status(), &cfg, T).unwrap().stratum, 3);
        // Lost the servers: holdover, while the dispersion is believable.
        assert!(h.decide(&waiting, &cfg, T + 3600 * NANOS).is_some());
        assert!(h.decide(&waiting, &cfg, T + 100_000 * NANOS).is_none(), "past MAXDIST");
        // A spike in a good clock keeps what it had.
        let mut h = Holdover::default();
        h.decide(&status(), &cfg, T);
        let spike = NtpStatus {
            clock: ClockState::HoldingSpike,
            synced_stratum: Some(9),
            ..status()
        };
        assert_eq!(h.decide(&spike, &cfg, T).unwrap().stratum, 3);
        // A jump the operator must confirm: the clock is in doubt, silence.
        let panic = NtpStatus {
            clock: ClockState::AwaitingConfirmation,
            ..status()
        };
        assert!(h.decide(&panic, &cfg, T).is_none());
        // Only measuring: served only if the clock is close.
        let mut h = Holdover::default();
        let close = NtpStatus {
            clock: ClockState::NotSet,
            ..status()
        };
        assert!(h.decide(&close, &cfg, T).is_some());
        let far = NtpStatus {
            clock: ClockState::NotSet,
            system_offset_ms: Some(5000.0),
            ..status()
        };
        assert!(h.decide(&far, &cfg, T).is_none());
    }

    #[test]
    fn the_local_clock_is_the_fallback_at_its_stratum() {
        let cfg = NtpServer {
            use_local_clock: true,
            local_clock_stratum: 7,
            ..NtpServer::default()
        };
        let mut h = Holdover::default();
        let waiting = NtpStatus {
            status: NtpState::UsingLocalClock,
            ..NtpStatus::default()
        };
        let v = h.decide(&waiting, &cfg, T).unwrap();
        assert_eq!(v.stratum, 7);
        assert_eq!(v.reference_id, *b"LOCL");
        assert!(v.usable_at(T + 1_000_000 * NANOS), "never ages");
        // A real source wins.
        assert_eq!(h.decide(&status(), &cfg, T).unwrap().stratum, 3);
    }

    fn spawned(session: Shared, port: u16) -> super::super::Health {
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        let h = health.clone();
        std::thread::spawn(move || {
            let _ = run(&session, port, 2, &h);
        });
        health
    }

    fn free_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn query(port: u16) -> Result<Packet, String> {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let sent = Timestamp::from_unix_nanos(unix_nanos());
        sock.send(&Packet::client_request(sent).encode()).unwrap();
        let mut buf = [0u8; 128];
        let n = sock.recv(&mut buf).map_err(|e| e.to_string())?;
        let p = Packet::decode(&buf[..n]).map_err(|e| e.to_string())?;
        assert_eq!(p.origin, sent);
        check_reply(sent, &p).map_err(|e| e.to_string())?;
        Ok(p)
    }

    fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {what}");
    }

    /// The whole service on a free port: off, silent while unsynchronized,
    /// serving the local clock, then the client's time; counters report.
    #[test]
    fn the_service_answers_only_when_it_should() {
        let port = free_port();
        let session = shared(Session::virtual_lab());
        let health = spawned(session.clone(), port);
        std::thread::sleep(TICK * 2);
        assert!(query(port).is_err(), "off by default");
        assert!(!lock(&session).ntp_server_stats().listening);

        lock(&session)
            .execute("system.ntp.server.set", &json!({"enabled": true}))
            .unwrap();
        wait_for("listening", || lock(&session).ntp_server_stats().listening);
        assert!(query(port).is_err(), "not synchronized: silence");
        wait_for("the count", || lock(&session).ntp_server_stats().unsynchronized >= 1);
        assert_eq!(lock(&session).ntp_server_stats().serving, NtpServing::No);

        lock(&session)
            .execute(
                "system.ntp.server.set",
                &json!({"use_local_clock": true, "local_clock_stratum": 9}),
            )
            .unwrap();
        wait_for("the local clock", || query(port).is_ok_and(|p| p.stratum == 9));
        wait_for("the state", || {
            lock(&session).ntp_server_stats().serving == NtpServing::LocalClock
        });

        // The client synchronizes: stratum + 1, on the next tick.
        {
            let mut s = lock(&session);
            s.execute(
                "system.ntp.client.set",
                &json!({"enabled": true, "servers": ["192.0.2.9"]}),
            )
            .unwrap();
            let now = u64::try_from(unix_nanos() / NANOS).unwrap();
            s.set_ntp_status(NtpStatus {
                last_sync: Some(now),
                ..status()
            });
        }
        wait_for("the client's time", || query(port).is_ok_and(|p| p.stratum == 3));
        let p = query(port).unwrap();
        assert_eq!(p.reference_id, [192, 0, 2, 9]);
        assert_eq!(p.mode, MODE_SERVER);
        assert_ne!(p.mode, MODE_CLIENT);
        wait_for("the upstream state", || {
            let st = lock(&session).ntp_server_stats();
            st.serving == NtpServing::Upstream && st.stratum == Some(3) && st.replies > 0
        });

        // Outside the list: silence, counted.
        lock(&session)
            .execute("system.ntp.server.set", &json!({"allowed": ["192.0.2.0/24"]}))
            .unwrap();
        wait_for("the new list", || query(port).is_err());
        wait_for("denied", || lock(&session).ntp_server_stats().denied > 0);

        // Off closes the sockets.
        lock(&session)
            .execute("system.ntp.server.set", &json!({"enabled": false}))
            .unwrap();
        wait_for("closed", || !lock(&session).ntp_server_stats().listening);
        health.stop();
    }
}
