//! One accepted control connection: its socket timeouts, TCP keepalive and
//! connection slot (control audit).
//!
//! - **Keepalive.** A peer that vanishes without a FIN or RST (cable pulled,
//!   route or address removed, firewall drop: what Safe Mode exists for)
//!   would leave its thread blocked in `read` forever, so its Safe Mode
//!   would never be undone. Every accepted socket gets TCP keepalive and,
//!   on Linux, `TCP_USER_TIMEOUT`: the kernel then fails the read after
//!   [`Timeouts::dead_peer`] and the connection's `hang_up` runs.
//! - **Deadlines.** The TLS handshake and the WebSocket HTTP head must
//!   finish within [`Timeouts::handshake`] in total, not per `read` (a peer
//!   sending one byte every few seconds cannot hold a slot). [`Sock`] sets
//!   the remaining time before every read system call.
//! - **Logged out = short leash.** Until a request on the connection is
//!   authenticated it may stay idle only [`Timeouts::unauthenticated_idle`]
//!   and stay logged out at most [`Timeouts::login_grace`] in total; only
//!   [`MAX_UNAUTHENTICATED`] of an endpoint's
//!   [`crate::server::MAX_CONNECTIONS`] slots (at most
//!   [`MAX_UNAUTHENTICATED_PER_SOURCE`] per network source) may be in that
//!   state, so idle or trickling strangers cannot lock the operator out. Once logged in
//!   there is no idle limit (an MCP server or a GUI may sit idle for hours):
//!   keepalive finds the dead ones.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Most connections of one endpoint that have not logged in yet.
pub const MAX_UNAUTHENTICATED: usize = 8;
/// Most of those from one network source (an IPv4 address or an IPv6 /64).
/// Loopback peers are not limited per source (they all share one address).
pub const MAX_UNAUTHENTICATED_PER_SOURCE: usize = 4;

/// Socket timeouts of an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeouts {
    /// Total time for the TLS handshake, and again for the HTTP head of a
    /// WebSocket port.
    pub handshake: Duration,
    /// How long a connection that has not logged in may stay silent.
    pub unauthenticated_idle: Duration,
    /// How long a connection may stay logged out in total, busy or not
    /// (SSH's `LoginGraceTime`): a stranger trickling a byte, or a `ping`,
    /// before every idle timeout would otherwise keep its slot forever.
    pub login_grace: Duration,
    /// TCP keepalive: silence before the first probe.
    pub keepalive_idle: Duration,
    /// TCP keepalive: time between probes.
    pub keepalive_interval: Duration,
    /// TCP keepalive: unanswered probes before the connection is dropped.
    pub keepalive_probes: u32,
    /// A write that makes no progress this long drops the connection (a
    /// client that stops reading a big reply).
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            unauthenticated_idle: Duration::from_secs(30),
            login_grace: Duration::from_secs(60),
            keepalive_idle: Duration::from_secs(15),
            keepalive_interval: Duration::from_secs(5),
            keepalive_probes: 3,
            write: Duration::from_secs(30),
        }
    }
}

impl Timeouts {
    /// How long a silent dead peer keeps its connection: the first probe
    /// plus every retry.
    pub fn dead_peer(&self) -> Duration {
        self.keepalive_interval
            .saturating_mul(self.keepalive_probes)
            .saturating_add(self.keepalive_idle)
    }
}

/// Turn on TCP keepalive (and `TCP_USER_TIMEOUT` on Linux, which also
/// bounds unacknowledged data) on an accepted socket.
pub fn keepalive(tcp: &TcpStream, t: &Timeouts) -> io::Result<()> {
    let sock = socket2::SockRef::from(tcp);
    let params = socket2::TcpKeepalive::new().with_time(t.keepalive_idle);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    let params = params.with_interval(t.keepalive_interval);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let params = params.with_retries(t.keepalive_probes);
    sock.set_tcp_keepalive(&params)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    sock.set_tcp_user_timeout(Some(t.dead_peer()))?;
    Ok(())
}

/// The source a peer is counted under: an IPv4 address (also when mapped
/// into IPv6), or the /64 of an IPv6 address (one subscriber usually holds
/// a whole /64, so per-address counts are trivially dodged).
pub fn source_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let [a, b, c, d, ..] = v6.segments();
                IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
            }
        },
    }
}

#[derive(Debug, Default)]
struct Table {
    active: usize,
    unauthenticated: usize,
    per_source: HashMap<IpAddr, usize>,
}

/// The connection slots of one endpoint.
#[derive(Debug, Clone, Default)]
pub(crate) struct Slots(Arc<Mutex<Table>>);

impl Slots {
    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A slot for a new, not yet logged-in connection from `peer`, or why
    /// there is none.
    pub(crate) fn take(&self, peer: Option<IpAddr>, max: usize) -> Result<Slot, &'static str> {
        let source = peer.filter(|p| !p.is_loopback()).map(source_of);
        let mut t = self.table();
        if t.active >= max {
            return Err("too many connections");
        }
        if t.unauthenticated >= MAX_UNAUTHENTICATED {
            return Err("too many connections that have not logged in");
        }
        if let Some(src) = source
            && t.per_source.get(&src).copied().unwrap_or(0) >= MAX_UNAUTHENTICATED_PER_SOURCE
        {
            return Err("too many connections from this address that have not logged in");
        }
        t.active = t.active.saturating_add(1);
        t.unauthenticated = t.unauthenticated.saturating_add(1);
        if let Some(src) = source {
            let n = t.per_source.entry(src).or_insert(0);
            *n = n.saturating_add(1);
        }
        Ok(Slot {
            slots: self.clone(),
            source,
            unauthenticated: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> (usize, usize) {
        let t = self.table();
        (t.active, t.unauthenticated)
    }
}

/// A taken slot; given back on drop (also when the thread panics).
#[derive(Debug)]
pub(crate) struct Slot {
    slots: Slots,
    source: Option<IpAddr>,
    unauthenticated: bool,
}

impl Slot {
    fn authenticated(&mut self) {
        if !std::mem::replace(&mut self.unauthenticated, false) {
            return;
        }
        let mut t = self.slots.table();
        t.unauthenticated = t.unauthenticated.saturating_sub(1);
        if let Some(src) = self.source {
            let gone = match t.per_source.get_mut(&src) {
                Some(n) => {
                    *n = n.saturating_sub(1);
                    *n == 0
                }
                None => false,
            };
            if gone {
                t.per_source.remove(&src);
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.authenticated();
        let mut t = self.slots.table();
        t.active = t.active.saturating_sub(1);
    }
}

/// An accepted TCP socket with its read deadline, idle limit and slot.
/// Every read sets the socket's read timeout to what is left.
#[derive(Debug)]
pub struct Sock {
    tcp: TcpStream,
    timeouts: Timeouts,
    deadline: Option<Instant>,
    idle: Option<Duration>,
    /// The read timeout last set on the socket.
    applied: Option<Option<Duration>>,
    authenticated: bool,
    slot: Option<Slot>,
}

impl Sock {
    pub(crate) fn new(tcp: TcpStream, timeouts: Timeouts, slot: Option<Slot>) -> Self {
        let deadline = Instant::now().checked_add(timeouts.handshake);
        Self {
            tcp,
            timeouts,
            deadline,
            idle: None,
            applied: None,
            authenticated: false,
            slot,
        }
    }

    pub fn tcp(&self) -> &TcpStream {
        &self.tcp
    }

    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }

    /// Reads fail once `deadline` passes (`None`: no deadline).
    pub fn set_deadline(&mut self, deadline: Option<Duration>) {
        self.deadline = deadline.and_then(|d| Instant::now().checked_add(d));
    }

    /// Handshake over: until [`Sock::authenticated`], the logged-out idle
    /// limit and the login grace deadline (no deadline once logged in).
    pub fn handshake_done(&mut self) {
        self.deadline = None;
        if !self.authenticated {
            self.idle = Some(self.timeouts.unauthenticated_idle);
            self.deadline = Instant::now().checked_add(self.timeouts.login_grace);
        }
    }

    /// A request on this connection was authenticated: no idle limit, and
    /// the slot no longer counts as logged out.
    pub fn authenticated(&mut self) {
        self.authenticated = true;
        self.idle = None;
        self.deadline = None;
        if let Some(slot) = self.slot.as_mut() {
            slot.authenticated();
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        let left = match self.deadline {
            None => None,
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "deadline passed (handshake or login grace)",
                    ));
                }
                Some(left)
            }
        };
        Ok(match (left, self.idle) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        })
    }
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let t = self.read_timeout()?;
        if self.applied != Some(t) {
            self.tcp.set_read_timeout(t)?;
            self.applied = Some(t);
        }
        // On Unix an expired SO_RCVTIMEO comes back as EAGAIN (WouldBlock):
        // callers see one kind for "the time ran out".
        self.tcp.read(buf).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock => io::Error::new(io::ErrorKind::TimedOut, e),
            _ => e,
        })
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn sources_group_ipv6_by_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_of(a), source_of(b));
        assert_ne!(source_of(a), source_of(c));
        let mapped: IpAddr = "::ffff:10.0.0.9".parse().unwrap();
        assert_eq!(source_of(mapped), "10.0.0.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn logged_out_slots_are_capped_per_source_and_in_total() {
        let slots = Slots::default();
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        let mut held: Vec<Slot> = (0..MAX_UNAUTHENTICATED_PER_SOURCE)
            .map(|i| slots.take(ip(&format!("2001:db8::{i}")), 16).unwrap())
            .collect();
        // Same /64: refused; another source still gets in.
        assert!(slots.take(ip("2001:db8::ffff"), 16).is_err());
        held.push(slots.take(ip("10.0.0.1"), 16).unwrap());
        // Loopback is not limited per source, only in total.
        while slots.counts().1 < MAX_UNAUTHENTICATED {
            held.push(slots.take(ip("127.0.0.1"), 16).unwrap());
        }
        assert!(slots.take(ip("127.0.0.1"), 16).is_err());
        // Logging in frees the logged-out slot (and the per-source count).
        held[0].authenticated();
        assert!(slots.take(ip("2001:db8::ffff"), 16).is_ok());
        assert_eq!(
            slots.counts(),
            (MAX_UNAUTHENTICATED, MAX_UNAUTHENTICATED - 1)
        );
        drop(held);
        assert_eq!(slots.counts(), (0, 0));
    }

    #[test]
    fn total_cap_holds_for_logged_in_connections() {
        let slots = Slots::default();
        let mut held = Vec::new();
        for _ in 0..3 {
            let mut s = slots.take(None, 3).unwrap();
            s.authenticated();
            held.push(s);
        }
        assert!(slots.take(None, 3).is_err());
        held.pop();
        assert!(slots.take(None, 3).is_ok());
    }

    #[test]
    fn deadline_bounds_the_total_not_each_read() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (tcp, _) = l.accept().unwrap();
        let t = Timeouts {
            handshake: Duration::from_millis(400),
            ..Timeouts::default()
        };
        let mut sock = Sock::new(tcp, t, None);
        let start = Instant::now();
        let feeder = std::thread::spawn(move || {
            // One byte every 100 ms: each read succeeds, the total must not.
            for _ in 0..20 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let mut b = [0u8; 1];
        let err = loop {
            match sock.read(&mut b) {
                Ok(0) => panic!("the feeder closed first"),
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        // The feeder keeps each read alive for 2 s; ending well before that
        // proves the deadline is on the total. The bound is loose because a
        // loaded CI runner delays the wake-ups (flaked at 900 ms, 2026-10-24).
        assert!(start.elapsed() < Duration::from_millis(1600));
        feeder.join().unwrap();
    }

    #[test]
    fn keepalive_is_set() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let _c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (tcp, _) = l.accept().unwrap();
        assert!(!socket2::SockRef::from(&tcp).keepalive().unwrap());
        keepalive(&tcp, &Timeouts::default()).unwrap();
        let s = socket2::SockRef::from(&tcp);
        assert!(s.keepalive().unwrap());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(s.tcp_keepalive_time().unwrap(), Duration::from_secs(15));
            assert_eq!(s.tcp_keepalive_interval().unwrap(), Duration::from_secs(5));
            assert_eq!(s.tcp_keepalive_retries().unwrap(), 3);
            assert_eq!(s.tcp_user_timeout().unwrap(), Some(Duration::from_secs(30)));
        }
    }
}
