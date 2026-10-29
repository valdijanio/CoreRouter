//! Router Advertisements on Ethernet (G3.9ha, `/ipv6 nd`): the Linux kernel
//! never sends them, so without this a host or a RouterOS behind
//! CoreRouter gets no SLAAC address and no default route.
//!
//! One thread and **one** raw ICMPv6 socket for every interface, like
//! radvd: the kernel adds the IPv6 header and the checksum (RFC 3542 §3.1),
//! the destination's scope id picks the interface and the kernel picks its
//! link-local source (RFC 4861 §6.2.3). A socket filter lets only RS and
//! RA through. Measured on 1000 interfaces (2026-10-29, **medido**): one
//! socket sends an RA in 12 µs and holds 1 fd, a socket per interface takes
//! 40 µs and 1000 fds; the whole round is ~12 ms every 200–600 s, so more
//! threads would buy nothing.
//!
//! Every [`TICK`] the thread takes the plan of the running config
//! ([`corerouter_engine::ipv6_nd::plan`], under the session lock, no I/O)
//! and [`Sender::follow`]s it, then sends what is due and answers what came
//! in, without the lock. RFC 4861:
//! - §6.2.4: up to 3 RAs at most 16 s apart when an interface starts (or
//!   its RA changes), then one every MinRtrAdvInterval..MaxRtrAdvInterval,
//!   uniformly spread;
//! - §6.2.6: a valid RS (§6.1.1) is answered by a multicast RA within
//!   0..500 ms, never sooner than `ra-delay` after the last one;
//! - §6.2.5: an interface that stops advertising (entry removed or
//!   disabled, the daemon stopping) sends final RAs with Router Lifetime 0;
//!   a prefix that leaves an RA goes out three more times with lifetimes 0
//!   (RFC 9096 §3.5; RouterOS does the same);
//! - §6.2.7: another router's RA on the link with different values is
//!   logged once and shown as a conflict.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::ipv6_nd::{Advert, Live, NdIfStatus, NdStatus, PlanPrefix, plan_live};
use corerouter_engine::{Shared, lock};
use corerouter_model::IfName;
use corerouter_proto_pppoe::nd::{
    self, MAX_INITIAL_RTR_ADVERTISEMENTS, ParsedRa, PrefixInfo, RaConfig, RaTimer,
};
use corerouter_proto_pppoe::timer::Millis;
use ipnet::Ipv6Net;

/// How often the thread looks at the config.
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(1)
};
/// RFC 4861 §10: MAX_RA_DELAY_TIME.
const MAX_RA_DELAY_MS: u64 = 500;
/// RFC 4861 §10: MAX_FINAL_RTR_ADVERTISEMENTS.
const MAX_FINAL: u8 = 3;
/// Times a prefix that left an RA is still sent with lifetimes 0.
const DEPRECATE_SENDS: u8 = 3;
/// Retry an interface whose send failed (no link-local yet, link down).
const RETRY_MS: u64 = 1_000;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "router-advertisement",
    flags: &[],
    topic: "interface",
    enable: "ipv6.nd.add interface=…",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

/// One RA to put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Out {
    pub interface: IfName,
    pub ifindex: u32,
    pub message: Vec<u8>,
    /// A final RA (Router Lifetime 0).
    pub last: bool,
}

/// What the kernel says about an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Link {
    pub ifindex: u32,
    pub mac: Option<[u8; 6]>,
}

#[derive(Debug, Clone)]
struct Port {
    link: Link,
    advert: Advert,
    timer: RaTimer,
    /// Prefixes that left the RA, with sends left.
    deprecated: Vec<(Ipv6Net, u8)>,
    status: NdIfStatus,
    /// The last other router's disagreement logged (RFC 4861 §6.2.7).
    logged_conflict: Option<String>,
}

#[derive(Debug, Clone)]
struct Ceasing {
    interface: IfName,
    link: Link,
    advert: Advert,
    left: u8,
    next_at: Millis,
}

/// The sender's state machine, without sockets: what to send when, from
/// the plan, the clock and the solicitations.
#[derive(Debug, Default)]
pub(crate) struct Sender {
    ports: BTreeMap<IfName, Port>,
    ceasing: Vec<Ceasing>,
    rng: u64,
}

impl Sender {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            rng: seed | 1,
            ..Self::default()
        }
    }

    fn rand(&mut self) -> u32 {
        // xorshift64: spreading timers needs no cryptographic quality.
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 32) as u32
    }

    /// Takes the interfaces of `adverts` (`link` finds them in the kernel;
    /// `None`: not there yet, tried again next time). Returns the
    /// interfaces that joined and left, for the all-routers group.
    pub(crate) fn follow(
        &mut self,
        now: Millis,
        adverts: &[Advert],
        link: &mut dyn FnMut(&IfName) -> Option<Link>,
    ) -> (Vec<Link>, Vec<Link>) {
        let mut joined = Vec::new();
        let mut left = Vec::new();
        let gone: Vec<IfName> = self
            .ports
            .keys()
            .filter(|n| !adverts.iter().any(|a| &a.interface == *n))
            .cloned()
            .collect();
        for name in gone {
            if let Some(p) = self.ports.remove(&name) {
                left.push(p.link);
                self.ceasing.push(Ceasing {
                    interface: name,
                    link: p.link,
                    advert: p.advert,
                    left: MAX_FINAL,
                    next_at: now,
                });
            }
        }
        for a in adverts {
            match self.ports.get_mut(&a.interface) {
                Some(p) if p.advert == *a => {}
                // Only the clock moved the DHCPv6-PD lifetimes: the next RA
                // carries them, no rapid re-advertising.
                Some(p) if p.advert.same_but_clock(a) => p.advert = a.clone(),
                Some(p) => {
                    // RFC 4861 §6.2.4: changed information MAY be sent at
                    // the initial, rapid rate; prefixes that left go out
                    // with lifetimes 0 (RFC 9096 §3.5).
                    for old in &p.advert.prefixes {
                        if !a.prefixes.iter().any(|n| n.prefix == old.prefix) {
                            p.deprecated.retain(|(d, _)| *d != old.prefix);
                            p.deprecated.push((old.prefix, DEPRECATE_SENDS));
                        }
                    }
                    p.deprecated.retain(|(d, _)| !a.prefixes.iter().any(|n| n.prefix == *d));
                    p.advert = a.clone();
                    p.timer.initial_left = MAX_INITIAL_RTR_ADVERTISEMENTS;
                    let soon = p.timer.last_sent.map_or(now, |t| now.max(t + delay_ms(&p.advert)));
                    p.timer.next_at = p.timer.next_at.min(soon);
                }
                None => {
                    let Some(l) = link(&a.interface) else { continue };
                    // A ceasing RA for the same interface is moot now.
                    self.ceasing.retain(|c| c.interface != a.interface);
                    joined.push(l);
                    self.ports.insert(
                        a.interface.clone(),
                        Port {
                            link: l,
                            advert: a.clone(),
                            timer: RaTimer::new(now),
                            deprecated: Vec::new(),
                            status: NdIfStatus::default(),
                            logged_conflict: None,
                        },
                    );
                }
            }
        }
        (joined, left)
    }

    /// The earliest time something is due.
    pub(crate) fn next_due(&self) -> Option<Millis> {
        let a = self.ports.values().map(|p| p.timer.next_at).min();
        let b = self.ceasing.iter().map(|c| c.next_at).min();
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }

    /// The RAs due at `now`; their timers move on as if they were sent
    /// (a failed send is reported with [`Sender::failed`]).
    pub(crate) fn due(&mut self, now: Millis) -> Vec<Out> {
        let mut out = Vec::new();
        let names: Vec<IfName> = self
            .ports
            .iter()
            .filter(|(_, p)| p.timer.next_at <= now)
            .map(|(n, _)| n.clone())
            .collect();
        for name in names {
            let r = self.rand();
            let Some(p) = self.ports.get_mut(&name) else { continue };
            let deprecated: Vec<Ipv6Net> = p.deprecated.iter().map(|(d, _)| *d).collect();
            let message = nd::router_advert_icmp(&ra_config(&p.advert, p.link.mac, &deprecated, false));
            for d in &mut p.deprecated {
                d.1 = d.1.saturating_sub(1);
            }
            p.deprecated.retain(|d| d.1 > 0);
            let e = &p.advert.entry;
            let (min, max) = (u64::from(e.ra_interval_min) * 1000, u64::from(e.ra_interval_max) * 1000);
            p.timer.sent(now, r, min, max);
            out.push(Out {
                interface: name.clone(),
                ifindex: p.link.ifindex,
                message,
                last: false,
            });
        }
        for c in self.ceasing.iter_mut().filter(|c| c.next_at <= now) {
            let all: Vec<Ipv6Net> = c.advert.prefixes.iter().map(|p| p.prefix).collect();
            out.push(Out {
                interface: c.interface.clone(),
                ifindex: c.link.ifindex,
                message: nd::router_advert_icmp(&ra_config(&c.advert, c.link.mac, &all, true)),
                last: true,
            });
            c.left = c.left.saturating_sub(1);
            c.next_at = now + delay_ms(&c.advert);
        }
        self.ceasing.retain(|c| c.left > 0);
        out
    }

    /// Every interface's final RA at once (the daemon is stopping).
    pub(crate) fn shutdown(&mut self) -> Vec<Out> {
        let ports = std::mem::take(&mut self.ports);
        let mut out: Vec<Out> = ports
            .into_iter()
            .map(|(name, p)| {
                let all: Vec<Ipv6Net> = p.advert.prefixes.iter().map(|x| x.prefix).collect();
                Out {
                    interface: name,
                    ifindex: p.link.ifindex,
                    message: nd::router_advert_icmp(&ra_config(&p.advert, p.link.mac, &all, true)),
                    last: true,
                }
            })
            .collect();
        for c in std::mem::take(&mut self.ceasing) {
            let all: Vec<Ipv6Net> = c.advert.prefixes.iter().map(|x| x.prefix).collect();
            out.push(Out {
                interface: c.interface,
                ifindex: c.link.ifindex,
                message: nd::router_advert_icmp(&ra_config(&c.advert, c.link.mac, &all, true)),
                last: true,
            });
        }
        out
    }

    pub(crate) fn sent(&mut self, name: &IfName, unix: u64) {
        if let Some(p) = self.ports.get_mut(name) {
            p.status.ra_sent += 1;
            p.status.last_ra = Some(unix);
            p.status.error = None;
        }
    }

    pub(crate) fn failed(&mut self, name: &IfName, now: Millis, why: String) {
        if let Some(p) = self.ports.get_mut(name) {
            p.status.error = Some(why);
            p.timer.next_at = p.timer.next_at.min(now + RETRY_MS);
            // The RA did not go out: it does not count as an initial one.
            p.timer.initial_left = p.timer.initial_left.max(1);
        }
    }

    /// A valid Router Solicitation on `ifindex` (RFC 4861 §6.2.6): a
    /// multicast RA within 0..MAX_RA_DELAY_TIME, not sooner than `ra-delay`
    /// after the last one, unless one is due sooner anyway.
    pub(crate) fn solicited(&mut self, now: Millis, ifindex: u32) {
        let r = u64::from(self.rand()) % MAX_RA_DELAY_MS;
        let Some(p) = self.ports.values_mut().find(|p| p.link.ifindex == ifindex) else {
            return;
        };
        p.status.rs_received += 1;
        let mut at = now + r;
        if let Some(t) = p.timer.last_sent {
            at = at.max(t + delay_ms(&p.advert));
        }
        p.timer.next_at = p.timer.next_at.min(at);
    }

    /// Another router's RA on `ifindex`: what disagrees with ours (RFC 4861
    /// §6.2.7), the text to log when it changed.
    pub(crate) fn other_router(&mut self, ifindex: u32, ra: &ParsedRa) -> Option<String> {
        let p = self.ports.values_mut().find(|p| p.link.ifindex == ifindex)?;
        let ours = ra_config(&p.advert, None, &[], false);
        let mut diff = Vec::new();
        // §6.2.7: zero (unspecified) values are not compared.
        if ra.hop_limit != 0 && ours.hop_limit != 0 && ra.hop_limit != ours.hop_limit {
            diff.push(format!("hop limit {} (ours {})", ra.hop_limit, ours.hop_limit));
        }
        if ra.managed != ours.managed {
            diff.push(format!("M flag {} (ours {})", u8::from(ra.managed), u8::from(ours.managed)));
        }
        if ra.other != ours.other {
            diff.push(format!("O flag {} (ours {})", u8::from(ra.other), u8::from(ours.other)));
        }
        if ra.reachable_ms != 0 && ours.reachable_ms != 0 && ra.reachable_ms != ours.reachable_ms {
            diff.push(format!("reachable time {} ms (ours {})", ra.reachable_ms, ours.reachable_ms));
        }
        if ra.retrans_ms != 0 && ours.retrans_ms != 0 && ra.retrans_ms != ours.retrans_ms {
            diff.push(format!("retransmit interval {} ms (ours {})", ra.retrans_ms, ours.retrans_ms));
        }
        if let (Some(a), Some(b)) = (ra.mtu, ours.mtu)
            && a != b
        {
            diff.push(format!("MTU {a} (ours {b})"));
        }
        for x in &ra.prefixes {
            if let Some(o) = ours.prefixes.iter().find(|o| o.prefix == x.prefix && o.len == x.len)
                && (o.valid != x.valid || o.preferred != x.preferred)
            {
                diff.push(format!(
                    "{}/{} lifetimes {}/{} s (ours {}/{})",
                    x.prefix, x.len, x.valid, x.preferred, o.valid, o.preferred
                ));
            }
        }
        let text = (!diff.is_empty()).then(|| format!("router {} sends {}", ra.src, diff.join(", ")));
        p.status.conflict = text.clone();
        if text != p.logged_conflict {
            p.logged_conflict = text.clone();
            return text;
        }
        None
    }

    /// The counters and deprecated prefixes, for `ipv6.nd.list`.
    pub(crate) fn status(&self) -> NdStatus {
        NdStatus {
            running: true,
            interfaces: self.ports.iter().map(|(n, p)| (n.clone(), p.status.clone())).collect(),
            deprecated: self
                .ports
                .iter()
                .filter(|(_, p)| !p.deprecated.is_empty())
                .map(|(n, p)| (n.clone(), p.deprecated.iter().map(|d| d.0).collect()))
                .collect(),
        }
    }
}

fn delay_ms(a: &Advert) -> u64 {
    u64::from(a.entry.ra_delay.max(1)) * 1000
}

fn prefix_info(p: &PlanPrefix) -> PrefixInfo {
    PrefixInfo {
        prefix: p.prefix.addr(),
        len: p.prefix.prefix_len(),
        on_link: p.on_link,
        autonomous: p.autonomous,
        valid: p.valid,
        preferred: p.preferred,
    }
}

/// The RA of `a`; `deprecated` go along with lifetimes 0; `last`: a final
/// RA (Router Lifetime 0, RFC 4861 §6.2.5).
fn ra_config(a: &Advert, mac: Option<[u8; 6]>, deprecated: &[Ipv6Net], last: bool) -> RaConfig {
    let e = &a.entry;
    let mut prefixes: Vec<PrefixInfo> = if last {
        Vec::new()
    } else {
        a.prefixes.iter().map(prefix_info).collect()
    };
    for d in deprecated {
        if !prefixes.iter().any(|p| p.prefix == d.addr() && p.len == d.prefix_len()) {
            prefixes.push(PrefixInfo {
                prefix: d.addr(),
                len: d.prefix_len(),
                on_link: true,
                autonomous: true,
                valid: 0,
                preferred: 0,
            });
        }
    }
    RaConfig {
        hop_limit: e.hop_limit,
        managed: e.managed_address_configuration,
        other: e.other_configuration,
        router_lifetime: if last { 0 } else { u16::try_from(e.ra_lifetime).unwrap_or(u16::MAX) },
        reachable_ms: e.reachable_time,
        retrans_ms: e.retransmit_interval,
        mtu: e.mtu,
        prefixes,
        sllao: if e.advertise_mac_address { mac } else { None },
        rdnss: a.rdnss.clone(),
        dnssl: a.dnssl.clone(),
        dns_lifetime: if last { 0 } else { a.dns_lifetime },
        preference: e.ra_preference.bits(),
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_lab(session: &Shared) -> bool {
    lock(session).backend().starts_with("virtual lab")
}

fn run(session: &Shared, health: &super::Health) {
    let origin = Instant::now();
    let clock = || u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut sender = Sender::new(seed);
    let mut sock: Option<sock::Raw> = None;
    let mut last_status = NdStatus::default();
    let mut next_plan = 0;
    let mut planned: Option<(u32, Live)> = None;
    let mut p = corerouter_engine::ipv6_nd::Plan::default();
    loop {
        health.beat();
        let now = clock();
        if now >= next_plan {
            next_plan = now + TICK.as_millis() as u64;
            if is_lab(session) {
                health.disabled(Some("virtual lab: no kernel to send Router Advertisements on"));
                if !health.sleep(TICK) {
                    return;
                }
                continue;
            }
            // The plan depends on the running config, the DHCPv6-PD
            // pools and the DNS DHCPv6 learned: taken again when one of
            // them changed (1000 VLANs: 257 µs under the lock, **medido**),
            // and every tick while a delegated prefix counts down (its
            // lifetimes, RFC 9096 §3.4). Followed every tick: an interface
            // may show up in the kernel later.
            {
                let s = lock(session);
                let cfg = s.store().running();
                let live = Live::of(&s, cfg);
                let key = (s.store().current_revision(), Live { now_ms: None, ..live.clone() });
                let counting = live.pools.iter().any(|x| x.prefix.is_some());
                if counting || planned.as_ref() != Some(&key) {
                    p = plan_live(cfg, &live);
                    planned = Some(key);
                }
            }
            health.disabled(p.adverts.is_empty().then_some("ipv6.nd: no interface advertises"));
            if sock.is_none() && !p.adverts.is_empty() {
                match sock::Raw::open() {
                    Ok(s) => {
                        health.clear_error();
                        sock = Some(s);
                    }
                    Err(e) => health.error(format!("raw ICMPv6 socket: {e}")),
                }
            }
            if let Some(s) = &sock {
                let (joined, left) = sender.follow(now, &p.adverts, &mut sock::link);
                for l in joined {
                    s.join(l.ifindex);
                }
                for l in left {
                    s.leave(l.ifindex);
                }
            }
        }
        let Some(s) = &sock else {
            if !health.sleep(TICK) {
                return;
            }
            continue;
        };
        for o in sender.due(now) {
            match s.send(&o.message, o.ifindex) {
                Ok(()) => sender.sent(&o.interface, unix_secs()),
                Err(e) => {
                    let why = format!("sending on {}: {e}", o.interface);
                    log::debug!("ipv6 nd: {why}");
                    sender.failed(&o.interface, now, why);
                }
            }
        }
        let status = sender.status();
        if status != last_status {
            if let Some(st) = lock(session).ext_mut::<NdStatus>() {
                *st = status.clone();
            }
            last_status = status;
        }
        if health.stopping() {
            for o in sender.shutdown() {
                let _ = s.send(&o.message, o.ifindex);
            }
            if let Some(st) = lock(session).ext_mut::<NdStatus>() {
                *st = NdStatus::default();
            }
            return;
        }
        // Wait for a solicitation until the next RA or the next plan.
        let until = sender.next_due().unwrap_or(next_plan).min(next_plan);
        let wait = Duration::from_millis(until.saturating_sub(clock()).clamp(1, TICK.as_millis() as u64));
        match s.recv(wait) {
            Ok(Some(Inbound::Rs { ifindex })) => sender.solicited(clock(), ifindex),
            Ok(Some(Inbound::Ra { ifindex, ra })) => {
                if let Some(text) = sender.other_router(ifindex, &ra) {
                    log::warn!("ipv6 nd: {text} (RFC 4861 §6.2.7)");
                    lock(session).log_event(
                        &["interface", "warning"],
                        corerouter_engine::logging::DAEMON,
                        format!("ipv6 nd: {text} (RFC 4861 §6.2.7: roteadores do mesmo enlace divergem)"),
                        serde_json::Value::Null,
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                health.error(format!("receiving: {e}"));
                if !health.sleep(TICK) {
                    return;
                }
            }
        }
    }
}

/// What the socket read.
pub(crate) enum Inbound {
    Rs { ifindex: u32 },
    Ra { ifindex: u32, ra: ParsedRa },
}

/// The raw ICMPv6 socket, through `socket2` and `nix` (no `unsafe`).
mod sock {
    use std::io::IoSliceMut;
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::os::fd::{AsFd, AsRawFd};
    use std::time::Duration;

    use corerouter_model::IfName;
    use corerouter_proto_pppoe::nd;
    use nix::libc;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg, setsockopt, sockopt};
    use socket2::{Domain, Protocol, SockAddr, SockFilter, Socket, Type};

    use super::{Inbound, Link};

    pub(super) struct Raw(Socket);

    fn nix_io(e: nix::Error) -> std::io::Error {
        std::io::Error::from_raw_os_error(e as i32)
    }

    /// Classic BPF: on an IPv6 raw socket the program sees the ICMPv6
    /// message, so byte 0 is the type; keep 133 (RS) and 134 (RA).
    const FILTER: [SockFilter; 5] = [
        SockFilter::new(0x30, 0, 0, 0),                       // ldb [0]
        SockFilter::new(0x15, 2, 0, nd::icmp::ROUTER_SOLICIT as u32), // jeq 133 → accept
        SockFilter::new(0x15, 1, 0, nd::icmp::ROUTER_ADVERT as u32),  // jeq 134 → accept
        SockFilter::new(0x06, 0, 0, 0),                       // ret 0
        SockFilter::new(0x06, 0, 0, 0xffff),                  // ret all
    ];

    impl Raw {
        pub(super) fn open() -> std::io::Result<Self> {
            let s = Socket::new(Domain::IPV6, Type::RAW.cloexec(), Some(Protocol::ICMPV6))?;
            s.attach_filter(&FILTER)?;
            // RFC 4861 §6.1.1/§6.1.2: ND messages go out with hop limit 255,
            // and come in with it (checked on each RS).
            s.set_multicast_hops_v6(255)?;
            s.set_unicast_hops_v6(255)?;
            s.set_multicast_loop_v6(false)?;
            setsockopt(&s.as_fd(), sockopt::Ipv6RecvPacketInfo, &true).map_err(nix_io)?;
            setsockopt(&s.as_fd(), sockopt::Ipv6RecvHopLimit, &true).map_err(nix_io)?;
            Ok(Self(s))
        }

        /// Join all-routers on `ifindex`, where RSs go (RFC 4861 §6.2.2;
        /// the kernel already did if forwarding is on).
        pub(super) fn join(&self, ifindex: u32) {
            let _ = self.0.join_multicast_v6(&nd::ALL_ROUTERS, ifindex);
        }

        pub(super) fn leave(&self, ifindex: u32) {
            let _ = self.0.leave_multicast_v6(&nd::ALL_ROUTERS, ifindex);
        }

        /// To all nodes on `ifindex` (RFC 4861 §6.2.6: the usual answer
        /// to an RS is multicast too).
        pub(super) fn send(&self, message: &[u8], ifindex: u32) -> std::io::Result<()> {
            let to = SocketAddrV6::new(nd::ALL_NODES, 0, 0, ifindex);
            self.0.send_to(message, &SockAddr::from(to)).map(|_| ())
        }

        /// One RS or RA, waiting at most `wait`; `None` on a timeout or a
        /// message that fails the checks.
        pub(super) fn recv(&self, wait: Duration) -> std::io::Result<Option<Inbound>> {
            let ms = u16::try_from(wait.as_millis()).unwrap_or(u16::MAX);
            let mut fds = [PollFd::new(self.0.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::from(ms)) {
                Ok(0) => return Ok(None),
                Ok(_) => {}
                Err(nix::Error::EINTR) => return Ok(None),
                Err(e) => return Err(nix_io(e)),
            }
            let mut buf = [0u8; 1500];
            let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo, libc::c_int);
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = recvmsg::<SockaddrIn6>(
                self.0.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::MSG_DONTWAIT,
            );
            let msg = match msg {
                Ok(m) => m,
                Err(nix::Error::EAGAIN) => return Ok(None),
                Err(e) => return Err(nix_io(e)),
            };
            let (mut ifindex, mut hops) = (0u32, 0u8);
            for c in msg.cmsgs().map_err(nix_io)? {
                match c {
                    ControlMessageOwned::Ipv6PacketInfo(i) => ifindex = i.ipi6_ifindex,
                    ControlMessageOwned::Ipv6HopLimit(h) => hops = u8::try_from(h).unwrap_or(0),
                    _ => {}
                }
            }
            let src = msg.address.map_or(Ipv6Addr::UNSPECIFIED, |a| a.ip());
            let n = msg.bytes;
            let Some(body) = buf.get(..n) else { return Ok(None) };
            if body.first() == Some(&nd::icmp::ROUTER_SOLICIT) {
                return Ok(nd::parse_rs_icmp(src, hops, body).ok().map(|_| Inbound::Rs { ifindex }));
            }
            // RFC 4861 §6.1.2: hop limit 255, link-local source.
            if hops != 255 || !src.is_unicast_link_local() {
                return Ok(None);
            }
            Ok(nd::parse_ra_icmp(src, body).ok().map(|ra| Inbound::Ra { ifindex, ra }))
        }
    }

    /// The kernel's index and MAC of `name`, in this network namespace.
    pub(super) fn link(name: &IfName) -> Option<Link> {
        let ifindex = nix::net::if_::if_nametoindex(name.as_str()).ok()?;
        let mac = nix::ifaddrs::getifaddrs().ok().and_then(|mut it| {
            it.find_map(|a| {
                (a.interface_name == name.as_str())
                    .then(|| a.address.and_then(|x| x.as_link_addr().and_then(|l| l.addr())))
                    .flatten()
            })
        });
        Some(Link { ifindex, mac })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ipv6_nd::NdInterface;
    use corerouter_model::ItemId;

    fn advert(name: &str, prefixes: &[&str]) -> Advert {
        let mut e = NdInterface::new(ItemId(1), name.parse().unwrap());
        (e.ra_interval_min, e.ra_interval_max) = (200, 600);
        Advert {
            interface: name.parse().unwrap(),
            entry: e,
            prefixes: prefixes
                .iter()
                .map(|p| PlanPrefix {
                    prefix: p.parse().unwrap(),
                    valid: 2_592_000,
                    preferred: 604_800,
                    on_link: true,
                    autonomous: true,
                    origin: corerouter_engine::ipv6_nd::Origin::Static(ItemId(1)),
                })
                .collect(),
            rdnss: vec!["2001:db8::53".parse().unwrap()],
            dnssl: vec!["isp.example".into()],
            dns_lifetime: 1800,
            warnings: Vec::new(),
        }
    }

    fn links() -> impl FnMut(&IfName) -> Option<Link> {
        |n: &IfName| {
            Some(Link {
                ifindex: n.as_str().bytes().last().map_or(0, u32::from),
                mac: Some([2, 0, 0, 0, 0, 1]),
            })
        }
    }

    fn ra(o: &Out) -> ParsedRa {
        nd::parse_ra_icmp("fe80::1".parse().unwrap(), &o.message).unwrap()
    }

    /// The times of the RAs sent on one interface in `ms`.
    fn times(s: &mut Sender, from: Millis, ms: Millis) -> Vec<Millis> {
        let mut out = Vec::new();
        for t in (from..from + ms).step_by(100) {
            for _ in s.due(t) {
                out.push(t);
            }
        }
        out
    }

    #[test]
    fn initial_ras_then_the_configured_interval() {
        let mut s = Sender::new(7);
        let (joined, _) = s.follow(0, &[advert("lan2", &["2001:db8:2::/64"])], &mut links());
        assert_eq!(joined.len(), 1);
        let t = times(&mut s, 0, 3_000_000);
        // RFC 4861 §6.2.4: the first at once, three ≤ 16 s apart, then
        // 200..600 s.
        assert_eq!(t[0], 0);
        assert!(t[1] - t[0] <= 16_000 && t[2] - t[1] <= 16_000, "{t:?}");
        for w in t[2..].windows(2) {
            assert!((200_000..600_000).contains(&(w[1] - w[0])), "{t:?}");
        }
        let o = &s.due(10_000_000)[0];
        let r = ra(o);
        assert_eq!(r.router_lifetime, 1800);
        assert_eq!(r.sllao, Some([2, 0, 0, 0, 0, 1]));
        assert_eq!(r.prefixes[0].valid, 2_592_000);
        // RFC 8106 §5.1/§5.2.
        assert_eq!(r.rdnss, ["2001:db8::53".parse::<std::net::Ipv6Addr>().unwrap()]);
        assert_eq!(r.dns_lifetime, Some(1800));
        assert!(!r.dnssl_raw.is_empty());
        assert!(r.prefixes[0].autonomous && r.prefixes[0].on_link);
    }

    #[test]
    fn solicitation_is_answered_within_half_a_second_but_not_twice_in_ra_delay() {
        let mut s = Sender::new(3);
        s.follow(0, &[advert("lan2", &["2001:db8:2::/64"])], &mut links());
        // Past the initial ones.
        let _ = times(&mut s, 0, 100_000);
        let ix = u32::from(b'2');
        s.solicited(150_000, ix);
        let at = s.next_due().unwrap();
        assert!((150_000..150_500).contains(&at), "{at}");
        assert_eq!(s.due(at).len(), 1);
        // Another RS right away: not before ra-delay (3 s) after that RA.
        s.solicited(at + 10, ix);
        assert!(s.next_due().unwrap() >= at + 3_000);
        assert_eq!(s.status().interfaces.values().next().unwrap().rs_received, 2);
    }

    #[test]
    fn removed_interface_sends_final_ras_with_lifetime_zero() {
        let mut s = Sender::new(5);
        s.follow(0, &[advert("lan2", &["2001:db8:2::/64"])], &mut links());
        let _ = s.due(0);
        let (_, left) = s.follow(1000, &[], &mut links());
        assert_eq!(left.len(), 1);
        let finals: Vec<Out> = (1000..20_000).step_by(100).flat_map(|t| s.due(t)).collect();
        assert_eq!(finals.len(), usize::from(MAX_FINAL));
        for f in &finals {
            assert!(f.last);
            let r = ra(f);
            // RFC 4861 §6.2.5, and the prefix deprecated (RFC 9096 §3.5).
            assert_eq!(r.router_lifetime, 0);
            assert_eq!(r.dns_lifetime, Some(0), "RFC 8106 §5.1: 0 = stop using them");
            assert_eq!((r.prefixes[0].valid, r.prefixes[0].preferred), (0, 0));
        }
        assert_eq!(s.next_due(), None);
    }

    #[test]
    fn a_prefix_that_leaves_goes_out_three_times_deprecated() {
        let mut s = Sender::new(9);
        s.follow(0, &[advert("lan2", &["2001:db8:2::/64", "2001:db8:22::/64"])], &mut links());
        let _ = times(&mut s, 0, 100_000);
        s.follow(100_000, &[advert("lan2", &["2001:db8:2::/64"])], &mut links());
        assert_eq!(s.status().deprecated.values().next().unwrap().len(), 1);
        let ras: Vec<ParsedRa> = (100_000..400_000).step_by(100).flat_map(|t| s.due(t)).map(|o| ra(&o)).collect();
        let dep = |r: &ParsedRa| r.prefixes.iter().any(|p| p.prefix == "2001:db8:22::".parse::<std::net::Ipv6Addr>().unwrap() && p.valid == 0);
        assert!(ras.len() >= 3);
        assert!(ras[..3].iter().all(dep), "{ras:?}");
        assert!(!ras[3..].iter().any(dep));
        assert!(s.status().deprecated.is_empty());
    }

    #[test]
    fn changed_ra_goes_out_quickly_and_shutdown_says_goodbye() {
        let mut s = Sender::new(11);
        s.follow(0, &[advert("lan2", &["2001:db8:2::/64"])], &mut links());
        let _ = times(&mut s, 0, 100_000);
        let mut a = advert("lan2", &["2001:db8:2::/64"]);
        a.entry.other_configuration = true;
        s.follow(100_000, &[a], &mut links());
        assert!(s.next_due().unwrap() <= 103_000);
        let bye = s.shutdown();
        assert_eq!(bye.len(), 1);
        assert_eq!(ra(&bye[0]).router_lifetime, 0);
    }

    #[test]
    fn dhcp_pd_lifetimes_counting_down_do_not_restart_the_burst() {
        let mut s = Sender::new(13);
        let mut a = advert("lan2", &["2001:db8:2::/64"]);
        a.prefixes[0].origin = corerouter_engine::ipv6_nd::Origin::Pool(ItemId(9));
        s.follow(0, std::slice::from_ref(&a), &mut links());
        let _ = times(&mut s, 0, 100_000);
        let next = s.next_due().unwrap();
        a.prefixes[0].valid -= 100;
        s.follow(100_000, std::slice::from_ref(&a), &mut links());
        assert_eq!(s.next_due(), Some(next), "same schedule");
        let o = s.due(next);
        assert_eq!(ra(&o[0]).prefixes[0].valid, 2_592_000 - 100, "the new lifetime goes out");
    }

    #[test]
    fn other_router_disagreeing_is_reported_once() {
        let mut s = Sender::new(1);
        s.follow(0, &[advert("lan2", &["2001:db8:2::/64"])], &mut links());
        let ix = u32::from(b'2');
        let mut theirs = ParsedRa {
            src: "fe80::99".parse().unwrap(),
            hop_limit: 64,
            other: true,
            ..ParsedRa::default()
        };
        let t = s.other_router(ix, &theirs).unwrap();
        assert!(t.contains("O flag 1 (ours 0)"), "{t}");
        assert_eq!(s.other_router(ix, &theirs), None, "logged once");
        theirs.other = false;
        assert_eq!(s.other_router(ix, &theirs), None);
        assert_eq!(s.status().interfaces.values().next().unwrap().conflict, None);
    }

    #[test]
    fn interface_missing_in_the_kernel_waits() {
        let mut s = Sender::new(1);
        let (j, _) = s.follow(0, &[advert("lan2", &[])], &mut |_: &IfName| None);
        assert!(j.is_empty());
        assert_eq!(s.next_due(), None);
    }
}
