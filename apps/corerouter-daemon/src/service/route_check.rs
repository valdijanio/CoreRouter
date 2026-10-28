//! Check-gateway of static routes (G1.27f): the probes, on this service's
//! own thread, outside the session lock.
//!
//! Once a second the thread asks the engine for the targets
//! (`Session::route_check_targets`: the routes grouped by method, gateway
//! and table — N routes through one gateway, one probe) and hands what the
//! probes found to `Session::route_check_report`, which keeps the state
//! machine and moves the routes in the data plane. In between, the lock is
//! not taken: [`Schedule`] says which probe leaves when (spread over the
//! interval by a hash of the target, so 1 000 gateways are 100 probes a
//! second, not 1 000 at once), and the sockets are this thread's:
//!
//! - `ping`: one ICMP socket per device (none, the `ip%interface`
//!   interface, or the VRF) for every gateway behind it; replies are
//!   matched by sequence number and source;
//! - `arp`: one `AF_PACKET` socket per interface; any ARP frame from the
//!   gateway (reply or announcement) is an answer.
//!
//! `bfd` sends nothing here: the `bfd` service runs the sessions and the
//! engine follows their state.
//!
//! Why one thread: a probe costs a `sendto` and its reply a `recvfrom`
//! (a few µs, **medido** in `docs/perf.md`); 1 000 gateways every 10 s
//! keep the thread under 1 % of a core, so a second thread would only add
//! a lock around the schedule.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use corerouter_engine::gateway_check::{
    CHECK_INTERVAL_MS, CHECK_WAIT_MS, Due, ProbeHow, Schedule, Target,
};
use corerouter_engine::{Shared, lock};
use corerouter_hal::neigh::ArpPinger;
use corerouter_hal::probe::{Probe, ProbeError, ProbeSocket, ReplyKind, SharedProber, SocketOptions, overhead};
use corerouter_model::IfName;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "route-check",
    flags: &[super::Flag {
        name: "--route-check-interval",
        value: Some("<ms>"),
        help: "check-gateway interval of static routes (default 10000, as RouterOS; 100..=60000)",
    }],
    topic: "route",
    enable: "ip.route.add check_gateway=ping|arp|bfd",
    depends: &[],
    start,
};

/// How often the thread wakes to send due probes and read replies: the
/// probes leave at most this late (**medido**, `## perf` of G1.27f).
const TICK: Duration = Duration::from_millis(20);
const SYNC_EVERY: Duration = Duration::from_secs(1);
/// Replies read per socket per tick.
const RECV_BUDGET: usize = 4096;

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let interval = match ctx.flag("--route-check-interval").filter(|v| !v.is_empty()) {
        None => CHECK_INTERVAL_MS,
        Some(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| (100..=60_000).contains(n))
            .ok_or_else(|| format!("--route-check-interval {v:?}: 100..=60000 ms"))?,
    };
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, interval, health);
        Ok(())
    }))
}

/// The thread's sockets.
#[derive(Default)]
struct Sockets {
    prober: Option<SharedProber>,
    ping: HashMap<Option<String>, Box<dyn ProbeSocket>>,
    arp: HashMap<IfName, Box<dyn ArpPinger>>,
}

fn run(session: &Shared, interval: u64, health: &super::Health) {
    let start = Instant::now();
    let ms = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut sched = Schedule::new(interval, CHECK_WAIT_MS.min(interval / 2));
    let mut socks = Sockets::default();
    let mut results: Vec<(Target, bool)> = Vec::new();
    let mut arp_buf = Vec::new();
    let mut sync_at: Option<Instant> = None;
    while health.sleep(TICK) {
        health.beat();
        if sync_at.is_none_or(|t| t.elapsed() >= SYNC_EVERY) {
            sync_at = Some(Instant::now());
            sync(session, &mut sched, &mut socks, ms(), health);
        }
        if sched.is_empty() {
            continue;
        }
        let now = ms();
        for d in sched.due(now) {
            send(&mut sched, &mut socks, d, &mut results);
        }
        collect(&mut sched, &mut socks, &mut results, &mut arp_buf);
        results.extend(sched.expired(ms()).into_iter().map(|t| (t, false)));
        if !results.is_empty() {
            lock(session).route_check_report(&results, None);
            results.clear();
        }
    }
}

/// Take the targets from the engine; open the sockets new ones need and
/// close the ones nobody uses any more.
fn sync(session: &Shared, sched: &mut Schedule, socks: &mut Sockets, now: u64, health: &super::Health) {
    let (targets, prober, pingers) = {
        let mut s = lock(session);
        let targets = s.route_check_targets(None);
        let prober = if socks.prober.is_none()
            && targets.iter().any(|t| matches!(t.how, ProbeHow::Ping { .. }))
        {
            Some(s.route_check_prober())
        } else {
            None
        };
        let mut pingers = Vec::new();
        for t in &targets {
            if let ProbeHow::Arp { link, .. } = &t.how
                && !socks.arp.contains_key(link)
                && !pingers.iter().any(|(l, _)| l == link)
            {
                pingers.push((link.clone(), s.route_check_arp(link)));
            }
        }
        (targets, prober, pingers)
    };
    match prober {
        Some(Ok(p)) => socks.prober = Some(p),
        Some(Err(e)) => health.error(format!("no ICMP prober: {e}")),
        None => {}
    }
    for (link, p) in pingers {
        match p {
            Ok(p) => {
                socks.arp.insert(link, p);
            }
            Err(e) => log::warn!("check-gateway: no ARP socket on {link}: {e}"),
        }
    }
    socks.arp.retain(|l, _| targets.iter().any(|t| matches!(&t.how, ProbeHow::Arp { link, .. } if link == l)));
    socks.ping.retain(|d, _| {
        targets
            .iter()
            .any(|t| matches!(&t.how, ProbeHow::Ping { device } if device == d))
    });
    let n = targets.len();
    sched.sync(targets, now);
    if n == 0 {
        health.disabled(Some("no static route has check_gateway=ping or arp"));
    } else {
        health.disabled(None);
        let avg = sched.late_ms_sum.checked_div(sched.sent).unwrap_or(0);
        health.event(format!(
            "{n} gateways every {} s; probes late {avg} ms on average, {} ms at most",
            sched.interval_ms / 1000,
            sched.late_ms_max
        ));
    }
}

fn send(sched: &mut Schedule, socks: &mut Sockets, d: Due, results: &mut Vec<(Target, bool)>) {
    match &d.how {
        ProbeHow::Ping { device } => {
            if !socks.ping.contains_key(device) {
                let Some(prober) = socks.prober.as_ref() else {
                    sched.lost(&d.target);
                    results.push((d.target, false));
                    return;
                };
                let options = SocketOptions {
                    device: device.clone(),
                    ..SocketOptions::default()
                };
                match prober.open(&options) {
                    Ok(sock) => {
                        socks.ping.insert(device.clone(), sock);
                    }
                    Err(e) => {
                        log::warn!("check-gateway: no ICMP socket ({}): {e}", device.as_deref().unwrap_or("main"));
                        sched.lost(&d.target);
                        results.push((d.target, false));
                        return;
                    }
                }
            }
            let probe = Probe {
                dst: d.target.gateway,
                seq: d.seq,
                ttl: None,
                size: overhead(d.target.gateway).saturating_add(28),
            };
            let sent = socks.ping.get_mut(device).map(|s| s.send(&probe));
            match sent {
                Some(Ok(())) => {}
                // "No route", "too big": an answer for this probe — a miss.
                Some(Err(ProbeError::Unreachable(_) | ProbeError::TooBig(_))) => {
                    sched.lost(&d.target);
                    results.push((d.target, false));
                }
                Some(Err(e)) => {
                    log::debug!("check-gateway: ping {}: {e}", d.target.gateway);
                    socks.ping.remove(device);
                    sched.lost(&d.target);
                    results.push((d.target, false));
                }
                None => {
                    sched.lost(&d.target);
                    results.push((d.target, false));
                }
            }
        }
        ProbeHow::Arp { link, src } => {
            let IpAddr::V4(gw) = d.target.gateway else {
                sched.lost(&d.target);
                results.push((d.target, false));
                return;
            };
            let Some(p) = socks.arp.get_mut(link) else {
                sched.lost(&d.target);
                results.push((d.target, false));
                return;
            };
            match p.request(*src, gw) {
                Ok(true) => {}
                // A pinger without batch (the virtual lab answers at once).
                Ok(false) => {
                    let answered = p
                        .ping(*src, gw, Duration::from_millis(1))
                        .ok()
                        .flatten()
                        .is_some();
                    if answered {
                        results.extend(sched.arp(link, gw).into_iter().map(|t| (t, true)));
                    } else {
                        sched.lost(&d.target);
                        results.push((d.target, false));
                    }
                }
                Err(e) => {
                    log::debug!("check-gateway: arp {gw} on {link}: {e}");
                    // The interface may be gone or renamed: open it again
                    // at the next sync.
                    socks.arp.remove(link);
                    sched.lost(&d.target);
                    results.push((d.target, false));
                }
            }
        }
        ProbeHow::Unreachable(_) => {
            sched.lost(&d.target);
            results.push((d.target, false));
        }
    }
}

/// Read every socket's replies without waiting.
fn collect(
    sched: &mut Schedule,
    socks: &mut Sockets,
    results: &mut Vec<(Target, bool)>,
    arp_buf: &mut Vec<(Ipv4Addr, [u8; 6])>,
) {
    let mut broken = Vec::new();
    for (device, sock) in &mut socks.ping {
        for _ in 0..RECV_BUDGET {
            match sock.recv(Duration::ZERO) {
                Ok(Some(r)) => {
                    if r.kind == ReplyKind::Echo
                        && let Some(t) = sched.echo(r.from, r.seq)
                    {
                        results.push((t, true));
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    log::debug!("check-gateway: ICMP socket: {e}");
                    broken.push(device.clone());
                    break;
                }
            }
        }
    }
    for d in broken {
        socks.ping.remove(&d);
    }
    for (link, p) in &mut socks.arp {
        arp_buf.clear();
        if p.replies(arp_buf).is_err() {
            continue;
        }
        for (ip, _mac) in arp_buf.iter() {
            results.extend(sched.arp(link, *ip).into_iter().map(|t| (t, true)));
        }
    }
}
