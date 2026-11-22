//! MPLS echo responder (G3.5b, RFC 8029 §4.4): answers LSP ping and
//! traceroute that reach this router, as egress or transit LSR, so the
//! tools work between two CoreRouters (and with Cisco, Junos, Nokia).
//!
//! - On while `/mpls settings lsp-ping-responder` is (the default) and
//!   some interface takes labeled packets; it listens on those.
//! - **Rate limit** (RFC 8029 §5: "A rate limiter SHOULD be applied"): a
//!   token bucket of `lsp-ping-rate` replies per second (burst of one
//!   second's worth), taken *before* any work, so a flood costs the kernel
//!   copy and a counter. A reply is never larger than the request plus the
//!   mappings ([`corerouter_hal::lsp::respond::MAX_REPLY`]) and goes only
//!   to the request's source: no amplification.
//! - The supervisor's thread does all the I/O; the session lock is taken
//!   every 2 s to read the plan and at most once a second to publish the
//!   counters, never around a socket.
//!
//! - **ICMP time exceeded (G3.9d):** the same taps hear labeled packets
//!   whose TTL expires here (the Linux forwarder drops them without an
//!   error, so traceroute showed `*`); `/mpls settings icmp-ttl-exceeded`
//!   (default on) sends the error with the RFC 4950 label stack
//!   (`corerouter_hal::lsp::expired`), behind its own token bucket of
//!   `icmp-rate` per second, also taken before any work.
//! - **ICMP too big (G3.9da):** with `/mpls settings icmp-too-big` (default
//!   on) the MPLS tap also copies frames longer than the smallest way out
//!   of the label table (the kernel drops a labeled packet that does not
//!   fit, silently); `corerouter_hal::lsp::too_big` decides and builds the
//!   fragmentation needed / packet too big.
//! - **Per-source limit (G3.9da):** before the global bucket, one of
//!   `icmp-rate-per-source` per second for the source the error would go
//!   to (as Linux's per-peer `icmp_ratelimit`), so a host flooding TTL 1
//!   costs its own share and another one's traceroute still answers
//!   (`corerouter_hal::lsp::rate`, bounded to 4096 sources).
//!
//! Why one thread: the requests are rare (a few per second when someone
//! traces, 100/s at the limit), each costs ~10 µs (a cached lookup and an
//! encode, **estimado**), and a second core would only share the rate
//! limit. The work per packet that matters is the kernel's (the BPF filter
//! on the MPLS interfaces), see `docs/mpls.md`.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use corerouter_engine::lsp_responder::{self, Counters, IcmpCounters, Plan};
use corerouter_engine::{Shared, lock};
use corerouter_hal::lsp::rate::{Bucket, IcmpLimit, Refused};
use corerouter_hal::lsp::{expired, too_big};
use corerouter_hal::lsp::respond::{Verdict, respond};
use corerouter_hal::lsp::{Frame, LspResponderIo, wire};
use corerouter_model::service::Listen;

/// How often the plan (setting, rate, interfaces) is read again.
const TICK: Duration = Duration::from_secs(2);
/// Longest wait for a request, so a stop or a plan change is noticed.
const WAIT: Duration = Duration::from_millis(500);
/// How often the counters are copied into the session.
const PUBLISH: Duration = Duration::from_secs(1);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "lsp-ping",
    flags: &[],
    topic: "route",
    enable: "mpls.settings.set lsp_ping_responder=yes (the default; idle until an interface takes MPLS)",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| run(&session, health)))
}

/// Whether an error to `to` may go now; counts the refusals.
fn allowed(limit: &mut IcmpLimit, to: Option<IpAddr>, c: &mut IcmpCounters) -> bool {
    match limit.take(to, Instant::now()) {
        Ok(()) => true,
        Err(Refused::Source) => {
            c.rate_limited_source += 1;
            false
        }
        Err(Refused::Global) => {
            c.rate_limited += 1;
            false
        }
    }
}

/// Send `icmp` (or count why not).
fn send_error(
    i: &mut dyn LspResponderIo,
    icmp: Result<expired::Icmp, &'static str>,
    c: &mut IcmpCounters,
) -> bool {
    match icmp {
        Ok(a) => match i.send_icmp(&a) {
            Ok(()) => {
                c.sent += 1;
                true
            }
            Err(err) => {
                c.drop("send failed");
                c.error = Some(err.to_string());
                false
            }
        },
        Err(why) => {
            c.drop(why);
            false
        }
    }
}

fn publish(session: &Shared, c: &Counters) {
    lsp_responder::set_counters(&mut lock(session), c.clone());
}

fn run(session: &Shared, health: &super::Health) -> Result<(), String> {
    let mut io: Option<Box<dyn LspResponderIo>> = None;
    let mut counters = Counters::default();
    let mut bucket = Bucket::new(1, Instant::now());
    let mut limit = IcmpLimit::new(1, 1, Instant::now());
    let mut plan: Option<Plan> = None;
    let mut next_plan = Instant::now();
    let mut published = Instant::now();
    loop {
        if health.stopping() {
            counters.running = false;
            publish(session, &counters);
            return Ok(());
        }
        health.beat();
        let now = Instant::now();
        if now >= next_plan {
            next_plan = now + TICK;
            let p = lsp_responder::plan(&lock(session));
            if !p.enabled {
                if io.take().is_some() || counters.running {
                    counters.running = false;
                    publish(session, &counters);
                }
                health.listen(Vec::new());
                health.disabled(Some(if p.interfaces.is_empty() {
                    "no interface takes MPLS (mpls.interface / mpls.ldp.interface)"
                } else {
                    "lsp_ping_responder=no, icmp_ttl_exceeded=no and icmp_too_big=no"
                }));
                plan = Some(p);
                if !health.sleep(TICK) {
                    return Ok(());
                }
                continue;
            }
            if io.is_none() {
                let opened = lsp_responder::io(&lock(session));
                match opened {
                    Ok(i) => {
                        io = Some(i);
                        health.clear_error();
                    }
                    // The lab: nothing to answer on (its LSPs answer
                    // themselves, `lsp::sim`).
                    Err(corerouter_hal::HalError::Unsupported(why)) => {
                        health.disabled(Some(&why));
                        if !health.sleep(TICK * 30) {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(e) => {
                        health.error(e.to_string());
                        counters.error = Some(e.to_string());
                        publish(session, &counters);
                        if !health.sleep(TICK * 5) {
                            return Ok(());
                        }
                        continue;
                    }
                }
            }
            if plan.as_ref() != Some(&p)
                && let Some(i) = io.as_mut()
            {
                counters.failed = i.set_interfaces(&p.interfaces);
                bucket.set_rate(p.rate);
                i.hear_too_big(p.too_big);
                limit.global.set_rate(p.icmp_rate);
                limit.per_source.set_rate(p.icmp_rate_per_source);
                for (name, why) in &counters.failed {
                    health.error(format!("{name}: {why}"));
                }
                health.disabled(None);
                health.listen(vec![Listen::new(
                    "udp",
                    std::net::SocketAddr::from(([0, 0, 0, 0], wire::PORT)),
                )]);
                health.event(format!("answering on {} interfaces", p.interfaces.len()));
                counters.running = true;
                publish(session, &counters);
            }
            plan = Some(p);
        }
        let Some(i) = io.as_mut() else {
            if !health.sleep(TICK) {
                return Ok(());
            }
            continue;
        };
        let (echo, icmp, big) = plan
            .as_ref()
            .map_or((false, false, false), |p| (p.echo, p.icmp, p.too_big));
        match i.recv(WAIT) {
            Ok(Some(Frame::Expired(e))) if icmp => {
                let c = &mut counters.icmp;
                c.expired += 1;
                // The buckets first, as for echo replies.
                if allowed(&mut limit, expired::origin(&e.packet), c) {
                    let a = expired::answer(&e, i.view());
                    send_error(i.as_mut(), a, c);
                }
            }
            Ok(Some(Frame::TooBig(t))) if big => {
                let c = &mut counters.icmp;
                c.too_big += 1;
                if allowed(&mut limit, too_big::origin(&t), c) {
                    let a = too_big::answer(&t, i.view());
                    if send_error(i.as_mut(), a, c) {
                        c.too_big_sent += 1;
                    }
                }
            }
            Ok(Some(Frame::Expired(_) | Frame::TooBig(_))) => {}
            Ok(Some(Frame::Echo(_))) if !echo => counters.ignored += 1,
            Ok(Some(Frame::Echo(heard))) => {
                counters.heard += 1;
                // The bucket first: a flood costs a counter, nothing more.
                if !bucket.take(Instant::now()) {
                    counters.rate_limited += 1;
                } else {
                    let ntp = i.now_ntp();
                    match respond(&heard, i.view(), ntp) {
                        Verdict::Reply {
                            to,
                            from,
                            tos,
                            payload,
                            return_code,
                        } => match i.send(to, from, tos, &payload) {
                            Ok(()) => {
                                counters.replied += 1;
                                *counters.codes.entry(return_code).or_insert(0) += 1;
                            }
                            Err(e) => counters.error = Some(e.to_string()),
                        },
                        Verdict::Drop(_) => counters.ignored += 1,
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                health.error(e.to_string());
                counters.error = Some(e.to_string());
                if !health.sleep(Duration::from_secs(1)) {
                    return Ok(());
                }
            }
        }
        if published.elapsed() >= PUBLISH {
            published = Instant::now();
            counters.tap = i.tap();
            publish(session, &counters);
        }
    }
}
