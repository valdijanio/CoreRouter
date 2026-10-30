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
//!
//! Why one thread: the requests are rare (a few per second when someone
//! traces, 100/s at the limit), each costs ~10 µs (a cached lookup and an
//! encode, **estimado**), and a second core would only share the rate
//! limit. The work per packet that matters is the kernel's (the BPF filter
//! on the MPLS interfaces), see `docs/mpls.md`.

use std::time::{Duration, Instant};

use corerouter_engine::lsp_responder::{self, Counters, Plan};
use corerouter_engine::{Shared, lock};
use corerouter_hal::lsp::expired;
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

/// A token bucket: `rate` per second, at most `rate` saved.
struct Bucket {
    rate: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn new(rate: u32) -> Self {
        Self {
            rate: f64::from(rate.max(1)),
            tokens: f64::from(rate.max(1)),
            at: Instant::now(),
        }
    }

    fn set_rate(&mut self, rate: u32) {
        self.rate = f64::from(rate.max(1));
        self.tokens = self.tokens.min(self.rate);
    }

    fn take(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
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
    let mut bucket = Bucket::new(1);
    let mut icmp_bucket = Bucket::new(1);
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
                    "lsp_ping_responder=no and icmp_ttl_exceeded=no"
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
                icmp_bucket.set_rate(p.icmp_rate);
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
        let (echo, icmp) = plan.as_ref().map_or((false, false), |p| (p.echo, p.icmp));
        match i.recv(WAIT) {
            Ok(Some(Frame::Expired(e))) if icmp => {
                let c = &mut counters.icmp;
                c.expired += 1;
                // The bucket first, as for echo replies.
                if !icmp_bucket.take(Instant::now()) {
                    c.rate_limited += 1;
                } else {
                    match expired::answer(&e, i.view()) {
                        Ok(a) => match i.send_icmp(&a) {
                            Ok(()) => c.sent += 1,
                            Err(err) => {
                                c.drop("send failed");
                                c.error = Some(err.to_string());
                            }
                        },
                        Err(why) => c.drop(why),
                    }
                }
            }
            Ok(Some(Frame::Expired(_))) => {}
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
            publish(session, &counters);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bucket_allows_the_rate_and_a_one_second_burst() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10);
        b.at = t0;
        let burst = (0..50).filter(|_| b.take(t0)).count();
        assert_eq!(burst, 10);
        // Half a second later: 5 more.
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!((0..50).filter(|_| b.take(t1)).count(), 5);
        // Never more than a second's worth saved.
        let t2 = t1 + Duration::from_secs(60);
        assert_eq!((0..50).filter(|_| b.take(t2)).count(), 10);
        b.set_rate(2);
        let t3 = t2 + Duration::from_secs(5);
        assert_eq!((0..50).filter(|_| b.take(t3)).count(), 2);
    }
}
