//! Tools › Bandwidth Test (G6.4b): a throughput test with the iperf3
//! protocol, against any `iperf3 -s` or another CoreRouter's
//! bandwidth server.
//!
//! The engine has no sockets: the daemon registers a [`BandwidthBackend`]
//! (its iperf3 client) with [`Session::set_bandwidth_backend`]. Without
//! one (the in-process lab of the GUI and the CLI) the test runs on
//! [`SimBandwidth`], deterministic and labelled "simulated". The job turns
//! the backend's per-second [`Sample`]s into task events and a running
//! summary (rates, UDP loss and jitter, the router's CPU), and the
//! [`Outcome`] into the final numbers, including what the far end saw.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use corerouter_proto_iperf::{Direction, Params, Proto};
use serde::Serialize;
use serde_json::{Value, json};

use crate::Session;
use crate::tasks::TaskCtx;

/// Longest test a client may ask for (seconds).
pub const MAX_DURATION: u32 = 300;
/// Samples kept in the summary (one per second: the whole test).
const MAX_SAMPLES: usize = MAX_DURATION as usize + 10;

/// What to test.
#[derive(Debug, Clone, PartialEq)]
pub struct TestRequest {
    /// As typed: an address or a name.
    pub host: String,
    /// The address, when `host` is one.
    pub addr: Option<IpAddr>,
    pub port: u16,
    pub params: Params,
}

/// One second of a test, as this router saw it.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Sample {
    /// Seconds since the test started (end of the interval).
    pub t: f64,
    /// Interval length, seconds.
    pub secs: f64,
    /// Bytes this router sent and received in the interval.
    pub sent: u64,
    pub received: u64,
    /// UDP, receiving: datagrams lost and expected in the interval, and the
    /// running jitter (ms).
    pub lost: Option<u64>,
    pub packets: Option<u64>,
    pub jitter_ms: Option<f64>,
    /// The router's CPU (all cores), percent.
    pub cpu: Option<f64>,
}

/// Totals of one direction at the end.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Way {
    /// Bytes the sender sent and the receiver got.
    pub sent: u64,
    pub received: u64,
    pub secs: f64,
    /// UDP, at the receiver.
    pub lost: Option<u64>,
    pub packets: Option<u64>,
    pub jitter_ms: Option<f64>,
    /// TCP retransmissions at the sender, when it knows them.
    pub retransmits: Option<u64>,
}

/// How a test ended.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Outcome {
    /// Router → server, and server → router (the ones the test had).
    pub upload: Option<Way>,
    pub download: Option<Way>,
    /// The far end's CPU (iperf3 reports its own process; another
    /// CoreRouter the whole machine).
    pub remote_cpu: Option<f64>,
    /// The server's text report, when it sent one.
    pub server_output: Option<String>,
    /// The address actually used.
    pub address: Option<String>,
}

/// Runs a test against `req`. `wait(d)` sleeps up to `d` and is `false`
/// once the task was stopped (`wait(ZERO)` only asks); `on_sample` gets one
/// [`Sample`] per second.
pub trait BandwidthBackend: Send + Sync {
    fn describe(&self) -> String;

    fn run(
        &self,
        req: &TestRequest,
        wait: &dyn Fn(Duration) -> bool,
        on_sample: &mut dyn FnMut(Sample),
    ) -> Result<Outcome, String>;
}

pub type SharedBandwidth = Arc<dyn BandwidthBackend>;

/// The bandwidth server's state, as the daemon reports it.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ServerStatus {
    /// `stopped`, `listening`, `testing`, `failed`.
    pub state: String,
    pub listening: Option<String>,
    pub tests_served: u64,
    pub refused: u64,
    /// The test running now, or the last one: client, protocol, direction,
    /// streams, seconds, bytes, result.
    pub current: Option<Value>,
    pub last: Option<Value>,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Slot {
    backend: Option<SharedBandwidth>,
    server: ServerStatus,
}

impl Session {
    /// Let `tool.bandwidth-test.start` use the daemon's iperf3 client.
    pub fn set_bandwidth_backend(&mut self, b: SharedBandwidth) {
        if let Some(slot) = self.ext_mut::<Slot>() {
            slot.backend = Some(b);
        }
    }

    pub(crate) fn bandwidth_backend(&self) -> Option<SharedBandwidth> {
        self.ext::<Slot>().and_then(|s| s.backend.clone())
    }

    /// What the daemon's bandwidth server is doing (`tool.bandwidth-server.get`).
    pub fn set_bandwidth_server_status(&mut self, st: ServerStatus) {
        if let Some(slot) = self.ext_mut::<Slot>() {
            slot.server = st;
        }
    }

    pub(crate) fn bandwidth_server_status(&self) -> ServerStatus {
        let mut st = self.ext::<Slot>().map(|s| s.server.clone()).unwrap_or_default();
        if st.state.is_empty() {
            // No daemon has reported (the in-process lab): nothing listens.
            st.state = "stopped".into();
        }
        st
    }
}

/// A deterministic network for the lab: TCP fills a 940 Mbit/s path
/// (less for addresses of the lossy tunnel, `198.51.100.0/24`: 40 Mbit/s
/// and 25 % UDP loss, like the simulated pings), UDP gets what it asks up
/// to the path. Rates wobble a little second to second.
#[derive(Debug, Clone, Default)]
pub struct SimBandwidth;

fn sim_path(addr: Option<IpAddr>) -> (f64, f64, f64) {
    // (path bit/s, UDP loss fraction, jitter ms)
    match addr {
        Some(IpAddr::V4(v)) if v.octets()[..3] == [198, 51, 100] => (40e6, 0.25, 4.0),
        _ => (940e6, 0.0, 0.08),
    }
}

impl BandwidthBackend for SimBandwidth {
    fn describe(&self) -> String {
        "simulated (no daemon: the in-process lab)".into()
    }

    fn run(
        &self,
        req: &TestRequest,
        wait: &dyn Fn(Duration) -> bool,
        on_sample: &mut dyn FnMut(Sample),
    ) -> Result<Outcome, String> {
        let p = &req.params;
        let (path, loss, jitter) = sim_path(req.addr);
        let ways: f64 = if p.direction == Direction::Both { 2.0 } else { 1.0 };
        let want = match p.proto {
            Proto::Tcp if p.bandwidth == 0 => path,
            _ => (p.bandwidth as f64 * f64::from(p.parallel)).min(path),
        };
        let (mut up, mut down) = (Way::default(), Way::default());
        for s in 1..=p.time {
            if !wait(Duration::from_secs(1)) {
                break;
            }
            let wobble = 1.0 + 0.03 * (f64::from(s) * 1.7).sin();
            let bytes = (want * wobble / 8.0) as u64;
            let got = match p.proto {
                Proto::Udp => (bytes as f64 * (1.0 - loss)) as u64,
                Proto::Tcp => bytes,
            };
            let sending = p.direction != Direction::Receive;
            let receiving = p.direction != Direction::Send;
            let packets = bytes / u64::from(p.len.max(1));
            let lost = (packets as f64 * loss) as u64;
            if sending {
                up.sent += bytes;
                up.received += got;
                up.secs = f64::from(s);
            }
            if receiving {
                down.sent += bytes;
                down.received += got;
                down.secs = f64::from(s);
            }
            let udp_rx = p.proto == Proto::Udp && receiving;
            on_sample(Sample {
                t: f64::from(s),
                secs: 1.0,
                sent: if sending { bytes } else { 0 },
                received: if receiving { got } else { 0 },
                lost: udp_rx.then_some(lost),
                packets: udp_rx.then_some(packets),
                jitter_ms: udp_rx.then_some(jitter * wobble),
                cpu: Some(8.0 + 14.0 * ways * want / 1e9 * wobble),
            });
        }
        let udp = |w: &mut Way| {
            if p.proto == Proto::Udp {
                let packets = w.sent / u64::from(p.len.max(1));
                w.packets = Some(packets);
                w.lost = Some((packets as f64 * loss) as u64);
                w.jitter_ms = Some(jitter);
            } else {
                w.retransmits = Some(0);
            }
        };
        udp(&mut up);
        udp(&mut down);
        Ok(Outcome {
            upload: (p.direction != Direction::Receive).then_some(up),
            download: (p.direction != Direction::Send).then_some(down),
            remote_cpu: Some(5.0 * ways),
            server_output: None,
            address: req.addr.map(|a| a.to_string()),
        })
    }
}

fn bps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        (bytes as f64 * 8.0 / secs).round()
    }
}

fn way_json(w: &Way) -> Value {
    json!({
        "sent": w.sent,
        "received": w.received,
        "secs": w.secs,
        "sent_bps": bps(w.sent, w.secs),
        "received_bps": bps(w.received, w.secs),
        "lost": w.lost,
        "packets": w.packets,
        "loss_pct": w.lost.zip(w.packets).map(|(l, p)| if p == 0 { 0.0 } else { (l as f64 / p as f64 * 1000.0).round() / 10.0 }),
        "jitter_ms": w.jitter_ms.map(|j| (j * 1000.0).round() / 1000.0),
        "retransmits": w.retransmits,
    })
}

/// The task: run `req` on `backend`, emitting a sample per second.
pub fn run_job(req: TestRequest, backend: SharedBandwidth, ctx: &TaskCtx) -> Result<(), String> {
    let p = req.params.clone();
    let base = json!({
        "address": req.host,
        "port": req.port,
        "protocol": match p.proto { Proto::Tcp => "tcp", Proto::Udp => "udp" },
        "direction": match p.direction { Direction::Send => "send", Direction::Receive => "receive", Direction::Both => "both" },
        "streams": p.parallel,
        "duration": p.time,
        "bandwidth": p.bandwidth,
        "backend": backend.describe(),
    });
    let mut samples: Vec<Value> = Vec::new();
    let (mut sent, mut received, mut secs) = (0u64, 0u64, 0.0f64);
    let (mut cpu_sum, mut cpu_n, mut cpu_max) = (0.0f64, 0u32, 0.0f64);
    let (mut peak_tx, mut peak_rx) = (0.0f64, 0.0f64);
    let summary = |samples: &[Value], extra: Value| {
        let mut s = base.clone();
        if let (Value::Object(o), Value::Object(e)) = (&mut s, extra) {
            o.extend(e);
            o.insert("samples".into(), json!(samples));
        }
        s
    };
    let wait = |d: Duration| if d.is_zero() { !ctx.stopped() } else { ctx.sleep(d) };
    let mut on_sample = |s: Sample| {
        sent += s.sent;
        received += s.received;
        secs = s.t;
        let tx = bps(s.sent, s.secs);
        let rx = bps(s.received, s.secs);
        peak_tx = peak_tx.max(tx);
        peak_rx = peak_rx.max(rx);
        if let Some(c) = s.cpu {
            cpu_sum += c;
            cpu_n += 1;
            cpu_max = cpu_max.max(c);
        }
        let ev = json!({
            "t": s.t,
            "tx_bps": tx,
            "rx_bps": rx,
            "lost": s.lost,
            "packets": s.packets,
            "jitter_ms": s.jitter_ms.map(|j| (j * 1000.0).round() / 1000.0),
            "cpu": s.cpu.map(|c| (c * 10.0).round() / 10.0),
        });
        if samples.len() < MAX_SAMPLES {
            samples.push(ev.clone());
        }
        ctx.emit(ev);
        ctx.summary(summary(
            &samples,
            totals_json(sent, received, secs, peak_tx, peak_rx, cpu_sum, cpu_n, cpu_max),
        ));
    };
    let outcome = backend.run(&req, &wait, &mut on_sample);
    let last = totals_json(sent, received, secs, peak_tx, peak_rx, cpu_sum, cpu_n, cpu_max);
    match outcome {
        Ok(o) => {
            let mut extra = last;
            if let Value::Object(e) = &mut extra {
                e.insert("upload".into(), o.upload.as_ref().map_or(Value::Null, way_json));
                e.insert("download".into(), o.download.as_ref().map_or(Value::Null, way_json));
                e.insert("remote_cpu".into(), json!(o.remote_cpu.map(|c| (c * 10.0).round() / 10.0)));
                e.insert("server_output".into(), json!(o.server_output));
                e.insert("resolved".into(), json!(o.address));
            }
            ctx.summary(summary(&samples, extra));
            Ok(())
        }
        Err(e) => {
            ctx.summary(summary(&samples, last));
            if ctx.stopped() { Ok(()) } else { Err(e) }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn totals_json(
    sent: u64,
    received: u64,
    secs: f64,
    peak_tx: f64,
    peak_rx: f64,
    cpu_sum: f64,
    cpu_n: u32,
    cpu_max: f64,
) -> Value {
    json!({
        "tx_avg_bps": bps(sent, secs),
        "rx_avg_bps": bps(received, secs),
        "tx_peak_bps": peak_tx,
        "rx_peak_bps": peak_rx,
        "cpu_avg": (cpu_n > 0).then(|| (cpu_sum / f64::from(cpu_n) * 10.0).round() / 10.0),
        "cpu_max": (cpu_n > 0).then_some((cpu_max * 10.0).round() / 10.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Clock, TaskCell};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FakeClock(AtomicU64);

    impl Clock for FakeClock {
        fn elapsed(&self) -> Duration {
            Duration::from_micros(self.0.load(Ordering::Relaxed))
        }
        fn sleep(&self, d: Duration) {
            self.0.fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        }
    }

    fn req(proto: Proto, direction: Direction, bandwidth: u64, addr: &str) -> TestRequest {
        TestRequest {
            host: addr.into(),
            addr: addr.parse().ok(),
            port: 5201,
            params: Params {
                proto,
                direction,
                time: 3,
                bandwidth,
                len: 1460,
                ..Params::default()
            },
        }
    }

    #[test]
    fn simulated_tcp_both_ways() {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        let ctx = TaskCtx::new(&cell, &clock);
        run_job(req(Proto::Tcp, Direction::Both, 0, "192.0.2.9"), Arc::new(SimBandwidth), &ctx).unwrap();
        let (events, s) = cell.snapshot();
        assert_eq!(events.len(), 3);
        assert_eq!(s["samples"].as_array().unwrap().len(), 3);
        let up = s["upload"]["received_bps"].as_f64().unwrap();
        assert!((900e6..980e6).contains(&up), "{up}");
        assert!(s["download"]["received_bps"].as_f64().unwrap() > 900e6);
        assert!(s["cpu_avg"].as_f64().unwrap() > 0.0);
        assert_eq!(s["direction"], "both");
        assert_eq!(s["remote_cpu"], 10.0);
    }

    #[test]
    fn simulated_udp_loss_on_the_lossy_tunnel() {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        let ctx = TaskCtx::new(&cell, &clock);
        run_job(req(Proto::Udp, Direction::Receive, 10_000_000, "198.51.100.7"), Arc::new(SimBandwidth), &ctx).unwrap();
        let (events, s) = cell.snapshot();
        assert!(events.iter().all(|e| e["lost"].as_u64().unwrap() > 0));
        assert_eq!(s["download"]["loss_pct"], 25.0);
        assert!(s["upload"].is_null(), "receive only");
        assert!(s["download"]["jitter_ms"].as_f64().unwrap() > 1.0);
    }
}
