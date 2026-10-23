//! Traffic Flow (G4.4b): IPFIX / NetFlow v9 export from the conntrack
//! events, as `/ip traffic-flow` configures it.
//!
//! Two threads, so a slow collector or a table read never makes the
//! kernel drop events:
//!
//! - the **reader** (a helper) only takes events off the netlink socket
//!   and appends them to a queue of fixed size ([`QUEUE`]); when the queue
//!   is full the new events are dropped and counted;
//! - the **exporter** (the service's loop) drains the queue in batches,
//!   runs the meter (`proto-flow`), reads the table for the active and
//!   inactive timeouts, encodes once per collector and sends — outside the
//!   session lock, which it takes once per tick to store the batch and the
//!   status.
//!
//! Only the collectors of the running config get a socket: a target that
//! is removed or disabled loses its socket and its queue at the next tick
//! (nothing goes anywhere else). Over UDP a dead collector shows as send
//! errors (ICMP port unreachable on the connected socket); over TCP the
//! messages wait in a bounded queue while it reconnects.

use std::collections::VecDeque;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::traffic_flow::{IfRouter, port_blocks};
use corerouter_engine::{Shared, lock};
use corerouter_hal::conntrack::{Event, EventSource, TableReader};
use corerouter_model::traffic_flow::{
    FlowState, FlowTarget, FlowTransport, FlowVersion, TargetState, TargetStatus, TrafficFlow,
    TrafficFlowStatus,
};
use corerouter_proto_flow::export::{Config as ExportConfig, DEFAULT_MESSAGE};
use corerouter_proto_flow::{Exporter, Meta, Meter, MeterConfig, Record, Version};

const TICK: Duration = Duration::from_millis(100);
/// Events between the reader and the exporter (about 200 bytes each:
/// 50 MB at most, **estimado**); one second of a very big CGNAT.
pub(crate) const QUEUE: usize = 262_144;
/// Events per `recv` of the reader.
const BATCH: usize = 4096;
/// Events the exporter takes per tick (its work stays bounded).
const DRAIN: usize = 200_000;
/// Messages waiting for a TCP collector, in bytes.
const TCP_QUEUE: usize = 8 << 20;
const RECONNECT: Duration = Duration::from_secs(2);
/// The IPFIX observation domain / v9 source id of this router.
const DOMAIN: u32 = 1;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "traffic-flow",
    flags: &[],
    topic: "firewall",
    enable: "ip.traffic-flow.set enabled=yes",
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The fixed-size queue between the reader and the exporter.
#[derive(Default)]
pub(crate) struct Queue {
    q: Mutex<VecDeque<Event>>,
    dropped: AtomicU64,
    read: AtomicU64,
}

impl Queue {
    pub(crate) fn push(&self, batch: &mut Vec<Event>, cap: usize) {
        self.read.fetch_add(batch.len() as u64, Ordering::Relaxed);
        let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        let room = cap.saturating_sub(q.len());
        if batch.len() > room {
            let lost = batch.len() - room;
            self.dropped.fetch_add(lost as u64, Ordering::Relaxed);
            batch.truncate(room);
        }
        q.extend(batch.drain(..));
    }

    fn take(&self, max: usize, out: &mut Vec<Event>) {
        let mut q = self.q.lock().unwrap_or_else(PoisonError::into_inner);
        let n = q.len().min(max);
        out.extend(q.drain(..n));
    }

    fn len(&self) -> usize {
        self.q.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

/// The reader thread's loop.
fn read_events(mut src: Box<dyn EventSource>, queue: Arc<Queue>, stop: Arc<AtomicBool>, lost: Arc<AtomicU64>) {
    let mut buf = Vec::with_capacity(BATCH);
    let lab = src.name() == "lab";
    while !stop.load(Ordering::Relaxed) {
        let t0 = Instant::now();
        match src.recv(100, BATCH, &mut buf) {
            Ok(()) => {}
            Err(e) => {
                log::warn!("traffic-flow: {e}");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        let n = buf.len();
        queue.push(&mut buf, QUEUE);
        lost.store(src.lost(), Ordering::Relaxed);
        // The lab answers at once: not a busy loop. (The kernel's `recv`
        // waits in `poll`; sleeping there would overrun its buffer.)
        if lab && n < BATCH && t0.elapsed() < Duration::from_millis(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

enum Sock {
    Udp(UdpSocket),
    Tcp {
        stream: Option<TcpStream>,
        queue: VecDeque<Vec<u8>>,
        bytes: usize,
        /// Bytes of the front message already written.
        sent: usize,
        next_try: Instant,
    },
}

/// One collector: its exporter (templates, sequence) and socket.
struct Target {
    cfg: FlowTarget,
    nat_destination: bool,
    exp: Exporter,
    sock: Option<Sock>,
    st: TargetStatus,
    rate: Rate,
}

fn bind_any(dst: IpAddr, src: Option<IpAddr>) -> SocketAddr {
    let ip = src.unwrap_or(if dst.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    });
    SocketAddr::new(ip, 0)
}

impl Target {
    fn new(cfg: FlowTarget, boot_ms: u64, nat_destination: bool) -> Self {
        let exp = Exporter::new(ExportConfig {
            version: match cfg.version {
                FlowVersion::V9 => Version::V9,
                FlowVersion::Ipfix => Version::Ipfix,
            },
            domain: DOMAIN,
            max_size: DEFAULT_MESSAGE,
            refresh_ms: u64::from(cfg.template_timeout) * 1000,
            refresh_packets: cfg.template_refresh,
            stream: cfg.transport == FlowTransport::Tcp,
            boot_ms,
            nat_destination,
        });
        Self {
            st: TargetStatus {
                id: cfg.id,
                state: TargetState::Sending,
                records: 0,
                messages: 0,
                bytes: 0,
                records_per_min: 0,
                template_sends: 0,
                last_template: None,
                queue: 0,
                dropped: 0,
                send_errors: 0,
                last_error: None,
            },
            cfg,
            nat_destination,
            exp,
            sock: None,
            rate: Rate::default(),
        }
    }

    fn dst(&self) -> SocketAddr {
        SocketAddr::new(self.cfg.dst_address, self.cfg.port)
    }

    fn fail(&mut self, e: impl std::fmt::Display) {
        self.st.send_errors += 1;
        self.st.state = TargetState::Error;
        self.st.last_error = Some(e.to_string());
    }

    fn open(&mut self) {
        if self.sock.is_some() {
            return;
        }
        match self.cfg.transport {
            FlowTransport::Udp => {
                let s = UdpSocket::bind(bind_any(self.cfg.dst_address, self.cfg.src_address))
                    .and_then(|s| s.connect(self.dst()).map(|()| s));
                match s {
                    Ok(s) => self.sock = Some(Sock::Udp(s)),
                    Err(e) => self.fail(format!("cannot open the UDP socket: {e}")),
                }
            }
            FlowTransport::Tcp => {
                self.sock = Some(Sock::Tcp {
                    stream: None,
                    queue: VecDeque::new(),
                    bytes: 0,
                    sent: 0,
                    next_try: Instant::now(),
                });
            }
        }
    }

    /// Encode `recs` and send them (or queue them, over TCP).
    fn export(&mut self, now: u64, recs: &[Record], meta: &Meta) {
        self.open();
        self.exp.set_meta(meta.clone());
        let before = self.exp.counters();
        let mut msgs = Vec::new();
        self.exp.encode(now, recs, &mut msgs);
        let after = self.exp.counters();
        if after.template_sends > before.template_sends {
            self.st.template_sends = after.template_sends;
            self.st.last_template = Some(now / 1000);
        }
        let n = recs.len() as u64;
        match self.sock.as_mut() {
            Some(Sock::Udp(s)) => {
                let mut failed = None;
                let mut lost = 0;
                for m in &msgs {
                    match s.send(m) {
                        Ok(_) => {
                            self.st.messages += 1;
                            self.st.bytes += m.len() as u64;
                        }
                        Err(e) => {
                            lost += 1;
                            failed = Some(e);
                        }
                    }
                }
                match failed {
                    Some(e) => {
                        self.st.dropped += lost;
                        self.fail(format!("send to {}: {e}", self.dst()));
                    }
                    None if !msgs.is_empty() => {
                        self.st.state = TargetState::Sending;
                        self.st.last_error = None;
                    }
                    None => {}
                }
                self.st.records += n;
            }
            Some(Sock::Tcp { queue, bytes, .. }) => {
                for m in msgs {
                    if *bytes + m.len() > TCP_QUEUE {
                        self.st.dropped += 1;
                        continue;
                    }
                    *bytes += m.len();
                    queue.push_back(m);
                }
                self.st.records += n;
                self.flush_tcp(now);
            }
            None => self.st.dropped += msgs.len() as u64,
        }
        self.rate.add(now, n);
    }

    /// Connect when due, then write what the queue holds without blocking.
    fn flush_tcp(&mut self, now: u64) {
        let dst = self.dst();
        let mut error: Option<String> = None;
        let due = matches!(
            &self.sock,
            Some(Sock::Tcp { stream: None, next_try, .. }) if Instant::now() >= *next_try
        );
        if due {
            // std cannot bind a TCP client to `src_address`: the route
            // picks the source.
            let res = TcpStream::connect_timeout(&dst, Duration::from_millis(500));
            let mut templates = Vec::new();
            if res.is_ok() {
                // RFC 7011 §8.1: a new connection gets the templates first.
                self.exp.reset_stream();
                self.exp.encode(now, &[], &mut templates);
            }
            if let Some(Sock::Tcp {
                stream,
                queue,
                bytes,
                sent,
                next_try,
            }) = self.sock.as_mut()
            {
                *next_try = Instant::now() + RECONNECT;
                match res {
                    Ok(s) => {
                        let _ = s.set_nonblocking(true);
                        let _ = s.set_nodelay(true);
                        *stream = Some(s);
                        *sent = 0;
                        for m in templates.into_iter().rev() {
                            *bytes += m.len();
                            queue.push_front(m);
                        }
                    }
                    Err(e) => error = Some(format!("connect to {dst}: {e}")),
                }
            }
        }
        let (mut msgs, mut wrote) = (0u64, 0u64);
        let Some(Sock::Tcp {
            stream,
            queue,
            bytes,
            sent,
            ..
        }) = self.sock.as_mut()
        else {
            return;
        };
        if let Some(s) = stream.as_mut() {
            while let Some(front) = queue.front() {
                let rest = front.get(*sent..).unwrap_or(&[]);
                match s.write(rest) {
                    Ok(0) => {
                        error = Some("the collector closed the connection".into());
                        break;
                    }
                    Ok(w) => {
                        *sent += w;
                        if *sent >= front.len() {
                            *bytes = bytes.saturating_sub(front.len());
                            msgs += 1;
                            wrote += front.len() as u64;
                            queue.pop_front();
                            *sent = 0;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => {
                        error = Some(format!("write to {dst}: {e}"));
                        break;
                    }
                }
            }
            if error.is_some() {
                *stream = None;
                *sent = 0;
            }
        }
        let up = stream.is_some();
        self.st.queue = queue.len() as u64;
        self.st.messages += msgs;
        self.st.bytes += wrote;
        match error {
            Some(e) => {
                self.fail(e);
                if !up {
                    self.st.state = TargetState::Connecting;
                }
            }
            None if up => {
                self.st.state = TargetState::Sending;
                self.st.last_error = None;
            }
            None => self.st.state = TargetState::Connecting,
        }
    }
}

/// Keep the unchanged targets, rebuild the changed, drop the removed and
/// disabled (their sockets close with them).
fn sync_targets(targets: &mut Vec<Target>, tf: &TrafficFlow, boot_ms: u64) {
    let wanted: Vec<&FlowTarget> = tf.targets.iter().filter(|t| !t.disabled).collect();
    let dst = tf.nat_events_destination;
    targets.retain(|t| t.nat_destination == dst && wanted.iter().any(|w| **w == t.cfg));
    for w in wanted {
        if !targets.iter().any(|t| t.cfg == *w) {
            targets.push(Target::new(w.clone(), boot_ms, dst));
        }
    }
}

/// Records over the last minute, by second.
#[derive(Default)]
struct Rate(VecDeque<(u64, u64)>);

impl Rate {
    fn add(&mut self, now_ms: u64, n: u64) {
        let sec = now_ms / 1000;
        match self.0.back_mut() {
            Some((s, c)) if *s == sec => *c += n,
            _ => self.0.push_back((sec, n)),
        }
        while self.0.front().is_some_and(|(s, _)| *s + 60 <= sec) {
            self.0.pop_front();
        }
    }

    fn per_min(&self, now_ms: u64) -> u64 {
        let sec = now_ms / 1000;
        self.0
            .iter()
            .filter(|(s, _)| *s + 60 > sec)
            .map(|(_, c)| c)
            .sum()
    }
}

/// A running exporter: the reader, the meter and the collectors.
struct Running {
    stop: Arc<AtomicBool>,
    queue: Arc<Queue>,
    lost: Arc<AtomicU64>,
    table: Box<dyn TableReader>,
    meter: Meter,
    targets: Vec<Target>,
    next_scan: Instant,
    rate: Rate,
    source: String,
    accounting: (Option<bool>, Option<bool>),
    boot_ms: u64,
    /// The router's log read up to here (CGNAT block events).
    log_seq: u64,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn meter_config(tf: &TrafficFlow) -> MeterConfig {
    MeterConfig {
        active_ms: u64::from(tf.active_flow_timeout) * 1000,
        inactive_ms: u64::from(tf.inactive_flow_timeout) * 1000,
        sampling: tf.sampling_interval.max(1),
        max_entries: usize::try_from(tf.cache_entries).unwrap_or(usize::MAX),
        flows: true,
        nat_events: tf.nat_events,
        nat_destination: tf.nat_events_destination,
    }
}

/// How often the table is read: the inactive timeout (at least 10 s), never
/// later than the active one.
fn scan_every(tf: &TrafficFlow) -> Duration {
    let inactive = tf.inactive_flow_timeout.max(10);
    Duration::from_secs(u64::from(inactive.min(tf.active_flow_timeout.max(10))))
}

impl Running {
    fn open(session: &Shared, health: &super::Health, tf: &TrafficFlow) -> Result<Self, String> {
        let src = lock(session).traffic_flow_source()?;
        let source = src.name().to_owned();
        let accounting = src.accounting();
        let table = src.table_reader();
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(Queue::default());
        let lost = Arc::new(AtomicU64::new(0));
        {
            let (stop, queue, lost) = (stop.clone(), queue.clone(), lost.clone());
            health
                .spawn("traffic-flow-reader", move || read_events(src, queue, stop, lost))
                .map_err(|e| format!("cannot start the reader: {e}"))?;
        }
        Ok(Self {
            stop,
            queue,
            lost,
            table,
            meter: Meter::new(meter_config(tf)),
            targets: Vec::new(),
            next_scan: Instant::now(),
            rate: Rate::default(),
            source,
            accounting,
            boot_ms: now_ms(),
            log_seq: lock(session).log_seq(),
        })
    }

    fn tick(&mut self, session: &Shared, tf: &TrafficFlow, router: &IfRouter, meta: &Meta) {
        let cfg = meter_config(tf);
        if *self.meter.config() != cfg {
            self.meter.set_config(cfg);
        }
        sync_targets(&mut self.targets, tf, self.boot_ms);
        let now = now_ms();
        let mut events = Vec::new();
        self.queue.take(DRAIN, &mut events);
        let mut recs = Vec::new();
        for e in &events {
            self.meter.event(e, now, router, &mut recs);
        }
        if Instant::now() >= self.next_scan {
            self.next_scan = Instant::now() + scan_every(tf);
            match self.table.read() {
                Ok((table, complete)) => self.meter.scan(&table, complete, now, router, &mut recs),
                Err(e) => log::warn!("traffic-flow: reading the table: {e}"),
            }
        }
        if tf.nat_events {
            let log = lock(session).log_since(self.log_seq);
            self.log_seq = log.last().map_or(self.log_seq, |e| e.seq);
            recs.extend(port_blocks(&log));
        }
        self.export(now, &recs, meta);
        // G4.4f: the same records to the ClickHouse exporter, if it wants them.
        super::analytics::submit_records(&recs, Some(router));
        if !recs.is_empty() && tf.retention_hours > 0 && tf.retention_records > 0 {
            lock(session).traffic_flow_store(&recs, now);
        }
    }

    fn export(&mut self, now: u64, recs: &[Record], meta: &Meta) {
        for t in &mut self.targets {
            t.export(now, recs, meta);
        }
        self.rate.add(now, recs.len() as u64);
    }

    /// Report what is pending and stop (traffic flow turned off).
    fn finish(mut self, session: &Shared, meta: &Meta) {
        let now = now_ms();
        let mut recs = Vec::new();
        self.meter.flush(now, &mut recs);
        self.export(now, &recs, meta);
        super::analytics::submit_records(&recs, None);
        if !recs.is_empty() {
            lock(session).traffic_flow_store(&recs, now);
        }
    }

    fn status(&self) -> TrafficFlowStatus {
        let now = now_ms();
        let m = self.meter.stats();
        TrafficFlowStatus {
            state: FlowState::Running,
            source: self.source.clone(),
            last_error: None,
            events: self.queue.read.load(Ordering::Relaxed),
            kernel_overruns: self.lost.load(Ordering::Relaxed),
            queue: self.queue.len() as u64,
            queue_size: QUEUE as u64,
            queue_dropped: self.queue.dropped.load(Ordering::Relaxed),
            cache_used: self.meter.len() as u64,
            cache_full: m.cache_full,
            sampled_out: m.sampled_out,
            vanished: m.vanished,
            flows: m.flows,
            nat_events: m.nat_events,
            records_per_min: self.rate.per_min(now),
            accounting: self.accounting.0,
            timestamps: self.accounting.1,
            targets: self
                .targets
                .iter()
                .map(|t| TargetStatus {
                    records_per_min: t.rate.per_min(now),
                    ..t.st.clone()
                })
                .collect(),
            updated: now / 1000,
        }
    }
}

fn run(session: &Shared, health: &super::Health) {
    let mut running: Option<Running> = None;
    let mut cache: Option<(u32, TrafficFlow, IfRouter, Meta)> = None;
    let mut last_status = Instant::now();
    let mut retry = Instant::now();
    while health.sleep(TICK) {
        health.beat();
        // The settings and the interface map, rebuilt only on a new revision.
        {
            let s = lock(session);
            let rev = s.store().current_revision();
            if cache.as_ref().is_none_or(|c| c.0 != rev) {
                let cfg = s.store().running();
                let tf = cfg.ip.traffic_flow.clone();
                let router = IfRouter::new(cfg);
                let meta = Meta {
                    sampling_interval: tf.sampling_interval.max(1),
                    interfaces: router.names(),
                };
                cache = Some((rev, tf, router, meta));
            }
        }
        let Some((_, tf, router, meta)) = cache.as_ref() else {
            continue;
        };
        if !tf.enabled {
            if let Some(r) = running.take() {
                r.finish(session, meta);
                health.event("stopped");
            }
            health.disabled(Some("traffic flow is off (ip.traffic-flow.set enabled=yes)"));
            continue;
        }
        health.disabled(None);
        if running.is_none() && Instant::now() >= retry {
            match Running::open(session, health, tf) {
                Ok(r) => {
                    health.clear_error();
                    health.event(format!("reading {} events", r.source));
                    running = Some(r);
                }
                Err(e) => {
                    retry = Instant::now() + Duration::from_secs(10);
                    health.error(&e);
                    lock(session).traffic_flow_set_status(TrafficFlowStatus {
                        state: FlowState::Error,
                        last_error: Some(e),
                        updated: now_ms() / 1000,
                        ..TrafficFlowStatus::default()
                    });
                }
            }
        }
        let Some(r) = running.as_mut() else { continue };
        r.tick(session, tf, router, meta);
        if last_status.elapsed() >= Duration::from_secs(1) {
            last_status = Instant::now();
            let st = r.status();
            match st.targets.iter().find(|t| t.state == TargetState::Error) {
                Some(t) => health.error(format!(
                    "target {}: {}",
                    t.id,
                    t.last_error.as_deref().unwrap_or("error")
                )),
                None => health.clear_error(),
            }
            lock(session).traffic_flow_set_status(st);
        }
    }
    if let (Some(r), Some((_, _, _, meta))) = (running.take(), cache.as_ref()) {
        r.finish(session, meta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ItemId;
    use corerouter_hal::conntrack::{Conn, EventKind, Tuple};

    fn ev(i: u32) -> Event {
        let a: IpAddr = "100.64.0.1".parse().unwrap();
        Event {
            kind: EventKind::New,
            conn: Conn {
                id: i,
                protocol: 17,
                orig: Tuple { src: a, dst: a, src_port: 1, dst_port: 2 },
                reply: Tuple { src: a, dst: a, src_port: 2, dst_port: 1 },
                status: 0,
                timeout: 0,
                tcp_state: None,
                mark: 0,
                orig_packets: 0,
                orig_bytes: 0,
                reply_packets: 0,
                reply_bytes: 0,
            },
            start_ns: None,
            stop_ns: None,
        }
    }

    #[test]
    fn a_full_queue_drops_and_counts() {
        let q = Queue::default();
        let mut b: Vec<Event> = (0..10).map(ev).collect();
        q.push(&mut b, 6);
        assert_eq!((q.len(), q.dropped.load(Ordering::Relaxed)), (6, 4));
        let mut out = Vec::new();
        q.take(4, &mut out);
        assert_eq!((out.len(), q.len()), (4, 2));
        assert_eq!(out[0].conn.id, 0, "oldest first");
    }

    #[test]
    fn the_rate_is_a_sliding_minute() {
        let mut r = Rate::default();
        r.add(0, 10);
        r.add(30_000, 5);
        assert_eq!(r.per_min(59_000), 15);
        assert_eq!(r.per_min(61_000), 5);
    }

    #[test]
    fn removed_and_disabled_targets_lose_their_socket() {
        let mut tf = TrafficFlow::default();
        let mut a = FlowTarget::new(ItemId(1), "127.0.0.1".parse().unwrap());
        a.port = 9;
        let mut b = a.clone();
        b.id = ItemId(2);
        b.port = 10;
        tf.targets = vec![a, b.clone()];
        let mut targets: Vec<Target> = Vec::new();
        let sync = |targets: &mut Vec<Target>, tf: &TrafficFlow| sync_targets(targets, tf, 0);
        sync(&mut targets, &tf);
        assert_eq!(targets.len(), 2);
        tf.targets[1].disabled = true;
        sync(&mut targets, &tf);
        assert_eq!(targets.len(), 1);
        tf.targets.clear();
        sync(&mut targets, &tf);
        assert!(targets.is_empty());
    }
}
