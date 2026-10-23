//! Torch (G6.4a): the traffic of one interface, per flow, live — RouterOS'
//! `/tool torch`.
//!
//! The job reads frames from a [`CaptureSocket`] (AF_PACKET on Linux,
//! simulated in the lab), groups them by the fields the operator picked
//! (src, dst, protocol, ports, VLAN, DSCP, MAC) and, once per interval,
//! emits the rates of the top rows and the totals.
//!
//! Each row is one conversation seen from the interface: `src` is the side
//! the traffic comes from on this interface (the source of what is
//! received, the destination of what is sent), `dst` the far side. So the
//! row of a subscriber on an access port reads "subscriber → site", Rx is
//! what the subscriber sent and Tx what the router sent to them (RouterOS
//! shows a conversation on one line the same way).
//!
//! Above [`SAMPLE_ABOVE_PPS`] the job samples (`sampling: auto`): the
//! socket keeps one frame in N (in the kernel, before any copy) and every
//! kept frame counts N times. The rows are then estimates, flagged so, and
//! the warning says by how much. The interface's own counters (when the
//! backend has them) give the real totals and how much of the traffic the
//! capture saw.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use corerouter_hal::capture::{
    CaptureSocket, CaptureSpec, Decoded, Dir, ETH_P_IPV4, ETH_P_IPV6, FrameBatch, LinkTotals,
    SharedCapture, decode, ethertype_name, mac_text, proto_name,
};
use corerouter_hal::probe::{AsInfo, Lookup, SharedProber};
use ipnet::IpNet;
use serde_json::{Map, Value, json};

use super::mtr::address_scope;
use crate::tasks::TaskCtx;

/// Above this rate (packets per second, both ways) `auto` samples.
pub const SAMPLE_ABOVE_PPS: u64 = 500_000;
/// What sampling aims to leave for the job to read.
const TARGET_PPS: u64 = 250_000;
/// Below this, `auto` stops sampling (hysteresis, so it does not flap).
const SAMPLE_BELOW_PPS: u64 = 300_000;
/// Largest sampling rate.
pub const MAX_SAMPLE: u32 = 4096;
/// Distinct rows held in one interval; past it, the rest is "others".
const MAX_KEYS: usize = 65_536;
/// Frames read per call.
const BATCH: usize = 1024;
/// Longest single wait for frames, so a stop is noticed quickly.
const MAX_WAIT: Duration = Duration::from_millis(100);
/// AS answers kept (cleared when full).
const MAX_AS_CACHE: usize = 4096;
/// The capture sees less than this share of the interface's packets:
/// something drops frames (the socket's buffer, the CPU).
const SEEN_WARN_PCT: f64 = 90.0;

/// Fields rows are grouped by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Group {
    pub src: bool,
    pub dst: bool,
    pub proto: bool,
    pub port: bool,
    pub vlan: bool,
    pub dscp: bool,
    pub mac: bool,
}

/// The names `group` takes, in display order.
pub const GROUP_FIELDS: [&str; 7] = ["src", "dst", "proto", "port", "vlan", "dscp", "mac"];

impl Group {
    pub fn set(&mut self, field: &str) -> bool {
        let slot = match field {
            "src" => &mut self.src,
            "dst" => &mut self.dst,
            "proto" => &mut self.proto,
            "port" => &mut self.port,
            "vlan" => &mut self.vlan,
            "dscp" => &mut self.dscp,
            "mac" => &mut self.mac,
            _ => return false,
        };
        *slot = true;
        true
    }

    pub fn names(&self) -> Vec<&'static str> {
        let on = [
            self.src, self.dst, self.proto, self.port, self.vlan, self.dscp, self.mac,
        ];
        GROUP_FIELDS
            .iter()
            .zip(on)
            .filter_map(|(n, on)| on.then_some(*n))
            .collect()
    }
}

/// Which frames count. Addresses and ports as the rows show them (`src`
/// is the interface's side).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub src: Option<IpNet>,
    pub dst: Option<IpNet>,
    /// Either port.
    pub port: Option<u16>,
    pub proto: Option<u8>,
    pub vlan: Option<u16>,
    pub dscp: Option<u8>,
    pub mac: Option<[u8; 6]>,
}

/// One frame as seen from the interface (`src` = this side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oriented {
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: Option<u8>,
    pub ethertype: u16,
    pub vlan: Option<u16>,
    pub dscp: Option<u8>,
    /// The MAC on this side.
    pub mac: [u8; 6],
}

impl Oriented {
    /// `d` turned so that `src` is this side of the interface. `vlan`: the
    /// VLAN device it came through, which wins over a tag in the frame.
    pub fn of(d: &Decoded, dir: Dir, vlan: Option<u16>) -> Self {
        let rx = dir == Dir::Rx;
        let (src, dst) = if rx { (d.src, d.dst) } else { (d.dst, d.src) };
        let (src_port, dst_port) = if rx {
            (d.src_port, d.dst_port)
        } else {
            (d.dst_port, d.src_port)
        };
        Self {
            src,
            dst,
            src_port,
            dst_port,
            proto: d.proto,
            ethertype: d.ethertype,
            vlan: vlan.or(d.vlan),
            dscp: d.dscp,
            mac: if rx { d.src_mac } else { d.dst_mac },
        }
    }
}

impl Filter {
    pub fn matches(&self, o: &Oriented) -> bool {
        let net = |want: &Option<IpNet>, got: Option<IpAddr>| match want {
            None => true,
            Some(n) => got.is_some_and(|a| n.contains(&a)),
        };
        net(&self.src, o.src)
            && net(&self.dst, o.dst)
            && self
                .port
                .is_none_or(|p| o.src_port == Some(p) || o.dst_port == Some(p))
            && self.proto.is_none_or(|p| o.proto == Some(p))
            && self.vlan.is_none_or(|v| o.vlan == Some(v))
            && self.dscp.is_none_or(|v| o.dscp == Some(v))
            && self.mac.is_none_or(|m| o.mac == m)
    }
}

/// How the job samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    /// 1:N above [`SAMPLE_ABOVE_PPS`], with a warning.
    Auto,
    /// Never: every frame (may drop some at high rates).
    Off,
    /// Always 1 in N.
    Fixed(u32),
}

/// The key of a row: the grouped fields, the others `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    proto: Option<u8>,
    /// For frames that are not IP, with `proto` grouped.
    ethertype: Option<u16>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    vlan: Option<u16>,
    dscp: Option<u8>,
    mac: Option<[u8; 6]>,
}

fn key(g: &Group, o: &Oriented) -> Key {
    let ip = matches!(o.ethertype, ETH_P_IPV4 | ETH_P_IPV6);
    Key {
        src: o.src.filter(|_| g.src),
        dst: o.dst.filter(|_| g.dst),
        proto: o.proto.filter(|_| g.proto && ip),
        ethertype: (g.proto && !ip).then_some(o.ethertype),
        src_port: o.src_port.filter(|_| g.port),
        dst_port: o.dst_port.filter(|_| g.port),
        vlan: o.vlan.filter(|_| g.vlan),
        dscp: o.dscp.filter(|_| g.dscp),
        mac: g.mac.then_some(o.mac),
    }
}

/// Counts of one row in one interval, already scaled by the sampling.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Counts {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
}

impl Counts {
    fn add(&mut self, dir: Dir, bytes: u64, weight: u64) {
        let (b, p) = match dir {
            Dir::Tx => (&mut self.tx_bytes, &mut self.tx_packets),
            Dir::Rx => (&mut self.rx_bytes, &mut self.rx_packets),
        };
        *b = b.saturating_add(bytes.saturating_mul(weight));
        *p = p.saturating_add(weight);
    }

    fn merge(&mut self, o: &Counts) {
        self.tx_bytes = self.tx_bytes.saturating_add(o.tx_bytes);
        self.rx_bytes = self.rx_bytes.saturating_add(o.rx_bytes);
        self.tx_packets = self.tx_packets.saturating_add(o.tx_packets);
        self.rx_packets = self.rx_packets.saturating_add(o.rx_packets);
    }

    fn total_bytes(&self) -> u64 {
        self.tx_bytes.saturating_add(self.rx_bytes)
    }

    /// `{tx_bps, rx_bps, tx_pps, rx_pps}` over `secs`.
    fn rates(&self, secs: f64) -> Map<String, Value> {
        let per = |n: u64, k: f64| (n as f64 * k / secs).round();
        let mut m = Map::new();
        m.insert("tx_bps".into(), json!(per(self.tx_bytes, 8.0)));
        m.insert("rx_bps".into(), json!(per(self.rx_bytes, 8.0)));
        m.insert("tx_pps".into(), json!(per(self.tx_packets, 1.0)));
        m.insert("rx_pps".into(), json!(per(self.rx_packets, 1.0)));
        m
    }
}

pub struct TorchJob {
    pub interface: String,
    pub spec: CaptureSpec,
    pub group: Group,
    pub filter: Filter,
    pub sampling: Sampling,
    /// Stop after this long (`None`: until stopped).
    pub duration: Option<Duration>,
    /// How often rows are emitted (RouterOS' freeze-frame interval).
    pub interval: Duration,
    /// Rows shown; the rest is summed up as "others".
    pub top: usize,
    /// Origin AS of the far side (`dst`), when asked.
    pub as_lookup: Option<SharedProber>,
}

/// The aggregator: frames in, an event per interval out. Separate from the
/// socket so tests feed it frames directly.
pub struct Torch {
    group: Group,
    filter: Filter,
    rows: HashMap<Key, Counts>,
    /// Frames past [`MAX_KEYS`] distinct rows.
    overflow: Counts,
    /// Frames that matched the filter (scaled) / that were read.
    matched: u64,
    read: u64,
    /// Every kept frame counts this many times.
    pub sample: u32,
    as_cache: HashMap<IpAddr, Option<AsInfo>>,
}

impl Torch {
    pub fn new(group: Group, filter: Filter, sample: u32) -> Self {
        Self {
            group,
            filter,
            rows: HashMap::new(),
            overflow: Counts::default(),
            matched: 0,
            read: 0,
            sample: sample.max(1),
            as_cache: HashMap::new(),
        }
    }

    pub fn ingest(&mut self, batch: &FrameBatch) {
        let weight = u64::from(self.sample);
        for (meta, data) in batch.iter() {
            self.read = self.read.saturating_add(weight);
            let Some(d) = decode(data) else { continue };
            let o = Oriented::of(&d, meta.dir, meta.vlan);
            if !self.filter.matches(&o) {
                continue;
            }
            self.matched = self.matched.saturating_add(weight);
            let k = key(&self.group, &o);
            let bytes = u64::from(meta.wire_len);
            if let Some(c) = self.rows.get_mut(&k) {
                c.add(meta.dir, bytes, weight);
            } else if self.rows.len() < MAX_KEYS {
                let mut c = Counts::default();
                c.add(meta.dir, bytes, weight);
                self.rows.insert(k, c);
            } else {
                self.overflow.add(meta.dir, bytes, weight);
            }
        }
    }

    fn origin(&mut self, prober: &SharedProber, ip: IpAddr) -> Option<AsInfo> {
        if address_scope(ip).is_some() {
            return None;
        }
        if let Some(known) = self.as_cache.get(&ip) {
            return known.clone();
        }
        match prober.origin_as(ip) {
            Lookup::Pending => None,
            Lookup::Done(info) => {
                if self.as_cache.len() >= MAX_AS_CACHE {
                    self.as_cache.clear();
                }
                self.as_cache.insert(ip, info.clone());
                info
            }
        }
    }

    /// The interval's event (rates over `secs`), and a fresh interval.
    pub fn flush(&mut self, secs: f64, top: usize, as_lookup: Option<&SharedProber>) -> Value {
        let secs = secs.max(0.001);
        let mut rows: Vec<(Key, Counts)> = self.rows.drain().collect();
        rows.sort_by(|a, b| {
            b.1.total_bytes()
                .cmp(&a.1.total_bytes())
                .then_with(|| (b.1.tx_packets + b.1.rx_packets).cmp(&(a.1.tx_packets + a.1.rx_packets)))
        });
        let mut total = self.overflow;
        for (_, c) in &rows {
            total.merge(c);
        }
        let mut others = self.overflow;
        let mut others_rows = 0usize;
        let mut out = Vec::new();
        for (i, (k, c)) in rows.iter().enumerate() {
            if i >= top {
                others.merge(c);
                others_rows += 1;
                continue;
            }
            let mut r = c.rates(secs);
            let put = |r: &mut Map<String, Value>, name: &str, v: Value| {
                r.insert(name.into(), v);
            };
            if let Some(a) = k.src {
                put(&mut r, "src", json!(a.to_string()));
                put(&mut r, "src_scope", json!(address_scope(a)));
            }
            if let Some(a) = k.dst {
                put(&mut r, "dst", json!(a.to_string()));
                put(&mut r, "dst_scope", json!(address_scope(a)));
                if let Some(info) = as_lookup.and_then(|p| self.origin(p, a)) {
                    put(&mut r, "asn", json!(info.asn));
                    put(&mut r, "as_name", json!(info.name));
                    put(&mut r, "as_prefix", json!(info.prefix));
                }
            }
            if let Some(p) = k.proto {
                put(&mut r, "proto", json!(proto_name(p)));
            }
            if let Some(t) = k.ethertype {
                put(&mut r, "proto", json!(ethertype_name(t)));
            }
            if let Some(p) = k.src_port {
                put(&mut r, "src_port", json!(p));
            }
            if let Some(p) = k.dst_port {
                put(&mut r, "dst_port", json!(p));
            }
            if let Some(v) = k.vlan {
                put(&mut r, "vlan", json!(v));
            }
            if let Some(v) = k.dscp {
                put(&mut r, "dscp", json!(v));
            }
            if let Some(m) = &k.mac {
                put(&mut r, "mac", json!(mac_text(m)));
            }
            out.push(Value::Object(r));
        }
        let mut others_v = others.rates(secs);
        others_v.insert("rows".into(), json!(others_rows));
        others_v.insert("overflow".into(), json!(self.overflow != Counts::default()));
        let ev = json!({
            "rows": out,
            "others": others_v,
            "total": total.rates(secs),
            "matched_pps": (self.matched as f64 / secs).round(),
            "read_pps": (self.read as f64 / secs).round(),
            "sampling": self.sample,
            "estimated": self.sample > 1,
        });
        self.overflow = Counts::default();
        self.matched = 0;
        self.read = 0;
        ev
    }
}

/// The sampling rate `auto` wants at `pps`, given the current one.
pub fn auto_sample(pps: u64, current: u32) -> u32 {
    if current <= 1 {
        if pps <= SAMPLE_ABOVE_PPS {
            return 1;
        }
    } else if pps < SAMPLE_BELOW_PPS {
        return 1;
    }
    let want = pps.div_ceil(TARGET_PPS).clamp(1, u64::from(MAX_SAMPLE));
    let want = u32::try_from(want).unwrap_or(MAX_SAMPLE);
    // Only a change of 2× or more: the rate moves all the time.
    if current > 1 && want < current.saturating_mul(2) && want.saturating_mul(2) > current {
        current
    } else {
        want
    }
}

fn delta(now: &LinkTotals, before: &LinkTotals) -> LinkTotals {
    LinkTotals {
        rx_packets: now.rx_packets.saturating_sub(before.rx_packets),
        tx_packets: now.tx_packets.saturating_sub(before.tx_packets),
        rx_bytes: now.rx_bytes.saturating_sub(before.rx_bytes),
        tx_bytes: now.tx_bytes.saturating_sub(before.tx_bytes),
    }
}

/// Run a Torch until stopped (or `duration`).
pub fn run(job: TorchJob, capture: SharedCapture, ctx: &TaskCtx) -> Result<(), String> {
    let first = match job.sampling {
        Sampling::Fixed(n) => n.clamp(1, MAX_SAMPLE),
        Sampling::Auto | Sampling::Off => 1,
    };
    let mut spec = job.spec.clone();
    spec.sample = first;
    let mut sock: Box<dyn CaptureSocket> = capture.open(&spec).map_err(|e| e.to_string())?;
    let mut torch = Torch::new(job.group, job.filter.clone(), first);
    let mut batch = FrameBatch::new(BATCH);
    let mut kernel_before = sock.totals();
    let start = ctx.now();
    let mut last = start;
    let mut next = start.saturating_add(job.interval);
    let base = json!({
        "interface": job.interface,
        "group": job.group.names(),
        "backend": capture.describe(),
        "interval_ms": job.interval.as_millis() as u64,
    });
    let mut seconds = 0u64;
    loop {
        if ctx.stopped() {
            return Ok(());
        }
        let now = ctx.now();
        if job.duration.is_some_and(|d| now.saturating_sub(start) >= d) {
            return Ok(());
        }
        let wait = next.saturating_sub(now).min(MAX_WAIT);
        batch.clear();
        sock.recv(wait, &mut batch).map_err(|e| e.to_string())?;
        torch.ingest(&batch);
        if !sock.blocks() {
            let spent = ctx.now().saturating_sub(now);
            if spent < wait && !ctx.sleep(wait.saturating_sub(spent)) {
                return Ok(());
            }
        }
        let now = ctx.now();
        if now < next {
            continue;
        }
        let secs = now.saturating_sub(last).as_secs_f64();
        last = now;
        next = next.saturating_add(job.interval).max(now);
        seconds += 1;
        let mut ev = torch.flush(secs, job.top, job.as_lookup.as_ref());
        let kernel_now = sock.totals();
        let mut warnings: Vec<String> = Vec::new();
        let mut real_pps = None;
        if let (Some(k), Some(b), Value::Object(o)) = (&kernel_now, &kernel_before, &mut ev) {
            let d = delta(k, b);
            let per = |n: u64, f: f64| (n as f64 * f / secs.max(0.001)).round();
            o.insert(
                "kernel".into(),
                json!({
                    "tx_bps": per(d.tx_bytes, 8.0), "rx_bps": per(d.rx_bytes, 8.0),
                    "tx_pps": per(d.tx_packets, 1.0), "rx_pps": per(d.rx_packets, 1.0),
                }),
            );
            let pkts = d.rx_packets.saturating_add(d.tx_packets);
            real_pps = Some((pkts as f64 / secs.max(0.001)) as u64);
            let read = o.get("read_pps").and_then(Value::as_f64).unwrap_or(0.0);
            if pkts > 0 {
                let seen = (read * secs / pkts as f64 * 100.0).min(100.0);
                o.insert("seen_pct".into(), json!((seen * 10.0).round() / 10.0));
                // The first interval starts before the socket's first frame.
                if seen < SEEN_WARN_PCT && seconds > 1 && torch.sample == 1 {
                    warnings.push(format!(
                        "the capture saw {seen:.0}% of the interface's packets: \
                         the router could not keep up (sampling: auto helps)"
                    ));
                }
            }
        }
        kernel_before = kernel_now;
        if job.sampling == Sampling::Auto {
            let pps = real_pps.unwrap_or_else(|| {
                ev.get("read_pps").and_then(Value::as_f64).unwrap_or(0.0) as u64
            });
            let want = auto_sample(pps, torch.sample);
            if want != torch.sample && sock.set_sampling(want).is_ok() {
                torch.sample = want;
            }
        }
        if torch.sample > 1 {
            warnings.push(format!(
                "sampling 1:{}: above {} kpps only one packet in {} is read; \
                 rows are estimates",
                torch.sample,
                SAMPLE_ABOVE_PPS / 1000,
                torch.sample
            ));
        }
        if let Value::Object(o) = &mut ev {
            o.insert("t".into(), json!(seconds));
            o.insert("warnings".into(), json!(warnings));
            o.insert("sampling_mode".into(), json!(match job.sampling {
                Sampling::Auto => "auto",
                Sampling::Off => "off",
                Sampling::Fixed(_) => "fixed",
            }));
        }
        let mut summary = ev.clone();
        if let (Value::Object(s), Value::Object(b)) = (&mut summary, &base) {
            for (k, v) in b {
                s.insert(k.clone(), v.clone());
            }
        }
        ctx.summary(summary);
        ctx.emit(ev);
    }
}

/// `12.4Mbps`, as RouterOS prints a rate.
pub fn rate(bps: f64) -> String {
    let (v, unit) = if bps >= 1e9 {
        (bps / 1e9, "Gbps")
    } else if bps >= 1e6 {
        (bps / 1e6, "Mbps")
    } else if bps >= 1e3 {
        (bps / 1e3, "kbps")
    } else {
        (bps, "bps")
    };
    if unit == "bps" {
        format!("{v:.0}{unit}")
    } else {
        format!("{v:.1}{unit}")
    }
}

/// The terminal's column header.
pub fn text_header() -> String {
    format!(
        "{:<5} {:<28} {:<28} {:<6} {:>10} {:>10} {:>8} {:>8}",
        "VLAN", "SRC", "DST", "PROTO", "TX", "RX", "TX-PKTS", "RX-PKTS"
    )
}

/// One interval as terminal lines: the top rows (at most 20) and a total.
pub fn text_line(ev: &Value) -> String {
    let f = |v: &Value, k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    let s = |v: &Value, k: &str| match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    };
    let side = |v: &Value, addr: &str, port: &str| match (s(v, addr), s(v, port)) {
        (a, p) if p.is_empty() => a,
        (a, p) if a.contains(':') => format!("[{a}]:{p}"),
        (a, p) if a.is_empty() => format!(":{p}"),
        (a, p) => format!("{a}:{p}"),
    };
    let mut out = Vec::new();
    let rows = ev.get("rows").and_then(Value::as_array);
    for r in rows.into_iter().flatten().take(20) {
        let mut dst = side(r, "dst", "dst_port");
        if let Some(asn) = r.get("asn").and_then(Value::as_u64) {
            dst = format!("{dst} AS{asn}");
        }
        out.push(format!(
            "{:<5} {:<28} {:<28} {:<6} {:>10} {:>10} {:>8} {:>8}",
            s(r, "vlan"),
            side(r, "src", "src_port"),
            dst,
            s(r, "proto"),
            rate(f(r, "tx_bps")),
            rate(f(r, "rx_bps")),
            f(r, "tx_pps"),
            f(r, "rx_pps"),
        ));
    }
    let t = ev.get("total").unwrap_or(&Value::Null);
    let sampling = ev.get("sampling").and_then(Value::as_u64).unwrap_or(1);
    out.push(format!(
        "{:<5} {:<28} {:<28} {:<6} {:>10} {:>10} {:>8} {:>8}{}",
        "",
        "TOTAL",
        "",
        "",
        rate(f(t, "tx_bps")),
        rate(f(t, "rx_bps")),
        f(t, "tx_pps"),
        f(t, "rx_pps"),
        if sampling > 1 { format!("  (sampled 1:{sampling})") } else { String::new() },
    ));
    out.push(String::new());
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Clock, TaskCell};
    use corerouter_hal::capture::{CaptureDevice, HEADERS_SNAPLEN, SimCapture};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f
    }

    fn group(fields: &[&str]) -> Group {
        let mut g = Group::default();
        for f in fields {
            assert!(g.set(f));
        }
        g
    }

    #[test]
    fn a_conversation_is_one_row_with_tx_and_rx() {
        let mut t = Torch::new(group(&["src", "dst"]), Filter::default(), 1);
        let mut b = FrameBatch::new(16);
        let sub = [100, 64, 0, 9];
        let site = [8, 8, 8, 8];
        // The subscriber sends 2 × 100 B; the router sends back 3 × 1000 B.
        b.push(Duration::ZERO, Dir::Rx, None, 100, &frame(sub, site, 5000, 443));
        b.push(Duration::ZERO, Dir::Rx, None, 100, &frame(sub, site, 5000, 443));
        for _ in 0..3 {
            b.push(Duration::ZERO, Dir::Tx, None, 1000, &frame(site, sub, 443, 5000));
        }
        t.ingest(&b);
        let ev = t.flush(1.0, 10, None);
        let rows = ev["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "{ev}");
        let r = &rows[0];
        assert_eq!((r["src"].as_str(), r["dst"].as_str()), (Some("100.64.0.9"), Some("8.8.8.8")));
        assert_eq!(r["src_scope"], "cgnat");
        assert_eq!((r["rx_bps"].as_f64(), r["tx_bps"].as_f64()), (Some(1600.0), Some(24_000.0)));
        assert_eq!((r["rx_pps"].as_f64(), r["tx_pps"].as_f64()), (Some(2.0), Some(3.0)));
        assert!(r.get("src_port").is_none(), "ports not grouped");
        // A fresh interval after the flush.
        assert_eq!(t.flush(1.0, 10, None)["rows"], json!([]));
    }

    #[test]
    fn grouping_by_port_and_proto_and_filtering() {
        let g = group(&["src", "proto", "port"]);
        let f = Filter {
            dst: Some("8.8.0.0/16".parse().unwrap()),
            port: Some(443),
            ..Filter::default()
        };
        let mut t = Torch::new(g, f, 1);
        let mut b = FrameBatch::new(16);
        b.push(Duration::ZERO, Dir::Rx, None, 60, &frame([10, 0, 0, 1], [8, 8, 8, 8], 1, 443));
        b.push(Duration::ZERO, Dir::Rx, None, 60, &frame([10, 0, 0, 1], [8, 8, 4, 4], 2, 443));
        b.push(Duration::ZERO, Dir::Rx, None, 60, &frame([10, 0, 0, 1], [9, 9, 9, 9], 3, 443));
        b.push(Duration::ZERO, Dir::Rx, None, 60, &frame([10, 0, 0, 1], [8, 8, 8, 8], 4, 80));
        t.ingest(&b);
        let ev = t.flush(1.0, 10, None);
        let rows = ev["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "{ev}");
        assert!(rows.iter().all(|r| r["proto"] == "tcp" && r["dst_port"] == 443 && r.get("dst").is_none()));
        assert_eq!(ev["matched_pps"], 2.0);
        assert_eq!(ev["read_pps"], 4.0);
    }

    #[test]
    fn top_rows_and_the_rest_as_others() {
        let mut t = Torch::new(group(&["src"]), Filter::default(), 1);
        let mut b = FrameBatch::new(64);
        for i in 1..=5u8 {
            for _ in 0..i {
                b.push(Duration::ZERO, Dir::Rx, None, 100, &frame([10, 0, 0, i], [1, 1, 1, 1], 1, 2));
            }
        }
        t.ingest(&b);
        let ev = t.flush(2.0, 2, None);
        let rows = ev["rows"].as_array().unwrap();
        assert_eq!(rows[0]["src"], "10.0.0.5");
        assert_eq!(rows[1]["src"], "10.0.0.4");
        assert_eq!(ev["others"]["rows"], 3);
        // 6 frames of 100 B in 2 s.
        assert_eq!(ev["others"]["rx_bps"], 2400.0);
        assert_eq!(ev["total"]["rx_pps"], 8.0, "7.5, rounded");
    }

    #[test]
    fn sampled_frames_count_n_times() {
        let mut t = Torch::new(group(&["src"]), Filter::default(), 8);
        let mut b = FrameBatch::new(4);
        b.push(Duration::ZERO, Dir::Rx, None, 100, &frame([10, 0, 0, 1], [1, 1, 1, 1], 1, 2));
        t.ingest(&b);
        let ev = t.flush(1.0, 10, None);
        assert_eq!(ev["rows"][0]["rx_pps"], 8.0);
        assert_eq!(ev["estimated"], true);
    }

    #[test]
    fn vlan_from_the_device_wins_and_non_ip_has_its_ethertype() {
        let mut t = Torch::new(group(&["vlan", "proto", "mac"]), Filter::default(), 1);
        let mut b = FrameBatch::new(4);
        b.push(Duration::ZERO, Dir::Rx, Some(42), 60, &frame([10, 0, 0, 1], [1, 1, 1, 1], 1, 2));
        let mut arp = vec![0xFF; 6];
        arp.extend_from_slice(&[2, 0, 0, 0, 0, 9, 0x08, 0x06]);
        b.push(Duration::ZERO, Dir::Rx, None, 60, &arp);
        t.ingest(&b);
        let ev = t.flush(1.0, 10, None);
        let rows = ev["rows"].as_array().unwrap();
        assert!(rows.iter().any(|r| r["vlan"] == 42 && r["proto"] == "tcp" && r["mac"] == "02:00:00:00:00:02"));
        assert!(rows.iter().any(|r| r["proto"] == "arp" && r["mac"] == "02:00:00:00:00:09"));
    }

    #[test]
    fn auto_sampling_has_hysteresis() {
        assert_eq!(auto_sample(100_000, 1), 1);
        assert_eq!(auto_sample(500_000, 1), 1);
        assert_eq!(auto_sample(600_000, 1), 3);
        assert_eq!(auto_sample(450_000, 3), 3, "between the thresholds: keep");
        assert_eq!(auto_sample(700_000, 3), 3, "less than 2× change: keep");
        assert_eq!(auto_sample(2_000_000, 3), 8);
        assert_eq!(auto_sample(250_000, 8), 1);
        assert_eq!(auto_sample(u64::MAX, 1), MAX_SAMPLE);
    }

    /// Simulated time: sleeping moves it on.
    struct FakeClock(AtomicU64);

    impl Clock for FakeClock {
        fn elapsed(&self) -> Duration {
            Duration::from_micros(self.0.load(Ordering::Relaxed))
        }
        fn sleep(&self, d: Duration) {
            self.0.fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        }
    }

    #[test]
    fn the_job_on_simulated_traffic() {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        let ctx = TaskCtx::new(&cell, &clock);
        let job = TorchJob {
            interface: "ether1".into(),
            spec: CaptureSpec {
                devices: vec![CaptureDevice { name: "ether1".into(), vlan: None }],
                snaplen: HEADERS_SNAPLEN,
                sample: 1,
            },
            group: group(&["src", "dst"]),
            filter: Filter::default(),
            sampling: Sampling::Auto,
            duration: Some(Duration::from_secs(3)),
            interval: Duration::from_secs(1),
            top: 64,
            as_lookup: Some(Arc::new(corerouter_hal::SimProber::default())),
        };
        run(job, Arc::new(SimCapture), &ctx).unwrap();
        let (events, summary) = cell.snapshot();
        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(summary["interface"], "ether1");
        assert_eq!(summary["group"], json!(["src", "dst"]));
        assert_eq!(summary["sampling"], 1);
        let rows = summary["rows"].as_array().unwrap();
        assert!(rows.len() >= 5);
        assert!(rows.iter().any(|r| r["dst"] == "8.8.8.8" && r["asn"] == 64_999));
        assert!(rows.iter().any(|r| r["dst"] == "198.19.3.10" && r["as_name"] == "SIM-ACCESS"));
        // The lab's counters match what was read: everything was seen.
        assert_eq!(summary["seen_pct"], 100.0);
        let k = summary["kernel"]["tx_pps"].as_f64().unwrap();
        let t = summary["total"]["tx_pps"].as_f64().unwrap();
        assert!((k - t).abs() <= 1.0, "{k} vs {t}");
    }
}
