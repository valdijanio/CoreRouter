//! Packet sniffer (G6.4a): the frames of one interface into a pcap file,
//! for Wireshark — RouterOS' `/tool sniffer`, bounded.
//!
//! The file is built in memory (the engine has no file system: it runs in
//! wasm too) and handed out in pieces by `tool.sniffer.download`. It never
//! grows past its limit nor runs past its duration: a capture left running
//! cannot fill the router's memory. The same filter as Torch picks the
//! frames; `snaplen` cuts each one (headers only by default — payloads are
//! subscribers' data).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use corerouter_hal::capture::{
    CaptureSpec, FrameBatch, PCAP_HEADER_LEN, PCAP_RECORD_HEADER_LEN, SharedCapture, decode,
    pcap_header, pcap_record,
};
use serde_json::json;

use super::torch::{Filter, Oriented};
use crate::tasks::TaskCtx;

/// Frames read per call.
const BATCH: usize = 512;
const MAX_WAIT: Duration = Duration::from_millis(100);

/// A capture file being written, shared with `tool.sniffer.download`.
pub type PcapFile = Arc<Mutex<Vec<u8>>>;

pub struct SnifferJob {
    pub interface: String,
    pub spec: CaptureSpec,
    pub filter: Filter,
    /// The file stops growing at this size (bytes, header included).
    pub limit: usize,
    pub duration: Duration,
    /// Unix time (seconds) when it started, for the packets' timestamps;
    /// `None` without a clock (they then start at 1970).
    pub start_unix: Option<u64>,
    pub file: PcapFile,
}

/// Run the sniffer until its duration, its size limit, or a stop.
pub fn run(job: SnifferJob, capture: SharedCapture, ctx: &TaskCtx) -> Result<(), String> {
    let mut sock = capture.open(&job.spec).map_err(|e| e.to_string())?;
    {
        let mut f = job.file.lock().unwrap_or_else(PoisonError::into_inner);
        f.clear();
        f.extend_from_slice(&pcap_header(job.spec.snaplen));
    }
    let base = Duration::from_secs(job.start_unix.unwrap_or(0));
    let mut batch = FrameBatch::new(BATCH);
    let start = ctx.now();
    let mut next = start.saturating_add(Duration::from_secs(1));
    let (mut packets, mut wire_bytes, mut skipped) = (0u64, 0u64, 0u64);
    let mut full = false;
    let mut record = Vec::new();
    let summary = |packets: u64, wire: u64, skipped: u64, size: usize, end: Option<&str>| {
        json!({
            "interface": job.interface,
            "packets": packets,
            "bytes": wire,
            "file_size": size,
            "limit": job.limit,
            "snaplen": job.spec.snaplen,
            "dropped_by_limit": skipped,
            "duration_s": job.duration.as_secs(),
            "end": end,
        })
    };
    loop {
        let now = ctx.now();
        let end = if ctx.stopped() {
            Some("stopped")
        } else if full {
            Some("file limit reached")
        } else if now.saturating_sub(start) >= job.duration {
            Some("duration reached")
        } else {
            None
        };
        let size = job.file.lock().unwrap_or_else(PoisonError::into_inner).len();
        if let Some(why) = end {
            ctx.summary(summary(packets, wire_bytes, skipped, size, Some(why)));
            return Ok(());
        }
        if now >= next {
            next = next.saturating_add(Duration::from_secs(1)).max(now);
            ctx.emit(json!({
                "t": now.saturating_sub(start).as_secs(),
                "packets": packets,
                "bytes": wire_bytes,
                "file_size": size,
            }));
            ctx.summary(summary(packets, wire_bytes, skipped, size, None));
        }
        let wait = next.saturating_sub(now).min(MAX_WAIT);
        batch.clear();
        sock.recv(wait, &mut batch).map_err(|e| e.to_string())?;
        if !batch.is_empty() {
            let mut f = job.file.lock().unwrap_or_else(PoisonError::into_inner);
            for (meta, data) in batch.iter() {
                let Some(d) = decode(data) else { continue };
                if !job.filter.matches(&Oriented::of(&d, meta.dir, meta.vlan)) {
                    continue;
                }
                if f.len() + PCAP_RECORD_HEADER_LEN + data.len() > job.limit {
                    full = true;
                    skipped += 1;
                    continue;
                }
                record.clear();
                pcap_record(&mut record, base.saturating_add(meta.at), data, meta.wire_len);
                f.extend_from_slice(&record);
                packets += 1;
                wire_bytes += u64::from(meta.wire_len);
            }
        }
        if !sock.blocks() {
            let spent = ctx.now().saturating_sub(now);
            if spent < wait && !ctx.sleep(wait.saturating_sub(spent)) {
                let size = job.file.lock().unwrap_or_else(PoisonError::into_inner).len();
                ctx.summary(summary(packets, wire_bytes, skipped, size, Some("stopped")));
                return Ok(());
            }
        }
    }
}

/// Smallest useful file: the header and one minimal frame.
pub const MIN_LIMIT: usize = PCAP_HEADER_LEN + PCAP_RECORD_HEADER_LEN + 64;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Clock, TaskCell};
    use corerouter_hal::capture::{CaptureDevice, HEADERS_SNAPLEN, SimCapture};
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

    fn job(limit: usize, duration: u64, filter: Filter) -> (SnifferJob, PcapFile) {
        let file: PcapFile = Arc::default();
        (
            SnifferJob {
                interface: "ether1".into(),
                spec: CaptureSpec {
                    devices: vec![CaptureDevice { name: "ether1".into(), vlan: None }],
                    snaplen: HEADERS_SNAPLEN,
                    sample: 1,
                },
                filter,
                limit,
                duration: Duration::from_secs(duration),
                start_unix: Some(1_700_000_000),
                file: Arc::clone(&file),
            },
            file,
        )
    }

    /// Walk the records of a pcap file: (count, every one within snaplen).
    fn records(f: &[u8]) -> usize {
        let mut at = PCAP_HEADER_LEN;
        let mut n = 0;
        while at < f.len() {
            let incl = u32::from_le_bytes(f[at + 8..at + 12].try_into().unwrap()) as usize;
            let orig = u32::from_le_bytes(f[at + 12..at + 16].try_into().unwrap()) as usize;
            assert!(incl <= usize::from(HEADERS_SNAPLEN) && incl <= orig);
            let secs = u32::from_le_bytes(f[at..at + 4].try_into().unwrap());
            assert!(secs >= 1_700_000_000);
            at += PCAP_RECORD_HEADER_LEN + incl;
            n += 1;
        }
        assert_eq!(at, f.len());
        n
    }

    #[test]
    fn stops_at_the_duration_with_a_valid_file() {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        let (j, file) = job(64 << 20, 2, Filter::default());
        run(j, Arc::new(SimCapture), &TaskCtx::new(&cell, &clock)).unwrap();
        let (_, summary) = cell.snapshot();
        assert_eq!(summary["end"], "duration reached");
        let f = file.lock().unwrap();
        assert_eq!(&f[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(records(&f) as u64, summary["packets"].as_u64().unwrap());
        assert!(summary["packets"].as_u64().unwrap() > 1000);
    }

    #[test]
    fn never_grows_past_its_limit() {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        let (j, file) = job(10_000, 60, Filter::default());
        run(j, Arc::new(SimCapture), &TaskCtx::new(&cell, &clock)).unwrap();
        let (_, summary) = cell.snapshot();
        assert_eq!(summary["end"], "file limit reached");
        let f = file.lock().unwrap();
        assert!(f.len() <= 10_000);
        records(&f);
        assert!(clock.elapsed() < Duration::from_secs(2), "stops at once");
    }

    #[test]
    fn the_filter_picks_the_frames() {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        let filter = Filter {
            port: Some(53),
            ..Filter::default()
        };
        let (j, file) = job(64 << 20, 1, filter);
        run(j, Arc::new(SimCapture), &TaskCtx::new(&cell, &clock)).unwrap();
        let f = file.lock().unwrap();
        let mut at = PCAP_HEADER_LEN;
        while at < f.len() {
            let incl = u32::from_le_bytes(f[at + 8..at + 12].try_into().unwrap()) as usize;
            let d = decode(&f[at + 16..at + 16 + incl]).unwrap();
            assert!(d.src_port == Some(53) || d.dst_port == Some(53));
            at += 16 + incl;
        }
        assert!(records(&f) > 10);
    }
}
