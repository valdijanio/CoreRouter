//! G1.30j — the Wi-Fi snooper's cost per frame a monitor hands over: the
//! radiotap and 802.11 parsers, the estimate of airtime, and the table
//! (the transmitter's and the station's entries in hash maps). This is
//! what the sniffer's thread pays for every frame (the socket's own cost
//! is one `recvmsg`, as Torch's).
//!
//! Frames: the lab's air on channel 44 (`lab_wifi_air`: beacons, Wi-Fi
//! 4/5/6 data, ACKs, a deauthentication and a handshake), and the same with
//! 4096 stations already in the table, to show the cost does not grow with
//! it.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench wifi_snoop`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::time::Duration;

use corerouter_engine::tools::wifi_snoop::Snooper;
use corerouter_hal::capture::FrameBatch;
use corerouter_hal::ieee80211::{self, RadioSpec};
use corerouter_hal::lab_wifi::LabWifi;
use corerouter_hal::lab_wifi_air::LabMonitor;
use corerouter_hal::wifi_monitor::{MonitorMode, MonitorSpec, WifiMonitor};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// 5 s of the lab's air on 5220 MHz.
fn frames() -> Vec<Vec<u8>> {
    let w = LabWifi::default();
    w.add_radio("wifi1".parse().unwrap());
    let m = LabMonitor::new(w);
    let mut s = m
        .open(&MonitorSpec {
            radio: "wifi1".into(),
            mode: MonitorMode::Exclusive,
            freq_mhz: Some(5220),
            width_mhz: 20,
        })
        .unwrap();
    let mut out = Vec::new();
    for _ in 0..50 {
        let mut b = FrameBatch::new(4096);
        s.recv(Duration::from_millis(100), &mut b).unwrap();
        out.extend(b.iter().map(|(_, d)| d.to_vec()));
    }
    out
}

/// A table that already holds `n` stations (probe requests from each).
fn crowded(n: u32) -> Snooper {
    let mut s = Snooper::default();
    for i in 0..n {
        let m = i.to_be_bytes();
        let mut d = Vec::new();
        ieee80211::build_radiotap(
            &mut d,
            &RadioSpec {
                freq_mhz: 5220,
                rate_500k: 12,
                ..RadioSpec::default()
            },
        );
        d.extend_from_slice(&[0x40, 0, 0, 0]);
        d.extend_from_slice(&[0xff; 6]);
        d.extend_from_slice(&[2, 0x77, m[0], m[1], m[2], m[3]]);
        d.extend_from_slice(&[0xff; 6]);
        d.extend_from_slice(&[0, 0]);
        s.add(0, &d, 5220);
    }
    s
}

fn per_frame(c: &mut Criterion) {
    let air = frames();
    let mut g = c.benchmark_group("wifi_snoop");
    g.throughput(Throughput::Elements(air.len() as u64));
    g.bench_function("parse_only", |b| {
        b.iter(|| {
            for d in &air {
                let r = ieee80211::radiotap(black_box(d)).unwrap();
                let f = ieee80211::frame(d.get(r.len..).unwrap(), r.fcs_len()).unwrap();
                black_box((ieee80211::info(&f), ieee80211::airtime_us(&r, d.len())));
            }
        });
    });
    let mut small = Snooper::default();
    g.bench_function("table_lab", |b| {
        b.iter(|| {
            for (i, d) in air.iter().enumerate() {
                black_box(small.add(i as u64, black_box(d), 5220));
            }
        });
    });
    let mut big = crowded(4096);
    g.bench_function("table_4096_stations", |b| {
        b.iter(|| {
            for (i, d) in air.iter().enumerate() {
                black_box(big.add(i as u64, black_box(d), 5220));
            }
        });
    });
    g.finish();
    // The once-a-second cost: the table into JSON.
    let mut g = c.benchmark_group("wifi_snoop_snapshot");
    g.bench_function("lab", |b| b.iter(|| black_box(small.snapshot())));
    g.bench_function("4096_stations", |b| b.iter(|| black_box(big.snapshot())));
    g.finish();
}

criterion_group!(benches, per_frame);
criterion_main!(benches);
