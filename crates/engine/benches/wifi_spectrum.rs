//! G1.30i — what a spectral scan costs the engine per tick (250 ms, with
//! the session locked): the samples that arrived laid on the grid and
//! counted into each channel's usage, then the row closed
//! ([`Spectrum::feed`], [`Spectrum::end_frame`]); and, when a window asks,
//! the classification of the last 10 s. An ath9k in background mode sends
//! some 1000 to 4000 samples a second (`spectral_period`, `spectral_count`):
//! 250 to 1000 a tick, 64 bins each.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench wifi_spectrum`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;

use corerouter_engine::wifi_spectrum::{CLASSIFY_ROWS, Range, Spectrum};
use corerouter_hal::wifi::SpectralSample;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// A 20 MHz sample of channel `ch` of 2.4 GHz, a Wi-Fi block at −70 dBm.
fn sample(ch: u32, i: usize) -> SpectralSample {
    let center = (2407 + 5 * ch) as f32;
    let step = 20.0 / 64.0;
    let start = center - 10.0 + step / 2.0;
    SpectralSample {
        tsf: i as u64,
        start_mhz: start,
        step_mhz: step,
        dbm: (0..64)
            .map(|b| {
                if (6..58).contains(&b) && i.is_multiple_of(3) {
                    -70
                } else {
                    -95 - (b % 3) as i8
                }
            })
            .collect(),
    }
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("wifi_spectrum");
    for per_tick in [250usize, 1000] {
        let samples: Vec<SpectralSample> = (0..per_tick)
            .map(|i| sample(1 + (i % 13) as u32, i))
            .collect();
        g.throughput(Throughput::Elements(per_tick as u64));
        g.bench_function(format!("tick_2ghz_{per_tick}_samples"), |b| {
            let mut sp = Spectrum::new(Range::Band(2400, 2500), u64::MAX);
            b.iter(|| {
                sp.feed(black_box(&samples));
                sp.end_frame();
            })
        });
    }
    g.throughput(Throughput::Elements(1));
    let mut sp = Spectrum::new(Range::Band(2400, 2500), u64::MAX);
    let samples: Vec<SpectralSample> = (0..250).map(|i| sample(1 + (i % 13) as u32, i)).collect();
    for _ in 0..CLASSIFY_ROWS {
        sp.feed(&samples);
        sp.end_frame();
    }
    g.bench_function("classify_last_10s_400_points", |b| {
        b.iter(|| black_box(sp.classify(&[])))
    });
    g.bench_function("usage_and_noise", |b| {
        b.iter(|| (black_box(sp.channel_usage()), black_box(sp.noise())))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
