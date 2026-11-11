//! G1.30i — what reading the elements of one access point costs: the hex
//! of `BSS <n>` (`ie=`) decoded and walked for the channel, the generation
//! and the BSS Load ([`ie::from_hex`], [`ie::parse`]). Paid once per access
//! point per scan (at most 256), off the engine's lock (in the radio's
//! thread), so it bounds nothing on the data path; measured to say so.
//!
//! ```sh
//! cargo bench -p corerouter-hal --bench wifi_ie
//! ```

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;

use corerouter_hal::lab_wifi::{LabChannel, elements};
use corerouter_hal::wifi::ie;
use criterion::{Criterion, criterion_group, criterion_main};

/// A Wi-Fi 7 access point's elements, 160 MHz, with BSS Load, padded with
/// vendor elements to the size of a real one (some 500 bytes: the access
/// point the HAL tests read is 260 bytes without its vendor elements).
fn hex() -> String {
    let mut ies = elements(
        5500,
        LabChannel {
            width_mhz: 160,
            center_mhz: 5570,
            generation: 7,
            load: Some((12, 90)),
        },
    );
    while ies.len() < 500 {
        ies.extend([221, 30]);
        ies.extend([0x50u8; 30]);
    }
    ies.iter().map(|b| format!("{b:02x}")).collect()
}

fn bench(c: &mut Criterion) {
    let text = hex();
    let bytes = ie::from_hex(&text).unwrap();
    assert_eq!(ie::parse(&bytes, 5500).width_mhz, 160);
    c.bench_function("wifi_ie/hex_and_parse_500_bytes", |b| {
        b.iter(|| ie::parse(&ie::from_hex(black_box(&text)).unwrap(), 5500))
    });
    c.bench_function("wifi_ie/parse_500_bytes", |b| {
        b.iter(|| ie::parse(black_box(&bytes), 5500))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
