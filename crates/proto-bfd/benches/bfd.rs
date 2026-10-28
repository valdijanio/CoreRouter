//! G3.6 — the per-packet work of the BFD engine: decode, Keyed SHA1
//! sign/verify, one received packet through the session machine, and a
//! thread's timer wheel with 1 000 sessions at 50 ms (one second of
//! timers: 20 000 transmissions).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-bfd --bench bfd`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;

use corerouter_proto_bfd::auth::{self, AuthConfig, RcvSeq};
use corerouter_proto_bfd::packet::{MAX_LEN, Packet, State};
use corerouter_proto_bfd::session::{Config, Session};
use corerouter_proto_bfd::wheel::Wheel;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn fast() -> Config {
    Config {
        desired_min_tx: 50_000,
        required_min_rx: 50_000,
        ..Config::default()
    }
}

fn up_packet(your: u32) -> ([u8; MAX_LEN], usize) {
    let mut p = Packet::new(0x2222);
    p.state = State::Up;
    p.your_discr = your;
    p.desired_min_tx = 50_000;
    p.required_min_rx = 50_000;
    let mut out = [0u8; MAX_LEN];
    let n = p.encode(&mut out);
    (out, n)
}

fn codec(c: &mut Criterion) {
    let mut g = c.benchmark_group("bfd_codec");
    g.throughput(Throughput::Elements(1));
    let (raw, n) = up_packet(7);
    g.bench_function("decode", |b| {
        b.iter(|| Packet::decode(black_box(&raw[..n])).unwrap())
    });
    let p = Packet::decode(&raw[..n]).unwrap();
    g.bench_function("encode", |b| {
        let mut out = [0u8; MAX_LEN];
        b.iter(|| black_box(&p).encode(&mut out))
    });
    let a = AuthConfig::new(true, 1, b"bench-key").unwrap();
    g.bench_function("sha1_sign", |b| {
        let mut out = [0u8; MAX_LEN];
        let mut seq = 0u32;
        b.iter(|| {
            let mut q = p;
            seq = seq.wrapping_add(1);
            auth::sign(&mut q, &a, seq, &mut out)
        })
    });
    let mut q = p;
    let mut signed = [0u8; MAX_LEN];
    let sn = auth::sign(&mut q, &a, 5, &mut signed);
    let sp = Packet::decode(&signed[..sn]).unwrap();
    g.bench_function("sha1_verify", |b| {
        b.iter(|| auth::verify(black_box(&signed[..sn]), &sp, &a, RcvSeq::default()).unwrap())
    });
    g.finish();
}

fn session(c: &mut Criterion) {
    let mut g = c.benchmark_group("bfd_session");
    g.throughput(Throughput::Elements(1));
    // An Up session receiving its peer's periodic packet.
    let mut s = Session::new(7, fast(), 0, 1);
    let (raw, n) = up_packet(7);
    let p = Packet::decode(&raw[..n]).unwrap();
    let mut now = 1_000u64;
    s.receive(&raw[..n], &p, now).unwrap();
    g.bench_function("receive_up", |b| {
        b.iter(|| {
            now += 50_000;
            s.receive(&raw[..n], &p, now).unwrap()
        })
    });
    g.bench_function("build", |b| {
        let mut out = [0u8; MAX_LEN];
        b.iter(|| s.build(false, &mut out))
    });
    g.finish();

    // One second of a thread with 1 000 sessions at 50 ms: every timer
    // fires, the session builds its packet, the wheel takes the next.
    let mut g = c.benchmark_group("bfd_wheel");
    g.throughput(Throughput::Elements(20_000));
    g.sample_size(20);
    g.bench_function("1000_sessions_1s", |b| {
        b.iter_batched(
            || {
                let mut w = Wheel::new(1_000, 4096, 0);
                let mut ss: Vec<Session> = (0..1000u32)
                    .map(|i| Session::new(i + 1, fast(), 0, u64::from(i)))
                    .collect();
                for (i, s) in ss.iter_mut().enumerate() {
                    let (raw, n) = up_packet(i as u32 + 1);
                    let p = Packet::decode(&raw[..n]).unwrap();
                    s.receive(&raw[..n], &p, 0).unwrap();
                    w.insert(s.next_deadline().unwrap(), i as u32);
                }
                (w, ss)
            },
            |(mut w, mut ss)| {
                let mut due = Vec::new();
                let mut out = [0u8; MAX_LEN];
                let mut sent = 0u32;
                for t in (0..1_000_000u64).step_by(1_000) {
                    due.clear();
                    w.advance(t, &mut due);
                    for &k in &due {
                        let s = &mut ss[k as usize];
                        // Keep the peer alive: no detection expiry.
                        let (raw, n) = up_packet(k + 1);
                        let p = Packet::decode(&raw[..n]).unwrap();
                        let _ = s.receive(&raw[..n], &p, t);
                        let f = s.on_timer(t);
                        if f.send {
                            s.build(false, &mut out);
                            sent += 1;
                        }
                        if let Some(at) = s.next_deadline() {
                            w.insert(at, k);
                        }
                    }
                }
                black_box(sent)
            },
            criterion::BatchSize::LargeInput,
        )
    });
    g.finish();
}

criterion_group!(benches, codec, session);
criterion_main!(benches);
