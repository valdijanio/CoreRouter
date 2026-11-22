//! G0.3f: what grouping the "login without a password" warning costs, under
//! the session lock a login takes anyway. `ungrouped` is what every such
//! login did before (a line each); `repeat` is a login counted into its
//! group with one group and with the table full; `new_source_full_table` is
//! a login from a source never seen with the table full (the quietest group
//! leaves); `tick_full_table` is the once-a-second look at every group.

use std::hint::black_box;

use corerouter_engine::Session;
use corerouter_engine::logging::MAX_GROUPS;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

const TOPICS: &[&str] = &["system", "account", "warning"];

fn message(from: &str) -> String {
    format!("Login sem senha: usuário admin de {from} (tls); defina uma senha (user.set)")
}

fn detail(from: &str) -> Value {
    json!({"user": "admin", "address": from, "via": format!("tls {from}:45466"), "no_password": true})
}

fn full_table() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_000);
    for n in 0..MAX_GROUPS {
        let from = format!("10.0.{}.{}", n / 250, n % 250);
        s.log_event_grouped(
            &format!("auth.no_password admin {from}"),
            TOPICS,
            "auth",
            message(&from),
            detail(&from),
        );
    }
    s
}

fn bench(c: &mut Criterion) {
    let from = "192.168.0.180";
    let key = format!("auth.no_password admin {from}");

    let mut plain = Session::virtual_lab();
    plain.tick(1_000);
    c.bench_function("log_grouped/ungrouped", |b| {
        b.iter(|| plain.log_event(TOPICS, "auth", message(from), detail(from)));
    });

    let mut one = Session::virtual_lab();
    one.tick(1_000);
    c.bench_function("log_grouped/repeat", |b| {
        b.iter(|| {
            black_box(one.log_event_grouped(&key, TOPICS, "auth", message(from), detail(from)))
        });
    });

    let mut full = full_table();
    full.log_event_grouped(&key, TOPICS, "auth", message(from), detail(from));
    c.bench_function("log_grouped/repeat_full_table", |b| {
        b.iter(|| {
            black_box(full.log_event_grouped(&key, TOPICS, "auth", message(from), detail(from)))
        });
    });

    let mut flood = full_table();
    let mut n = 0u32;
    c.bench_function("log_grouped/new_source_full_table", |b| {
        b.iter(|| {
            n = n.wrapping_add(1);
            let from = format!("2001:db8:{:x}:{:x}::", n >> 16, n & 0xffff);
            let key = format!("auth.no_password admin {from}");
            black_box(flood.log_event_grouped(&key, TOPICS, "auth", message(&from), detail(&from)))
        });
    });

    let mut ticking = full_table();
    c.bench_function("log_grouped/tick_full_table", |b| {
        // The same second: every window stays open, as in all but one tick
        // in thirty.
        b.iter(|| ticking.tick(black_box(1_001)));
    });
    let mut idle = Session::virtual_lab();
    idle.tick(1_000);
    c.bench_function("log_grouped/tick_no_group", |b| {
        b.iter(|| idle.tick(black_box(1_001)));
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
