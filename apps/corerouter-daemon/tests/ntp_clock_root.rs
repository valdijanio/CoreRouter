//! G4.6b: the daemon sets a real clock, as root, in the lab VM only: step,
//! slew, the refusal above 1000 s and its confirmation. The clock goes back
//! where it was at the end, even when the test fails.
//!
//! ```sh
//! cargo xtask vm-lab run -- 'systemctl stop systemd-timesyncd chrony; \
//!     COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-daemon --test ntp_clock_root -- --nocapture'
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::*;
use corerouter_hal::clock::SystemClock;
use corerouter_hal_linux::clock::LinuxClock;
use corerouter_proto_ntp::{MODE_SERVER, Packet, Timestamp};
use rustix::time::{ClockId, clock_gettime};
use serde_json::{Value, json};

const PORT: &str = "7984";
const MS: i64 = 1_000_000;
const SEC: i64 = 1_000 * MS;

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn daemon(dir: &Path) -> Kill {
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(common::token_file(None, dir))
    .env("RUST_LOG", "info")
    // G4.6m: the boot's first-step mark of this run only (the first sample,
    // 2 s, spends it; the 1100 s after it must still ask).
    .env("COREROUTER_RUNTIME_DIR", dir)
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    let d = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());
    d
}

fn raw() -> i128 {
    let t = clock_gettime(ClockId::MonotonicRaw);
    i128::from(t.tv_sec) * 1_000_000_000 + i128::from(t.tv_nsec)
}

fn wall() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i128
}

/// Wall clock minus the crystal: moves only with the clock's corrections.
fn gap() -> i128 {
    wall() - raw()
}

/// A server on the crystal: it does not follow the clock under test, so its
/// offset to that clock is exactly what the test says.
fn server(skew: Arc<AtomicI64>, reference_gap: i128) {
    let sock = UdpSocket::bind("127.0.0.1:123").unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 128];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Packet::decode(&buf[..n]) else {
                continue;
            };
            let now = raw() + reference_gap + i128::from(skew.load(Ordering::Relaxed));
            let now = Timestamp::from_unix_nanos(now);
            let reply = Packet {
                version: 4,
                mode: MODE_SERVER,
                stratum: 2,
                reference_id: *b"TEST",
                origin: req.transmit,
                receive: now,
                transmit: now,
                ..Packet::default()
            };
            let _ = sock.send_to(&reply.encode(), from);
        }
    });
}

/// Puts the clock back, whatever happens.
struct Restore(i128);

impl Drop for Restore {
    fn drop(&mut self) {
        let mut clock = LinuxClock::realtime();
        let _ = clock.set_frequency_ppm(0.0);
        let _ = clock.step(i64::try_from(self.0 - gap()).unwrap_or(0));
    }
}

fn status() -> Value {
    run("system.ntp.client.get", json!({})).unwrap()
}

/// A config change makes the client ask at once.
fn ask_now(poll: &mut u32) {
    *poll = if *poll == 10 { 11 } else { 10 };
    run("system.ntp.client.set", json!({"max_poll": *poll})).unwrap();
}

#[test]
fn the_daemon_steps_slews_and_asks() {
    if std::env::var_os("COREROUTER_CLOCK_ROOT").is_none_or(|v| v != "1") {
        eprintln!("skipped: lab VM only, set COREROUTER_CLOCK_ROOT=1");
        return;
    }
    let start = gap();
    let _restore = Restore(start);
    let skew = Arc::new(AtomicI64::new(2 * SEC));
    server(skew.clone(), start);
    let dir = std::env::temp_dir().join(format!("crclock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _daemon = daemon(&dir);
    let moved = || (gap() - start) as f64 / 1e6;

    // First answer, 2 s: a step (RFC 5905 §11.3, NSET).
    run(
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["127.0.0.1"]}),
    )
    .unwrap();
    wait_for("the step", || status()["clock"] == "stepped");
    eprintln!("moved {:.3} ms, status {}", moved(), status());
    assert!((moved() - 2000.0).abs() < 10.0, "moved {} ms", moved());
    assert!(status()["clock_error"].is_null(), "{}", status());

    // 3 ms: a slew. At 16 s it has taken it all, and the frequency is back.
    let mut poll = 10;
    skew.store(2 * SEC + 3 * MS, Ordering::Relaxed);
    ask_now(&mut poll);
    wait_for("the slew", || status()["clock"] == "slewing");
    let clock = LinuxClock::realtime();
    let during = clock.frequency_ppm().unwrap();
    eprintln!("slewing at {during} ppm: {}", status());
    assert!(during > 100.0, "{during}");
    std::thread::sleep(Duration::from_secs(18));
    let after = clock.frequency_ppm().unwrap();
    assert!(after.abs() < 5.0, "{after} ppm after the slew");
    eprintln!("moved {:.3} ms after the slew", moved());
    assert!((moved() - 2003.0).abs() < 1.5, "moved {} ms", moved());

    // 1100 s more: nothing moves until the operator says so.
    skew.store(1102 * SEC, Ordering::Relaxed);
    let before = moved();
    ask_now(&mut poll);
    wait_for("the question", || {
        status()["clock"] == "awaiting-confirmation"
    });
    let st = status();
    eprintln!("awaiting: {st}");
    assert!(
        (st["pending_step_ms"].as_f64().unwrap() - 1_099_997.0).abs() < 100.0,
        "{st}"
    );
    assert!((moved() - before).abs() < 2.0);
    run("system.ntp.client.confirm-step", json!({})).unwrap();
    ask_now(&mut poll);
    wait_for("the confirmed step", || status()["clock"] == "stepped");
    eprintln!("moved {:.3} ms after the confirmation", moved());
    assert!((moved() - 1_102_000.0).abs() < 20.0, "moved {} ms", moved());
    assert!(status()["pending_step_ms"].is_null());

    // Off: the frequency stays at the drift.
    run("system.ntp.client.set", json!({"enabled": false})).unwrap();
    wait_for("stopped", || status()["status"] == "stopped");
    assert!(clock.frequency_ppm().unwrap().abs() < 5.0);
}
